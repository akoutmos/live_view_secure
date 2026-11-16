defmodule LiveViewSecure.Security.ProtocolTest do
  @moduledoc """
  Red-team tests at the LiveView wire-protocol level.

  Harness: a real Phoenix endpoint (Bandit) with a production-shaped router
  (session cookie, CSRF, live routes, a live_session), a dead render fetched
  over real HTTP, and a real websocket (WebSockex) speaking the V2 JSON
  protocol by hand: `[join_ref, ref, topic, event, payload]`. No LiveViewTest
  helpers are involved in sending anything, so these payloads are exactly what
  a hostile client can put on the wire.

  Every test asserts the SECURE behavior: a failing test is a vulnerability.
  The last describe block records behavior that is a documented limitation
  or plain LiveView behavior; those tests assert what actually happens and
  say so in their names.
  """
  use ExUnit.Case, async: false
  import ExUnit.CaptureLog

  alias LiveViewSecure.Test.Protocol.{Endpoint, Recorder, Wire}

  @moduletag :capture_log

  setup_all do
    port = Endpoint.start!(&start_supervised!/1)
    start_supervised!(Recorder)
    %{port: port}
  end

  setup do
    Recorder.reset()
    :ok
  end

  defp recorded(where), do: for({^where, event, params} <- Recorder.all(), do: {event, params})

  # Bandit logs a crashed request around the time it sends the 500.
  defp wait_for_log(result) do
    Process.sleep(100)
    result
  end

  ## Join

  describe "join: where the hook gets attached" do
    # on_mount/4 refuses to run unless the module itself declares
    # {LiveViewSecure, opts}, so the dead render fails and no session token is
    # ever issued for such a page.
    test "a live_session-only LiveViewSecure hook is refused at the dead render",
         %{port: port} do
      {status, log} = with_log(fn -> wait_for_log(Wire.http_status(port, "/session-guarded")) end)
      assert status == 500
      assert log =~ "(ArgumentError) on_mount {LiveViewSecure, ...} must be declared in"
      assert log =~ "LiveViewSecure.Test.Protocol.SessionGuardedLive itself"
    end

    test "a live_session declaring LiveViewSecure with other opts than the module is refused",
         %{port: port} do
      {status, log} = with_log(fn -> wait_for_log(Wire.http_status(port, "/mismatch")) end)
      assert status == 500
      assert log =~ "must be declared in LiveViewSecure.Test.Protocol.MismatchLive itself"
    end

    test "a live_session declaring exactly the module's opts is refused too (double attach)",
         %{port: port} do
      {status, log} = with_log(fn -> wait_for_log(Wire.http_status(port, "/same-opts")) end)
      assert status == 500
      assert log =~ "LiveViewSecure.attach/2 was called twice on the same socket"
    end

    test "no join rewrite skips a module-level hook: cross-session url, redirects, static, sticky",
         %{port: port} do
      rewrites = [
        &Map.put(&1, "url", "http://localhost:#{port}/admin"),
        &(&1 |> Map.delete("url") |> Map.put("redirect", "http://localhost:#{port}/admin")),
        &(&1 |> Map.delete("url") |> Map.put("redirect", "http://localhost:#{port}/hooked")),
        &Map.put(&1, "static", nil),
        &Map.put(&1, "sticky", true)
      ]

      for rewrite <- rewrites do
        page = Wire.get_page!(port, "/app-hooked")

        case Wire.join(Wire.connect!(page), page, payload: rewrite) do
          {:ok, conn} ->
            {_, conn} = Wire.event(conn, "click", "delete_user", %{"id" => "5"})
            {_, _} = Wire.event(conn, "click", "app_action", %{"id" => "5"})

          {:error, _refused} ->
            :ok
        end
      end

      for where <- [:app_hooked, :hooked_live, :session_hook, :early_hook] do
        assert recorded(where) == [], "#{where} saw a forged event"
      end
    end

    test "an event pipelined right behind phx_join is still verified", %{port: port} do
      page = Wire.get_page!(port, "/admin")
      ws = Wire.connect!(page)
      topic = "lv:" <> page.id

      Wire.send_msg(ws, ["1", "1", topic, "phx_join", Wire.default_join_payload(page)])
      forged = %{"type" => "click", "event" => "delete_user", "value" => %{"id" => "5"}}
      Wire.send_msg(ws, ["1", "2", topic, "event", forged])

      assert {:reply, %{"status" => "ok"}} = Wire.await(ws, topic, "1")
      assert {:reply, %{"status" => "ok"}} = Wire.await(ws, topic, "2")
      assert recorded(:admin) == []
    end

    test "events on a topic that was never joined, or after phx_leave, reach nothing",
         %{port: port} do
      page = Wire.get_page!(port, "/admin")
      ws = Wire.connect!(page)
      forged = %{"type" => "click", "event" => "delete_user", "value" => %{"id" => "5"}}

      Wire.send_msg(ws, ["1", "2", "lv:" <> page.id, "event", forged])
      assert {:reply, %{"status" => "error"}} = Wire.await(ws, "lv:" <> page.id, "2")

      {:ok, conn} = Wire.join(ws, page)
      {_left, conn} = Wire.push(conn, "phx_leave", %{})
      {result, _} = Wire.push(conn, forged)
      assert result in [:crashed, {:error, %{"reason" => "unmatched topic"}}]
      assert recorded(:admin) == []
    end
  end

  ## Event types and value shapes

  describe "event types and value decoding" do
    test "a signed click sent over the wire reaches the handler with exactly the signed values",
         %{port: port} do
      conn = Wire.open!(port, "/admin")
      values = Wire.phx_values(conn, "#delete-7")

      {{:ok, _}, _} = Wire.event(conn, "click", "delete_user", Map.put(values, "value", ""))
      assert [{"delete_user", %{"id" => "7", "__sig" => _, "value" => ""}}] = recorded(:admin)
    end

    test "forged payloads are rejected for every event type the channel accepts",
         %{port: port} do
      types = ~w(click keyup keydown blur focus hook submit change window zzz) ++ ["", nil, 1]

      for type <- types do
        # Fresh process per type, so a crash in one can't hide the others.
        conn = Wire.open!(port, "/admin")
        %{"__sig" => tok7} = Wire.phx_values(conn, "#delete-7")

        {r1, conn} = Wire.event(conn, type, "delete_user", %{"id" => "5"})
        {r2, conn} = Wire.event(conn, type, "delete_user", %{"id" => "5", "__sig" => tok7})

        {r3, conn} =
          Wire.event(conn, type, "delete_user", %{"id" => "7", "__sig" => tok7, "x" => "1"})

        {r4, _} = Wire.event(conn, type, "archive", %{"id" => "5"})

        # on_failure: :halt, so the process must have survived every rejection.
        assert Enum.all?([r1, r2, r3, r4], &match?({:ok, _}, &1)), "type #{inspect(type)}"
      end

      assert recorded(:admin) == []

      # Positive control for the oracle: the genuine payload does get through.
      conn = Wire.open!(port, "/admin")
      {{:ok, _}, _} = Wire.event(conn, "click", "delete_user", Wire.phx_values(conn, "#delete-7"))
      assert [{"delete_user", %{"id" => "7"}}] = recorded(:admin)
    end

    test "unsigned-param policies hold on the wire (signed_push and key events)", %{port: port} do
      conn = Wire.open!(port, "/admin")
      {"archive", archive} = Wire.pushed(conn, "#archive-7")
      search = Wire.phx_values(conn, "#search")

      conn =
        Enum.reduce(
          [
            {"archive", Map.delete(archive, "scope")},
            {"archive", Map.put(archive, "scope", "everything")},
            {"archive", Map.put(archive, "value", "x")},
            {"search", Map.put(search, "scope", "admins")},
            {"search", Map.merge(search, %{"key" => "a", "value" => "b", "extra" => "1"})}
          ],
          conn,
          fn {event, value}, conn ->
            {{:ok, _}, conn} = Wire.event(conn, "keyup", event, value)
            conn
          end
        )

      assert recorded(:admin) == []

      # ["key", "value"] are let through for "search", with any content (documented).
      {{:ok, _}, _} =
        Wire.event(conn, "keyup", "search", Map.merge(search, %{"key" => "a", "value" => %{}}))

      assert [{"search", %{"scope" => "users", "value" => %{}}}] = recorded(:admin)
    end

    test "every shape of \"value\" is rejected under events: :all unless it is the signed map",
         %{port: port} do
      conn = Wire.open!(port, "/hook")
      %{"__sig" => tok, "by" => "1"} = Wire.phx_values(conn, "#inc")

      bad_values = [
        "1",
        ["1"],
        nil,
        1,
        1.5,
        true,
        %{},
        %{"by" => "1"},
        %{"by" => 1, "__sig" => tok},
        %{"by" => 1.0, "__sig" => tok},
        %{"by" => nil, "__sig" => tok},
        %{"by" => ["1"], "__sig" => tok},
        %{"by" => %{"0" => "1"}, "__sig" => tok},
        %{"by" => "1 ", "__sig" => tok},
        %{"by" => "01", "__sig" => tok},
        %{"by" => "1", "__sig" => [tok]},
        %{"by" => "1", "__sig" => %{"a" => tok}},
        %{"by" => "1", "__sig" => nil},
        %{"by" => "1", "__sig" => tok <> " "},
        %{"by" => "1", "__sig" => " " <> tok},
        %{"by" => "1", "__sig" => tok <> "="},
        %{"by" => "1", "__sig" => tok, "x" => nil},
        %{"by" => "1", "__sig" => tok, "value" => nil},
        # Round 2 made integer 0 benign (an <li>'s DOM value). Its look-alikes aren't.
        %{"by" => "1", "__sig" => tok, "value" => 0.0},
        %{"by" => "1", "__sig" => tok, "value" => "0"},
        %{"by" => "1", "__sig" => tok, "value" => 1},
        %{"by" => "1", "__sig" => tok, "value" => -1},
        %{"by" => "1", "__sig" => tok, "value" => [0]},
        %{"by" => "1", "__sig" => tok, "value" => false},
        %{"by" => "1", "__sig" => tok, "value" => []},
        %{"by" => "1", "__sig" => tok, "value" => " "},
        %{"by" => "1", "__sig" => tok, "" => ""},
        %{"by" => "1", "__sig" => tok, "By" => "1"}
      ]

      conn =
        Enum.reduce(bad_values, conn, fn value, conn ->
          {{:ok, _}, conn} = Wire.event(conn, "click", "inc", value)
          conn
        end)

      assert recorded(:hook_live) == []

      # And the genuine article still works.
      {{:ok, _}, conn} = Wire.event(conn, "click", "inc", %{"by" => "1", "__sig" => tok})

      {{:ok, _}, conn} =
        Wire.event(conn, "hook", "inc", %{"by" => "1", "__sig" => tok, "value" => ""})

      # Intended round-2 change: "value" => 0 is the benign DOM value of an <li>.
      {{:ok, _}, _} =
        Wire.event(conn, "click", "inc", %{"by" => "1", "__sig" => tok, "value" => 0})

      assert [{"inc", _}, {"inc", _}, {"inc", %{"value" => 0}}] = recorded(:hook_live)
    end

    test "[:all, {name, opts}]: a per-event rule only loosens that event", %{port: port} do
      conn = Wire.open!(port, "/hook")
      kb = Wire.phx_values(conn, "#kb")
      inc = Wire.phx_values(conn, "#inc")

      cases = [
        {"inc", Map.put(inc, "key", "a")},
        {"kb", %{"scope" => "k", "key" => "a"}},
        {"kb", Map.merge(kb, %{"key" => "a", "value" => "x"})},
        {"kb", Map.put(kb, "scope", "z")},
        {"validate", Map.put(kb, "scope", "z")}
      ]

      conn =
        Enum.reduce(cases, conn, fn {event, value}, conn ->
          {{:ok, _}, conn} = Wire.event(conn, "keyup", event, value)
          conn
        end)

      # "validate" is in :except, so it passes unverified (documented).
      assert [{"validate", _}] = recorded(:hook_live)

      {{:ok, _}, _} = Wire.event(conn, "keyup", "kb", Map.put(kb, "key", "Enter"))
      assert [{"validate", _}, {"kb", %{"key" => "Enter", "scope" => "k"}}] = recorded(:hook_live)
    end

    test "a JS hook's pushEvent payload is verified like any other", %{port: port} do
      conn = Wire.open!(port, "/hook")
      {"pull", %{"n" => "1", "__sig" => tok}} = Wire.pushed(conn, "#hook", "data-push")

      {_, conn} = Wire.event(conn, "hook", "pull", %{"n" => "2", "__sig" => tok})
      {_, conn} = Wire.event(conn, "hook", "pull", %{"n" => 1, "__sig" => tok})
      {_, conn} = Wire.event(conn, "hook", "pull", [%{"n" => "1", "__sig" => tok}])
      assert recorded(:hook_live) == []

      {{:ok, _}, _} = Wire.event(conn, "hook", "pull", %{"n" => "1", "__sig" => tok})
      assert [{"pull", %{"n" => "1"}}] = recorded(:hook_live)
    end

    test "urlencoded \"form\" payloads: duplicates, nesting, empty names, meta and _target",
         %{port: port} do
      conn = Wire.open!(port, "/admin")
      %{"__sig" => tok7} = Wire.phx_values(conn, "#delete-7")
      t = URI.encode_www_form(tok7)

      # {urlencoded value, extra top-level payload, expected}. :reach means the
      # handler may run, but only with id "7".
      cases = [
        {"id=7&__sig=#{t}", %{}, :reach},
        {"i%64=7&__sig=#{t}", %{}, :reach},
        {"id=5&id=7&__sig=#{t}", %{}, :reach},
        {"id=7&id=5&__sig=#{t}", %{}, :reject},
        {"id[]=7&__sig=#{t}", %{}, :reject},
        {"id[x]=7&__sig=#{t}", %{}, :reject},
        {"id=7&id[]=5&__sig=#{t}", %{}, :reject},
        {"id=7&__sig[]=#{t}", %{}, :reject},
        {"id=7&__sig[a]=", %{}, :reject},
        {"id=7&__sig=#{t}&__sig=x", %{}, :reject},
        {"id=7&__sig=#{t}&=x", %{}, :reject},
        {"id=7&__sig=#{t}&id%00=5", %{}, :reject},
        {"id=7&__sig=#{t}&_target=id", %{}, :reject},
        {"id=7&__sig=#{t}&value=5", %{}, :reject},
        {"id=7&__sig=#{t}", %{"meta" => %{"id" => "5"}}, :reject},
        {"id=7&__sig=#{t}", %{"meta" => %{"id" => 7}}, :reject},
        {"id=7&__sig=#{t}", %{"meta" => %{"admin" => "true"}}, :reject},
        {"id=7", %{"meta" => %{"__sig" => tok7}}, :reach},
        {"id=7&__sig=#{t}", %{"meta" => %{"__sig" => "x"}}, :reject}
      ]

      Enum.reduce(cases, conn, fn {urlencoded, extra, expected}, conn ->
        Recorder.reset()
        {_, conn} = Wire.event(conn, "form", "delete_user", urlencoded, extra)
        got = recorded(:admin)

        case expected do
          :reject ->
            assert got == [],
                   "#{urlencoded} #{inspect(extra)} reached the handler: #{inspect(got)}"

          :reach ->
            assert [{"delete_user", params}] = got
            assert Map.delete(params, "__sig") == %{"id" => "7"}
        end

        conn
      end)
    end

    test "form tokens (unsigned: :allow) still pin every signed field", %{port: port} do
      conn = Wire.open!(port, "/admin")
      tok = Wire.attr(conn, "#post-form input[name=__sig]", "value")
      t = URI.encode_www_form(tok)
      # Round 2: the "new" form's token signs no keys; `signed: ["id"]` must stop
      # a client from adding "id" next to it as an unsigned param.
      new_t = conn |> Wire.attr("#new-form input[name=__sig]", "value") |> URI.encode_www_form()

      cases = [
        {"id=7&__sig=#{t}&title=x", %{}},
        {"id=99&id=7&__sig=#{t}", %{}},
        {"id[]=99&__sig=#{t}", %{}},
        {"id[a]=99&__sig=#{t}", %{}},
        {"__sig=#{t}&title=x", %{}},
        {"id=99&__sig=#{t}", %{"meta" => %{"id" => "7"}}},
        {"id=99&__sig=#{t}", %{"meta" => %{"id" => ["99"]}}},
        {"id=7&__sig=#{new_t}&title=x", %{}},
        {"i%64=7&__sig=#{new_t}", %{}},
        {"id[]=7&__sig=#{new_t}", %{}},
        {"id[x]=7&__sig=#{new_t}", %{}},
        {"id=&__sig=#{new_t}", %{}},
        {"__sig=#{new_t}&title=x", %{"meta" => %{"id" => "7"}}},
        {"__sig=#{new_t}&title=x", %{"meta" => %{"id" => nil}}}
      ]

      conn =
        Enum.reduce(cases, conn, fn {urlencoded, extra}, conn ->
          {{:ok, _}, conn} = Wire.event(conn, "form", "save", urlencoded, extra)
          conn
        end)

      assert recorded(:admin) == []

      # :allow means extra params ride along (documented), but id stays 99.
      {{:ok, _}, conn} =
        Wire.event(conn, "form", "save", "id=7&id=99&__sig=#{t}&title=x&role[admin]=1")

      assert [{"save", %{"id" => "99", "title" => "x", "role" => %{"admin" => "1"}}}] =
               recorded(:admin)

      # And the "new" form works as long as nobody adds an id.
      Recorder.reset()
      {{:ok, _}, _} = Wire.event(conn, "form", "save", "__sig=#{new_t}&title=y")
      assert [{"save", params}] = recorded(:admin)
      refute Map.has_key?(params, "id")
    end

    test "duplicate keys inside the raw JSON frame can't smuggle a second value",
         %{port: port} do
      conn = Wire.open!(port, "/admin")
      %{"__sig" => tok7} = Wire.phx_values(conn, "#delete-7")
      topic = conn.topic

      for {ref, value_json} <- [
            {"500", ~s({"id":"5","id":"7","__sig":"#{tok7}"})},
            {"501", ~s({"id":"7","id":"5","__sig":"#{tok7}"})},
            {"502", ~s({"id":"7","__sig":"#{tok7}","__sig":"x"})}
          ] do
        raw =
          ~s(["1","#{ref}","#{topic}","event",{"type":"click","event":"delete_user","value":#{value_json}}])

        :ok = LiveViewSecure.Test.Protocol.Client.send_text(conn.ws, raw)
        assert {:reply, _} = Wire.await(conn.ws, topic, ref)
      end

      # Whatever the JSON decoder keeps, the hook and the handler see the same
      # map, so the handler only ever gets the signed id.
      for {"delete_user", params} <- recorded(:admin) do
        assert params["id"] == "7"
      end
    end

    test "event names that only look like a declared one never reach its clause",
         %{port: port} do
      conn = Wire.open!(port, "/exact")
      %{"__sig" => tok7} = Wire.phx_values(conn, "#delete-7")

      lookalikes =
        [
          "Delete_user",
          "DELETE_USER",
          "delete_user ",
          " delete_user",
          "delete_user\n",
          "delete_user\t",
          "delete_user\u0000",
          "delete_user​",
          "dеlete_user",
          "delete＿user",
          "delete-user",
          ["delete_user"],
          %{"delete_user" => true},
          1,
          nil,
          true
        ]

      Enum.reduce(lookalikes, conn, fn name, conn ->
        {{:ok, _}, conn} = Wire.event(conn, "click", name, %{"id" => "5"})
        {{:ok, _}, conn} = Wire.event(conn, "click", name, %{"id" => "5", "__sig" => tok7})
        conn
      end)

      assert recorded(:exact) == []
      # They did reach the app, just not the "delete_user" clause: undeclared
      # names aren't the hook's business, and Elixir matches names byte for byte.
      assert length(recorded(:exact_fallback)) == 2 * length(lookalikes)
    end

    test "under events: :all, look-alike and non-string event names are rejected too",
         %{port: port} do
      conn = Wire.open!(port, "/hook")

      Enum.reduce(
        ["Validate", "validate ", "validate\u0000", ["validate"], nil, 1, %{"a" => 1}, "inc"],
        conn,
        fn name, conn ->
          {{:ok, _}, conn} = Wire.event(conn, "click", name, %{"by" => "1"})
          conn
        end
      )

      assert recorded(:hook_live) == []
    end

    test "\"lv:\" events never reach hooks or handlers", %{port: port} do
      conn = Wire.open!(port, "/admin")
      {{:ok, _}, conn} = Wire.event(conn, "click", "lv:clear-flash", %{"key" => "info"})
      {result, _} = Wire.event(conn, "click", "lv:delete_user", %{"id" => "5"})
      assert result == :crashed
      assert recorded(:admin) == []
    end
  end

  ## cid targeting

  describe "cid targeting" do
    test "a component's own signed event works when sent to its cid", %{port: port} do
      conn = Wire.open!(port, "/components")
      cid = Wire.cid(conn, "#secure")
      values = Wire.phx_values(conn, "#secure-remove")

      {{:ok, _}, _} = Wire.event(conn, "click", "remove", values, %{"cid" => cid})
      assert [{"remove", %{"item" => "s1"}}] = recorded(:secure_component)
    end

    test "tokens don't cross between a LiveView and its hooked component", %{port: port} do
      conn = Wire.open!(port, "/components")
      secure_cid = Wire.cid(conn, "#secure")
      parent_values = Wire.phx_values(conn, "#parent-remove")
      component_values = Wire.phx_values(conn, "#secure-remove")

      # Parent's token retargeted at the component.
      {_, conn} = Wire.event(conn, "click", "remove", parent_values, %{"cid" => secure_cid})
      # Component's token with the cid dropped (so the parent handles it).
      {_, conn} = Wire.event(conn, "click", "remove", component_values)
      {_, conn} = Wire.event(conn, "click", "remove", component_values, %{"cid" => nil})
      {_, _} = Wire.event(conn, "click", "remove", component_values, %{"cid" => false})

      assert recorded(:secure_component) == []
      assert recorded(:components_parent) == []
    end

    test "a token from one instance of a hooked component is rejected by another instance",
         %{port: port} do
      conn = Wire.open!(port, "/components")
      values = Wire.phx_values(conn, "#secure-remove")
      other_cid = Wire.cid(conn, "#secure2")

      {{:ok, _}, _} = Wire.event(conn, "click", "remove", values, %{"cid" => other_cid})
      assert recorded(:secure_component) == []
    end

    test "nonexistent or malformed cids never reach a handler", %{port: port} do
      for cid <- [999_999, -1, 0, 1.5, "1", "#secure", [1], %{"cid" => 1}, true] do
        conn = Wire.open!(port, "/components")
        cid = if cid == "#secure", do: Integer.to_string(Wire.cid(conn, "#secure")), else: cid
        Wire.event(conn, "click", "remove", %{"item" => "zzz"}, %{"cid" => cid})
      end

      assert Recorder.all() == []
    end
  end

  ## Nested LiveViews and live_patch

  describe "nested LiveViews and live_patch" do
    test "a nested LiveView with its own on_mount has its own key", %{port: port} do
      parent = Wire.open!(port, "/nested")
      {:ok, child} = Wire.join_child(parent, "child-guarded")

      parent_values = Wire.phx_values(parent, "#parent-remove")
      child_values = Wire.phx_values(child, "#child-remove")

      {_, child} = Wire.event(child, "click", "remove", parent_values)
      {_, parent} = Wire.event(parent, "click", "remove", child_values)
      assert Recorder.all() == []

      {{:ok, _}, _} = Wire.event(child, "click", "remove", child_values)
      {{:ok, _}, _} = Wire.event(parent, "click", "remove", parent_values)
      assert [{"remove", %{"item" => "c1"}}] = recorded(:nested_guarded)
      assert [{"remove", %{"item" => "p0"}}] = recorded(:nested_parent)
    end

    test "the hook is still attached after live_patch", %{port: port} do
      conn = Wire.open!(port, "/patch")
      url = "http://localhost:#{port}/patch?page=2"
      {{:ok, _}, conn} = Wire.push(conn, "live_patch", %{"url" => url})

      {_, conn} = Wire.event(conn, "click", "goto", %{"page" => "9"})
      assert recorded(:patch_live) == []

      values = Wire.phx_values(conn, "#next")
      assert values["page"] == "2"
      {{:ok, _}, _} = Wire.event(conn, "click", "goto", values)
      assert [{"goto", %{"page" => "2"}}] = recorded(:patch_live)
    end
  end

  ## The existing fixtures, over the wire

  describe "existing fixtures over a real socket" do
    test "UsersLive: the README's PoC attacks fail on the wire as well", %{port: port} do
      for forged <- [
            fn _c -> %{"id" => "5"} end,
            fn c -> %{"id" => "5", "__sig" => Wire.phx_values(c, "#view-5")["__sig"]} end,
            fn c -> %{"id" => "5", "__sig" => Wire.phx_values(c, "#delete-7")["__sig"]} end,
            fn c -> Map.put(Wire.phx_values(c, "#delete-7"), "force", "true") end
          ] do
        conn = Wire.open!(port, "/users")
        assert {:crashed, _} = Wire.event(conn, "click", "delete_user", forged.(conn))
      end
    end

    test "CartLive: a component's token can't be reused for another item", %{port: port} do
      conn = Wire.open!(port, "/cart")
      cid = Wire.cid(conn, "#cart")
      values = Wire.phx_values(conn, "#remove-b")

      assert {:crashed, _} =
               Wire.event(conn, "click", "remove", Map.put(values, "item", "z"), %{"cid" => cid})
    end
  end

  ## Round 2: the new mechanisms, over the wire

  describe "round 2: hook ordering" do
    @hooks [:session_hook, :early_hook, :mount_hook, :params_hook, :hooked_live]

    test "a forged event reaches no :handle_event hook, whether attached before or after the verifier",
         %{port: port} do
      conn = Wire.open!(port, "/hooked")
      delete = Wire.phx_values(conn, "#delete-7")
      app = Wire.phx_values(conn, "#app-action")

      forged = [
        {"delete_user", %{"id" => "5"}},
        {"app_action", %{"id" => "5"}},
        {"app_action", delete},
        {"delete_user", app},
        {"app_action", Map.put(app, "id", "5")},
        {"app_action", Map.put(app, "x", "1")}
      ]

      # Pipelined, so nothing between the frames could re-order hooks.
      {results, conn} =
        Wire.pipeline(
          conn,
          for({e, v} <- forged, do: %{"type" => "click", "event" => e, "value" => v})
        )

      assert Enum.all?(results, &match?({:ok, _}, &1))
      for where <- @hooks, do: assert(recorded(where) == [], "#{where} saw a forged event")

      # Positive control: a genuine event reaches every hook, verifier first.
      {{:ok, _}, conn} = Wire.event(conn, "click", "delete_user", delete)
      for where <- @hooks, do: assert([{"delete_user", ^delete}] = recorded(where))

      # A genuine app_action is halted by the app's own (earliest) hook, as written.
      {{:ok, _}, _} = Wire.event(conn, "click", "app_action", app)
      assert [_, {"app_action", ^app}] = recorded(:session_hook)
      assert [{"delete_user", _}] = recorded(:hooked_live)
    end

    test "hooks still come after the verifier after a live_patch re-runs handle_params",
         %{port: port} do
      conn = Wire.open!(port, "/hooked")
      {{:ok, _}, conn} = Wire.push(conn, "live_patch", %{"url" => conn.page.url <> "?x=1"})
      {{:ok, _}, _} = Wire.event(conn, "click", "app_action", %{"id" => "5"})
      for where <- @hooks, do: assert(recorded(where) == [], "#{where} saw a forged event")
    end
  end

  describe "round 2: single_use over the raw socket" do
    test "a single-use token works once, even when the same frame is pipelined 6 times",
         %{port: port} do
      conn = Wire.open!(port, "/bank")
      t100 = Wire.phx_values(conn, "#transfer-100")
      click = %{"type" => "click", "event" => "transfer", "value" => t100}

      {results, conn} = Wire.pipeline(conn, List.duplicate(click, 6))

      # Replays are :revoked, which is dropped without raising (on_failure: :raise here).
      refute :crashed in results
      assert [{"transfer", %{"amount" => "100"}}] = recorded(:bank)

      # The accepted one re-rendered the buttons; no replay caused a re-render.
      assert [{:ok, %{"diff" => _}} | replays] = results
      assert Enum.all?(replays, &(&1 == {:ok, %{}})), inspect(replays)
      assert Wire.unsolicited_diffs(conn) == []

      # The fresh token works exactly once more.
      t100_again = Wire.phx_values(conn, "#transfer-100")
      assert t100_again["__sig"] != t100["__sig"]
      {_, _} = Wire.pipeline(conn, List.duplicate(%{click | "value" => t100_again}, 3))
      assert [_, _] = recorded(:bank)
    end

    test "accepting one single-use event re-issues only that pair's token, and its replay is dropped",
         %{port: port} do
      conn = Wire.open!(port, "/bank")
      t100 = Wire.phx_values(conn, "#transfer-100")

      payloads =
        for {event, sel} <- [
              {"transfer", "#transfer-100"},
              {"transfer", "#transfer-5"},
              {"noop", "#noop"}
            ] do
          %{"type" => "click", "event" => event, "value" => Wire.phx_values(conn, sel)}
        end

      # Other pairs rendered at the same time (other rows, stream items, clicks
      # in flight) keep working after the single-use accept...
      {results, conn} = Wire.pipeline(conn, payloads)
      refute :crashed in results

      assert [
               {"transfer", %{"amount" => "100"}},
               {"transfer", %{"amount" => "5"}},
               {"noop", _}
             ] = recorded(:bank)

      # ...while the used token is dead: replays are dropped, never handled twice.
      {results, _conn} =
        Wire.pipeline(
          conn,
          List.duplicate(%{"type" => "click", "event" => "transfer", "value" => t100}, 3)
        )

      refute :crashed in results
      assert length(recorded(:bank)) == 3
    end

    test "a rejoin pipelined between two uses of the token doesn't give it a second life",
         %{port: port} do
      conn = Wire.open!(port, "/bank")
      t100 = Wire.phx_values(conn, "#transfer-100")
      click = %{"type" => "click", "event" => "transfer", "value" => t100}
      join = Wire.default_join_payload(conn.page)

      # Use, rejoin the same topic with the same session token (a new process),
      # use again, and a third time on the new join_ref, all in one burst.
      for frame <- [
            ["1", "10", conn.topic, "event", click],
            ["2", "11", conn.topic, "phx_join", join],
            ["2", "12", conn.topic, "event", click],
            ["2", "13", conn.topic, "event", click]
          ],
          do: Wire.send_msg(conn.ws, frame)

      # Let everything land, then count.
      Process.sleep(300)
      assert [{"transfer", %{"amount" => "100"}}] = recorded(:bank)
    end

    test "a used token with tampered values is an invalid signature, not a :revoked drop",
         %{port: port} do
      conn = Wire.open!(port, "/bank")
      t100 = Wire.phx_values(conn, "#transfer-100")
      {{:ok, _}, conn} = Wire.event(conn, "click", "transfer", t100)

      assert {:crashed, _} =
               Wire.event(conn, "click", "transfer", Map.put(t100, "amount", "100000"))

      assert [{"transfer", %{"amount" => "100"}}] = recorded(:bank)
    end

    test "single-use in a component: once per token, and the LiveView's tokens are untouched",
         %{port: port} do
      conn = Wire.open!(port, "/bank")
      cid = Wire.cid(conn, "#items")

      take = %{
        "type" => "click",
        "event" => "take",
        "value" => Wire.phx_values(conn, "#take"),
        "cid" => cid
      }

      noop = Wire.phx_values(conn, "#noop")

      {results, conn} = Wire.pipeline(conn, List.duplicate(take, 4))
      refute :crashed in results
      assert [{"take", %{"item" => "t"}}] = recorded(:item_component)

      {{:ok, _}, _} = Wire.event(conn, "click", "noop", noop)
      assert [{"noop", _}] = recorded(:bank)
    end
  end

  describe "round 2: :revoked and stale components" do
    test "after a client-triggered rotation, old tokens are dropped without running anything",
         %{port: port} do
      conn = Wire.open!(port, "/bank")
      cid = Wire.cid(conn, "#items")
      old_t100 = Wire.phx_values(conn, "#transfer-100")
      old_remove = Wire.phx_values(conn, "#remove-a")

      {{:ok, _}, conn} = Wire.event(conn, "click", "rotate", %{})

      stale_remove = %{
        "type" => "click",
        "event" => "remove",
        "value" => old_remove,
        "cid" => cid
      }

      old_transfer = %{"type" => "click", "event" => "transfer", "value" => old_t100}

      {results, conn} = Wire.pipeline(conn, List.duplicate(stale_remove, 10) ++ [old_transfer])
      refute :crashed in results
      assert Recorder.all() == []

      # Exactly one re-render: the stale component refreshing itself on the first
      # revoked event. Later replays don't re-render it again.
      assert [{:ok, %{"diff" => %{"c" => _}}} | rest] = results
      assert Enum.all?(rest, &(&1 == {:ok, %{}})), inspect(rest)
      assert Wire.unsolicited_diffs(conn) == []

      # The refreshed component tokens work.
      new_remove = Wire.phx_values(conn, "#remove-a")
      assert new_remove["__sig"] != old_remove["__sig"]
      {{:ok, _}, _} = Wire.event(conn, "click", "remove", new_remove, %{"cid" => cid})
      assert [{"remove", %{"item" => "a"}}] = recorded(:item_component)
    end

    test "rotations and stale events interleaved by the client never start a re-render loop",
         %{port: port} do
      conn = Wire.open!(port, "/bank")
      cid = Wire.cid(conn, "#items")
      old_remove = Wire.phx_values(conn, "#remove-a")
      rotate = %{"type" => "click", "event" => "rotate", "value" => %{}}
      stale = %{"type" => "click", "event" => "remove", "value" => old_remove, "cid" => cid}

      {results, conn} = Wire.pipeline(conn, List.flatten(List.duplicate([rotate, stale], 10)))

      # A component whose LiveView rotated since it last rendered treats its
      # dead tokens as :revoked: it drops the event and refreshes, once per
      # rotation. Nothing is handled, nothing crashes, and no diffs arrive
      # unprompted (no re-render loop).
      refute :crashed in results
      assert Recorder.all() == []
      assert Wire.unsolicited_diffs(conn) == []
    end

    test "a token from just before one rotation is dropped, from two rotations back it raises",
         %{port: port} do
      conn = Wire.open!(port, "/bank")
      noop = Wire.phx_values(conn, "#noop")

      {{:ok, _}, conn} = Wire.event(conn, "click", "rotate", %{})
      assert {{:ok, %{}}, conn} = Wire.event(conn, "click", "noop", noop)
      {{:ok, _}, conn} = Wire.event(conn, "click", "rotate", %{})
      assert {:crashed, _} = Wire.event(conn, "click", "noop", noop)
      assert recorded(:bank) == []
    end
  end

  describe "round 2: foreign contexts" do
    test "a component handed its parent's context rejects the parent's tokens",
         %{port: port} do
      conn = Wire.open!(port, "/components")
      leaky = Wire.cid(conn, "#leaky")
      parent = Wire.phx_values(conn, "#parent-remove")
      component = Wire.phx_values(conn, "#secure-remove")

      {results, conn} =
        Wire.pipeline(conn, [
          %{"type" => "click", "event" => "remove", "value" => parent, "cid" => leaky},
          %{"type" => "click", "event" => "remove", "value" => component, "cid" => leaky},
          %{"type" => "click", "event" => "remove", "value" => %{"item" => "x"}, "cid" => leaky}
        ])

      assert Enum.all?(results, &match?({:ok, _}, &1))
      assert recorded(:leaky_component) == []

      # Positive control: the parent's token still works where it belongs.
      {{:ok, _}, _} = Wire.event(conn, "click", "remove", parent)
      assert [{"remove", %{"item" => "p0"}}] = recorded(:components_parent)
    end

    test "a nested LiveView that adopts its parent's context (via session) rejects its tokens",
         %{port: port} do
      parent = Wire.open!(port, "/foreign-nested")
      {:ok, child} = Wire.join_child(parent, "foreign-child")
      parent_token = Wire.phx_values(parent, "#parent-remove")

      {results, _} =
        Wire.pipeline(child, [
          %{"type" => "click", "event" => "remove", "value" => parent_token},
          %{"type" => "click", "event" => "remove", "value" => %{"item" => "p0"}}
        ])

      assert Enum.all?(results, &match?({:ok, _}, &1))
      assert recorded(:foreign_child) == []
    end
  end

  ## Documented limitations / LiveView behavior. These PASS, and they assert
  ## what actually happens, so the coverage record says what isn't protected.

  describe "documented limitations and LiveView behavior (not covered by the hook)" do
    test "LIMITATION (documented): a component without attach/2 is unverified, even inside an events: :all LiveView",
         %{port: port} do
      conn = Wire.open!(port, "/components")
      plain_cid = Wire.cid(conn, "#plain")

      {{:ok, _}, _} =
        Wire.event(conn, "click", "remove", %{"item" => "anything"}, %{"cid" => plain_cid})

      assert [{"remove", %{"item" => "anything"}}] = recorded(:plain_component)
    end

    test "LIMITATION (documented): a nested LiveView without its own on_mount is unverified, whatever the parent declares",
         %{port: port} do
      parent = Wire.open!(port, "/nested")
      {:ok, child} = Wire.join_child(parent, "child-plain")

      {{:ok, _}, _} = Wire.event(child, "click", "remove", %{"item" => "anything"})
      assert [{"remove", %{"item" => "anything"}}] = recorded(:nested_plain)
    end

    test "LIVEVIEW BEHAVIOR: upload progress callbacks run on unsigned client messages, even with events: :all",
         %{port: port} do
      conn = Wire.open!(port, "/upload")
      ref = Wire.attr(conn, "input[type=file]", "data-phx-upload-ref")

      entry = %{
        "ref" => "0",
        "name" => "evil.txt",
        "relative_path" => "",
        "size" => 10,
        "type" => "text/plain",
        "last_modified" => 1
      }

      {{:ok, _}, conn} = Wire.push(conn, "allow_upload", %{"ref" => ref, "entries" => [entry]})

      {{:ok, _}, _} =
        Wire.push(conn, "progress", %{"ref" => ref, "entry_ref" => "0", "progress" => 50})

      assert [{50, "evil.txt"}] = recorded(:upload_progress)
      assert recorded(:upload_live) == []
    end

    test "LIVEVIEW BEHAVIOR: an \"uploads\" map riding on a REJECTED event still registers upload entries (on_failure: :halt)",
         %{port: port} do
      conn = Wire.open!(port, "/upload")
      ref = Wire.attr(conn, "input[type=file]", "data-phx-upload-ref")
      assert Wire.attr(conn, "input[type=file]", "data-phx-active-refs") == ""

      entry = %{
        "ref" => "9",
        "name" => "evil.txt",
        "relative_path" => "",
        "size" => 10,
        "type" => "text/plain",
        "last_modified" => 1
      }

      # Unsigned "save": the hook rejects it, but the channel applied the
      # "uploads" map to the socket before the hook ran.
      {{:ok, _}, conn} =
        Wire.event(conn, "form", "save", "id=2", %{"uploads" => %{ref => [entry]}})

      assert recorded(:upload_live) == []
      assert Wire.attr(conn, "input[type=file]", "data-phx-active-refs") == "9"
    end
  end

  describe "round 2: documented limitations and LiveView behavior (these pass)" do
    test "BY DESIGN: single_use is per LiveView process, so each page load gets one use",
         %{port: port} do
      for _tab <- 1..2 do
        conn = Wire.open!(port, "/bank")
        t100 = Wire.phx_values(conn, "#transfer-100")

        Wire.pipeline(
          conn,
          List.duplicate(%{"type" => "click", "event" => "transfer", "value" => t100}, 2)
        )
      end

      assert [{"transfer", _}, {"transfer", _}] = recorded(:bank)
    end
  end

  describe "component lifecycle messages" do
    test "destroying a hooked component's cid doesn't open a path around its hook",
         %{port: port} do
      conn = Wire.open!(port, "/components")
      cid = Wire.cid(conn, "#secure")

      {_, conn} = Wire.push(conn, "cids_will_destroy", %{"cids" => [cid]})
      {_, conn} = Wire.event(conn, "click", "remove", %{"item" => "zzz"}, %{"cid" => cid})
      {_, conn} = Wire.push(conn, "cids_destroyed", %{"cids" => [cid]})
      {_, _} = Wire.event(conn, "click", "remove", %{"item" => "zzz"}, %{"cid" => cid})

      assert Recorder.all() == []
    end
  end
end
