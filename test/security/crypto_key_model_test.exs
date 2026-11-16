defmodule LiveViewSecure.Security.CryptoRevokeLive do
  @moduledoc false
  use Phoenix.LiveView
  import LiveViewSecure.HTML

  on_mount(
    {LiveViewSecure,
     events: ["delete", {"save", unsigned: :allow, signed: ["id"]}], on_failure: :raise}
  )

  def mount(_params, _session, socket), do: {:ok, assign(socket, log: [])}

  def render(assigns) do
    ~H"""
    <button id="delete" {signed_attrs(@live_view_secure, "delete", id: 7)}>delete</button>
    <form id="new" phx-submit="save"><.signed_inputs secure={@live_view_secure} event="save" /></form>
    <ul id="log">
      <li :for={e <- @log}>{e}</li>
    </ul>
    """
  end

  def handle_event("delete", params, socket), do: log(socket, "deleted #{inspect(params)}")
  def handle_event("save", params, socket), do: log(socket, "saved #{inspect(params)}")
  def handle_event("rotate", _params, socket), do: {:noreply, LiveViewSecure.rotate(socket)}

  defp log(socket, entry), do: {:noreply, update(socket, :log, &(&1 ++ [entry]))}
end

defmodule LiveViewSecure.Security.CryptoBankLive do
  @moduledoc false
  use Phoenix.LiveView
  import LiveViewSecure.HTML

  on_mount({LiveViewSecure, events: [{"transfer", single_use: true}, "noop"], on_failure: :halt})

  def mount(_params, _session, socket), do: {:ok, assign(socket, balance: 1_000_000)}

  def render(assigns) do
    ~H"""
    <button id="transfer" {signed_attrs(@live_view_secure, "transfer", amount: 1)}>send</button>
    <button id="noop" {signed_attrs(@live_view_secure, "noop")}>noop</button>
    <span id="balance">{@balance}</span>
    """
  end

  def handle_event("transfer", %{"amount" => a}, socket),
    do: {:noreply, update(socket, :balance, &(&1 - String.to_integer(a)))}

  def handle_event("noop", _params, socket), do: {:noreply, socket}
  def handle_event("rotate", _params, socket), do: {:noreply, LiveViewSecure.rotate(socket)}
end

defmodule LiveViewSecure.Security.CryptoKeyModelTest do
  @moduledoc """
  Attacks on the round-2 key model: a per-process root key in `:atomics`,
  per-context keys `HMAC(root, "live_view_secure/context-key/v1" <> id)`,
  rotation, the `:revoked` path, `single_use`, and key leakage.

  Every test asserts the SECURE behaviour, so a failing test is a vulnerability.
  """
  use ExUnit.Case, async: false
  use ExUnitProperties

  import Phoenix.ConnTest
  import Phoenix.LiveViewTest

  alias LiveViewSecure.{Context, Signer}
  alias LiveViewSecure.Security.{CryptoBankLive, CryptoRevokeLive}
  alias Phoenix.LiveComponent.CID

  @endpoint LiveViewSecure.Test.Endpoint
  @moduletag :capture_log

  @derive_domain "live_view_secure/context-key/v1"
  @mac_domain "live_view_secure/v1"

  ## Helpers

  defp lv_context, do: Context.new(nil, {:all_except, MapSet.new()}, fresh_root: true)
  defp component_context(n), do: Context.new(%CID{cid: n})

  defp root_state, do: Process.get({Context, :root})

  defp root_bytes(ref),
    do: for(i <- 1..4, into: <<>>, do: <<:atomics.get(ref, i)::64>>)

  defp current_root, do: root_state() |> elem(1) |> root_bytes()

  defp signed(ctx, event, values), do: Map.put(values, "__sig", Signer.sign(ctx, event, values))

  defp token_with_key(key, event, values) do
    keys = values |> Map.keys() |> Enum.sort()
    lp = fn b -> <<byte_size(b)::64>> <> b end

    data = [
      @mac_domain,
      lp.(event),
      <<length(keys)::32>>,
      Enum.map(keys, &[lp.(&1), lp.(values[&1])])
    ]

    mac = :crypto.mac(:hmac, :sha256, key, data) |> binary_part(0, 16)
    Enum.join(keys, ",") <> "." <> Base.url_encode64(mac, padding: false)
  end

  # Every way key bytes could plausibly be printed or serialized.
  defp encodings(secret) do
    [
      secret,
      Base.encode16(secret),
      Base.encode16(secret, case: :lower),
      Base.encode64(secret),
      Base.url_encode64(secret, padding: false),
      inspect(secret),
      inspect(:binary.bin_to_list(secret)),
      secret |> :binary.bin_to_list() |> Enum.join(", ")
    ]
  end

  defp refute_contains(haystack, secrets, label) do
    for secret <- secrets, enc <- encodings(secret) do
      refute :binary.match(haystack, enc) != :nomatch, "#{label} contains key bytes"
    end
  end

  describe "derivation and domain separation" do
    test "key = HMAC-SHA256(root, domain <> id), never the root itself" do
      ctx = lv_context()
      root = current_root()
      key = Context.key(ctx)

      assert byte_size(root) == 32 and byte_size(ctx.id) == 16
      assert key == :crypto.mac(:hmac, :sha256, root, @derive_domain <> ctx.id)
      refute key == root
      refute key == :crypto.mac(:hmac, :sha256, root, ctx.id)
    end

    test "the two domain strings can't be confused (neither is a prefix of the other)" do
      refute String.starts_with?(@derive_domain, @mac_domain)
      refute String.starts_with?(@mac_domain, @derive_domain)
    end

    test "tokens MAC'd with anything but this context's derived key don't verify" do
      ctx = lv_context()
      sibling = component_context(1)
      root = current_root()
      values = %{"id" => "7"}

      keys = [
        root,
        :crypto.mac(:hmac, :sha256, root, ctx.id),
        :crypto.mac(:hmac, :sha256, root, @derive_domain),
        :crypto.mac(:hmac, :sha256, root, @mac_domain <> ctx.id),
        :crypto.mac(:hmac, :sha256, ctx.id, @derive_domain <> ctx.id),
        Context.key(sibling)
      ]

      for key <- keys do
        params = Map.put(values, "__sig", token_with_key(key, "delete", values))
        assert {:error, :invalid_signature} = Signer.verify(ctx, "delete", params, :deny)
      end

      # sanity: the same construction with the real key verifies
      real = Map.put(values, "__sig", token_with_key(Context.key(ctx), "delete", values))
      assert :ok = Signer.verify(ctx, "delete", real, :deny)
    end

    test "a context's key can't be computed in another process" do
      ctx = lv_context()

      assert {%ArgumentError{}, _} =
               Task.async(fn ->
                 try do
                   Context.key(ctx)
                 rescue
                   e -> {e, __STACKTRACE__}
                 end
               end)
               |> Task.await()

      # nor can it verify there (a process with its own root gets the wrong key)
      params = signed(ctx, "e", %{})

      assert {:raised, _} =
               Task.async(fn ->
                 lv_context()

                 try do
                   Signer.verify(ctx, "e", params, :deny)
                 rescue
                   e -> {:raised, e}
                 end
               end)
               |> Task.await()
    end
  end

  describe "key generation" do
    test "roots are 256-bit, unique per process, and not from the seedable :rand" do
      roots =
        1..2_000
        |> Task.async_stream(fn _ ->
          :rand.seed(:exsss, {1, 2, 3})
          lv_context()
          current_root()
        end)
        |> Enum.map(fn {:ok, root} -> root end)

      assert Enum.all?(roots, &(byte_size(&1) == 32))
      assert length(Enum.uniq(roots)) == 2_000

      bits = IO.iodata_to_binary(roots)
      ones = for(<<bit::1 <- bits>>, reduce: 0, do: (acc -> acc + bit))
      # 8 sigma of a fair coin over 512,000 flips is ~0.0056
      assert abs(ones / bit_size(bits) - 0.5) < 0.0056
    end

    test "ids and derived keys are unique across 20k contexts in one process" do
      lv_context()
      ctxs = for n <- 1..20_000, do: component_context(n)
      assert ctxs |> Enum.map(& &1.id) |> Enum.uniq() |> length() == 20_000
      assert ctxs |> Enum.map(&Context.key/1) |> Enum.uniq() |> length() == 20_000
    end

    test "rotation always mints a fresh root (:process) or id (:local)" do
      ctx = lv_context()
      {1, r1, nil} = root_state()
      ctx2 = Context.rotate(ctx, :process)
      {2, r2, ^r1} = root_state()
      refute root_bytes(r1) == root_bytes(r2)
      refute ctx2.id == ctx.id
      assert ctx2.prev_id == ctx.id

      ctx3 = Context.rotate(ctx2, :local)
      {2, ^r2, ^r1} = root_state()
      refute ctx3.id in [ctx.id, ctx2.id]
      refute Context.key(ctx3) == Context.key(ctx2)
    end
  end

  describe "isolation and rotation, against a model" do
    # Model of the documented semantics. A token is identified by the context
    # lineage that issued it and the (root generation, id) it was signed under.
    #   * :ok       iff same lineage, current root, current id
    #   * :revoked  iff same lineage, signed at most one root back with the
    #               current or previous id (a click in flight / a replay)
    #   * otherwise :invalid_signature, and never :ok/:revoked across contexts.
    defp expected({lineage, gen, id}, %{lineage: lineage} = v, current_gen) do
      cond do
        gen == current_gen and id == v.ctx.id -> :ok
        gen in [current_gen, current_gen - 1] and id in [v.ctx.id, v.ctx.prev_id] -> :revoked
        true -> :invalid_signature
      end
    end

    defp expected(_token, _verifier, _current_gen), do: :invalid_signature

    defp run_action({:sign, who, ev}, state) do
      v = state.contexts[who]
      {gen, _, _} = root_state()
      values = %{"n" => Integer.to_string(length(state.tokens))}
      params = signed(v.ctx, ev, values)
      %{state | tokens: [{ev, params, {v.lineage, gen, v.ctx.id}} | state.tokens]}
    end

    defp run_action(:rotate_process, state) do
      update_in(state.contexts.lv.ctx, &Context.rotate(&1, :process))
    end

    defp run_action({:rotate_local, who}, state) do
      update_in(state.contexts[who].ctx, &Context.rotate(&1, :local))
    end

    defp run_action({:verify, who, index}, %{tokens: tokens} = state) when tokens != [] do
      {ev, params, origin} = Enum.at(tokens, rem(index, length(tokens)))
      v = state.contexts[who]
      {gen, _, _} = root_state()
      got = Signer.verify(v.ctx, ev, params, :deny)
      want = expected(origin, v, gen)

      assert got == if(want == :ok, do: :ok, else: {:error, want}),
             "verify in #{who} of a token from #{inspect(origin)}: got #{inspect(got)}, " <>
               "expected #{inspect(want)}"

      state
    end

    defp run_action({:verify, _, _}, state), do: state

    property "tokens never cross contexts, and :ok/:revoked follow rotation exactly" do
      who = member_of([:lv, :c1, :c2])

      action =
        frequency([
          {4, tuple({constant(:sign), who, member_of(["a", "b"])})},
          {1, constant(:rotate_process)},
          {2, tuple({constant(:rotate_local), who})},
          {6, tuple({constant(:verify), who, integer(0..50)})}
        ])

      check all(actions <- list_of(action, min_length: 1, max_length: 40), max_runs: 400) do
        state = %{
          contexts: %{
            lv: %{lineage: :lv, ctx: lv_context()},
            c1: %{lineage: :c1, ctx: component_context(1)},
            c2: %{lineage: :c2, ctx: component_context(2)}
          },
          tokens: []
        }

        Enum.reduce(actions, state, &run_action/2)
      end
    end

    test "a revoked match is only ever the exact token: any tampering is not :revoked" do
      ctx = lv_context()
      params = signed(ctx, "delete", %{"id" => "7", "scope" => "mine"})
      ctx = Context.rotate(ctx, :process)
      assert {:error, :revoked} = Signer.verify(ctx, "delete", params, :deny)

      assert {:error, :invalid_signature} =
               Signer.verify(ctx, "delete", %{params | "id" => "8"}, :deny)

      assert {:error, :invalid_signature} = Signer.verify(ctx, "archive", params, :deny)

      assert {:error, {:missing_params, ["scope"]}} =
               Signer.verify(ctx, "delete", Map.delete(params, "scope"), :deny)

      assert {:error, :invalid_signature} =
               Signer.verify(ctx, "delete", %{params | "id" => 7}, :deny)
    end
  end

  describe "[FINDING] the :revoked path hides tampering" do
    # :revoked is always halted (never raised) and documented as a normal
    # trickle. But check_mac runs before the unsigned/signed checks, so a
    # genuine pre-rotation (or already used single-use) token carrying
    # injected params is reported as :revoked, not as the tampering it is.

    test "extra unsigned params on a revoked token are reported as unsigned, not :revoked" do
      ctx = lv_context()
      params = signed(ctx, "delete", %{"id" => "7"}) |> Map.put("admin", "true")
      assert {:error, {:unsigned_params, ["admin"]}} = Signer.verify(ctx, "delete", params, :deny)

      ctx = Context.rotate(ctx, :process)
      assert {:error, {:unsigned_params, ["admin"]}} = Signer.verify(ctx, "delete", params, :deny)
    end

    test "a protected (:signed) param on a revoked token is reported as unsigned, not :revoked" do
      ctx = lv_context()
      params = signed(ctx, "save", %{}) |> Map.put("id", "999")
      ctx = Context.rotate(ctx, :local)

      assert {:error, {:unsigned_params, ["id"]}} =
               Signer.verify(ctx, "save", params, :allow, ["id"])
    end

    test "with on_failure: :raise, injected params ride a revoked token without a crash" do
      test_pid = self()
      ref = make_ref()

      :telemetry.attach(
        {__MODULE__, ref},
        [:live_view_secure, :event, :rejected],
        fn _, _, meta, _ -> send(test_pid, {:rejected, meta.reason, meta.action}) end,
        nil
      )

      on_exit(fn -> :telemetry.detach({__MODULE__, ref}) end)
      Process.flag(:trap_exit, true)

      {:ok, view, _html} = live_isolated(build_conn(), CryptoRevokeLive)

      [sig] =
        view
        |> element("#delete")
        |> render()
        |> LazyHTML.from_fragment()
        |> LazyHTML.attribute("phx-value-__sig")

      render_click(view, "rotate", %{})

      tampered = %{"id" => "7", "__sig" => sig, "value" => "", "cascade" => "all"}

      result =
        try do
          render_click(view, "delete", tampered)
          :survived
        catch
          :exit, _ -> :raised
        end

      assert_received {:rejected, reason, action}

      assert {reason, action, result} == {{:unsigned_params, ["cascade"]}, :raise, :raised},
             "tampering was classified as #{inspect(reason)} and #{action}ed"
    end
  end

  describe "single_use" do
    defp sig_of(view, id) do
      [sig] =
        view
        |> element("##{id}")
        |> render()
        |> LazyHTML.from_fragment()
        |> LazyHTML.attribute("phx-value-__sig")

      sig
    end

    defp balance(view),
      do: view |> element("#balance") |> render() |> LazyHTML.from_fragment() |> LazyHTML.text()

    property "no single-use token is ever accepted twice, whatever the interleaving" do
      action =
        frequency([
          {3, constant(:click)},
          {4, tuple({constant(:replay), integer(0..30)})},
          {1, constant(:noop)},
          {1, constant(:rotate)}
        ])

      check all(actions <- list_of(action, min_length: 1, max_length: 25), max_runs: 60) do
        {:ok, view, _html} = live_isolated(build_conn(), CryptoBankLive)

        {_seen, accepted} =
          Enum.reduce(actions, {[], MapSet.new()}, fn action, {seen, accepted} ->
            before = String.to_integer(balance(view))

            sig =
              case action do
                :click -> sig_of(view, "transfer")
                {:replay, i} when seen != [] -> Enum.at(seen, rem(i, length(seen)))
                _ -> nil
              end

            case action do
              :noop ->
                view |> element("#noop") |> render_click()

              :rotate ->
                render_click(view, "rotate", %{})

              _ when is_binary(sig) ->
                render_click(view, "transfer", %{"amount" => "1", "__sig" => sig, "value" => ""})

              _ ->
                :ok
            end

            spent = before - String.to_integer(balance(view))
            assert spent in [0, 1]
            # non-vacuous: the button as currently rendered always works
            if action == :click, do: assert(spent == 1, "a fresh token was refused")

            if spent == 1 do
              refute MapSet.member?(accepted, sig), "token accepted twice"
              {[sig | seen], MapSet.put(accepted, sig)}
            else
              {if(sig, do: [sig | seen], else: seen), accepted}
            end
          end)

        assert 1_000_000 - String.to_integer(balance(view)) == MapSet.size(accepted)
      end
    end

    test "a consumed token is :revoked, then invalid after the next consumption" do
      {:ok, view, _html} = live_isolated(build_conn(), CryptoBankLive)
      first = sig_of(view, "transfer")
      replay = %{"amount" => "1", "__sig" => first, "value" => ""}

      view |> element("#transfer") |> render_click()
      render_click(view, "transfer", replay)
      view |> element("#transfer") |> render_click()
      render_click(view, "transfer", replay)

      assert balance(view) == "999998"
    end
  end

  describe "key bytes don't leak" do
    test "not through the struct, inspect, term_to_binary or the formatted process dictionary" do
      ctx = lv_context()
      comp = component_context(1)
      ctx2 = Context.rotate(ctx, :process)
      {_, current, previous} = root_state()

      secrets = [
        root_bytes(current),
        root_bytes(previous),
        Context.key(ctx2),
        Context.key(comp)
        | Context.revoked_keys(ctx2)
      ]

      for term <- [ctx, ctx2, comp, %{assigns: %{live_view_secure: ctx2}}] do
        refute_contains(:erlang.term_to_binary(term), secrets, "term_to_binary")
        refute_contains(inspect(term, structs: false, limit: :infinity), secrets, "inspect")
        refute_contains(IO.iodata_to_binary(:io_lib.format(~c"~p", [term])), secrets, "~p")
      end

      {:dictionary, dict} = Process.info(self(), :dictionary)
      refute_contains(inspect(dict, limit: :infinity), secrets, "dictionary")
      refute_contains(:erlang.term_to_binary(dict), secrets, "serialized dictionary")
    end

    test "not through a crashing LiveView's logs, crash report or rejection telemetry" do
      test_pid = self()
      ref = make_ref()

      :telemetry.attach(
        {__MODULE__, ref},
        [:live_view_secure, :event, :rejected],
        fn _, _, meta, _ -> send(test_pid, {:meta, meta}) end,
        nil
      )

      on_exit(fn -> :telemetry.detach({__MODULE__, ref}) end)
      Process.flag(:trap_exit, true)
      {:ok, view, _html} = live_isolated(build_conn(), CryptoRevokeLive)
      render_click(view, "rotate", %{})

      # White-box: read the LiveView's roots out of its process dictionary.
      {:dictionary, dict} = Process.info(view.pid, :dictionary)
      {_gen, current, previous} = :proplists.get_value({Context, :root}, dict)
      ctx = :sys.get_state(view.pid).socket.assigns.live_view_secure
      roots = [root_bytes(current), root_bytes(previous)]

      secrets =
        roots ++
          for root <- roots,
              id <- [ctx.id, ctx.prev_id],
              do: :crypto.mac(:hmac, :sha256, root, @derive_domain <> id)

      log =
        ExUnit.CaptureLog.capture_log([level: :debug], fn ->
          bad = %{"id" => "8", "__sig" => "id." <> String.duplicate("A", 22)}
          catch_exit(render_click(view, "delete", bad))
          Process.sleep(100)
        end)

      assert_received {:meta, meta}
      assert log =~ "InvalidEventError"
      refute_contains(log, secrets, "crash log")
      refute_contains(:erlang.term_to_binary(meta), secrets, "telemetry metadata")

      refute_contains(
        inspect(meta, limit: :infinity, structs: false),
        secrets,
        "telemetry metadata"
      )
    end
  end

  describe "CPU bounds with revoked candidates" do
    test "an invalid token after rotations costs at most 4 MACs (linear in payload)" do
      ctx = lv_context() |> Context.rotate(:process) |> Context.rotate(:local)
      assert length(Context.revoked_keys(ctx)) == 3
      big = :binary.copy("a", 20_000_000)
      bad = "id." <> String.duplicate("A", 22)

      {us, result} =
        :timer.tc(fn -> Signer.verify(ctx, "e", %{"id" => big, "__sig" => bad}, :deny) end)

      assert result == {:error, :invalid_signature}
      assert us < 1_000_000
    end
  end
end
