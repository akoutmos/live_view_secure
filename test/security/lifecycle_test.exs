Code.require_file("lifecycle_helper.exs", __DIR__)

defmodule LiveViewSecure.Security.LifecycleTest do
  @moduledoc """
  Red-team tests for state, lifecycle, rotation, single use and replay.

  Every test asserts the SECURE (and, where tagged `:usability`, the usable)
  behavior, so a failing test is a problem. A misconfiguration that makes the
  page raise while mounting or rendering counts as blocked: it's caught in
  development. Tests whose names start with "(fail-closed)" pass and document
  usability costs that fail closed.

  Tags:

    * `:usability` - fail-closed problems: legitimate clicks dropped, raised,
      or dead. Not security issues.
    * `skip: "by design ..."` - accepted, documented gaps (replay without
      `single_use`, `phx-target` written as its own attribute). Run them with
      `mix test --include skip` to see them fail.

  Diff sizes for single_use are printed with `MEASURE=1`.
  """
  use ExUnit.Case, async: false

  import Phoenix.ConnTest
  import Phoenix.LiveViewTest

  alias LiveViewSecure.InvalidEventError

  alias LiveViewSecure.Security.Lifecycle.{
    ApprovalsLive,
    AssignNewParentLive,
    ClobberLive,
    DoubleModuleLive,
    EarlyHooksLive,
    Endpoint,
    HookReplyLive,
    LeakyParentLive,
    MisconfiguredHostLive,
    NestedParentLive,
    PanelHostLive,
    RaisingHostLive,
    RepeatLive,
    SingleUseHostLive,
    StaleRenderLive,
    StreamItemsLive,
    TempSingleUseLive
  }

  @endpoint Endpoint
  @moduletag :capture_log

  @approvals_events ["approve", "view", "transfer", "purge", "delete_item"]
  @halt [events: @approvals_events, on_failure: :halt]

  @single_use_approvals [
    events: [
      {"approve", single_use: true},
      "view",
      {"transfer", single_use: true},
      "purge",
      {"delete_item", single_use: true}
    ]
  ]

  @repeat [
    events: [
      {"deposit", single_use: true},
      {"save_note", single_use: true, unsigned: :allow, signed: ["id"]},
      {"approve", single_use: true},
      "view"
    ]
  ]

  @stream_single_use [
    events: [{"delete_item", single_use: true}, "view_item", {"approve", single_use: true}]
  ]

  @by_design_replay "by design: tokens are reusable until rotate/1 unless the event is " <>
                      "declared single_use: true (to be documented in the README)"

  setup_all do
    Application.put_env(:live_view_secure, Endpoint,
      secret_key_base: String.duplicate("t", 64),
      live_view: [signing_salt: "lifecycle_test_salt"],
      render_errors: [formats: [html: LiveViewSecure.Security.Lifecycle.ErrorHTML], layout: false]
    )

    start_supervised!(Endpoint)
    :ok
  end

  setup do
    Process.flag(:trap_exit, true)
    {:ok, conn: Plug.Test.init_test_session(build_conn(), %{})}
  end

  ## Helpers

  defp live_with(conn, module, opts, session \\ %{}) do
    session = if opts, do: Map.put(session, "lvs_opts", opts), else: session
    {:ok, view, _html} = live_isolated(conn, module, session: session)
    view
  end

  defp approvals(conn, opts \\ nil), do: live_with(conn, ApprovalsLive, opts)

  defp attrs(view, selector) do
    view
    |> element(selector)
    |> render()
    |> LazyHTML.from_fragment()
    |> LazyHTML.attributes()
    |> hd()
    |> Map.new()
  end

  # The params a click on a signed_attrs/4 element sends (minus the DOM "value").
  defp click_params(view, selector) do
    for {"phx-value-" <> key, value} <- attrs(view, selector), into: %{}, do: {key, value}
  end

  defp event_of(view, selector), do: attrs(view, selector)["phx-click"]

  defp pushed_value(view, selector) do
    [["push", %{"value" => value}]] =
      view |> attrs(selector) |> Map.fetch!("phx-click") |> Jason.decode!()

    value
  end

  defp read_log(view, selector) do
    view
    |> render()
    |> LazyHTML.from_fragment()
    |> LazyHTML.query(selector <> " li")
    |> Enum.map(&LazyHTML.text/1)
  end

  # Runs `fun` (which pushes an event) and reports whether the handler ran.
  defp outcome(view, fun, log \\ "#log") do
    before = read_log(view, log)

    try do
      fun.()

      case read_log(view, log) -- before do
        [] -> :blocked
        new -> {:accepted, new}
      end
    catch
      :exit, {{%InvalidEventError{reason: reason}, _}, _} -> {:raised, reason}
    end
  end

  defp assert_blocked(view, fun, log \\ "#log") do
    case outcome(view, fun, log) do
      {:accepted, new} -> flunk("the event reached its handler, which logged #{inspect(new)}")
      other -> other
    end
  end

  defp assert_accepted(view, fun, log \\ "#log") do
    assert {:accepted, _} = outcome(view, fun, log)
  end

  defp click(view, event, params), do: fn -> render_click(view, event, params) end
  defp click_el(view, selector), do: fn -> view |> element(selector) |> render_click() end

  defp click_target(view, target, event, params),
    do: fn -> view |> with_target(target) |> render_click(event, params) end

  # A disconnected render followed by the connected mount, like a browser does.
  defp dead_render_then_connect(conn, module, session) do
    conn =
      conn
      |> Plug.Conn.put_private(:phoenix_endpoint, @endpoint)
      |> Phoenix.LiveView.Router.fetch_live_flash([])
      |> Phoenix.LiveView.Controller.live_render(module, session: session)

    dead_html = html_response(conn, 200)
    {:ok, view, _html} = live(conn)
    {dead_html, view}
  end

  defp dead_attr(dead_html, selector, name) do
    [value] =
      dead_html
      |> LazyHTML.from_document()
      |> LazyHTML.query(selector)
      |> LazyHTML.attribute(name)

    value
  end

  defp balance(view),
    do: view |> element("#balance") |> render() |> LazyHTML.from_fragment() |> LazyHTML.text()

  # A misconfiguration that raises while rendering is caught in development,
  # which counts as blocked.
  defp mount_misconfigured(conn, panel) do
    {:ok, view, _html} =
      live_isolated(conn, MisconfiguredHostLive, session: %{"panel" => panel})

    {:ok, view}
  rescue
    e in ArgumentError -> {:raised_at_render, Exception.message(e)}
  catch
    :exit, {{%ArgumentError{} = e, _}, _} -> {:raised_at_render, Exception.message(e)}
  end

  # Bytes of JSON diff the LiveView sends while `fun` runs.
  defp diff_bytes(view, fun) do
    :erlang.trace(view.pid, true, [:send])
    fun.()
    :erlang.trace(view.pid, false, [:send])
    ref = :erlang.trace_delivered(view.pid)
    receive do: ({:trace_delivered, _, ^ref} -> :ok)
    collect_diff_bytes(0)
  end

  defp collect_diff_bytes(acc) do
    receive do
      {:trace, _, :send, %Phoenix.Socket.Reply{payload: %{diff: diff}}, _} ->
        collect_diff_bytes(acc + byte_size(Jason.encode!(diff)))

      {:trace, _, :send, %Phoenix.Socket.Message{event: "diff", payload: diff}, _} ->
        collect_diff_bytes(acc + byte_size(Jason.encode!(diff)))

      {:trace, _, :send, _, _} ->
        collect_diff_bytes(acc)
    after
      0 -> acc
    end
  end

  ## 1. Replay without single_use (round-1 F2): by design, to be documented

  describe "replay within one process, default config" do
    @describetag skip: @by_design_replay

    test "a one-shot approval can't be replayed after its button is gone", %{conn: conn} do
      view = approvals(conn, @halt)
      params = click_params(view, "#approve-5")

      view |> element("#approve-5") |> render_click()
      refute has_element?(view, "#approve-5")

      assert_blocked(view, click(view, "approve", params))
    end

    test "a 'Send 100' button that hid itself can't be replayed to send again", %{conn: conn} do
      view = approvals(conn, @halt)
      value = pushed_value(view, "#transfer")

      view |> element("#transfer") |> render_click()
      outcomes = for _ <- 1..5, do: outcome(view, click(view, "transfer", value))
      accepted = Enum.count(outcomes, &match?({:accepted, _}, &1))

      assert accepted == 0,
             "the hidden transfer was replayed #{accepted} more times; balance is now #{balance(view)}"
    end

    test "a stream item's delete token still works after stream_delete/3", %{conn: conn} do
      view = approvals(conn, @halt)
      params = click_params(view, "#delete-item-1")

      view |> element("#delete-item-1") |> render_click()
      assert_blocked(view, click(view, "delete_item", params))
    end

    test "(app forgot rotate/1) a button hidden by a permission change still works", %{conn: conn} do
      view = approvals(conn, @halt)
      params = click_params(view, "#purge")

      view |> element("#demote") |> render_click()
      assert_blocked(view, click(view, "purge", params))
    end
  end

  describe "replay: rotate/1 after the change (documented mitigation)" do
    test "rotate/1 in the handler that hides the button kills the replay", %{conn: conn} do
      view = approvals(conn, @halt)
      params = click_params(view, "#purge")

      view |> element("#demote-rotate") |> render_click()
      refute has_element?(view, "#purge")

      assert :blocked = assert_blocked(view, click(view, "purge", params))
    end
  end

  ## 2. single_use: true

  describe "single_use: true" do
    test "replays of one-shot actions are dropped, even under on_failure: :raise", %{conn: conn} do
      view = approvals(conn, @single_use_approvals)

      # The stream item goes first: once anything single-use is accepted, the
      # stream's (never re-rendered) tokens are revoked (see the :usability tests).
      item = click_params(view, "#delete-item-1")
      view |> element("#delete-item-1") |> render_click()
      assert :blocked = outcome(view, click(view, "delete_item", item))

      approve = click_params(view, "#approve-5")
      view |> element("#approve-5") |> render_click()
      assert :blocked = outcome(view, click(view, "approve", approve))
      assert :blocked = outcome(view, click(view, "approve", approve))

      transfer = pushed_value(view, "#transfer")
      view |> element("#transfer") |> render_click()
      assert :blocked = outcome(view, click(view, "transfer", transfer))

      assert read_log(view, "#log") == ["deleted item 1", "approved 5", "sent 100 to acct-9"]
      assert Process.alive?(view.pid)

      # Older than one use (the shipped design counts every single-use accept
      # on the context): an ordinary invalid signature, which follows
      # on_failure. Never accepted either way.
      assert outcome(view, click(view, "approve", approve)) in [
               :blocked,
               {:raised, :invalid_signature}
             ]
    end

    test "a double click runs the handler once and doesn't crash the LiveView", %{conn: conn} do
      view = live_with(conn, RepeatLive, @repeat)
      value = pushed_value(view, "#deposit")

      render_click(view, "deposit", value)
      render_click(view, "deposit", value)

      assert read_log(view, "#log") == ["deposit 100"]
      assert Process.alive?(view.pid)
    end

    test "a button that stays on the page keeps working, with a fresh token each time",
         %{conn: conn} do
      view = live_with(conn, RepeatLive, @repeat)
      first = pushed_value(view, "#deposit")
      view |> element("#deposit") |> render_click()
      second = pushed_value(view, "#deposit")
      view |> element("#deposit") |> render_click()

      assert first["__sig"] != second["__sig"]
      assert read_log(view, "#log") == ["deposit 100", "deposit 100"]

      assert :blocked = outcome(view, click(view, "deposit", second))
      assert {:raised, :invalid_signature} = outcome(view, click(view, "deposit", first))
    end

    test "in-flight clicks on other rows and events never crash the LiveView", %{conn: conn} do
      # The shipped design drops them (the whole context gets a new id); a
      # per-pair design (findings/single_use_per_pair.patch) accepts them.
      # Either is secure: these buttons were rendered and never used.
      view = live_with(conn, RepeatLive, @repeat)
      approve_2 = click_params(view, "#approve-2")
      view_1 = click_params(view, "#view-1")

      # approve-1 is accepted; approve-2 and view-1 were sent before its diff arrived.
      view |> element("#approve-1") |> render_click()

      assert outcome(view, click(view, "approve", approve_2)) in [
               :blocked,
               {:accepted, ["approved 2"]}
             ]

      assert outcome(view, click(view, "view", view_1)) in [:blocked, {:accepted, ["viewed 1"]}]
      assert Process.alive?(view.pid)

      # approve-2 is never accepted twice.
      assert outcome(view, click(view, "approve", approve_2)) == :blocked

      # Re-rendered, the current buttons work.
      assert_accepted(view, click_el(view, "#view-1"))
    end

    test "a form can be submitted again after it re-renders; a double submit is dropped",
         %{conn: conn} do
      view = live_with(conn, RepeatLive, @repeat)

      view |> form("#note-form", %{"body" => "one"}) |> render_submit()
      view |> form("#note-form", %{"body" => "two"}) |> render_submit()
      assert read_log(view, "#log") == ["saved 1: one", "saved 1: two"]

      sig = attrs(view, "#note-form input[name=__sig]")["value"]
      render_submit(view, "save_note", %{"id" => "1", "__sig" => sig, "body" => "three"})
      render_submit(view, "save_note", %{"id" => "1", "__sig" => sig, "body" => "three again"})
      assert read_log(view, "#log") == ["saved 1: one", "saved 1: two", "saved 1: three"]
    end

    test "works in LiveComponents, and doesn't touch the LiveView's tokens", %{conn: conn} do
      {:ok, view, _html} = live_isolated(conn, SingleUseHostLive)
      params = click_params(view, "#redeem")
      host_view = click_params(view, "#host-view")

      view |> element("#redeem") |> render_click()
      view |> with_target("#panel") |> render_click("redeem", params)
      assert read_log(view, "#panel-log") == ["redeemed X1"]

      assert click_params(view, "#host-view") == host_view
      assert_accepted(view, click(view, "view", host_view))
    end

    test "rotate/1 still revokes the current tokens", %{conn: conn} do
      view = live_with(conn, RepeatLive, @repeat)
      view |> element("#deposit") |> render_click()
      current = pushed_value(view, "#deposit")

      render_click(view, "rotate", %{})
      assert :blocked = outcome(view, click(view, "deposit", current))
      assert_accepted(view, click_el(view, "#deposit"))
    end

    @tag :usability
    test "deleting one stream item leaves the other items' (never used) delete buttons working",
         %{conn: conn} do
      # The README's flagship case. A single-use accept gives the whole context
      # a new id, and stream items are never re-rendered, so every other item's
      # token is now revoked: their buttons are dead until the page remounts.
      view = live_with(conn, StreamItemsLive, @stream_single_use)

      assert_accepted(view, click_el(view, "#delete-item-1"))
      assert_accepted(view, click_el(view, "#delete-item-2"))
    end

    @tag :usability
    test "after two single-use actions elsewhere, an untouched stream item's button doesn't crash the LiveView",
         %{conn: conn} do
      # Two accepts move its tokens two ids back: :invalid_signature, which
      # follows on_failure (:raise here), not :revoked.
      view = live_with(conn, StreamItemsLive, @stream_single_use)

      assert_accepted(view, click_el(view, "#approve-5"))
      assert_accepted(view, click_el(view, "#approve-7"))

      result = outcome(view, click_el(view, "#view-item-1"))

      refute match?({:raised, _}, result),
             "a legitimate click crashed the LiveView: #{inspect(result)}"

      assert {:accepted, _} = result
    end

    test "(fail-closed, usability) every single-use accept wipes rows rendered from a temporary assign",
         %{conn: conn} do
      {:ok, view, _html} = live_isolated(conn, TempSingleUseLive)
      assert has_element?(view, "#open-1")

      view |> element("#deposit") |> render_click()

      refute has_element?(view, "#open-1")
    end

    test "diff cost: a single-use accept re-sends every signing expression, like rotate/1",
         %{conn: conn} do
      rows =
        for n <- [10, 100, 1000] do
          view = live_with(conn, RepeatLive, @repeat, %{"rows" => n})

          unrelated = diff_bytes(view, fn -> render_click(view, "tick", %{}) end)
          plain = diff_bytes(view, fn -> view |> element("#view-1") |> render_click() end)
          single_use = diff_bytes(view, fn -> view |> element("#approve-1") |> render_click() end)
          rotate = diff_bytes(view, fn -> render_click(view, "rotate", %{}) end)

          if System.get_env("MEASURE") do
            IO.puts(
              "rows=#{n}: unrelated change #{unrelated} B, plain signed event #{plain} B, " <>
                "single_use accept #{single_use} B, rotate/1 #{rotate} B"
            )
          end

          {n, plain, single_use}
        end

      [{_, p10, s10}, _, {_, p1000, s1000}] = rows
      assert p1000 == p10
      assert s1000 > 50 * s10
    end
  end

  ## 3. Rotation placement and races

  describe "rotation placement" do
    test "rotate/1 in handle_info/2 (e.g. a PubSub message) revokes and re-issues", %{conn: conn} do
      view = approvals(conn, @halt)
      old = click_params(view, "#view-5")

      send(view.pid, {:run, &LiveViewSecure.rotate/1})

      assert :blocked = assert_blocked(view, click(view, "view", old))
      assert click_params(view, "#view-5") != old
      assert_accepted(view, click_el(view, "#view-5"))
    end

    test "rotate/1 in a handle_info lifecycle hook revokes and re-issues", %{conn: conn} do
      view = approvals(conn, @halt)
      old = click_params(view, "#view-5")

      send(view.pid, :rotate_in_hook)

      assert :blocked = assert_blocked(view, click(view, "view", old))
      assert_accepted(view, click_el(view, "#view-5"))
    end

    test "rotate/1 in handle_async/3 revokes and re-issues", %{conn: conn} do
      view = approvals(conn, @halt)
      old_purge = click_params(view, "#purge")
      old_view = click_params(view, "#view-5")

      send(view.pid, :reload_perms_async)
      render_async(view)

      refute has_element?(view, "#purge")
      assert :blocked = assert_blocked(view, click(view, "purge", old_purge))
      assert :blocked = assert_blocked(view, click(view, "view", old_view))
      assert_accepted(view, click_el(view, "#view-5"))
    end

    test "a click in flight when a rotation lands is dropped, not raised (round-1 F9)",
         %{conn: conn} do
      view = approvals(conn)
      in_flight = click_params(view, "#view-5")

      send(view.pid, {:run, &LiveViewSecure.rotate/1})

      assert :blocked = assert_blocked(view, click(view, "view", in_flight))
      assert Process.alive?(view.pid)
    end

    @tag :usability
    @tag skip:
           "known limitation (documented): only the generation just before a rotation " <>
             "is recognized as :revoked; use on_failure: :halt if you rotate in quick succession"
    test "a click in flight across TWO quick rotations is dropped, not raised", %{conn: conn} do
      # Only one previous root/id is remembered, so a legitimate click sent
      # before two rotations (say two PubSub permission updates within one
      # round trip) is an :invalid_signature and crashes the LiveView.
      view = approvals(conn)
      in_flight = click_params(view, "#view-5")

      send(view.pid, {:run, &LiveViewSecure.rotate/1})
      send(view.pid, {:run, &LiveViewSecure.rotate/1})

      result = assert_blocked(view, click(view, "view", in_flight))

      assert result == :blocked,
             "a legitimate in-flight click crashed the LiveView: #{inspect(result)}"
    end
  end

  describe "rotation scope: LiveComponents" do
    test "rotate/1 in the parent revokes tokens rendered by its LiveComponents (round-1 F1)",
         %{conn: conn} do
      {:ok, view, _html} = live_isolated(conn, PanelHostLive)
      parent_old = click_params(view, "#parent-delete-1")
      component_old = click_params(view, "#panel-delete-1")

      view |> element("#demote") |> render_click()
      refute has_element?(view, "#panel-delete-1")

      assert :blocked = assert_blocked(view, click(view, "delete", parent_old))

      assert :blocked =
               assert_blocked(
                 view,
                 click_target(view, "#panel", "delete", component_old),
                 "#panel-log"
               )
    end

    test "a component that didn't re-render drops its first stale click and re-issues its tokens",
         %{conn: conn} do
      {:ok, view, _html} = live_isolated(conn, PanelHostLive)
      old = click_params(view, "#panel-b-delete-1")

      view |> element("#demote") |> render_click()
      assert click_params(view, "#panel-b-delete-1") == old

      assert :blocked = outcome(view, click_el(view, "#panel-b-delete-1"), "#panel-b-log")
      assert click_params(view, "#panel-b-delete-1") != old

      assert {:accepted, ["deleted 1"]} =
               outcome(view, click_el(view, "#panel-b-delete-1"), "#panel-b-log")

      assert :blocked =
               outcome(view, click_target(view, "#panel-b", "delete", old), "#panel-b-log")
    end

    test "under on_failure: :raise the stale click is dropped, and the re-issued token works",
         %{conn: conn} do
      {:ok, view, _html} = live_isolated(conn, RaisingHostLive)
      old = click_params(view, "#raising-delete-1")

      render_click(view, "rotate", %{})

      assert :blocked = outcome(view, click_el(view, "#raising-delete-1"), "#raising-log")
      assert {:accepted, _} = outcome(view, click_el(view, "#raising-delete-1"), "#raising-log")

      assert assert_blocked(view, click_target(view, "#raising", "delete", old), "#raising-log") in [
               :blocked,
               {:raised, :invalid_signature}
             ]
    end

    test "the stale refresh is bounded: one re-render per rotation, however many stale clicks",
         %{conn: conn} do
      {:ok, view, _html} = live_isolated(conn, PanelHostLive)
      old = click_params(view, "#panel-b-delete-1")
      render_click(view, "rotate", %{})

      first = diff_bytes(view, click_target(view, "#panel-b", "delete", old))
      rest = for _ <- 1..20, do: diff_bytes(view, click_target(view, "#panel-b", "delete", old))

      assert first > 0
      assert Enum.all?(rest, &(&1 == 0)), "stale clicks kept forcing re-renders: #{inspect(rest)}"
      assert read_log(view, "#panel-b-log") == []
    end

    @tag :usability
    test "after TWO parent rotations, a component that didn't re-render still recovers (:halt)",
         %{conn: conn} do
      # The refresh only runs on :ok and :revoked. Two rotations make the
      # component's tokens :invalid_signature, which never refreshes it, so
      # with on_failure: :halt its buttons stay dead for good.
      {:ok, view, _html} = live_isolated(conn, PanelHostLive)
      render_click(view, "rotate", %{})
      render_click(view, "rotate", %{})

      outcome(view, click_el(view, "#panel-b-delete-1"), "#panel-b-log")

      assert {:accepted, ["deleted 1"]} =
               outcome(view, click_el(view, "#panel-b-delete-1"), "#panel-b-log")
    end

    @tag :usability
    test "after TWO parent rotations, a stale component click is dropped, not raised (:raise)",
         %{conn: conn} do
      {:ok, view, _html} = live_isolated(conn, RaisingHostLive)
      render_click(view, "rotate", %{})
      render_click(view, "rotate", %{})

      result = outcome(view, click_el(view, "#raising-delete-1"), "#raising-log")
      assert result == :blocked, "a legitimate click crashed the LiveView: #{inspect(result)}"
    end
  end

  ## 4. Change tracking

  describe "change tracking" do
    test "no fail-open: every token rendered before rotate/1 stops verifying, however it was rendered",
         %{conn: conn} do
      {:ok, view, _html} = live_isolated(conn, StaleRenderLive)

      # (#ignored is left out: it never verifies, see below.)
      selectors = ~w(#precomputed #copied-ctx #closure #streamed-1 #temp-1 #fun-comp-1 #helper)
      before = for s <- selectors, do: {s, event_of(view, s), click_params(view, s)}

      for {_s, event, params} <- before, do: assert_accepted(view, click(view, event, params))

      render_click(view, "rotate", %{})

      for {s, event, params} <- before do
        assert assert_blocked(view, click(view, event, params)) == :blocked,
               "#{s} still verified after rotate/1"
      end
    end

    test "(fail-closed) signed attrs precomputed into another assign keep a dead token", %{
      conn: conn
    } do
      {:ok, view, _html} = live_isolated(conn, StaleRenderLive)
      old = click_params(view, "#precomputed")

      render_click(view, "rotate", %{})

      assert click_params(view, "#precomputed") == old
      assert :blocked = assert_blocked(view, click_el(view, "#precomputed"))
    end

    test "(fail-closed) a copied context signs with a revoked key, even for new elements",
         %{conn: conn} do
      {:ok, view, _html} = live_isolated(conn, StaleRenderLive)
      render_click(view, "rotate", %{})

      assert has_element?(view, "#copied-ctx-new")
      assert :blocked = assert_blocked(view, click_el(view, "#copied-ctx-new"))
      assert :blocked = assert_blocked(view, click_el(view, "#copied-ctx"))
    end

    test "(fail-closed) a closure that captured the context keeps a dead token", %{conn: conn} do
      {:ok, view, _html} = live_isolated(conn, StaleRenderLive)
      render_click(view, "rotate", %{})
      assert :blocked = assert_blocked(view, click_el(view, "#closure"))
    end

    test "(fail-closed) stream items keep dead tokens until re-inserted", %{conn: conn} do
      {:ok, view, _html} = live_isolated(conn, StaleRenderLive)
      old = click_params(view, "#streamed-1")
      render_click(view, "rotate", %{})

      assert click_params(view, "#streamed-1") == old
      assert :blocked = assert_blocked(view, click_el(view, "#streamed-1"))

      render_click(view, "reinsert_stream", %{})
      assert click_params(view, "#streamed-1") != old
      assert_accepted(view, click_el(view, "#streamed-1"))
    end

    test "(fail-closed) phx-update=\"ignore\" content keeps the DEAD RENDER's token, so it never verifies",
         %{conn: conn} do
      # The client never patches an ignored container's children, not even on
      # the join, so they keep the disconnected render's token, whose root
      # died with the HTTP request. Broken from the start, and after every
      # reconnect; with :raise every click crashes the LiveView.
      {dead_html, view} = dead_render_then_connect(conn, StaleRenderLive, %{})

      assert click_params(view, "#ignored")["__sig"] ==
               dead_attr(dead_html, "#ignored", "phx-value-__sig")

      assert :blocked = assert_blocked(view, click_el(view, "#ignored"))
      assert_accepted(view, click_el(view, "#fun-comp-1"))
    end

    test "(fail-closed, usability) rotate/1 wipes rows rendered from a temporary assign", %{
      conn: conn
    } do
      {:ok, view, _html} = live_isolated(conn, StaleRenderLive)
      assert has_element?(view, "#temp-1")

      render_click(view, "rotate", %{})

      refute has_element?(view, "#temp-1")
      refute has_element?(view, "#temp-2")
    end

    test "function components given secure= and helpers given assigns re-render fresh tokens",
         %{conn: conn} do
      {:ok, view, _html} = live_isolated(conn, StaleRenderLive)
      old_fun = click_params(view, "#fun-comp-1")
      old_helper = click_params(view, "#helper")

      render_click(view, "rotate", %{})

      assert click_params(view, "#fun-comp-1") != old_fun
      assert click_params(view, "#helper") != old_helper
      assert_accepted(view, click_el(view, "#fun-comp-1"))
      assert_accepted(view, click_el(view, "#helper"))
    end
  end

  ## 5. Hook ordering and integration

  describe "hook ordering" do
    test "an app :handle_event hook from a live_session on_mount no longer sees forged events (round-1 F4)",
         %{conn: conn} do
      {:ok, view, _html} = live(conn, "/ordered")

      assert :blocked = assert_blocked(view, click(view, "delete", %{"id" => "666"}))
      assert read_log(view, "#log") == []
    end

    test "hooks attached before (re-ordered) and after (mount/3) see only verified events, in order",
         %{conn: conn} do
      {:ok, view, _html} = live_isolated(conn, EarlyHooksLive)

      assert :blocked = assert_blocked(view, click(view, "delete", %{"id" => "666"}))
      assert read_log(view, "#log") == []

      view |> element("#delete-1") |> render_click()

      assert read_log(view, "#log") ==
               ["early_a saw delete", "early_b saw delete", "late saw delete", "deleted 1"]
    end

    test "app code can still detach its own re-ordered hook by id, and verification stays first",
         %{conn: conn} do
      {:ok, view, _html} = live_isolated(conn, EarlyHooksLive)
      render_click(view, "drop_early_a", %{})

      assert read_log(view, "#log") == [
               "early_a saw drop_early_a",
               "early_b saw drop_early_a",
               "late saw drop_early_a"
             ]

      assert :blocked = assert_blocked(view, click(view, "delete", %{"id" => "666"}))
      view |> element("#delete-1") |> render_click()

      assert read_log(view, "#log") --
               ["early_a saw drop_early_a", "early_b saw drop_early_a", "late saw drop_early_a"] ==
               ["early_b saw delete", "late saw delete", "deleted 1"]
    end

    test "on_mount twice in the module raises at mount", %{conn: conn} do
      assert_raise ArgumentError, ~r/called twice/, fn ->
        live_isolated(conn, DoubleModuleLive)
      end
    end

    test "on_mount in a live_session raises at mount", %{conn: conn} do
      assert_raise ArgumentError, ~r/must be declared in/, fn -> live(conn, "/double") end
    end

    test "clobbering @live_view_secure fails closed (:no_context)", %{conn: conn} do
      {:ok, view, _html} = live_isolated(conn, ClobberLive)
      params = click_params(view, "#delete-1")

      render_click(view, "clobber", %{})
      assert :blocked = assert_blocked(view, click(view, "delete", params))
    end
  end

  describe "cross-target replay (LiveComponents)" do
    test "a parent token is rejected by a component, and a component token by the parent",
         %{conn: conn} do
      {:ok, view, _html} = live_isolated(conn, PanelHostLive)
      parent = click_params(view, "#parent-delete-1")
      component = click_params(view, "#panel-delete-1")

      assert :blocked =
               assert_blocked(view, click_target(view, "#panel", "delete", parent), "#panel-log")

      assert :blocked = assert_blocked(view, click(view, "delete", component))
    end

    test "a token from one component instance is rejected by another instance", %{conn: conn} do
      {:ok, view, _html} = live_isolated(conn, PanelHostLive)
      from_a = click_params(view, "#panel-delete-1")

      assert :blocked =
               assert_blocked(
                 view,
                 click_target(view, "#panel-b", "delete", from_a),
                 "#panel-b-log"
               )
    end

    test "a component handed the parent's context as live_view_secure= doesn't accept the parent's tokens (round-1 F7)",
         %{conn: conn} do
      with {:ok, view} <- mount_misconfigured(conn, "shared") do
        parent = click_params(view, "#parent-delete-1")
        assert_blocked(view, click_target(view, "#shared", "delete", parent), "#shared-log")
      end
    end

    test "a component that signs with the parent's context (target: @myself) without attaching is caught (round-1 F3)",
         %{conn: conn} do
      with {:ok, view} <- mount_misconfigured(conn, "nohook") do
        assert_blocked(
          view,
          click_target(view, "#nohook", "delete", %{"id" => "666"}),
          "#nohook-log"
        )
      end
    end

    @tag skip: "by design: undetectable (no hook runs in the component); to be documented"
    test "same, with phx-target={@myself} written as its own attribute", %{conn: conn} do
      with {:ok, view} <- mount_misconfigured(conn, "nohook-attr") do
        assert_blocked(
          view,
          click_target(view, "#nohook-attr", "delete", %{"id" => "666"}),
          "#nohook-attr-log"
        )
      end
    end
  end

  describe "nested LiveViews" do
    test "parent and child (live_render) tokens don't cross", %{conn: conn} do
      {:ok, parent, _html} = live_isolated(conn, NestedParentLive)
      child = find_live_child(parent, "child")

      parent_token = click_params(parent, "#parent-delete-1")
      child_token = click_params(child, "#child-delete-9")

      assert :blocked = assert_blocked(child, click(child, "delete", parent_token), "#child-log")
      assert :blocked = assert_blocked(parent, click(parent, "delete", child_token))
    end

    test "dead render of a parent and its nested child (one process, two roots): no dead token verifies anywhere",
         %{conn: conn} do
      # The disconnected render mounts both LiveViews in the HTTP process, and
      # the child's attach replaces that process's root halfway through the
      # parent's render.
      {dead_html, parent} = dead_render_then_connect(conn, NestedParentLive, %{})
      child = find_live_child(parent, "child")

      dead_parent = %{
        "id" => "1",
        "__sig" => dead_attr(dead_html, "#parent-delete-1", "phx-value-__sig")
      }

      dead_child = %{
        "id" => "9",
        "__sig" => dead_attr(dead_html, "#child-delete-9", "phx-value-__sig")
      }

      for {view, log} <- [{parent, "#log"}, {child, "#child-log"}],
          params <- [dead_parent, dead_child] do
        assert :blocked = assert_blocked(view, click(view, "delete", params), log)
      end

      assert_accepted(parent, click_el(parent, "#parent-delete-1"))
      assert_accepted(child, click_el(child, "#child-delete-9"), "#child-log")
    end

    test "a nested LiveView that takes the parent's context via assign_new can't mint tokens for it (round-1 F6)",
         %{conn: conn} do
      result =
        try do
          {:ok, parent, _html} = live_isolated(conn, AssignNewParentLive)
          {:ok, parent, find_live_child(parent, "an-child")}
        catch
          :exit, {{%ArgumentError{} = e, _}, _} -> {:raised_at_render, Exception.message(e)}
        end

      with {:ok, parent, child} <- result do
        child_token = click_params(child, "#an-child-delete-77")
        assert_blocked(parent, click(parent, "delete", child_token))
      end
    end

    test "a context passed through a live_render session doesn't leak key material (round-1 F5)",
         %{conn: conn} do
      {:ok, _view, html} = live_isolated(conn, LeakyParentLive)

      terms =
        html
        |> LazyHTML.from_document()
        |> LazyHTML.query("[data-phx-session]")
        |> Enum.flat_map(&LazyHTML.attribute(&1, "data-phx-session"))
        |> Enum.map(&session_term/1)

      leaked = Enum.find_value(terms, &find_context/1)
      assert leaked, "expected the context in the child's session (test setup)"

      # No key material: no field that could hold a key, no 32-byte binary, and
      # no reference (the root lives in an :atomics ref in the process dict).
      fields = leaked |> Map.from_struct() |> Map.keys()
      refute Enum.any?(fields, &(&1 in [:key, :root, :secret]))
      refute Enum.any?(terms, &contains_key_material?/1)
    end
  end

  # data-phx-session is a Phoenix.Token: "SFMyNTY.<base64url(term)>.<mac>".
  defp session_term(token) do
    [_, payload, _] = String.split(token, ".")
    payload |> Base.url_decode64!(padding: false) |> :erlang.binary_to_term()
  end

  defp find_context(%LiveViewSecure.Context{} = ctx), do: ctx
  defp find_context(%_{}), do: nil
  defp find_context(%{} = map), do: Enum.find_value(map, fn {_k, v} -> find_context(v) end)

  defp find_context(tuple) when is_tuple(tuple),
    do: tuple |> Tuple.to_list() |> Enum.find_value(&find_context/1)

  defp find_context(list) when is_list(list), do: Enum.find_value(list, &find_context/1)
  defp find_context(_), do: nil

  defp contains_key_material?(term) when is_reference(term), do: true
  defp contains_key_material?(term) when is_binary(term), do: byte_size(term) == 32
  defp contains_key_material?(%{} = map), do: map |> Map.to_list() |> contains_key_material?()

  defp contains_key_material?(tuple) when is_tuple(tuple),
    do: tuple |> Tuple.to_list() |> contains_key_material?()

  defp contains_key_material?(list) when is_list(list),
    do: Enum.any?(list, &contains_key_material?/1)

  defp contains_key_material?(_), do: false

  ## 6. Remount / reconnect

  describe "remount and reconnect" do
    test "tokens from the disconnected (dead) render don't verify on the connected LiveView",
         %{conn: conn} do
      {dead_html, view} = dead_render_then_connect(conn, ApprovalsLive, %{"lvs_opts" => @halt})
      dead_sig = dead_attr(dead_html, "#approve-5", "phx-value-__sig")

      assert click_params(view, "#approve-5")["__sig"] != dead_sig

      assert :blocked =
               assert_blocked(view, click(view, "approve", %{"id" => "5", "__sig" => dead_sig}))
    end

    test "after a crash (on_failure: :raise) the remounted LiveView rejects the old tokens",
         %{conn: conn} do
      view = approvals(conn)
      old = click_params(view, "#approve-5")

      assert {:raised, :missing_signature} = outcome(view, click(view, "approve", %{"id" => "5"}))
      refute Process.alive?(view.pid)

      remounted = approvals(conn)
      assert {:raised, :invalid_signature} = outcome(remounted, click(remounted, "approve", old))
    end

    test "a component removed and re-added gets a fresh key", %{conn: conn} do
      {:ok, view, _html} = live_isolated(conn, PanelHostLive)
      old = click_params(view, "#panel-delete-1")

      render_click(view, "toggle_panel", %{})
      refute has_element?(view, "#panel")
      render_click(view, "toggle_panel", %{})

      assert click_params(view, "#panel-delete-1") != old

      assert :blocked =
               assert_blocked(view, click_target(view, "#panel", "delete", old), "#panel-log")
    end
  end

  ## 7. on_failure: :halt

  describe "on_failure: :halt" do
    test "the handler doesn't run, assigns don't change, the LiveView stays up", %{conn: conn} do
      view = approvals(conn, @halt)
      html_before = render(view)

      assert :blocked =
               assert_blocked(view, click(view, "transfer", %{"amount" => "100", "to" => "x"}))

      assert :blocked =
               assert_blocked(
                 view,
                 click(view, "approve", %{"id" => "5", "__sig" => "id.AAAAAAAAAAAAAAAAAAAAAA"})
               )

      assert Process.alive?(view.pid)
      assert render(view) == html_before
    end

    test "a hook push that expects a reply gets an ack with no reply, not a hang", %{conn: conn} do
      {:ok, view, _html} = live_isolated(conn, HookReplyLive)

      [["push", %{"value" => value}]] =
        view |> attrs("#hooked") |> Map.fetch!("data-push") |> Jason.decode!()

      render_hook(view, "fetch_secret", value)
      assert_reply(view, %{secret: "s3cret-1"})

      render_hook(view, "fetch_secret", %{"id" => "2"})
      %{proxy: {ref, _topic, _}} = view
      refute_received {^ref, {:reply, _}}
      assert view |> element("#hooked") |> render() =~ ~r/>\s*1\s*</
    end

    test "in a LiveComponent: the handler doesn't run and the component's state doesn't change",
         %{conn: conn} do
      {:ok, view, _html} = live_isolated(conn, PanelHostLive)

      assert :blocked =
               assert_blocked(
                 view,
                 click_target(view, "#panel", "delete", %{"id" => "1"}),
                 "#panel-log"
               )

      assert read_log(view, "#panel-log") == []
    end
  end
end
