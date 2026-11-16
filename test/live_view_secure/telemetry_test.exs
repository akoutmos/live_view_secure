defmodule LiveViewSecure.TelemetryTest do
  # Telemetry handlers and the default logger are global.
  use ExUnit.Case, async: false

  import ExUnit.CaptureLog
  import Phoenix.ConnTest
  import Phoenix.LiveViewTest

  alias LiveViewSecure.Test.{CartLive, StrictLive, UsersLive}

  @endpoint LiveViewSecure.Test.Endpoint
  @moduletag :capture_log

  @events [
    [:live_view_secure, :verify, :start],
    [:live_view_secure, :verify, :stop],
    [:live_view_secure, :verify, :exception],
    [:live_view_secure, :event, :rejected],
    [:live_view_secure, :event, :unverified],
    [:live_view_secure, :key, :rotate]
  ]

  setup do
    test_pid = self()
    handler_id = {__MODULE__, make_ref()}

    :telemetry.attach_many(
      handler_id,
      @events,
      fn event, measurements, meta, _ ->
        send(test_pid, {:telemetry, event, measurements, meta})
      end,
      nil
    )

    on_exit(fn -> :telemetry.detach(handler_id) end)
    Process.flag(:trap_exit, true)
    {:ok, conn: build_conn()}
  end

  defp sig(view, selector) do
    [value] =
      view
      |> element(selector)
      |> render()
      |> LazyHTML.from_fragment()
      |> LazyHTML.attribute("phx-value-__sig")

    value
  end

  test "a verified event emits a start/stop span", %{conn: conn} do
    {:ok, view, _html} = live_isolated(conn, UsersLive)
    view |> element("#delete-7") |> render_click()

    assert_received {:telemetry, [:live_view_secure, :verify, :start], %{system_time: _}, start}
    assert %{view: UsersLive, source: :view, event: "delete_user", socket: _} = start

    assert_received {:telemetry, [:live_view_secure, :verify, :stop], %{duration: duration}, stop}
    assert is_integer(duration) and duration >= 0
    assert %{result: :ok, reason: nil, reason_type: nil, event: "delete_user"} = stop

    refute_received {:telemetry, [:live_view_secure, :event, :rejected], _, _}
  end

  test "a rejection emits a :stop with the reason, then :rejected", %{conn: conn} do
    {:ok, view, _html} = live_isolated(conn, UsersLive)
    params = %{"id" => "5", "__sig" => sig(view, "#delete-7")}
    catch_exit(render_click(view, "delete_user", params))

    assert_received {:telemetry, [:live_view_secure, :verify, :stop], _, stop}

    assert %{result: :rejected, reason: :invalid_signature, reason_type: :invalid_signature} =
             stop

    assert_received {:telemetry, [:live_view_secure, :event, :rejected], %{count: 1}, rejected}

    assert %{
             view: UsersLive,
             source: :view,
             event: "delete_user",
             reason: :invalid_signature,
             reason_type: :invalid_signature,
             action: :raise
           } = rejected

    # Rejections are not exceptions.
    refute_received {:telemetry, [:live_view_secure, :verify, :exception], _, _}
  end

  test "reason_type drops the details from tuple reasons", %{conn: conn} do
    {:ok, view, _html} = live_isolated(conn, UsersLive)
    params = %{"id" => "7", "__sig" => sig(view, "#delete-7"), "force" => "1"}
    catch_exit(render_click(view, "delete_user", params))

    assert_received {:telemetry, [:live_view_secure, :event, :rejected], _,
                     %{reason: {:unsigned_params, ["force"]}, reason_type: :unsigned_params}}
  end

  test "rejections in :halt mode report action: :halt", %{conn: conn} do
    {:ok, view, _html} = live_isolated(conn, StrictLive)
    render_click(view, "inc", %{"by" => "5"})

    assert_received {:telemetry, [:live_view_secure, :event, :rejected], _,
                     %{view: StrictLive, reason_type: :missing_signature, action: :halt}}
  end

  test "undeclared events emit :unverified, flagging ones that carry a signature",
       %{conn: conn} do
    {:ok, view, _html} = live_isolated(conn, UsersLive)

    render_click(view, "demote", %{})

    assert_received {:telemetry, [:live_view_secure, :event, :unverified], %{count: 1},
                     %{view: UsersLive, event: "demote", signed: false}}

    refute_received {:telemetry, [:live_view_secure, :verify, :start], _, _}

    render_click(view, "demote", %{"__sig" => "whatever"})

    assert_received {:telemetry, [:live_view_secure, :event, :unverified], _,
                     %{event: "demote", signed: true}}
  end

  test "rotate/1 emits :rotate", %{conn: conn} do
    {:ok, view, _html} = live_isolated(conn, UsersLive)
    view |> element("#demote") |> render_click()

    assert_received {:telemetry, [:live_view_secure, :key, :rotate], %{count: 1}, meta}
    assert %{view: UsersLive, source: :view} = meta
    refute Map.has_key?(meta, :event)
  end

  test "component events report source: :component and the parent view", %{conn: conn} do
    {:ok, view, _html} = live_isolated(conn, CartLive)
    view |> element("#remove-a") |> render_click()

    assert_received {:telemetry, [:live_view_secure, :verify, :stop], _,
                     %{view: CartLive, source: :component, event: "remove", result: :ok}}
  end

  describe "default logger" do
    test "logs each rejection", %{conn: conn} do
      {:ok, view, _html} = live_isolated(conn, StrictLive)

      log = capture_log(fn -> render_click(view, "inc", %{"by" => "5"}) end)

      assert log =~ ~s(LiveViewSecure rejected event "inc" in LiveViewSecure.Test.StrictLive)
      assert log =~ "(view): :missing_signature [action: halt]"
    end

    test "escapes and truncates what the client controls", %{conn: conn} do
      {:ok, view, _html} = live_isolated(conn, StrictLive)
      event = "evil\nFAKE LOG LINE " <> String.duplicate("A", 1_000)
      params = Map.new(1..50, &{"k#{&1}", "v"})

      log = capture_log(fn -> render_click(view, event, params) end)

      # Only look at our line (LiveView's own debug logger prints the raw event too).
      [line] = log |> String.split("\n") |> Enum.filter(&(&1 =~ "LiveViewSecure rejected"))

      assert line =~ ~s(LiveViewSecure rejected event "evil\\nFAKE LOG LINE)
      refute line =~ String.duplicate("A", 200)
      assert line =~ ~s(" <> ... in LiveViewSecure.Test.StrictLive)
      refute log =~ ~r/^FAKE LOG LINE/m
    end

    test "can be detached and re-attached" do
      watched? = fn ->
        [:phoenix, :live_view, :handle_event, :start]
        |> :telemetry.list_handlers()
        |> Enum.any?(&(&1.id == {LiveViewSecure.Telemetry, :watch}))
      end

      assert watched?.()
      assert {:error, :already_exists} = LiveViewSecure.Telemetry.attach_default_logger()
      assert :ok = LiveViewSecure.Telemetry.detach_default_logger()
      refute watched?.()
      assert :ok = LiveViewSecure.Telemetry.attach_default_logger(level: :error)
      assert :ok = LiveViewSecure.Telemetry.detach_default_logger()
      assert :ok = LiveViewSecure.Telemetry.attach_default_logger()
    end
  end

  test "the exception message is truncated too" do
    error = %LiveViewSecure.InvalidEventError{
      view: StrictLive,
      event: String.duplicate("B", 1_000),
      reason: {:unsigned_params, Enum.map(1..100, &"k#{&1}")}
    }

    message = Exception.message(error)
    refute message =~ String.duplicate("B", 200)
    refute message =~ "k50"
  end
end
