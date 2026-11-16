defmodule LiveViewSecure.RotationTest.ItemComponent do
  use Phoenix.LiveComponent
  import LiveViewSecure.HTML

  def mount(socket) do
    {:ok, socket |> LiveViewSecure.attach(events: ["remove"]) |> assign(removed: [])}
  end

  def render(assigns) do
    ~H"""
    <div id={@id}>
      <button
        :for={item <- @items}
        id={"remove-#{item}"}
        {signed_attrs(@live_view_secure, "remove", [item: item], target: @myself)}
      >
        x
      </button>
      <span id="removed">{Enum.join(@removed, ",")}</span>
    </div>
    """
  end

  def handle_event("remove", %{"item" => item}, socket),
    do: {:noreply, update(socket, :removed, &(&1 ++ [item]))}
end

defmodule LiveViewSecure.RotationTest.BankLive do
  use Phoenix.LiveView
  import LiveViewSecure.HTML

  on_mount({LiveViewSecure, events: [{"transfer", single_use: true}, "noop"]})

  def mount(_params, _session, socket), do: {:ok, assign(socket, balance: 1000)}

  def render(assigns) do
    ~H"""
    <button id="transfer" {signed_attrs(@live_view_secure, "transfer", amount: 100)}>Send 100</button>
    <button id="noop" {signed_attrs(@live_view_secure, "noop")}>noop</button>
    <button id="rotate" phx-click="rotate">rotate</button>
    <span id="balance">{@balance}</span>
    <.live_component module={LiveViewSecure.RotationTest.ItemComponent} id="items" items={["a", "b"]} />
    """
  end

  def handle_event("transfer", %{"amount" => amount}, socket),
    do: {:noreply, update(socket, :balance, &(&1 - String.to_integer(amount)))}

  def handle_event("noop", _params, socket), do: {:noreply, socket}
  def handle_event("rotate", _params, socket), do: {:noreply, LiveViewSecure.rotate(socket)}
end

defmodule LiveViewSecure.RotationTest do
  use ExUnit.Case, async: false

  import Phoenix.ConnTest
  import Phoenix.LiveViewTest

  alias LiveViewSecure.RotationTest.BankLive

  @endpoint LiveViewSecure.Test.Endpoint
  @moduletag :capture_log

  setup do
    test_pid = self()
    handler_id = {__MODULE__, make_ref()}

    :telemetry.attach(
      handler_id,
      [:live_view_secure, :event, :rejected],
      fn _, _, meta, _ -> send(test_pid, {:rejected, meta.event, meta.reason, meta.action}) end,
      nil
    )

    on_exit(fn -> :telemetry.detach(handler_id) end)
    Process.flag(:trap_exit, true)
    {:ok, view, _html} = live_isolated(build_conn(), BankLive)
    {:ok, view: view}
  end

  defp attrs(view, selector) do
    node = view |> element(selector) |> render() |> LazyHTML.from_fragment()

    for name <- ["phx-value-amount", "phx-value-item", "phx-value-__sig"],
        [value] <- [LazyHTML.attribute(node, name)],
        into: %{},
        do: {String.replace_prefix(name, "phx-value-", ""), value}
  end

  defp balance(view),
    do: view |> element("#balance") |> render() |> LazyHTML.from_fragment() |> LazyHTML.text()

  describe "single_use: true" do
    test "a replayed token is dropped, the button keeps working with a new one", %{view: view} do
      first = attrs(view, "#transfer")
      view |> element("#transfer") |> render_click()
      assert balance(view) == "900"

      # Replays of the used token (a double click looks the same) never run the handler
      # and never crash the LiveView.
      for _ <- 1..5, do: render_click(view, "transfer", first)
      assert balance(view) == "900"
      assert_received {:rejected, "transfer", :revoked, :halt}

      # The re-rendered button has a fresh token and works once more.
      second = attrs(view, "#transfer")
      assert second["__sig"] != first["__sig"]
      view |> element("#transfer") |> render_click()
      assert balance(view) == "800"
    end

    test "only this context rotates: component tokens survive", %{view: view} do
      view |> element("#transfer") |> render_click()
      view |> element("#remove-a") |> render_click()
      assert view |> element("#removed") |> render() =~ ">a<"
    end
  end

  describe "rotate/1 on the LiveView" do
    test "revokes its components' tokens too, and the component recovers", %{view: view} do
      saved = attrs(view, "#remove-a")
      view |> element("#rotate") |> render_click()

      # The saved component token is revoked: dropped, handler not run, no crash.
      view |> with_target("#items") |> render_click("remove", saved)
      assert_received {:rejected, "remove", :revoked, :halt}
      refute view |> element("#removed") |> render() =~ ">a<"

      # That event refreshed the component, so its buttons carry fresh tokens again.
      assert attrs(view, "#remove-a")["__sig"] != saved["__sig"]
      view |> element("#remove-a") |> render_click()
      assert view |> element("#removed") |> render() =~ ">a<"

      # Two generations back no longer matches a revoked key. The component is
      # stale, though, so the first such click is dropped as :revoked and
      # refreshes it (findings/stale_component_refresh.patch). After that it's
      # a plain invalid signature, which raises.
      view |> element("#rotate") |> render_click()
      view |> element("#rotate") |> render_click()

      view |> with_target("#items") |> render_click("remove", saved)
      assert_received {:rejected, "remove", :revoked, :halt}

      assert {{%LiveViewSecure.InvalidEventError{reason: :invalid_signature}, _}, _} =
               catch_exit(view |> with_target("#items") |> render_click("remove", saved))
    end
  end
end
