defmodule LiveViewSecureTest do
  use ExUnit.Case, async: true

  alias Phoenix.LiveView.Socket

  defp socket do
    %Socket{private: %{lifecycle: %Phoenix.LiveView.Lifecycle{}}, assigns: %{__changed__: %{}}}
  end

  describe "attach/2" do
    test "assigns a context and the hook" do
      socket = LiveViewSecure.attach(socket(), events: ["go"])

      assert %LiveViewSecure.Context{} = socket.assigns.live_view_secure
      assert [%{id: :live_view_secure}] = socket.private.lifecycle.handle_event
    end

    test "requires :events" do
      assert_raise ArgumentError, ~r/which events/, fn ->
        LiveViewSecure.attach(socket(), :default)
      end

      assert_raise ArgumentError, ~r/which events/, fn -> LiveViewSecure.attach(socket(), []) end
    end

    test "validates options" do
      for bad <- [
            [events: "go"],
            [events: ["go"], except: ["x"]],
            [events: [123]],
            [events: [{"go", unsigned: :maybe}]],
            [events: [{"go", bogus: 1}]],
            [events: :all, on_failure: :ignore],
            [events: :all, typo: true]
          ] do
        assert_raise ArgumentError, fn -> LiveViewSecure.attach(socket(), bad) end
      end
    end

    test "accepts atoms for event and param names" do
      assert %Socket{} =
               LiveViewSecure.attach(socket(),
                 events: [:go, {:save, unsigned: [:title]}],
                 unsigned: :allow,
                 signed: [:id]
               )
    end
  end

  describe "on_mount/4" do
    defmodule NoOnMountLive do
      use Phoenix.LiveView
      def render(assigns), do: ~H""
    end

    @users_opts [events: ["view_user", "delete_user", "archive", {"save", unsigned: ["title"]}]]

    test "runs when the LiveView module declares it" do
      socket = %{socket() | view: LiveViewSecure.Test.UsersLive}
      assert {:cont, %Socket{}} = LiveViewSecure.on_mount(@users_opts, %{}, %{}, socket)
    end

    test "runs when only a live_session declares it" do
      socket = %{socket() | view: NoOnMountLive}

      assert {:cont, %Socket{} = socket} =
               LiveViewSecure.on_mount([events: ["go"]], %{}, %{}, socket)

      assert [%{id: :live_view_secure}] = socket.private.lifecycle.handle_event
    end
  end

  test "rotate/1 replaces the key and marks the assign as changed" do
    socket = LiveViewSecure.attach(socket(), events: ["go"])
    socket = %{socket | assigns: Map.put(socket.assigns, :__changed__, %{})}
    old_key = LiveViewSecure.Context.key(socket.assigns.live_view_secure)
    rotated = LiveViewSecure.rotate(socket)

    refute LiveViewSecure.Context.key(rotated.assigns.live_view_secure) == old_key
    assert Map.has_key?(rotated.assigns.__changed__, :live_view_secure)
  end
end
