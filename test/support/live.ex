defmodule LiveViewSecure.Test.UsersLive do
  @moduledoc false
  # The scenario from the original proof of concept: everyone sees a "view"
  # button for every user, but only deletable users get a "delete" button.
  use Phoenix.LiveView
  import LiveViewSecure.HTML

  on_mount(
    {LiveViewSecure,
     events: ["view_user", "delete_user", "archive", {"save", unsigned: ["title"]}]}
  )

  def mount(_params, _session, socket) do
    users = [%{id: 5, name: "Ann", deletable: false}, %{id: 7, name: "Bob", deletable: true}]
    {:ok, assign(socket, users: users, admin: true, log: [])}
  end

  def render(assigns) do
    ~H"""
    <div :for={user <- @users} id={"user-#{user.id}"}>
      {user.name}
      <button id={"view-#{user.id}"} {signed_attrs(@live_view_secure, "view_user", id: user.id)}>
        View
      </button>
      <button
        :if={@admin and user.deletable}
        id={"delete-#{user.id}"}
        {signed_attrs(@live_view_secure, "delete_user", id: user.id)}
      >
        Delete
      </button>
      <button
        id={"archive-#{user.id}"}
        phx-click={signed_push(@live_view_secure, "archive", value: %{id: user.id, scope: "mine"})}
      >
        Archive
      </button>
    </div>

    <form id="post-form" phx-submit="save">
      <.signed_inputs secure={@live_view_secure} event="save" values={%{id: 99}} />
      <input type="text" name="title" value="" />
    </form>

    <button id="demote" phx-click="demote">Demote me</button>

    <ul id="log">
      <li :for={entry <- Enum.reverse(@log)}>{entry}</li>
    </ul>
    """
  end

  def handle_event("view_user", %{"id" => id}, socket), do: log(socket, "viewed #{id}")
  def handle_event("delete_user", %{"id" => id}, socket), do: log(socket, "deleted #{id}")

  def handle_event("archive", params, socket),
    do: log(socket, "archived #{params["id"]} scope=#{Map.get(params, "scope", "everything")}")

  def handle_event("save", %{"id" => id, "title" => title}, socket),
    do: log(socket, "saved #{id} title=#{title}")

  # Not declared, so not verified. Permissions changed: revoke every token.
  def handle_event("demote", _params, socket) do
    socket |> assign(admin: false) |> LiveViewSecure.rotate() |> log("demoted")
  end

  defp log(socket, entry), do: {:noreply, update(socket, :log, &[entry | &1])}
end

defmodule LiveViewSecure.Test.StrictLive do
  @moduledoc false
  use Phoenix.LiveView
  import LiveViewSecure.HTML

  on_mount({LiveViewSecure, events: :all, except: ["validate"], on_failure: :halt})

  def mount(_params, _session, socket), do: {:ok, assign(socket, count: 0)}

  def render(assigns) do
    ~H"""
    <button id="inc" {signed_attrs(@live_view_secure, "inc", by: 1)}>+</button>
    <span id="count">{@count}</span>
    """
  end

  def handle_event("inc", %{"by" => by}, socket),
    do: {:noreply, update(socket, :count, &(&1 + String.to_integer(by)))}

  def handle_event("validate", _params, socket),
    do: {:noreply, update(socket, :count, &(&1 + 100))}

  def handle_event("anything", _params, socket),
    do: {:noreply, update(socket, :count, &(&1 + 1000))}
end

defmodule LiveViewSecure.Test.CartComponent do
  @moduledoc false
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

defmodule LiveViewSecure.Test.CartLive do
  @moduledoc false
  use Phoenix.LiveView

  def mount(_params, _session, socket), do: {:ok, socket}

  def render(assigns) do
    ~H"""
    <.live_component module={LiveViewSecure.Test.CartComponent} id="cart" items={["a", "b"]} />
    """
  end
end
