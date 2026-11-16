defmodule LiveViewSecure.Test.Protocol.AdminLive do
  @moduledoc false
  # Module-level on_mount, explicit event list, on_failure: :halt (so one
  # connection can take many hostile payloads). The catch-all handler records
  # every event that reaches it.
  use Phoenix.LiveView
  import LiveViewSecure.HTML
  alias LiveViewSecure.Test.Protocol.Recorder

  on_mount({LiveViewSecure,
   events: [
     "delete_user",
     "archive",
     "ping",
     # Round 2: `unsigned: :allow` now requires `:signed`. Keep :allow (so the
     # round-1 attacks still exercise it) and pin "id".
     {"save", unsigned: :allow, signed: ["id"]},
     {"search", unsigned: ["key", "value"]}
   ],
   on_failure: :halt})

  def mount(_params, _session, socket) do
    {:ok, assign(socket, users: [%{id: 5, deletable: false}, %{id: 7, deletable: true}])}
  end

  def render(assigns) do
    ~H"""
    <div :for={user <- @users} id={"user-#{user.id}"}>
      <button
        :if={user.deletable}
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
    <button id="ping" {signed_attrs(@live_view_secure, "ping")}>ping</button>
    <input
      id="search"
      name="q"
      {signed_attrs(@live_view_secure, "search", [scope: "users"], binding: "phx-keyup")}
    />
    <form id="post-form" phx-submit="save">
      <.signed_inputs secure={@live_view_secure} event="save" values={%{id: 99}} />
      <input type="text" name="title" value="" />
    </form>
    <%!-- A "new" form for the same event, with no server-provided values. --%>
    <form id="new-form" phx-submit="save">
      <.signed_inputs secure={@live_view_secure} event="save" values={%{}} />
      <input type="text" name="title" value="" />
    </form>
    """
  end

  def handle_event(event, params, socket) do
    Recorder.record(:admin, event, params)
    {:noreply, socket}
  end
end

defmodule LiveViewSecure.Test.Protocol.HookLive do
  @moduledoc false
  # events: :all. Every event other than "validate" must be signed. The
  # catch-all handler records whatever gets through.
  use Phoenix.LiveView
  import LiveViewSecure.HTML
  alias LiveViewSecure.Test.Protocol.Recorder

  # Round 2: all-mode with a per-event rule.
  on_mount(
    {LiveViewSecure,
     events: [:all, {"kb", unsigned: ["key"]}], except: ["validate"], on_failure: :halt}
  )

  def mount(_params, _session, socket), do: {:ok, socket}

  def render(assigns) do
    ~H"""
    <input id="kb" {signed_attrs(@live_view_secure, "kb", [scope: "k"], binding: "phx-keyup")} />
    <button id="inc" {signed_attrs(@live_view_secure, "inc", by: 1)}>+</button>
    <button id="empty" {signed_attrs(@live_view_secure, "empty")}>empty</button>
    <div id="hook" phx-hook="Thing" data-push={signed_push(@live_view_secure, "pull", value: %{n: 1})}>
    </div>
    """
  end

  def handle_event(event, params, socket) do
    Recorder.record(:hook_live, event, params)
    {:noreply, socket}
  end
end

defmodule LiveViewSecure.Test.Protocol.SecureComponent do
  @moduledoc false
  use Phoenix.LiveComponent
  import LiveViewSecure.HTML
  alias LiveViewSecure.Test.Protocol.Recorder

  def mount(socket) do
    {:ok, LiveViewSecure.attach(socket, events: ["remove"], on_failure: :halt)}
  end

  def render(assigns) do
    ~H"""
    <div id={@id}>
      <button
        id={"#{@id}-remove"}
        {signed_attrs(@live_view_secure, "remove", [item: "s1"], target: @myself)}
      >
        x
      </button>
    </div>
    """
  end

  def handle_event(event, params, socket) do
    Recorder.record(:secure_component, event, params)
    {:noreply, socket}
  end
end

defmodule LiveViewSecure.Test.Protocol.PlainComponent do
  @moduledoc false
  # Does NOT call LiveViewSecure.attach/2.
  use Phoenix.LiveComponent
  alias LiveViewSecure.Test.Protocol.Recorder

  def render(assigns) do
    ~H"""
    <div id={@id}>
      <button id="plain-remove" phx-click="remove" phx-value-item="p1" phx-target={@myself}>x</button>
    </div>
    """
  end

  def handle_event(event, params, socket) do
    Recorder.record(:plain_component, event, params)
    {:noreply, socket}
  end
end

defmodule LiveViewSecure.Test.Protocol.ComponentsLive do
  @moduledoc false
  use Phoenix.LiveView
  import LiveViewSecure.HTML
  alias LiveViewSecure.Test.Protocol.{LeakyComponent, PlainComponent, Recorder, SecureComponent}

  on_mount({LiveViewSecure, events: :all, on_failure: :halt})

  def mount(_params, _session, socket), do: {:ok, socket}

  def render(assigns) do
    ~H"""
    <button id="parent-remove" {signed_attrs(@live_view_secure, "remove", item: "p0")}>x</button>
    <.live_component module={SecureComponent} id="secure" />
    <.live_component module={SecureComponent} id="secure2" />
    <.live_component module={LeakyComponent} id="leaky" live_view_secure={@live_view_secure} />
    <.live_component module={PlainComponent} id="plain" />
    """
  end

  def handle_event(event, params, socket) do
    Recorder.record(:components_parent, event, params)
    {:noreply, socket}
  end
end

defmodule LiveViewSecure.Test.Protocol.NestedPlainChildLive do
  @moduledoc false
  # A nested LiveView WITHOUT its own on_mount.
  use Phoenix.LiveView
  alias LiveViewSecure.Test.Protocol.Recorder

  def mount(_params, _session, socket), do: {:ok, socket}
  def render(assigns), do: ~H"<p>plain child</p>"

  def handle_event(event, params, socket) do
    Recorder.record(:nested_plain, event, params)
    {:noreply, socket}
  end
end

defmodule LiveViewSecure.Test.Protocol.NestedGuardedChildLive do
  @moduledoc false
  use Phoenix.LiveView
  import LiveViewSecure.HTML
  alias LiveViewSecure.Test.Protocol.Recorder

  on_mount({LiveViewSecure, events: :all, on_failure: :halt})

  def mount(_params, _session, socket), do: {:ok, socket}

  def render(assigns) do
    ~H"""
    <button id="child-remove" {signed_attrs(@live_view_secure, "remove", item: "c1")}>x</button>
    """
  end

  def handle_event(event, params, socket) do
    Recorder.record(:nested_guarded, event, params)
    {:noreply, socket}
  end
end

defmodule LiveViewSecure.Test.Protocol.NestedParentLive do
  @moduledoc false
  use Phoenix.LiveView
  import LiveViewSecure.HTML
  alias LiveViewSecure.Test.Protocol.{NestedGuardedChildLive, NestedPlainChildLive, Recorder}

  on_mount({LiveViewSecure, events: :all, on_failure: :halt})

  def mount(_params, _session, socket), do: {:ok, socket}

  def render(assigns) do
    ~H"""
    <button id="parent-remove" {signed_attrs(@live_view_secure, "remove", item: "p0")}>x</button>
    {live_render(@socket, NestedPlainChildLive, id: "child-plain")}
    {live_render(@socket, NestedGuardedChildLive, id: "child-guarded")}
    """
  end

  def handle_event(event, params, socket) do
    Recorder.record(:nested_parent, event, params)
    {:noreply, socket}
  end
end

defmodule LiveViewSecure.Test.Protocol.UploadLive do
  @moduledoc false
  use Phoenix.LiveView
  import LiveViewSecure.HTML
  alias LiveViewSecure.Test.Protocol.Recorder

  on_mount({LiveViewSecure, events: :all, on_failure: :halt})

  def mount(_params, _session, socket) do
    {:ok,
     allow_upload(socket, :avatar,
       accept: :any,
       max_entries: 3,
       auto_upload: true,
       progress: &handle_progress/3
     )}
  end

  def render(assigns) do
    ~H"""
    <form id="upload-form" phx-submit="save" phx-change="validate">
      <.live_file_input upload={@uploads.avatar} />
      <.signed_inputs secure={@live_view_secure} event="save" values={%{id: 1}} />
    </form>
    """
  end

  def handle_progress(:avatar, entry, socket) do
    Recorder.record(:upload_progress, entry.progress, entry.client_name)
    {:noreply, socket}
  end

  def handle_event(event, params, socket) do
    Recorder.record(:upload_live, event, params)
    {:noreply, socket}
  end
end

defmodule LiveViewSecure.Test.Protocol.PatchLive do
  @moduledoc false
  use Phoenix.LiveView
  import LiveViewSecure.HTML
  alias LiveViewSecure.Test.Protocol.Recorder

  on_mount({LiveViewSecure, events: :all, on_failure: :halt})

  def mount(_params, _session, socket), do: {:ok, assign(socket, page: "1")}

  def handle_params(params, _uri, socket),
    do: {:noreply, assign(socket, page: params["page"] || "1")}

  def render(assigns) do
    ~H"""
    <button id="next" {signed_attrs(@live_view_secure, "goto", page: @page)}>next</button>
    """
  end

  def handle_event(event, params, socket) do
    Recorder.record(:patch_live, event, params)
    {:noreply, socket}
  end
end

defmodule LiveViewSecure.Test.Protocol.SessionGuardedLive do
  @moduledoc false
  # Protected ONLY by the live_session's on_mount (the README allows this:
  # "use either a live_session on_mount or a module-level one").
  #
  # The README's scenario: only admins get a (signed) delete button. This user
  # is not an admin, so nothing signed is rendered for them, and the hook is
  # the only thing standing between them and "delete_user".
  use Phoenix.LiveView
  import LiveViewSecure.HTML
  alias LiveViewSecure.Test.Protocol.Recorder

  def mount(_params, _session, socket) do
    {:ok, assign(socket, admin: false, users: [%{id: 5, name: "Ann"}, %{id: 7, name: "Bob"}])}
  end

  def render(assigns) do
    ~H"""
    <div :for={user <- @users} id={"user-#{user.id}"}>
      {user.name}
      <button
        :if={@admin}
        id={"delete-#{user.id}"}
        {signed_attrs(@live_view_secure, "delete_user", id: user.id)}
      >
        Delete
      </button>
    </div>
    """
  end

  def handle_event("delete_user", %{"id" => id}, socket) do
    Recorder.record(:session_guarded, "delete_user", %{"id" => id})
    {:noreply, socket}
  end
end

defmodule LiveViewSecure.Test.Protocol.ExactLive do
  @moduledoc false
  # Ordinary exact-match handler clauses, plus a fallback so that anything the
  # hook lets through is visible instead of crashing the process.
  use Phoenix.LiveView
  import LiveViewSecure.HTML
  alias LiveViewSecure.Test.Protocol.Recorder

  on_mount({LiveViewSecure, events: ["delete_user"], on_failure: :halt})

  def mount(_params, _session, socket), do: {:ok, socket}

  def render(assigns) do
    ~H"""
    <button id="delete-7" {signed_attrs(@live_view_secure, "delete_user", id: 7)}>Delete</button>
    """
  end

  def handle_event("delete_user", %{"id" => id}, socket) do
    Recorder.record(:exact, "delete_user", id)
    {:noreply, socket}
  end

  def handle_event(other, params, socket) do
    Recorder.record(:exact_fallback, other, params)
    {:noreply, socket}
  end
end

## Round 2 fixtures

defmodule LiveViewSecure.Test.Protocol.LeakyComponent do
  @moduledoc false
  # Attaches its own hook, but the parent passes `live_view_secure={...}`, so
  # the default update/2 replaces the component's context with the parent's.
  use Phoenix.LiveComponent
  alias LiveViewSecure.Test.Protocol.Recorder

  def mount(socket),
    do: {:ok, LiveViewSecure.attach(socket, events: ["remove"], on_failure: :halt)}

  def render(assigns), do: ~H(<div id={@id}>leaky</div>)

  def handle_event(event, params, socket) do
    Recorder.record(:leaky_component, event, params)
    {:noreply, socket}
  end
end

defmodule LiveViewSecure.Test.Protocol.ItemComponent do
  @moduledoc false
  use Phoenix.LiveComponent
  import LiveViewSecure.HTML
  alias LiveViewSecure.Test.Protocol.Recorder

  def mount(socket),
    do: {:ok, LiveViewSecure.attach(socket, events: ["remove", {"take", single_use: true}])}

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
      <button id="take" {signed_attrs(@live_view_secure, "take", [item: "t"], target: @myself)}>
        take
      </button>
    </div>
    """
  end

  def handle_event(event, params, socket) do
    Recorder.record(:item_component, event, params)
    {:noreply, socket}
  end
end

defmodule LiveViewSecure.Test.Protocol.BankLive do
  @moduledoc false
  # single_use, rotation and component staleness, with on_failure: :raise so
  # that anything other than a :revoked drop crashes the process.
  use Phoenix.LiveView
  import LiveViewSecure.HTML
  alias LiveViewSecure.Test.Protocol.{ItemComponent, Recorder}

  on_mount({LiveViewSecure, events: [{"transfer", single_use: true}, "noop"]})

  def mount(_params, _session, socket), do: {:ok, socket}

  def render(assigns) do
    ~H"""
    <button id="transfer-100" {signed_attrs(@live_view_secure, "transfer", amount: 100)}>100</button>
    <button id="transfer-5" {signed_attrs(@live_view_secure, "transfer", amount: 5)}>5</button>
    <button id="noop" {signed_attrs(@live_view_secure, "noop")}>noop</button>
    <.live_component module={ItemComponent} id="items" items={["a", "b"]} />
    """
  end

  # Undeclared: anyone can trigger a rotation (as an app might on a permission change).
  def handle_event("rotate", _params, socket), do: {:noreply, LiveViewSecure.rotate(socket)}

  def handle_event(event, params, socket) do
    Recorder.record(:bank, event, params)
    {:noreply, socket}
  end
end

defmodule LiveViewSecure.Test.Protocol.SessionHook do
  @moduledoc false
  # An app's live_session on_mount that acts on events in a :handle_event hook
  # (and halts, i.e. it handles them itself). Attached BEFORE LiveViewSecure.
  alias LiveViewSecure.Test.Protocol.Recorder

  def on_mount(:default, _params, _session, socket) do
    {:cont,
     Phoenix.LiveView.attach_hook(socket, :session_hook, :handle_event, fn event, params, s ->
       Recorder.record(:session_hook, event, params)
       if event == "app_action", do: {:halt, s}, else: {:cont, s}
     end)}
  end
end

defmodule LiveViewSecure.Test.Protocol.EarlyHook do
  @moduledoc false
  # A module-level on_mount listed BEFORE LiveViewSecure.
  alias LiveViewSecure.Test.Protocol.Recorder

  def on_mount(:default, _params, _session, socket) do
    {:cont,
     Phoenix.LiveView.attach_hook(socket, :early_hook, :handle_event, fn event, params, s ->
       Recorder.record(:early_hook, event, params)
       if event == "app_action", do: {:halt, s}, else: {:cont, s}
     end)}
  end
end

defmodule LiveViewSecure.Test.Protocol.HookedLive do
  @moduledoc false
  # Hooks attached at every point an app might: live_session on_mount (before),
  # an earlier module on_mount (before), mount/3 (after) and handle_params (after).
  use Phoenix.LiveView
  import LiveViewSecure.HTML
  alias LiveViewSecure.Test.Protocol.{EarlyHook, Recorder}

  on_mount(EarlyHook)
  on_mount({LiveViewSecure, events: ["delete_user", "app_action"], on_failure: :halt})

  def mount(_params, _session, socket) do
    {:ok,
     socket
     |> assign(params_hooked: false)
     |> attach_hook(:mount_hook, :handle_event, recorder(:mount_hook))}
  end

  def handle_params(_params, _uri, socket) do
    if socket.assigns.params_hooked do
      {:noreply, socket}
    else
      {:noreply,
       socket
       |> assign(params_hooked: true)
       |> attach_hook(:params_hook, :handle_event, recorder(:params_hook))}
    end
  end

  defp recorder(name) do
    fn event, params, s ->
      Recorder.record(name, event, params)
      if event == "app_action", do: {:halt, s}, else: {:cont, s}
    end
  end

  def render(assigns) do
    ~H"""
    <button id="delete-7" {signed_attrs(@live_view_secure, "delete_user", id: 7)}>x</button>
    <button id="app-action" {signed_attrs(@live_view_secure, "app_action", id: 7)}>x</button>
    """
  end

  def handle_event(event, params, socket) do
    Recorder.record(:hooked_live, event, params)
    {:noreply, socket}
  end
end

defmodule LiveViewSecure.Test.Protocol.AppHookedLive do
  @moduledoc false
  # In the :app_hooks live_session, LiveViewSecure in the module.
  use Phoenix.LiveView
  import LiveViewSecure.HTML
  alias LiveViewSecure.Test.Protocol.Recorder

  on_mount({LiveViewSecure, events: ["delete_user", "app_action"], on_failure: :halt})

  def mount(_params, _session, socket), do: {:ok, socket}

  def render(assigns) do
    ~H"""
    <button id="delete-7" {signed_attrs(@live_view_secure, "delete_user", id: 7)}>x</button>
    """
  end

  def handle_event(event, params, socket) do
    Recorder.record(:app_hooked, event, params)
    {:noreply, socket}
  end
end

defmodule LiveViewSecure.Test.Protocol.MismatchLive do
  @moduledoc false
  use Phoenix.LiveView
  on_mount({LiveViewSecure, events: ["delete_user"]})
  def mount(_params, _session, socket), do: {:ok, socket}
  def render(assigns), do: ~H"<p>mismatch</p>"
  def handle_event(_event, _params, socket), do: {:noreply, socket}
end

defmodule LiveViewSecure.Test.Protocol.SameOptsLive do
  @moduledoc false
  use Phoenix.LiveView
  on_mount({LiveViewSecure, events: ["delete_user"], on_failure: :halt})
  def mount(_params, _session, socket), do: {:ok, socket}
  def render(assigns), do: ~H"<p>same opts</p>"
  def handle_event(_event, _params, socket), do: {:noreply, socket}
end

defmodule LiveViewSecure.Test.Protocol.ForeignChildLive do
  @moduledoc false
  # A nested LiveView that adopts a context handed over in its session.
  use Phoenix.LiveView
  alias LiveViewSecure.Test.Protocol.Recorder

  on_mount({LiveViewSecure, events: ["remove"], on_failure: :halt})

  def mount(_params, %{"ctx" => ctx}, socket),
    do: {:ok, Phoenix.Component.assign(socket, :live_view_secure, ctx)}

  def render(assigns), do: ~H"<p>foreign child</p>"

  def handle_event(event, params, socket) do
    Recorder.record(:foreign_child, event, params)
    {:noreply, socket}
  end
end

defmodule LiveViewSecure.Test.Protocol.ForeignParentLive do
  @moduledoc false
  use Phoenix.LiveView
  import LiveViewSecure.HTML
  alias LiveViewSecure.Test.Protocol.ForeignChildLive

  on_mount({LiveViewSecure, events: ["remove"], on_failure: :halt})

  def mount(_params, _session, socket), do: {:ok, socket}

  def render(assigns) do
    ~H"""
    <button id="parent-remove" {signed_attrs(@live_view_secure, "remove", item: "p0")}>x</button>
    {live_render(@socket, ForeignChildLive,
      id: "foreign-child",
      session: %{"ctx" => @live_view_secure}
    )}
    """
  end

  def handle_event(_event, _params, socket), do: {:noreply, socket}
end
