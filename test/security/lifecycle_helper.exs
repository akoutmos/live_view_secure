# Test LiveViews, components, a router and an endpoint for
# test/security/lifecycle_test.exs, which loads this file with
# Code.require_file/2. (Named *_helper.exs so mix test neither loads it as a
# test file nor warns.)

defmodule LiveViewSecure.Security.Lifecycle.Opts do
  @moduledoc false
  # An on_mount that reads the LiveViewSecure options from the session, so one
  # test LiveView can run under several configurations:
  #
  #     live_isolated(conn, ApprovalsLive, session: %{"lvs_opts" => [events: ..., on_failure: :halt]})
  #
  # It calls attach/2 directly, and is declared in the view, so it runs on
  # every mount.
  @default [events: ["approve", "view", "transfer", "purge", "delete_item"]]

  def on_mount(:default, _params, session, socket) do
    {:cont, LiveViewSecure.attach(socket, Map.get(session, "lvs_opts", @default))}
  end
end

defmodule LiveViewSecure.Security.Lifecycle.Log do
  @moduledoc false
  # Every handler appends to @log, rendered as <ul id="log">, so a test can
  # tell exactly which handlers ran.
  def log(socket, entry), do: Phoenix.Component.update(socket, :log, &(&1 ++ [entry]))
end

defmodule LiveViewSecure.Security.Lifecycle.ApprovalsLive do
  @moduledoc false
  # Realistic "one-shot" actions whose buttons disappear after use:
  #
  #   * approve: a pending request's button goes away once approved. The handler
  #     trusts that it only ever renders the button for pending requests (the
  #     "forgotten check" this library is supposed to backstop).
  #   * transfer: "Send 100" is hidden once it has been sent.
  #   * delete_item: stream items, removed with stream_delete/3.
  #   * purge: admin-only, hidden after "demote".
  use Phoenix.LiveView
  import LiveViewSecure.HTML
  import LiveViewSecure.Security.Lifecycle.Log

  on_mount(LiveViewSecure.Security.Lifecycle.Opts)

  def mount(_params, _session, socket) do
    socket =
      socket
      |> assign(pending: [5, 7], balance: 1000, transferred: false, admin: true, log: [])
      |> stream(:items, [%{id: 1}, %{id: 2}])
      |> attach_hook(:perm_hook, :handle_info, fn
        :rotate_in_hook, socket -> {:halt, LiveViewSecure.rotate(socket)}
        _msg, socket -> {:cont, socket}
      end)

    {:ok, socket}
  end

  def render(assigns) do
    ~H"""
    <div :for={id <- @pending} id={"req-#{id}"}>
      <button id={"approve-#{id}"} {signed_attrs(@live_view_secure, "approve", id: id)}>
        Approve
      </button>
      <button id={"view-#{id}"} {signed_attrs(@live_view_secure, "view", id: id)}>View</button>
    </div>
    <button
      :if={not @transferred}
      id="transfer"
      phx-click={signed_push(@live_view_secure, "transfer", value: %{amount: 100, to: "acct-9"})}
    >
      Send 100
    </button>
    <button :if={@admin} id="purge" {signed_attrs(@live_view_secure, "purge", scope: "all")}>
      Purge
    </button>
    <ul id="items" phx-update="stream">
      <li :for={{dom_id, item} <- @streams.items} id={dom_id}>
        <button
          id={"delete-item-#{item.id}"}
          {signed_attrs(@live_view_secure, "delete_item", id: item.id)}
        >
          x
        </button>
      </li>
    </ul>
    <button id="demote" phx-click="demote">demote, forgetting rotate/1</button>
    <button id="demote-rotate" phx-click="demote_rotate">demote</button>
    <span id="balance">{@balance}</span>
    <ul id="log">
      <li :for={entry <- @log}>{entry}</li>
    </ul>
    """
  end

  def handle_event("approve", %{"id" => id}, socket) do
    {:noreply,
     socket |> update(:pending, &List.delete(&1, String.to_integer(id))) |> log("approved #{id}")}
  end

  def handle_event("view", %{"id" => id}, socket), do: {:noreply, log(socket, "viewed #{id}")}

  def handle_event("transfer", %{"amount" => amount, "to" => to}, socket) do
    {:noreply,
     socket
     |> update(:balance, &(&1 - String.to_integer(amount)))
     |> assign(transferred: true)
     |> log("sent #{amount} to #{to}")}
  end

  def handle_event("purge", _params, socket), do: {:noreply, log(socket, "purged")}

  def handle_event("delete_item", %{"id" => id}, socket) do
    {:noreply,
     socket
     |> stream_delete(:items, %{id: String.to_integer(id)})
     |> log("deleted item #{id}")}
  end

  # Not declared, so not verified.
  def handle_event("demote", _params, socket),
    do: {:noreply, socket |> assign(admin: false) |> log("demoted")}

  def handle_event("demote_rotate", _params, socket),
    do: {:noreply, socket |> assign(admin: false) |> LiveViewSecure.rotate() |> log("demoted")}

  # Lets a test run arbitrary code inside the LiveView process.
  def handle_info({:run, fun}, socket), do: {:noreply, fun.(socket)}

  # A permission reload that finishes in handle_async/3, then rotates there.
  def handle_info(:reload_perms_async, socket),
    do: {:noreply, start_async(socket, :perms, fn -> :demoted end)}

  def handle_async(:perms, {:ok, :demoted}, socket),
    do: {:noreply, socket |> assign(admin: false) |> LiveViewSecure.rotate()}
end

defmodule LiveViewSecure.Security.Lifecycle.StaleRenderLive do
  @moduledoc false
  # Ways an app can keep an old token in the DOM after rotate/1.
  use Phoenix.LiveView
  import LiveViewSecure.HTML
  import LiveViewSecure.Security.Lifecycle.Log

  on_mount(
    {LiveViewSecure,
     events: [
       "precomputed",
       "copied_ctx",
       "closure",
       "streamed",
       "ignored",
       "temp",
       "fun_comp",
       "helper_assigns"
     ],
     on_failure: :halt}
  )

  def mount(_params, _session, socket) do
    ctx = socket.assigns.live_view_secure

    socket =
      socket
      |> assign(log: [], tick: 0)
      # (a) signed attrs computed once in mount and stored in another assign
      |> assign(precomputed: signed_attrs(ctx, "precomputed", id: 1))
      # (b) the context copied into another assign
      |> assign(ctx_copy: ctx)
      # (c) a closure that captured the context
      |> assign(signer: fn id -> signed_attrs(ctx, "closure", id: id) end)
      # (d) stream items
      |> stream(:rows, [%{id: 1}])
      # (e) temporary assigns
      |> assign(temp_rows: [1, 2])

    {:ok, socket, temporary_assigns: [temp_rows: []]}
  end

  attr(:secure, :any, required: true)
  attr(:id, :integer, required: true)

  defp fun_comp(assigns) do
    ~H"""
    <button id={"fun-comp-#{@id}"} {signed_attrs(@secure, "fun_comp", id: @id)}>f</button>
    """
  end

  # A helper that takes the whole assigns map (no change tracking at all).
  defp helper_attrs(assigns, id),
    do: signed_attrs(assigns.live_view_secure, "helper_assigns", id: id)

  def render(assigns) do
    ~H"""
    <button id="precomputed" {@precomputed}>a</button>
    <button id="copied-ctx" {signed_attrs(@ctx_copy, "copied_ctx", id: 1)}>b</button>
    <button :if={@tick > 0} id="copied-ctx-new" {signed_attrs(@ctx_copy, "copied_ctx", id: 2)}>
      b2
    </button>
    <button id="closure" {@signer.(1)}>c</button>
    <ul id="rows" phx-update="stream">
      <li :for={{dom_id, row} <- @streams.rows} id={dom_id}>
        <button id={"streamed-#{row.id}"} {signed_attrs(@live_view_secure, "streamed", id: row.id)}>
          d
        </button>
      </li>
    </ul>
    <div id="ignored-box" phx-update="ignore">
      <button id="ignored" {signed_attrs(@live_view_secure, "ignored", id: 1)}>e</button>
    </div>
    <div id="temp-box">
      <button
        :for={id <- @temp_rows}
        id={"temp-#{id}"}
        {signed_attrs(@live_view_secure, "temp", id: id)}
      >
        t
      </button>
    </div>
    <.fun_comp secure={@live_view_secure} id={1} />
    <button id="helper" {helper_attrs(assigns, 1)}>h</button>
    <ul id="log">
      <li :for={entry <- @log}>{entry}</li>
    </ul>
    """
  end

  def handle_event("rotate", _params, socket),
    do: {:noreply, socket |> LiveViewSecure.rotate() |> update(:tick, &(&1 + 1))}

  def handle_event("reinsert_stream", _params, socket),
    do: {:noreply, stream(socket, :rows, [%{id: 1}], reset: true)}

  def handle_event(event, %{"id" => id}, socket), do: {:noreply, log(socket, "#{event} #{id}")}
end

## LiveComponents

defmodule LiveViewSecure.Security.Lifecycle.AdminPanel do
  @moduledoc false
  # Follows the README: attach/2 in mount, sign with its own @live_view_secure,
  # target @myself. The parent passes `admin` down.
  use Phoenix.LiveComponent
  import LiveViewSecure.HTML

  def mount(socket) do
    {:ok,
     socket |> LiveViewSecure.attach(events: ["delete"], on_failure: :halt) |> assign(log: [])}
  end

  def render(assigns) do
    ~H"""
    <div id={@id}>
      <button
        :if={@admin}
        id={"#{@id}-delete-1"}
        {signed_attrs(@live_view_secure, "delete", [id: 1], target: @myself)}
      >
        delete
      </button>
      <ul id={"#{@id}-log"}>
        <li :for={entry <- @log}>{entry}</li>
      </ul>
    </div>
    """
  end

  def handle_event("delete", %{"id" => id}, socket),
    do: {:noreply, update(socket, :log, &(&1 ++ ["deleted #{id}"]))}
end

defmodule LiveViewSecure.Security.Lifecycle.SharedCtxPanel do
  @moduledoc false
  # Calls attach/2 like AdminPanel, but the parent also passes its own context
  # in under the same name (`live_view_secure={@live_view_secure}`), which
  # overwrites the component's key on every update.
  use Phoenix.LiveComponent
  import LiveViewSecure.HTML

  def mount(socket) do
    {:ok,
     socket |> LiveViewSecure.attach(events: ["delete"], on_failure: :halt) |> assign(log: [])}
  end

  def render(assigns) do
    ~H"""
    <div id={@id}>
      <button
        id={"#{@id}-delete-2"}
        {signed_attrs(@live_view_secure, "delete", [id: 2], target: @myself)}
      >
        delete 2
      </button>
      <ul id={"#{@id}-log"}>
        <li :for={entry <- @log}>{entry}</li>
      </ul>
    </div>
    """
  end

  def handle_event("delete", %{"id" => id}, socket),
    do: {:noreply, update(socket, :log, &(&1 ++ ["deleted #{id}"]))}
end

defmodule LiveViewSecure.Security.Lifecycle.NoHookPanel do
  @moduledoc false
  # Signs with the parent's context (passed as `secure`), the way the
  # ArgumentError from Signer.sign/3 suggests ("pass @live_view_secure through
  # to this component"), and targets @myself. It never calls attach/2.
  use Phoenix.LiveComponent
  import LiveViewSecure.HTML

  def mount(socket), do: {:ok, assign(socket, log: [])}

  def render(assigns) do
    ~H"""
    <div id={@id}>
      <button id={"#{@id}-delete-3"} {signed_attrs(@secure, "delete", [id: 3], target: @myself)}>
        delete 3
      </button>
      <ul id={"#{@id}-log"}>
        <li :for={entry <- @log}>{entry}</li>
      </ul>
    </div>
    """
  end

  def handle_event("delete", %{"id" => id}, socket),
    do: {:noreply, update(socket, :log, &(&1 ++ ["deleted #{id}"]))}
end

defmodule LiveViewSecure.Security.Lifecycle.NoHookAttrPanel do
  @moduledoc false
  # Same as NoHookPanel, but with phx-target written as its own attribute
  # instead of signed_attrs/4's :target option.
  use Phoenix.LiveComponent
  import LiveViewSecure.HTML

  def mount(socket), do: {:ok, assign(socket, log: [])}

  def render(assigns) do
    ~H"""
    <div id={@id}>
      <button id={"#{@id}-delete-4"} {signed_attrs(@secure, "delete", id: 4)} phx-target={@myself}>
        delete 4
      </button>
      <ul id={"#{@id}-log"}>
        <li :for={entry <- @log}>{entry}</li>
      </ul>
    </div>
    """
  end

  def handle_event("delete", %{"id" => id}, socket),
    do: {:noreply, update(socket, :log, &(&1 ++ ["deleted #{id}"]))}
end

defmodule LiveViewSecure.Security.Lifecycle.PanelHostLive do
  @moduledoc false
  use Phoenix.LiveView
  import LiveViewSecure.HTML
  import LiveViewSecure.Security.Lifecycle.Log

  alias LiveViewSecure.Security.Lifecycle.AdminPanel

  on_mount({LiveViewSecure, events: ["delete"], on_failure: :halt})

  def mount(_params, _session, socket),
    do: {:ok, assign(socket, admin: true, log: [], show_panel: true)}

  def render(assigns) do
    ~H"""
    <button :if={@admin} id="parent-delete-1" {signed_attrs(@live_view_secure, "delete", id: 1)}>
      parent delete
    </button>
    <.live_component :if={@show_panel} module={AdminPanel} id="panel" admin={@admin} />
    <.live_component module={AdminPanel} id="panel-b" admin={true} />
    <button id="demote" phx-click="demote">demote</button>
    <ul id="log">
      <li :for={entry <- @log}>{entry}</li>
    </ul>
    """
  end

  def handle_event("delete", %{"id" => id}, socket),
    do: {:noreply, log(socket, "parent deleted #{id}")}

  # README "Revoking tokens": permissions changed, rotate.
  def handle_event("demote", _params, socket),
    do: {:noreply, socket |> assign(admin: false) |> LiveViewSecure.rotate()}

  def handle_event("toggle_panel", _params, socket),
    do: {:noreply, update(socket, :show_panel, &(not &1))}

  def handle_event("rotate", _params, socket), do: {:noreply, LiveViewSecure.rotate(socket)}

  def handle_info({:run, fun}, socket), do: {:noreply, fun.(socket)}
end

defmodule LiveViewSecure.Security.Lifecycle.MisconfiguredHostLive do
  @moduledoc false
  # Hosts one misconfigured component, chosen through the session.
  use Phoenix.LiveView
  import LiveViewSecure.HTML
  import LiveViewSecure.Security.Lifecycle.Log

  alias LiveViewSecure.Security.Lifecycle.{NoHookAttrPanel, NoHookPanel, SharedCtxPanel}

  on_mount({LiveViewSecure, events: ["delete"], on_failure: :halt})

  def mount(_params, %{"panel" => panel}, socket),
    do: {:ok, assign(socket, panel: panel, log: [])}

  def render(assigns) do
    ~H"""
    <button id="parent-delete-1" {signed_attrs(@live_view_secure, "delete", id: 1)}>
      parent delete
    </button>
    <.live_component
      :if={@panel == "shared"}
      module={SharedCtxPanel}
      id="shared"
      live_view_secure={@live_view_secure}
    />
    <.live_component
      :if={@panel == "nohook"}
      module={NoHookPanel}
      id="nohook"
      secure={@live_view_secure}
    />
    <.live_component
      :if={@panel == "nohook-attr"}
      module={NoHookAttrPanel}
      id="nohook-attr"
      secure={@live_view_secure}
    />
    <ul id="log">
      <li :for={entry <- @log}>{entry}</li>
    </ul>
    """
  end

  def handle_event("delete", %{"id" => id}, socket),
    do: {:noreply, log(socket, "parent deleted #{id}")}
end

## Nested LiveViews

defmodule LiveViewSecure.Security.Lifecycle.ChildLive do
  @moduledoc false
  use Phoenix.LiveView
  import LiveViewSecure.HTML
  import LiveViewSecure.Security.Lifecycle.Log

  on_mount({LiveViewSecure, events: ["delete"], on_failure: :halt})

  def mount(_params, _session, socket), do: {:ok, assign(socket, log: [])}

  def render(assigns) do
    ~H"""
    <button id="child-delete-9" {signed_attrs(@live_view_secure, "delete", id: 9)}>child delete</button>
    <ul id="child-log">
      <li :for={entry <- @log}>{entry}</li>
    </ul>
    """
  end

  def handle_event("delete", %{"id" => id}, socket),
    do: {:noreply, log(socket, "child deleted #{id}")}
end

defmodule LiveViewSecure.Security.Lifecycle.NestedParentLive do
  @moduledoc false
  use Phoenix.LiveView
  import LiveViewSecure.HTML
  import LiveViewSecure.Security.Lifecycle.Log

  on_mount({LiveViewSecure, events: ["delete"], on_failure: :halt})

  def mount(_params, _session, socket), do: {:ok, assign(socket, log: [])}

  def render(assigns) do
    ~H"""
    <button id="parent-delete-1" {signed_attrs(@live_view_secure, "delete", id: 1)}>delete</button>
    {live_render(@socket, LiveViewSecure.Security.Lifecycle.ChildLive, id: "child")}
    <ul id="log">
      <li :for={entry <- @log}>{entry}</li>
    </ul>
    """
  end

  def handle_event("delete", %{"id" => id}, socket),
    do: {:noreply, log(socket, "parent deleted #{id}")}
end

defmodule LiveViewSecure.Security.Lifecycle.SessionChildLive do
  @moduledoc false
  # A nested LiveView that is handed the parent's context through its session
  # (say, to forward it to a component). It never even signs with it.
  use Phoenix.LiveView

  def mount(_params, %{"secure" => secure}, socket),
    do: {:ok, assign(socket, secure: secure)}

  def render(assigns) do
    ~H"""
    <p id="session-child">child</p>
    """
  end
end

defmodule LiveViewSecure.Security.Lifecycle.LeakyParentLive do
  @moduledoc false
  use Phoenix.LiveView
  import LiveViewSecure.HTML
  import LiveViewSecure.Security.Lifecycle.Log

  on_mount({LiveViewSecure, events: ["delete"], on_failure: :halt})

  def mount(_params, _session, socket), do: {:ok, assign(socket, log: [])}

  def render(assigns) do
    ~H"""
    <button id="parent-delete-1" {signed_attrs(@live_view_secure, "delete", id: 1)}>delete</button>
    {live_render(@socket, LiveViewSecure.Security.Lifecycle.SessionChildLive,
      id: "leaky-child",
      session: %{"secure" => @live_view_secure}
    )}
    <ul id="log">
      <li :for={entry <- @log}>{entry}</li>
    </ul>
    """
  end

  def handle_event("delete", %{"id" => id}, socket),
    do: {:noreply, log(socket, "parent deleted #{id}")}
end

defmodule LiveViewSecure.Security.Lifecycle.AssignNewChildLive do
  @moduledoc false
  # A nested LiveView that "shares" its parent's context the way LiveView
  # shares assigns with nested children: assign_new/3. No on_mount of its own.
  use Phoenix.LiveView
  import LiveViewSecure.HTML

  def mount(_params, _session, socket),
    do: {:ok, assign_new(socket, :live_view_secure, fn -> raise "no parent context" end)}

  def render(assigns) do
    ~H"""
    <button id="an-child-delete-77" {signed_attrs(@live_view_secure, "delete", id: 77)}>x</button>
    """
  end

  def handle_event("delete", _params, socket), do: {:noreply, socket}
end

defmodule LiveViewSecure.Security.Lifecycle.AssignNewParentLive do
  @moduledoc false
  use Phoenix.LiveView
  import LiveViewSecure.HTML
  import LiveViewSecure.Security.Lifecycle.Log

  on_mount({LiveViewSecure, events: ["delete"], on_failure: :halt})

  def mount(_params, _session, socket), do: {:ok, assign(socket, log: [])}

  def render(assigns) do
    ~H"""
    <button id="parent-delete-1" {signed_attrs(@live_view_secure, "delete", id: 1)}>delete</button>
    {live_render(@socket, LiveViewSecure.Security.Lifecycle.AssignNewChildLive, id: "an-child")}
    <ul id="log">
      <li :for={entry <- @log}>{entry}</li>
    </ul>
    """
  end

  def handle_event("delete", %{"id" => id}, socket),
    do: {:noreply, log(socket, "parent deleted #{id}")}
end

## Hook ordering

defmodule LiveViewSecure.Security.Lifecycle.AppEventHook do
  @moduledoc false
  # An app-wide on_mount (typically in a live_session) that attaches its own
  # :handle_event hook. Here it implements a shared "bulk" action for every
  # LiveView in the session and halts, as hooks that fully handle an event do.
  import Phoenix.LiveView
  import LiveViewSecure.Security.Lifecycle.Log

  def on_mount(:default, _params, _session, socket) do
    {:cont,
     attach_hook(socket, :app_events, :handle_event, fn
       "delete", %{"id" => id}, socket -> {:halt, log(socket, "app hook deleted #{id}")}
       _event, _params, socket -> {:cont, socket}
     end)}
  end
end

defmodule LiveViewSecure.Security.Lifecycle.OrderedLive do
  @moduledoc false
  # Mounted under `live_session :app, on_mount: [AppEventHook]`, so the app's
  # hook is attached before this module's own on_mount.
  use Phoenix.LiveView
  import LiveViewSecure.HTML
  alias LiveViewSecure.Security.Lifecycle.Log

  on_mount({LiveViewSecure, events: ["delete"], on_failure: :halt})

  def mount(_params, _session, socket), do: {:ok, assign(socket, log: [])}

  def render(assigns) do
    ~H"""
    <button id="delete-1" {signed_attrs(@live_view_secure, "delete", id: 1)}>delete</button>
    <ul id="log">
      <li :for={entry <- @log}>{entry}</li>
    </ul>
    """
  end

  def handle_event("delete", %{"id" => id}, socket),
    do: {:noreply, Log.log(socket, "deleted #{id}")}
end

defmodule LiveViewSecure.Security.Lifecycle.DoubleAttachLive do
  @moduledoc false
  # Mounted under a live_session that already runs LiveViewSecure's on_mount.
  use Phoenix.LiveView

  on_mount({LiveViewSecure, events: :all})

  def mount(_params, _session, socket), do: {:ok, socket}
  def render(assigns), do: ~H"<p>double</p>"
end

defmodule LiveViewSecure.Security.Lifecycle.SessionSecuredLive do
  @moduledoc false
  # Protected only by its live_session's on_mount.
  use Phoenix.LiveView
  import LiveViewSecure.HTML
  import LiveViewSecure.Security.Lifecycle.Log

  def mount(_params, _session, socket), do: {:ok, assign(socket, log: [])}

  def render(assigns) do
    ~H"""
    <button id="delete-1" {signed_attrs(@live_view_secure, "delete", id: 1)}>delete</button>
    <ul id="log">
      <li :for={entry <- @log}>{entry}</li>
    </ul>
    """
  end

  def handle_event("delete", %{"id" => id}, socket), do: {:noreply, log(socket, "deleted #{id}")}
end

defmodule LiveViewSecure.Security.Lifecycle.UnhookedChildLive do
  @moduledoc false
  # Nested in SessionNestedLive with live_render, with no on_mount of its own.
  use Phoenix.LiveView
  import LiveViewSecure.Security.Lifecycle.Log

  def mount(_params, _session, socket), do: {:ok, assign(socket, log: [])}

  def render(assigns) do
    ~H"""
    <ul id="child-log">
      <li :for={entry <- @log}>{entry}</li>
    </ul>
    """
  end

  def handle_event("delete", %{"id" => id}, socket),
    do: {:noreply, log(socket, "child deleted #{id}")}
end

defmodule LiveViewSecure.Security.Lifecycle.SessionNestedLive do
  @moduledoc false
  # Routed in a live_session that declares LiveViewSecure, and nests a child.
  use Phoenix.LiveView

  def mount(_params, _session, socket), do: {:ok, socket}

  def render(assigns) do
    ~H"""
    {live_render(@socket, LiveViewSecure.Security.Lifecycle.UnhookedChildLive, id: "unhooked-child")}
    """
  end
end

defmodule LiveViewSecure.Security.Lifecycle.ClobberLive do
  @moduledoc false
  # App code that clobbers the @live_view_secure assign.
  use Phoenix.LiveView
  import LiveViewSecure.HTML
  import LiveViewSecure.Security.Lifecycle.Log

  on_mount({LiveViewSecure, events: ["delete"], on_failure: :halt})

  def mount(_params, _session, socket), do: {:ok, assign(socket, log: [])}

  def render(assigns) do
    ~H"""
    <button
      :if={@live_view_secure}
      id="delete-1"
      {signed_attrs(@live_view_secure, "delete", id: 1)}
    >
      delete
    </button>
    <ul id="log">
      <li :for={entry <- @log}>{entry}</li>
    </ul>
    """
  end

  def handle_event("delete", %{"id" => id}, socket), do: {:noreply, log(socket, "deleted #{id}")}

  def handle_event("clobber", _params, socket),
    do: {:noreply, assign(socket, live_view_secure: nil)}
end

defmodule LiveViewSecure.Security.Lifecycle.HookReplyLive do
  @moduledoc false
  # A JS hook pushes "fetch_secret" with pushEvent and expects a reply.
  use Phoenix.LiveView
  import LiveViewSecure.HTML

  on_mount({LiveViewSecure, events: ["fetch_secret"], on_failure: :halt})

  def mount(_params, _session, socket), do: {:ok, assign(socket, fetched: 0)}

  def render(assigns) do
    ~H"""
    <div
      id="hooked"
      phx-hook="Fetcher"
      data-push={signed_push(@live_view_secure, "fetch_secret", value: %{id: 1})}
    >
      {@fetched}
    </div>
    """
  end

  def handle_event("fetch_secret", %{"id" => id}, socket),
    do: {:reply, %{secret: "s3cret-#{id}"}, update(socket, :fetched, &(&1 + 1))}
end

## Single use

defmodule LiveViewSecure.Security.Lifecycle.RepeatLive do
  @moduledoc false
  # A repeatable action whose button stays on the page ("Deposit 100"), a form
  # meant to be submitted many times, and a list of N rows (for diff costs).
  use Phoenix.LiveView
  import LiveViewSecure.HTML
  import LiveViewSecure.Security.Lifecycle.Log

  on_mount(LiveViewSecure.Security.Lifecycle.Opts)

  def mount(_params, session, socket) do
    rows = Map.get(session, "rows", 2)
    {:ok, assign(socket, balance: 0, log: [], rows: Enum.to_list(1..rows), tick: 0)}
  end

  def render(assigns) do
    ~H"""
    <button id="deposit" phx-click={signed_push(@live_view_secure, "deposit", value: %{amount: 100})}>
      Deposit 100
    </button>
    <form id="note-form" phx-submit="save_note">
      <.signed_inputs secure={@live_view_secure} event="save_note" values={%{id: 1}} />
      <input type="text" name="body" value="" />
    </form>
    <div :for={id <- @rows} id={"row-#{id}"}>
      <button id={"approve-#{id}"} {signed_attrs(@live_view_secure, "approve", id: id)}>A</button>
      <button id={"view-#{id}"} {signed_attrs(@live_view_secure, "view", id: id)}>V</button>
    </div>
    <span id="tick">{@tick}</span>
    <span id="balance">{@balance}</span>
    <ul id="log">
      <li :for={entry <- @log}>{entry}</li>
    </ul>
    """
  end

  def handle_event("deposit", %{"amount" => amount}, socket) do
    {:noreply,
     socket |> update(:balance, &(&1 + String.to_integer(amount))) |> log("deposit #{amount}")}
  end

  def handle_event("save_note", %{"id" => id, "body" => body}, socket),
    do: {:noreply, log(socket, "saved #{id}: #{body}")}

  def handle_event("approve", %{"id" => id}, socket),
    do: {:noreply, log(socket, "approved #{id}")}

  def handle_event("view", %{"id" => id}, socket), do: {:noreply, log(socket, "viewed #{id}")}
  def handle_event("tick", _params, socket), do: {:noreply, update(socket, :tick, &(&1 + 1))}
  def handle_event("rotate", _params, socket), do: {:noreply, LiveViewSecure.rotate(socket)}
end

defmodule LiveViewSecure.Security.Lifecycle.StreamItemsLive do
  @moduledoc false
  # The README's flagship case: a stream (the server no longer holds the
  # items) with a single-use delete on every item and an ordinary "view"
  # button, plus a single-use "approve" outside the stream.
  use Phoenix.LiveView
  import LiveViewSecure.HTML
  import LiveViewSecure.Security.Lifecycle.Log

  on_mount(LiveViewSecure.Security.Lifecycle.Opts)

  def mount(_params, _session, socket) do
    {:ok,
     socket
     |> assign(log: [], pending: [5, 7])
     |> stream(:items, [%{id: 1}, %{id: 2}, %{id: 3}])}
  end

  def render(assigns) do
    ~H"""
    <ul id="items" phx-update="stream">
      <li :for={{dom_id, item} <- @streams.items} id={dom_id}>
        <button
          id={"delete-item-#{item.id}"}
          {signed_attrs(@live_view_secure, "delete_item", id: item.id)}
        >
          x
        </button>
        <button
          id={"view-item-#{item.id}"}
          {signed_attrs(@live_view_secure, "view_item", id: item.id)}
        >
          v
        </button>
      </li>
    </ul>
    <button
      :for={id <- @pending}
      id={"approve-#{id}"}
      {signed_attrs(@live_view_secure, "approve", id: id)}
    >
      approve
    </button>
    <ul id="log">
      <li :for={entry <- @log}>{entry}</li>
    </ul>
    """
  end

  def handle_event("delete_item", %{"id" => id}, socket) do
    {:noreply,
     socket |> stream_delete(:items, %{id: String.to_integer(id)}) |> log("deleted item #{id}")}
  end

  def handle_event("view_item", %{"id" => id}, socket),
    do: {:noreply, log(socket, "viewed item #{id}")}

  def handle_event("approve", %{"id" => id}, socket) do
    {:noreply,
     socket |> update(:pending, &List.delete(&1, String.to_integer(id))) |> log("approved #{id}")}
  end
end

defmodule LiveViewSecure.Security.Lifecycle.TempSingleUseLive do
  @moduledoc false
  # Rows rendered once from a temporary assign, next to a single-use button.
  use Phoenix.LiveView
  import LiveViewSecure.HTML
  import LiveViewSecure.Security.Lifecycle.Log

  on_mount({LiveViewSecure, events: [{"deposit", single_use: true}, "open"], on_failure: :halt})

  def mount(_params, _session, socket),
    do: {:ok, assign(socket, log: [], rows: [1, 2]), temporary_assigns: [rows: []]}

  def render(assigns) do
    ~H"""
    <button id="deposit" {signed_attrs(@live_view_secure, "deposit", amount: 100)}>deposit</button>
    <div id="rows">
      <button :for={id <- @rows} id={"open-#{id}"} {signed_attrs(@live_view_secure, "open", id: id)}>
        open
      </button>
    </div>
    <ul id="log">
      <li :for={entry <- @log}>{entry}</li>
    </ul>
    """
  end

  def handle_event("deposit", _params, socket), do: {:noreply, log(socket, "deposit")}
  def handle_event("open", %{"id" => id}, socket), do: {:noreply, log(socket, "opened #{id}")}
end

defmodule LiveViewSecure.Security.Lifecycle.SingleUsePanel do
  @moduledoc false
  use Phoenix.LiveComponent
  import LiveViewSecure.HTML

  def mount(socket) do
    {:ok,
     socket
     |> LiveViewSecure.attach(events: [{"redeem", single_use: true}])
     |> assign(log: [])}
  end

  def render(assigns) do
    ~H"""
    <div id={@id}>
      <button id="redeem" {signed_attrs(@live_view_secure, "redeem", [code: "X1"], target: @myself)}>
        redeem
      </button>
      <ul id="panel-log">
        <li :for={entry <- @log}>{entry}</li>
      </ul>
    </div>
    """
  end

  def handle_event("redeem", %{"code" => code}, socket),
    do: {:noreply, update(socket, :log, &(&1 ++ ["redeemed #{code}"]))}
end

defmodule LiveViewSecure.Security.Lifecycle.SingleUseHostLive do
  @moduledoc false
  use Phoenix.LiveView
  import LiveViewSecure.HTML
  import LiveViewSecure.Security.Lifecycle.Log

  on_mount({LiveViewSecure, events: ["view"]})

  def mount(_params, _session, socket), do: {:ok, assign(socket, log: [])}

  def render(assigns) do
    ~H"""
    <button id="host-view" {signed_attrs(@live_view_secure, "view", id: 1)}>view</button>
    <.live_component module={LiveViewSecure.Security.Lifecycle.SingleUsePanel} id="panel" />
    <ul id="log">
      <li :for={entry <- @log}>{entry}</li>
    </ul>
    """
  end

  def handle_event("view", %{"id" => id}, socket), do: {:noreply, log(socket, "viewed #{id}")}
end

## Components under on_failure: :raise

defmodule LiveViewSecure.Security.Lifecycle.RaisingPanel do
  @moduledoc false
  use Phoenix.LiveComponent
  import LiveViewSecure.HTML

  def mount(socket),
    do: {:ok, socket |> LiveViewSecure.attach(events: ["delete"]) |> assign(log: [])}

  def render(assigns) do
    ~H"""
    <div id={@id}>
      <button
        id="raising-delete-1"
        {signed_attrs(@live_view_secure, "delete", [id: 1], target: @myself)}
      >
        delete
      </button>
      <ul id="raising-log">
        <li :for={entry <- @log}>{entry}</li>
      </ul>
    </div>
    """
  end

  def handle_event("delete", %{"id" => id}, socket),
    do: {:noreply, update(socket, :log, &(&1 ++ ["deleted #{id}"]))}
end

defmodule LiveViewSecure.Security.Lifecycle.RaisingHostLive do
  @moduledoc false
  use Phoenix.LiveView

  on_mount({LiveViewSecure, events: ["noop"]})

  def mount(_params, _session, socket), do: {:ok, socket}

  def render(assigns) do
    ~H"""
    <.live_component module={LiveViewSecure.Security.Lifecycle.RaisingPanel} id="raising" />
    """
  end

  def handle_event("rotate", _params, socket), do: {:noreply, LiveViewSecure.rotate(socket)}
end

## More hook ordering

defmodule LiveViewSecure.Security.Lifecycle.TraceHook do
  @moduledoc false
  # App hooks that record which events they saw, in order.
  import Phoenix.LiveView
  import LiveViewSecure.Security.Lifecycle.Log

  def on_mount(name, _params, _session, socket), do: {:cont, attach(socket, name)}

  def attach(socket, name) do
    attach_hook(socket, name, :handle_event, fn event, _params, socket ->
      {:cont, log(socket, "#{name} saw #{event}")}
    end)
  end
end

defmodule LiveViewSecure.Security.Lifecycle.EarlyHooksLive do
  @moduledoc false
  # Two app hooks attached before LiveViewSecure, one after it (in mount/3).
  use Phoenix.LiveView
  import LiveViewSecure.HTML
  alias LiveViewSecure.Security.Lifecycle.TraceHook
  import LiveViewSecure.Security.Lifecycle.Log

  on_mount({LiveViewSecure.Security.Lifecycle.TraceHook, :early_a})
  on_mount({LiveViewSecure.Security.Lifecycle.TraceHook, :early_b})
  on_mount({LiveViewSecure, events: ["delete"], on_failure: :halt})

  def mount(_params, _session, socket) do
    {:ok,
     socket
     |> assign(log: [])
     |> TraceHook.attach(:late)}
  end

  def render(assigns) do
    ~H"""
    <button id="delete-1" {signed_attrs(@live_view_secure, "delete", id: 1)}>delete</button>
    <ul id="log">
      <li :for={entry <- @log}>{entry}</li>
    </ul>
    """
  end

  def handle_event("delete", %{"id" => id}, socket), do: {:noreply, log(socket, "deleted #{id}")}

  # Not declared. App code detaching its own (re-ordered) hook by id.
  def handle_event("drop_early_a", _params, socket),
    do: {:noreply, detach_hook(socket, :early_a, :handle_event)}
end

defmodule LiveViewSecure.Security.Lifecycle.DoubleModuleLive do
  @moduledoc false
  use Phoenix.LiveView

  on_mount({LiveViewSecure, events: ["a"]})
  on_mount({LiveViewSecure, events: ["b"]})

  def mount(_params, _session, socket), do: {:ok, socket}
  def render(assigns), do: ~H"<p>double</p>"
end

## Router + endpoint for live_session tests

defmodule LiveViewSecure.Security.Lifecycle.Router do
  @moduledoc false
  use Phoenix.Router
  import Phoenix.LiveView.Router

  alias LiveViewSecure.Security.Lifecycle

  live_session :app, on_mount: [Lifecycle.AppEventHook] do
    live("/ordered", Lifecycle.OrderedLive)
  end

  live_session :secured, on_mount: [{LiveViewSecure, events: ["delete"]}] do
    live("/double", Lifecycle.DoubleAttachLive)
    live("/session-secured", Lifecycle.SessionSecuredLive)
    live("/session-nested", Lifecycle.SessionNestedLive)
  end

  live_session :plain do
    live("/approvals", Lifecycle.ApprovalsLive)
  end
end

defmodule LiveViewSecure.Security.Lifecycle.ErrorHTML do
  @moduledoc false
  def render(template, _assigns), do: template
end

defmodule LiveViewSecure.Security.Lifecycle.Endpoint do
  @moduledoc false
  use Phoenix.Endpoint, otp_app: :live_view_secure

  socket("/live", Phoenix.LiveView.Socket)
  plug(LiveViewSecure.Security.Lifecycle.Router)
end
