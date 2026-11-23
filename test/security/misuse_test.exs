# Red-team tests: developer misuse, output safety, key leakage (rounds 1 and 2).
#
# Every test asserts the SECURE (or at least the intended) behavior, so a
# failing test is a finding. Tests that pass are the record of attacks that are
# correctly blocked. Test names start with the round-1 finding id (F1..F15) or
# R2-n for findings new in round 2. Tests tagged :known_limitation have no
# library fix proposed; exclude them with `--exclude known_limitation`.
#
# The LiveViews below each model a mistake a competent but busy developer
# could ship.

defmodule LiveViewSecure.Security.Misuse.Log do
  @moduledoc false
  def log(socket, entry), do: {:noreply, Phoenix.Component.update(socket, :log, &[entry | &1])}
end

defmodule LiveViewSecure.Security.Misuse.RenamedLive do
  @moduledoc false
  # The event used to be "delete_user". Template and handler were renamed to
  # "remove_user", :events was not.
  use Phoenix.LiveView
  import LiveViewSecure.HTML
  import LiveViewSecure.Security.Misuse.Log

  on_mount({LiveViewSecure, events: ["delete_user"]})

  def mount(_params, _session, socket), do: {:ok, assign(socket, log: [])}

  def render(assigns) do
    ~H"""
    <button id="remove-7" {signed_attrs(@live_view_secure, "remove_user", id: 7)}>Remove</button>
    <ul id="log">
      <li :for={e <- Enum.reverse(@log)}>{e}</li>
    </ul>
    """
  end

  def handle_event("remove_user", %{"id" => id}, socket), do: log(socket, "removed #{id}")
end

defmodule LiveViewSecure.Security.Misuse.AllInListLive do
  @moduledoc false
  # `events: [:all]` instead of `events: :all`.
  use Phoenix.LiveView
  import LiveViewSecure.HTML
  import LiveViewSecure.Security.Misuse.Log

  on_mount({LiveViewSecure, events: [:all]})

  def mount(_params, _session, socket), do: {:ok, assign(socket, log: [])}

  def render(assigns) do
    ~H"""
    <button id="delete-7" {signed_attrs(@live_view_secure, "delete_user", id: 7)}>Delete</button>
    <ul id="log">
      <li :for={e <- Enum.reverse(@log)}>{e}</li>
    </ul>
    """
  end

  def handle_event("delete_user", %{"id" => id}, socket), do: log(socket, "deleted #{id}")
end

defmodule LiveViewSecure.Security.Misuse.AtomEventsLive do
  @moduledoc false
  # Declared as an atom, signed as a string (and the other way around).
  use Phoenix.LiveView
  import LiveViewSecure.HTML
  import LiveViewSecure.Security.Misuse.Log

  on_mount({LiveViewSecure, events: [:delete_user, "archive"]})

  def mount(_params, _session, socket), do: {:ok, assign(socket, log: [])}

  def render(assigns) do
    ~H"""
    <button id="delete-7" {signed_attrs(@live_view_secure, "delete_user", id: 7)}>Delete</button>
    <button id="archive-7" {signed_attrs(@live_view_secure, :archive, id: 7)}>Archive</button>
    <ul id="log">
      <li :for={e <- Enum.reverse(@log)}>{e}</li>
    </ul>
    """
  end

  def handle_event("delete_user", %{"id" => id}, socket), do: log(socket, "deleted #{id}")
  def handle_event("archive", %{"id" => id}, socket), do: log(socket, "archived #{id}")
end

defmodule LiveViewSecure.Security.Misuse.ExceptSignedLive do
  @moduledoc false
  # Signs an event that :except excludes from verification.
  use Phoenix.LiveView
  import LiveViewSecure.HTML

  on_mount({LiveViewSecure, events: :all, except: ["validate"]})

  def mount(_params, _session, socket), do: {:ok, socket}

  def render(assigns) do
    ~H"""
    <button {signed_attrs(@live_view_secure, "validate", id: 1)}>x</button>
    """
  end
end

defmodule LiveViewSecure.Security.Misuse.SharedCtxComponent do
  @moduledoc false
  # A LiveComponent that signs with the parent's @live_view_secure (passed in as
  # an attr) instead of calling LiveViewSecure.attach/2, using `target:`.
  use Phoenix.LiveComponent
  import LiveViewSecure.HTML

  def mount(socket), do: {:ok, assign(socket, removed: [])}

  def render(assigns) do
    ~H"""
    <div id={@id}>
      <button
        :for={item <- @items}
        id={"remove-#{item}"}
        {signed_attrs(@secure, "remove", [item: item], target: @myself)}
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

defmodule LiveViewSecure.Security.Misuse.SharedCtxPhxTargetComponent do
  @moduledoc false
  # The same mistake, but phx-target is written as its own attribute (as most
  # LiveComponent examples do), so the helper never sees the target.
  use Phoenix.LiveComponent
  import LiveViewSecure.HTML

  def mount(socket), do: {:ok, assign(socket, removed: [])}

  def render(assigns) do
    ~H"""
    <div id={@id}>
      <button
        :for={item <- @items}
        id={"remove-#{item}"}
        phx-target={@myself}
        {signed_attrs(@secure, "remove", item: item)}
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

defmodule LiveViewSecure.Security.Misuse.SharedCtxLive do
  @moduledoc false
  use Phoenix.LiveView

  # The strictest posture the README offers.
  on_mount({LiveViewSecure, events: :all})

  def mount(_params, session, socket),
    do: {:ok, assign(socket, component: Module.concat([session["component"]]))}

  def render(assigns) do
    ~H"""
    <.live_component module={@component} id="cart" secure={@live_view_secure} items={["a", "b"]} />
    """
  end
end

defmodule LiveViewSecure.Security.Misuse.OverwritingComponent do
  @moduledoc false
  # Attaches its own hook, then overwrites its context with the parent's.
  use Phoenix.LiveComponent
  import LiveViewSecure.HTML

  def mount(socket) do
    {:ok, socket |> LiveViewSecure.attach(events: ["remove"]) |> assign(removed: [])}
  end

  def update(assigns, socket),
    do: {:ok, socket |> assign(assigns) |> assign(:live_view_secure, assigns.secure)}

  def render(assigns) do
    ~H"""
    <div id={@id}>
      <button
        :for={item <- @items}
        id={"remove-#{item}"}
        phx-target={@myself}
        {signed_attrs(@live_view_secure, "remove", item: item)}
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

defmodule LiveViewSecure.Security.Misuse.BulkActions do
  @moduledoc false
  # A shared on_mount (typically from a live_session) that handles a common
  # event in a :handle_event hook.
  def on_mount(:default, _params, _session, socket) do
    {:cont,
     Phoenix.LiveView.attach_hook(socket, :bulk_actions, :handle_event, fn
       "bulk_delete", %{"ids" => ids}, socket ->
         {:halt, Phoenix.Component.update(socket, :log, &["bulk deleted #{ids}" | &1])}

       _event, _params, socket ->
         {:cont, socket}
     end)}
  end
end

defmodule LiveViewSecure.Security.Misuse.EarlyHookLive do
  @moduledoc false
  use Phoenix.LiveView
  import LiveViewSecure.HTML

  on_mount(LiveViewSecure.Security.Misuse.BulkActions)
  on_mount({LiveViewSecure, events: :all})

  def mount(_params, _session, socket), do: {:ok, assign(socket, log: [])}

  def render(assigns) do
    ~H"""
    <button id="bulk" {signed_attrs(@live_view_secure, "bulk_delete", ids: "1,2")}>Delete selected</button>
    <ul id="log">
      <li :for={e <- Enum.reverse(@log)}>{e}</li>
    </ul>
    """
  end
end

defmodule LiveViewSecure.Security.Misuse.AllWithFormLive do
  @moduledoc false
  # Strict posture plus one signed form whose user fields stay unsigned.
  use Phoenix.LiveView
  import LiveViewSecure.HTML
  import LiveViewSecure.Security.Misuse.Log

  on_mount(
    {LiveViewSecure,
     events: [:all, {"save", unsigned: :allow, signed: ["id"]}], except: ["validate"]}
  )

  def mount(_params, _session, socket), do: {:ok, assign(socket, log: [])}

  def render(assigns) do
    ~H"""
    <button id="archive-7" phx-click={signed_push(@live_view_secure, "archive", value: %{id: 7})}>
      Archive
    </button>
    <form id="post" phx-change="validate" phx-submit="save">
      <.signed_inputs secure={@live_view_secure} event="save" values={%{id: 99}} />
      <input type="text" name="title" value="" />
    </form>
    <ul id="log">
      <li :for={e <- Enum.reverse(@log)}>{e}</li>
    </ul>
    """
  end

  def handle_event("archive", %{"id" => id} = params, socket),
    do: log(socket, "archived #{id} scope=#{Map.get(params, "scope", "mine")}")

  def handle_event("save", %{"id" => id, "title" => title}, socket),
    do: log(socket, "saved #{id} title=#{title}")

  def handle_event("validate", _params, socket), do: {:noreply, socket}
end

defmodule LiveViewSecure.Security.Misuse.SubmitterLive do
  @moduledoc false
  # One form, two submit buttons. Only editors see "Publish". The handler picks
  # its clause from the submitter's name/value.
  use Phoenix.LiveView
  import LiveViewSecure.HTML
  import LiveViewSecure.Security.Misuse.Log

  on_mount({LiveViewSecure, events: [{"save", unsigned: ["title", "action"]}]})

  def mount(_params, _session, socket), do: {:ok, assign(socket, editor: false, log: [])}

  def render(assigns) do
    ~H"""
    <form id="post" phx-submit="save">
      <.signed_inputs secure={@live_view_secure} event="save" values={%{id: 42}} />
      <input type="text" name="title" value="" />
      <button id="draft" name="action" value="draft">Save draft</button>
      <button :if={@editor} id="publish" name="action" value="publish">Publish</button>
    </form>
    <ul id="log">
      <li :for={e <- Enum.reverse(@log)}>{e}</li>
    </ul>
    """
  end

  def handle_event("save", %{"id" => id, "action" => "publish"}, socket),
    do: log(socket, "published #{id}")

  def handle_event("save", %{"id" => id}, socket), do: log(socket, "drafted #{id}")
end

defmodule LiveViewSecure.Security.Misuse.FormMismatchLive do
  @moduledoc false
  # The form posts "save_post"; the developer declared and signed "save".
  use Phoenix.LiveView
  import LiveViewSecure.HTML
  import LiveViewSecure.Security.Misuse.Log

  on_mount({LiveViewSecure, events: [{"save", unsigned: ["title"]}]})

  def mount(_params, _session, socket), do: {:ok, assign(socket, log: [])}

  def render(assigns) do
    ~H"""
    <form id="post" phx-submit="save_post">
      <.signed_inputs secure={@live_view_secure} event="save" values={%{id: 42}} />
      <input type="text" name="title" value="" />
    </form>
    <ul id="log">
      <li :for={e <- Enum.reverse(@log)}>{e}</li>
    </ul>
    """
  end

  def handle_event("save_post", %{"id" => id}, socket), do: log(socket, "saved #{id}")
end

defmodule LiveViewSecure.Security.Misuse.StaticClickLive do
  @moduledoc false
  # Signing added to an existing button that already had a phx-click. The
  # browser keeps the first of two duplicate attributes.
  use Phoenix.LiveView
  import LiveViewSecure.HTML
  import LiveViewSecure.Security.Misuse.Log

  on_mount({LiveViewSecure, events: ["delete_user"]})

  def mount(_params, _session, socket), do: {:ok, assign(socket, log: [])}

  def render(assigns) do
    ~H"""
    <button
      id="delete-7"
      phx-click="confirm_delete"
      {signed_attrs(@live_view_secure, "delete_user", id: 7)}
    >
      Delete
    </button>
    <ul id="log">
      <li :for={e <- Enum.reverse(@log)}>{e}</li>
    </ul>
    """
  end

  def handle_event("confirm_delete", %{"id" => id}, socket), do: log(socket, "deleted #{id}")
  def handle_event("delete_user", %{"id" => id}, socket), do: log(socket, "deleted #{id}")
end

defmodule LiveViewSecure.Security.Misuse.CollisionLive do
  @moduledoc false
  # A user-editable field shares its name with a signed hidden input.
  use Phoenix.LiveView
  import LiveViewSecure.HTML
  import LiveViewSecure.Security.Misuse.Log

  on_mount({LiveViewSecure, events: [{"save", unsigned: :allow, signed: ["id"]}]})

  def mount(_params, _session, socket), do: {:ok, assign(socket, field: "id", log: [])}

  def render(assigns) do
    ~H"""
    <form id="post" phx-submit="save">
      <.signed_inputs secure={@live_view_secure} event="save" values={%{id: 42}} />
      <input type="text" id="user-id" name={@field} value="" />
      <input type="text" name="title" value="" />
    </form>
    <ul id="log">
      <li :for={e <- Enum.reverse(@log)}>{e}</li>
    </ul>
    """
  end

  def handle_event("save", %{"id" => id}, socket), do: log(socket, "saved #{id}")
end

defmodule LiveViewSecure.Security.Misuse.DivLive do
  @moduledoc false
  # A clickable <div> (browsers send no "value") and a clickable <li>
  # (browsers send HTMLLIElement.value, which is the number 0).
  use Phoenix.LiveView
  import LiveViewSecure.HTML
  import LiveViewSecure.Security.Misuse.Log

  on_mount({LiveViewSecure, events: ["open", "pick"]})

  def mount(_params, _session, socket), do: {:ok, assign(socket, log: [])}

  def render(assigns) do
    ~H"""
    <div id="row-7" {signed_attrs(@live_view_secure, "open", id: 7)}>Row 7</div>
    <ul>
      <li :for={id <- [1, 2]} id={"item-#{id}"} {signed_attrs(@live_view_secure, "pick", id: id)}>
        Item {id}
      </li>
    </ul>
    <ul id="log">
      <li :for={e <- Enum.reverse(@log)}>{e}</li>
    </ul>
    """
  end

  def handle_event("open", %{"id" => id} = params, socket),
    do: log(socket, "opened #{id} value=#{inspect(params["value"])}")

  def handle_event("pick", %{"id" => id}, socket), do: log(socket, "picked #{id}")
end

defmodule LiveViewSecure.Security.Misuse.NewlineLive do
  @moduledoc false
  # A signed value from the database that the HTML parser would change.
  use Phoenix.LiveView
  import LiveViewSecure.HTML
  import LiveViewSecure.Security.Misuse.Log

  on_mount({LiveViewSecure, events: ["note", {"save", unsigned: :allow, signed: ["text"]}]})

  def mount(_params, session, socket),
    do: {:ok, assign(socket, text: session["text"], log: [])}

  def render(assigns) do
    ~H"""
    <button id="note" {signed_attrs(@live_view_secure, "note", text: @text)}>Note</button>
    <button id="push" phx-click={signed_push(@live_view_secure, "note", value: %{text: @text})}>
      Note
    </button>
    <form id="post" phx-submit="save">
      <.signed_inputs secure={@live_view_secure} event="save" values={%{text: @text}} />
    </form>
    <ul id="log">
      <li :for={e <- Enum.reverse(@log)}>{e}</li>
    </ul>
    """
  end

  def handle_event("note", %{"text" => text}, socket), do: log(socket, "note #{inspect(text)}")
  def handle_event("save", %{"text" => text}, socket), do: log(socket, "saved #{inspect(text)}")
end

defmodule LiveViewSecure.Security.Misuse.DynamicEventLive do
  @moduledoc false
  # The event name comes from data (here: the session).
  use Phoenix.LiveView
  import LiveViewSecure.HTML

  on_mount({LiveViewSecure, events: :all})

  def mount(_params, session, socket), do: {:ok, assign(socket, event: session["event"])}

  def render(assigns) do
    ~H"""
    <button id="go" {signed_attrs(@live_view_secure, @event, id: 1)}>Go</button>
    """
  end
end

defmodule LiveViewSecure.Security.Misuse.ChildLive do
  @moduledoc false
  use Phoenix.LiveView

  def mount(_params, _session, socket), do: {:ok, socket}
  def render(assigns), do: ~H"<p>child</p>"
end

defmodule LiveViewSecure.Security.Misuse.SessionLeakLive do
  @moduledoc false
  # Hands the parent's context to a nested LiveView through live_render's
  # :session (which Phoenix sends to the browser signed, not encrypted).
  use Phoenix.LiveView
  import LiveViewSecure.HTML
  import LiveViewSecure.Security.Misuse.Log

  on_mount({LiveViewSecure, events: ["delete_user"]})

  def mount(_params, _session, socket), do: {:ok, assign(socket, log: [])}

  def render(assigns) do
    ~H"""
    <button id="delete-7" {signed_attrs(@live_view_secure, "delete_user", id: 7)}>Delete</button>
    {live_render(@socket, LiveViewSecure.Security.Misuse.ChildLive,
      id: "child",
      session: %{"secure" => @live_view_secure, "assigns" => Map.delete(assigns, :socket)}
    )}
    <ul id="log">
      <li :for={e <- Enum.reverse(@log)}>{e}</li>
    </ul>
    """
  end

  def handle_event("delete_user", %{"id" => id}, socket), do: log(socket, "deleted #{id}")
end

defmodule LiveViewSecure.Security.Misuse.CrashLive do
  @moduledoc false
  use Phoenix.LiveView

  on_mount({LiveViewSecure, events: :all})

  def mount(_params, _session, socket), do: {:ok, socket}
  def render(assigns), do: ~H"<p>crash me</p>"
end

defmodule LiveViewSecure.Security.Misuse.NestedSignedLive do
  @moduledoc false
  # A Phoenix-style form (fields named post[...]). The developer tries to
  # protect post[author_id] with :signed.
  use Phoenix.LiveView
  import LiveViewSecure.HTML
  import LiveViewSecure.Security.Misuse.Log

  on_mount(
    {LiveViewSecure, events: [{"save", unsigned: :allow, signed: ["id", "post[author_id]"]}]}
  )

  def mount(_params, _session, socket), do: {:ok, assign(socket, log: [])}

  def render(assigns) do
    ~H"""
    <form id="post" phx-submit="save">
      <.signed_inputs secure={@live_view_secure} event="save" values={%{id: 42}} />
      <input type="text" name="post[title]" value="" />
    </form>
    <ul id="log">
      <li :for={e <- Enum.reverse(@log)}>{e}</li>
    </ul>
    """
  end

  def handle_event("save", %{"id" => id, "post" => post}, socket),
    do: log(socket, "saved #{id} author=#{post["author_id"] || "me"}")
end

defmodule LiveViewSecure.Security.Misuse.TwoFormsLive do
  @moduledoc false
  # A "new" form and an "edit" form for the same event. The edit form signs
  # author_id; :signed was written for id only.
  use Phoenix.LiveView
  import LiveViewSecure.HTML
  import LiveViewSecure.Security.Misuse.Log

  on_mount({LiveViewSecure, events: [{"save", unsigned: :allow, signed: ["id"]}]})

  def mount(_params, _session, socket), do: {:ok, assign(socket, log: [])}

  def render(assigns) do
    ~H"""
    <form id="new" phx-submit="save">
      <.signed_inputs secure={@live_view_secure} event="save" values={%{org_id: 1}} />
      <input type="text" name="title" value="" />
    </form>
    <form id="edit" phx-submit="save">
      <.signed_inputs
        secure={@live_view_secure}
        event="save"
        values={%{id: 5, author_id: 7, org_id: 1}}
      />
      <input type="text" name="title" value="" />
    </form>
    <ul id="log">
      <li :for={e <- Enum.reverse(@log)}>{e}</li>
    </ul>
    """
  end

  def handle_event("save", %{"id" => id} = params, socket),
    do: log(socket, "updated #{id} author=#{params["author_id"]}")

  def handle_event("save", params, socket),
    do: log(socket, "created author=#{params["author_id"] || "me"}")
end

defmodule LiveViewSecure.Security.Misuse.OptionalFieldLive do
  @moduledoc false
  # An optional association id that is nil for some records.
  use Phoenix.LiveView
  import LiveViewSecure.HTML
  import LiveViewSecure.Security.Misuse.Log

  on_mount({LiveViewSecure, events: ["open"]})

  def mount(_params, _session, socket) do
    users = [%{id: 1, manager_id: 9}, %{id: 2, manager_id: nil}]
    {:ok, assign(socket, users: users, log: [])}
  end

  def render(assigns) do
    ~H"""
    <button
      :for={u <- @users}
      id={"open-#{u.id}"}
      {signed_attrs(@live_view_secure, "open", id: u.id, manager_id: u.manager_id)}
    >
      Open
    </button>
    <ul id="log">
      <li :for={e <- Enum.reverse(@log)}>{e}</li>
    </ul>
    """
  end

  def handle_event("open", %{"id" => id} = params, socket),
    do: log(socket, "opened #{id} manager=#{params["manager_id"] || "none"}")
end

## A live_session wrapper around attach/2, and a raw client that joins the way a
## hand-crafted websocket message can.

defmodule LiveViewSecure.Security.Misuse.SecureHook do
  @moduledoc false
  # A team-wide policy module, put in a live_session:
  #     live_session :admin, on_mount: [{MyAppWeb.SecureHook, :default}]
  def on_mount(:default, _params, _session, socket) do
    {:cont, LiveViewSecure.attach(socket, events: :all)}
  end
end

defmodule LiveViewSecure.Security.Misuse.WrappedLive do
  @moduledoc false
  # Signs its buttons, but they load after mount (assign_async, a stream, a
  # message), so the first render doesn't touch @live_view_secure.
  use Phoenix.LiveView
  import LiveViewSecure.HTML

  def mount(_params, _session, socket), do: {:ok, assign(socket, users: [], log: [])}

  def render(assigns) do
    ~H"""
    <button
      :for={u <- @users}
      id={"delete-#{u}"}
      {signed_attrs(@live_view_secure, "delete_user", id: u)}
    >
      Delete
    </button>
    """
  end

  def handle_event("delete_user", %{"id" => id}, socket),
    do: {:noreply, update(socket, :log, &["deleted #{id}" | &1])}
end

defmodule LiveViewSecure.Security.Misuse.Router do
  @moduledoc false
  use Phoenix.Router
  import Phoenix.LiveView.Router

  live_session :admin, on_mount: [{LiveViewSecure.Security.Misuse.SecureHook, :default}] do
    live("/wrapped", LiveViewSecure.Security.Misuse.WrappedLive)
  end
end

defmodule LiveViewSecure.Security.Misuse.RawClient do
  @moduledoc false
  # Joins a LiveView with a session token like the one the dead render puts in
  # data-phx-session, optionally without the "url" the JS client always sends.

  alias Phoenix.LiveView.Static

  # Phoenix.Socket serializer callback: the channel sends encoded messages to
  # the transport, which is the test process.
  def encode!(msg), do: msg

  def join(endpoint, view, opts) do
    id = "phx-" <> Base.url_encode64(:crypto.strong_rand_bytes(9))
    topic = "lv:" <> id

    session =
      Static.sign_token(endpoint, %{
        id: id,
        view: view,
        root_view: view,
        router: opts[:router],
        live_session_name: opts[:live_session],
        parent_pid: nil,
        root_pid: nil,
        session: %{}
      })

    params = %{"session" => session, "static" => nil, "params" => %{"_mounts" => 0}}
    params = if url = opts[:url], do: Map.put(params, "url", url), else: params

    socket = %Phoenix.Socket{
      transport_pid: self(),
      serializer: __MODULE__,
      channel: view,
      endpoint: endpoint,
      private: %{connect_info: %{session: %{}}},
      topic: topic,
      join_ref: "1"
    }

    ref = make_ref()
    from = {self(), ref}
    {:ok, pid} = Phoenix.LiveView.Channel.start_link({endpoint, from})
    send(pid, {Phoenix.Channel, params, from, socket})

    receive do
      {^ref, {:ok, _reply}} -> {:ok, pid, topic}
      {^ref, other} -> {:error, other}
      {:EXIT, ^pid, reason} -> {:error, reason}
    after
      2000 -> {:error, :timeout}
    end
  end

  def click(pid, topic, event, value) do
    send(pid, %Phoenix.Socket.Message{
      topic: topic,
      event: "event",
      payload: %{"type" => "click", "event" => event, "value" => value},
      ref: "2",
      join_ref: "1"
    })

    receive do
      %Phoenix.Socket.Reply{ref: "2", status: :ok} -> :handled
      {:EXIT, ^pid, reason} -> {:crashed, reason}
    after
      2000 -> :timeout
    end
  end
end

defmodule LiveViewSecure.Security.MisuseTest do
  use ExUnit.Case, async: false

  import ExUnit.CaptureLog
  import Phoenix.ConnTest
  import Phoenix.LiveViewTest
  import Phoenix.Component, only: [sigil_H: 2]
  import LiveViewSecure.HTML

  alias LiveViewSecure.{Context, InvalidEventError, Signer}
  alias LiveViewSecure.Security.Misuse
  alias Plug.Conn.Query

  @endpoint LiveViewSecure.Test.Endpoint
  @moduletag :capture_log

  setup do
    Process.flag(:trap_exit, true)
    {:ok, conn: build_conn()}
  end

  ## Helpers

  # Mounts a LiveView. A misconfiguration that raises during mount/render is
  # the "caught loudly" outcome, so it's returned rather than raised.
  defp mount(conn, live, opts \\ []) do
    {:ok, view, _html} = live_isolated(conn, live, opts)
    {:ok, view}
  rescue
    e -> {:error, e}
  catch
    :exit, reason -> {:error, reason}
  end

  # Pushes an event the way a malicious client would.
  defp push(view, event, params) do
    {:handled, render_click(view, event, params)}
  catch
    :exit, {{%InvalidEventError{reason: reason}, _}, _} -> {:rejected, reason}
    :exit, reason -> {:crashed, reason}
  end

  defp submit(view, event, params) do
    {:handled, render_submit(view, event, params)}
  catch
    :exit, {{%InvalidEventError{reason: reason}, _}, _} -> {:rejected, reason}
    :exit, reason -> {:crashed, reason}
  end

  defp attrs_of(view, selector) do
    [{_tag, attrs, _children}] =
      view |> element(selector) |> render() |> LazyHTML.from_fragment() |> LazyHTML.to_tree()

    Map.new(attrs)
  end

  defp hidden_inputs(view, form_selector) do
    doc = view |> element(form_selector) |> render() |> LazyHTML.from_fragment()
    inputs = LazyHTML.query(doc, "input[type=hidden]")
    Map.new(Enum.zip(LazyHTML.attribute(inputs, "name"), LazyHTML.attribute(inputs, "value")))
  end

  defp telemetry(events) do
    test_pid = self()
    id = {__MODULE__, make_ref()}

    :telemetry.attach_many(
      id,
      events,
      fn event, _measurements, meta, _ -> send(test_pid, {:telemetry, event, meta}) end,
      nil
    )

    on_exit(fn -> :telemetry.detach(id) end)
  end

  # Secret material behind a context, read from the owning process (coupled to
  # the library's internals on purpose): the current and previous root keys,
  # and the context's derived key under each.
  defp secrets(pid, %Context{} = ctx) do
    dict = if pid == self(), do: Process.get(), else: elem(Process.info(pid, :dictionary), 1)
    {_, {_gen, current, previous}} = List.keyfind(dict, {Context, :root}, 0)

    roots =
      for ref <- [current, previous], ref != nil do
        for i <- 1..4, into: <<>>, do: <<:atomics.get(ref, i)::64>>
      end

    roots ++ Enum.map(roots, &derive(&1, ctx.id))
  end

  defp derive(root, id),
    do: :crypto.mac(:hmac, :sha256, root, ["live_view_secure/context-key/v1", id])

  defp live_secrets(view) do
    %{socket: socket} = :sys.get_state(view.pid)
    secrets(view.pid, socket.assigns.live_view_secure)
  end

  # Every encoding of a secret that could plausibly show up in text.
  defp leaks?(text, secrets) when is_binary(text) and is_list(secrets) do
    Enum.any?(secrets, fn secret ->
      bytes = :binary.bin_to_list(secret)

      [
        secret,
        Base.encode64(secret),
        Base.encode64(secret, padding: false),
        Base.url_encode64(secret, padding: false),
        Base.encode16(secret),
        Base.encode16(secret, case: :lower),
        bytes |> Enum.take(8) |> Enum.join(", "),
        bytes |> Enum.take(8) |> Enum.join(",")
      ]
      |> Enum.any?(&String.contains?(text, &1))
    end)
  end

  defp binaries_of_size(term, size) when is_binary(term),
    do: if(byte_size(term) == size, do: [term], else: [])

  defp binaries_of_size(term, size) when is_map(term),
    do: term |> Map.to_list() |> binaries_of_size(size)

  defp binaries_of_size(term, size) when is_tuple(term),
    do: term |> Tuple.to_list() |> binaries_of_size(size)

  defp binaries_of_size(term, size) when is_list(term),
    do: Enum.flat_map(term, &binaries_of_size(&1, size))

  defp binaries_of_size(_term, _size), do: []

  # What an attacker holding a key computes, from the token format documented
  # in lib/live_view_secure/signer.ex.
  defp forge_token(key, event, values) do
    keys = values |> Map.keys() |> Enum.sort()
    lp = fn bin -> [<<byte_size(bin)::64>>, bin] end

    data = [
      "live_view_secure/v1",
      lp.(event),
      <<length(keys)::32>>,
      Enum.map(keys, &[lp.(&1), lp.(Map.fetch!(values, &1))])
    ]

    mac = :crypto.mac(:hmac, :sha256, key, data) |> binary_part(0, 16)
    Enum.join(keys, ",") <> "." <> Base.url_encode64(mac, padding: false)
  end

  # The options of each `on_mount {LiveViewSecure, ...}` in a text, skipping
  # placeholders ("...") and interpolations.
  defp doc_examples(text) do
    ~r/on_mount[\s(]*\{LiveViewSecure,/
    |> Regex.scan(text, return: :index)
    |> Enum.map(fn [{start, len}] ->
      balanced(binary_part(text, start + len, byte_size(text) - start - len), 1, "")
    end)
    |> Enum.reject(&(&1 == nil or &1 =~ "..." or &1 =~ "\#{"))
  end

  defp balanced(_rest, 0, acc), do: binary_part(acc, 0, byte_size(acc) - 1)
  defp balanced(<<>>, _depth, _acc), do: nil

  defp balanced(<<c, rest::binary>>, depth, acc) when c in [?{, ?[, ?(],
    do: balanced(rest, depth + 1, acc <> <<c>>)

  defp balanced(<<c, rest::binary>>, depth, acc) when c in [?}, ?], ?)],
    do: balanced(rest, depth - 1, acc <> <<c>>)

  defp balanced(<<c, rest::binary>>, depth, acc), do: balanced(rest, depth, acc <> <<c>>)

  defp bare_socket do
    %Phoenix.LiveView.Socket{
      private: %{lifecycle: %Phoenix.LiveView.Lifecycle{}},
      assigns: %{__changed__: %{}}
    }
  end

  ## 1. Fail-open misconfiguration

  describe "fail-open misconfiguration" do
    test "F1: an event the template signs but :events doesn't declare is caught (renamed handler)",
         %{conn: conn} do
      case mount(conn, Misuse.RenamedLive) do
        {:error, error} ->
          assert Exception.message(error) =~ "remove_user"

        {:ok, view} ->
          refute match?({:handled, _}, push(view, "remove_user", %{"id" => "1"})),
                 "forged remove_user was accepted: the template signs it but nothing verifies it"
      end
    end

    test "F1: signing an event listed in :except is refused at render (blocked)", %{conn: conn} do
      assert {:error, %ArgumentError{message: message}} = mount(conn, Misuse.ExceptSignedLive)
      assert message =~ "validate"
    end

    test "F1: a form posting an undeclared event with signed inputs emits :unverified signed: true (blocked)",
         %{conn: conn} do
      telemetry([[:live_view_secure, :event, :unverified]])
      {:ok, view} = mount(conn, Misuse.FormMismatchLive)
      assert view |> form("#post", %{"title" => "x"}) |> render_submit() =~ "saved 42"
      assert_received {:telemetry, _, %{event: "save_post", signed: true}}
    end

    test "R2-1: the default logger warns about a signed event that nothing verifies", %{
      conn: conn
    } do
      # The telemetry above only helps if someone attached a handler. The
      # default logger only logs rejections, so in dev this mistake is silent.
      {:ok, view} = mount(conn, Misuse.FormMismatchLive)

      log =
        capture_log([level: :warning], fn ->
          assert view |> form("#post", %{"title" => "x"}) |> render_submit() =~ "saved 42"
        end)

      assert log =~ "save_post", "no warning that a signed event bypassed verification"
    end

    test "R2-1: a static phx-click in front of signed_attrs is flagged too", %{conn: conn} do
      # <button phx-click="confirm_delete" {signed_attrs(.., "delete_user", ..)}>:
      # the browser keeps the first phx-click, so the signed values go to an
      # undeclared event. Nothing can see this at render time.
      {:ok, view} = mount(conn, Misuse.StaticClickLive)

      log =
        capture_log([level: :warning], fn ->
          assert view |> element("#delete-7") |> render_click() =~ "deleted 7"
        end)

      assert log =~ "confirm_delete"
    end

    test "F4: `events: [:all]` (a list) means all (blocked)", %{conn: conn} do
      case mount(conn, Misuse.AllInListLive) do
        {:error, %ArgumentError{}} ->
          :ok

        {:ok, view} ->
          assert view |> element("#delete-7") |> render_click() =~ "deleted 7"
          assert {:rejected, :missing_signature} = push(view, "delete_user", %{"id" => "1"})
      end
    end

    test "F4: `:all` anywhere but first in :events raises (blocked)" do
      assert_raise ArgumentError, ~r/:all/, fn ->
        LiveViewSecure.attach(bare_socket(), events: ["delete", :all])
      end
    end

    test "atom and string event names are interchangeable (blocked)", %{conn: conn} do
      {:ok, view} = mount(conn, Misuse.AtomEventsLive)
      assert view |> element("#delete-7") |> render_click() =~ "deleted 7"
      assert view |> element("#archive-7") |> render_click() =~ "archived 7"
      assert {:rejected, :missing_signature} = push(view, "archive", %{"id" => "1"})
    end

    test "F3: a component signing with the parent's context via target: is refused at render (blocked)",
         %{conn: conn} do
      session = %{"component" => inspect(Misuse.SharedCtxComponent)}
      assert {:error, error} = mount(conn, Misuse.SharedCtxLive, session: session)
      assert Exception.message(error) =~ "component"
    end

    test "R2-2: a component with no hook of its own that receives signed events is flagged",
         %{conn: conn} do
      # The parent's context, phx-target written as its own attribute: the
      # render-time check can't see the target, the parent's `events: :all`
      # hook never sees component events, and the component has no hook.
      telemetry([[:live_view_secure, :event, :unverified]])
      session = %{"component" => inspect(Misuse.SharedCtxPhxTargetComponent)}
      {:ok, view} = mount(conn, Misuse.SharedCtxLive, session: session)

      log =
        capture_log([level: :warning], fn ->
          assert view |> element("#remove-a") |> render_click() =~ ">a<"
        end)

      assert_received {:telemetry, _, %{event: "remove", signed: true, source: :component}},
                      "no :unverified telemetry for a signed component event"

      assert log =~ "remove"
    end

    @tag :known_limitation
    test "R2-2: ...and a forged event to that component is rejected", %{conn: conn} do
      session = %{"component" => inspect(Misuse.SharedCtxPhxTargetComponent)}
      {:ok, view} = mount(conn, Misuse.SharedCtxLive, session: session)

      forged =
        try do
          {:handled, view |> with_target("#cart") |> render_click("remove", %{"item" => "zzz"})}
        catch
          :exit, reason -> {:rejected, reason}
        end

      refute match?({:handled, _}, forged),
             "a forged event to a hook-less component was accepted: #{inspect(forged)}"
    end

    test "F3: a component that overwrites its own context with the parent's is rejected (blocked)",
         %{conn: conn} do
      # OverwritingComponent attached its own hook, then replaced its context
      # with the parent's. Its own signing raises (context of another owner)...
      session = %{"component" => inspect(Misuse.OverwritingComponent)}

      case mount(conn, Misuse.SharedCtxLive, session: session) do
        {:error, _} ->
          :ok

        {:ok, view} ->
          result =
            try do
              {:handled, view |> element("#remove-a") |> render_click()}
            catch
              :exit, {{%InvalidEventError{reason: reason}, _}, _} -> {:rejected, reason}
            end

          assert {:rejected, :foreign_context} = result
      end
    end

    test "F5: verification runs before :handle_event hooks attached by earlier on_mounts (blocked)",
         %{conn: conn} do
      {:ok, view} = mount(conn, Misuse.EarlyHookLive)
      assert view |> element("#bulk") |> render_click() =~ "bulk deleted 1,2"

      {:ok, view} = mount(conn, Misuse.EarlyHookLive)
      assert {:rejected, :missing_signature} = push(view, "bulk_delete", %{"ids" => "1,2,3,4,5"})
    end

    test "F13: declaring the same event twice raises (blocked)" do
      assert_raise ArgumentError, fn ->
        LiveViewSecure.attach(bare_socket(),
          events: ["delete", {"delete", unsigned: :allow, signed: []}]
        )
      end

      assert_raise ArgumentError, fn ->
        LiveViewSecure.attach(bare_socket(), events: [:delete, "delete"])
      end
    end

    test "R2-3: attach/2 called from a live_session on_mount can't be skipped by a url-less join" do
      # LiveView before 1.1.34 / 1.2.14 skipped live_session hooks when the join
      # had no "url" (CVE-2026-126334), which skipped a policy module calling
      # attach/2 from a live_session's on_mount. The token RawClient signs has
      # no route_required? flag, like a token issued before the fix, so this
      # also covers LiveView's fallback for those.
      endpoint = LiveViewSecure.Test.Endpoint
      opts = [router: Misuse.Router, live_session: :admin]

      # Control: the JS client's join (with "url") runs the wrapper.
      assert {:ok, pid, topic} =
               Misuse.RawClient.join(
                 endpoint,
                 Misuse.WrappedLive,
                 opts ++ [url: "http://www.example.com/wrapped"]
               )

      assert %{socket: %{assigns: %{live_view_secure: %Context{}}}} = :sys.get_state(pid)
      assert {:crashed, _} = Misuse.RawClient.click(pid, topic, "delete_user", %{"id" => "1"})

      # Attack: the same session token, joined without "url", is refused.
      assert {:error, _} = Misuse.RawClient.join(endpoint, Misuse.WrappedLive, opts)
    end
  end

  ## 2. Policy loopholes and the :signed requirement

  describe "policy loopholes" do
    test "F6: events: :all can verify a form without loosening every click event (blocked)",
         %{conn: conn} do
      {:ok, view} = mount(conn, Misuse.AllWithFormLive)
      assert view |> form("#post", %{"title" => "Hi"}) |> render_submit() =~ "saved 99 title=Hi"
      assert view |> element("#archive-7") |> render_click() =~ "archived 7 scope=mine"

      %{"phx-click" => js} = attrs_of(view, "#archive-7")
      [["push", %{"value" => value}]] = Jason.decode!(js)

      assert {:rejected, {:unsigned_params, ["scope"]}} =
               push(view, "archive", Map.put(value, "scope", "everything"))

      {:ok, view} = mount(conn, Misuse.AllWithFormLive)
      assert {:rejected, :missing_signature} = push(view, "anything", %{})
    end

    @tag :known_limitation
    test "F7: a form's submitter value is not attacker-chosen", %{conn: conn} do
      {:ok, view} = mount(conn, Misuse.SubmitterLive)

      assert view
             |> form("#post", %{"title" => "x"})
             |> put_submitter("#draft")
             |> render_submit() =~ "drafted 42"

      params = Map.merge(hidden_inputs(view, "#post"), %{"title" => "x", "action" => "publish"})
      result = submit(view, "save", params)

      refute match?({:handled, _}, result) and elem(result, 1) =~ "published 42",
             "a submitter the page never rendered for this user was accepted"
    end

    test "F14: only an empty value (or 0) can be added to a :deny event (blocked)", %{conn: conn} do
      attempt = fn value ->
        {:ok, view} = mount(conn, Misuse.DivLive)
        attrs = attrs_of(view, "#row-7")
        push(view, "open", %{"id" => "7", "__sig" => attrs["phx-value-__sig"], "value" => value})
      end

      assert {:handled, html} = attempt.("")
      assert html =~ ~s(opened 7 value=&quot;&quot;)
      assert {:handled, _} = attempt.(0)

      for value <- ["x", " ", 1, 0.0, "0", %{}, ["x"], nil, false] do
        assert {:rejected, {:unsigned_params, ["value"]}} = attempt.(value)
      end
    end

    test "a user field named like a signed hidden input can't override it (blocked)",
         %{conn: conn} do
      {:ok, view} = mount(conn, Misuse.CollisionLive)

      result =
        try do
          {:handled, view |> form("#post", %{"id" => "1", "title" => "x"}) |> render_submit()}
        catch
          :exit, {{%InvalidEventError{reason: reason}, _}, _} -> {:rejected, reason}
        end

      assert {:rejected, :invalid_signature} = result
    end

    test "R2-4: a nested name in :signed is refused, not silently ignored", %{conn: conn} do
      # signed: ["post[author_id]"] never matches anything: params arrive
      # decoded as %{"post" => %{"author_id" => ...}}. The developer believes
      # post[author_id] is protected; the client sets it freely.
      case mount(conn, Misuse.NestedSignedLive) do
        {:error, %ArgumentError{message: message}} ->
          assert message =~ "post[author_id]"

        {:ok, view} ->
          params =
            view
            |> hidden_inputs("#post")
            |> Map.put("post", %{"title" => "x", "author_id" => "999"})

          result = submit(view, "save", params)

          refute match?({:handled, _}, result) and elem(result, 1) =~ "author=999",
                 "post[author_id] was listed in :signed but the client chose it"
      end
    end

    test "R2-4: a nested name in an :unsigned list is refused too" do
      assert_raise ArgumentError, ~r/post\[title\]/, fn ->
        LiveViewSecure.attach(bare_socket(), events: [{"save", unsigned: ["post[title]"]}])
      end
    end

    test "R2-5: a key signed for an `unsigned: :allow` event but missing from :signed is refused at render",
         %{conn: conn} do
      # The edit form signs author_id; :signed lists only id. The client takes
      # the new form's token (org_id only) and adds author_id as an "unsigned"
      # param: a post created in someone else's name.
      case mount(conn, Misuse.TwoFormsLive) do
        {:error, %ArgumentError{message: message}} ->
          # Either key will do: org_id and author_id are both signed and
          # both missing from :signed.
          assert message =~ ~r/author_id|org_id/

        {:ok, view} ->
          assert view |> form("#new", %{"title" => "x"}) |> render_submit() =~ "created author=me"

          params =
            view
            |> hidden_inputs("#new")
            |> Map.merge(%{"title" => "x", "author_id" => "7"})

          result = submit(view, "save", params)

          refute match?({:handled, _}, result) and elem(result, 1) =~ "created author=7",
                 "author_id is signed elsewhere for this event, but the client chose it"
      end
    end
  end

  ## 3. Output safety (HTML/JS injection)

  describe "output safety" do
    setup do
      {:ok, ctx: Context.new(nil, {:all_except, MapSet.new()}, fresh_root: true)}
    end

    test "values, target and event are attribute-escaped in signed_attrs (blocked)", %{ctx: ctx} do
      evil = ~s|" onmouseover="alert(1)' <script>&|
      assigns = %{ctx: ctx, evil: evil}

      html =
        rendered_to_string(~H"""
        <button {signed_attrs(@ctx, "go", [id: @evil], target: @evil)}>Go</button>
        """)

      [{"button", attrs, _}] = html |> LazyHTML.from_fragment() |> LazyHTML.to_tree()
      names = Enum.map(attrs, &elem(&1, 0))
      assert Enum.sort(names) == ["phx-click", "phx-target", "phx-value-__sig", "phx-value-id"]
      assert {"phx-value-id", evil} in attrs
      assert {"phx-target", evil} in attrs
      refute html =~ "<script>"
    end

    test "signed_push JSON is attribute-escaped (blocked)", %{ctx: ctx} do
      evil = ~s|</button><script>alert(1)</script>" '|
      assigns = %{ctx: ctx, evil: evil}

      html =
        rendered_to_string(~H"""
        <button phx-click={signed_push(@ctx, "go", value: %{id: @evil})}>Go</button>
        """)

      refute html =~ "<script>"

      [{"button", [{"phx-click", js}], _}] =
        html |> LazyHTML.from_fragment() |> LazyHTML.to_tree()

      assert [["push", %{"event" => "go", "value" => %{"id" => ^evil}}]] = Jason.decode!(js)
    end

    test "signed_inputs names and values are escaped (blocked)", %{ctx: ctx} do
      evil = ~s|"><script>alert(1)</script>|
      assigns = %{ctx: ctx, evil: evil}

      html =
        rendered_to_string(~H"""
        <.signed_inputs secure={@ctx} event="save" values={%{id: @evil}} />
        """)

      refute html =~ "<script>"

      assert ~s(<input type="hidden" name="id" value="&quot;&gt;&lt;script&gt;) <> _ =
               String.trim(html)

      assert_raise ArgumentError, fn ->
        signed_inputs(%{secure: ctx, event: "s", values: %{"a\"b" => 1}})
      end
    end

    test "raw {:safe, iodata} values are refused, not rendered unescaped (blocked)", %{ctx: ctx} do
      for channel_fun <- [
            fn v -> signed_attrs(ctx, "go", id: v) end,
            fn v -> signed_push(ctx, "go", value: %{id: v}) end,
            fn v -> signed_inputs(%{secure: ctx, event: "go", values: %{id: v}}) end
          ] do
        assert_raise ArgumentError, fn -> channel_fun.(Phoenix.HTML.raw("<script>")) end
      end
    end

    test "F8: :binding only accepts event bindings (blocked)", %{ctx: ctx} do
      for binding <- [
            "onclick",
            "href",
            "formaction",
            "srcdoc",
            ~s|x onmouseover="alert(1)"|,
            "phx-value-id",
            "phx-target",
            "phx-hook",
            "phx-mounted",
            "PHX-CLICK",
            :"phx-click",
            # The client sends its own "id" and "_overran" with these.
            "phx-viewport-top",
            "phx-viewport-bottom"
          ] do
        assert_raise ArgumentError, fn -> signed_attrs(ctx, "go", [], binding: binding) end
      end

      for binding <- ~w(phx-click phx-click-away phx-blur phx-focus phx-window-blur
                        phx-window-focus phx-keydown phx-keyup phx-window-keydown
                        phx-window-keyup phx-change phx-submit) do
        assert %{^binding => "go"} = signed_attrs(ctx, "go", [], binding: binding)
      end
    end

    test "F8: an event name the client would parse as JS commands is refused (blocked)",
         %{conn: conn} do
      evil = ~s([["navigate",{"href":"https://evil.example/phish"}]])

      case mount(conn, Misuse.DynamicEventLive, session: %{"event" => evil}) do
        {:error, %ArgumentError{}} ->
          :ok

        {:ok, view} ->
          result = view |> element("#go") |> render_click()

          refute match?({:error, {:live_redirect, %{to: "https://evil.example/phish"}}}, result),
                 "clicking a signed button navigated to an attacker URL"
      end

      for bad <- ["", "a\nb", "a\0b", <<0xFF>>, "[x", "\e[31m"] do
        assert_raise ArgumentError, fn -> signed_attrs(ctx_all(), bad) end
        assert_raise ArgumentError, fn -> signed_push(ctx_all(), bad) end
      end
    end

    test "event names that merely look odd still work (no false positives)" do
      ctx = ctx_all()

      for ok <- [" [x", "a[b]", "save:post", "délete", "x" <> String.duplicate("y", 500)] do
        assert %{"phx-click" => ^ok} = signed_attrs(ctx, ok)
      end
    end

    test "signing a struct uses String.Chars for both the signed and rendered value (blocked)",
         %{ctx: ctx} do
      dt = ~N[2024-01-01 10:00:00]
      assigns = %{ctx: ctx, dt: dt}

      html =
        rendered_to_string(~H"""
        <button {signed_attrs(@ctx, "go", at: @dt)}>Go</button>
        """)

      [{"button", attrs, _}] = html |> LazyHTML.from_fragment() |> LazyHTML.to_tree()
      attrs = Map.new(attrs)
      assert attrs["phx-value-at"] == "2024-01-01 10:00:00"

      params = %{"at" => attrs["phx-value-at"], "__sig" => attrs["phx-value-__sig"]}
      assert :ok = Signer.verify(ctx, "go", params, :deny)
    end
  end

  defp ctx_all, do: Context.new(nil, {:all_except, MapSet.new()}, fresh_root: true)

  ## 4. Rendered vs signed

  describe "rendered vs signed values" do
    test "F10: a CRLF value works on all three channels", %{conn: conn} do
      text = "line1\r\nline2\rline3"
      {:ok, view} = mount(conn, Misuse.NewlineLive, session: %{"text" => text})

      # phx-value-* and hidden inputs deliver what the HTML parser leaves (LF).
      assert view |> element("#note") |> render_click() =~
               "note &quot;line1\\nline2\\nline3&quot;"

      assert view |> form("#post") |> render_submit() =~ "saved &quot;line1\\nline2\\nline3&quot;"
      # JS.push values are JSON, so the CR survives.
      assert view |> element("#push") |> render_click() =~
               "note &quot;line1\\r\\nline2\\rline3&quot;"
    end

    test "F10: a NUL byte is delivered as U+FFFD and verifies", %{conn: conn} do
      {:ok, view} = mount(conn, Misuse.NewlineLive, session: %{"text" => "a\0b"})
      assert view |> element("#note") |> render_click() =~ "note &quot;a�b&quot;"
    end

    test "F10: normalization doesn't let one token stand for another value (blocked)" do
      # "a\r\nb" and "a\nb" sign identically on the HTML channels, by design:
      # the handler receives "a\nb" either way. No other pair collides, and
      # signed_push keeps them apart.
      ctx = ctx_all()
      sig = fn v -> signed_attrs(ctx, "go", t: v)["phx-value-__sig"] end
      assert sig.("a\r\nb") == sig.("a\nb")
      refute sig.("a\nb") == sig.("a\n\nb")
      refute sig.("a�b") == sig.("ab")
      push_sig = fn v -> signed_push(ctx, "go", value: %{t: v}).ops |> hd() |> Enum.at(1) end
      refute push_sig.("a\r\nb").value["__sig"] == push_sig.("a\nb").value["__sig"]
    end

    test "F10: invalid UTF-8 is refused on every channel (blocked)" do
      ctx = ctx_all()
      assert_raise ArgumentError, fn -> signed_attrs(ctx, "go", t: <<0xC3>>) end
      assert_raise ArgumentError, fn -> signed_push(ctx, "go", value: %{t: <<0xC3>>}) end
    end

    test "whitespace and LF survive all three channels (blocked)", %{conn: conn} do
      text = "  two\nlines\t "
      {:ok, view} = mount(conn, Misuse.NewlineLive, session: %{"text" => text})

      expected = text |> inspect() |> Phoenix.HTML.html_escape() |> Phoenix.HTML.safe_to_string()
      assert view |> element("#note") |> render_click() =~ "note #{expected}"
      assert view |> element("#push") |> render_click() =~ "note #{expected}"
      assert view |> form("#post") |> render_submit() =~ "saved #{expected}"
    end

    test "F10: a browser click on a signed <li> (value 0) is accepted (blocked)", %{conn: conn} do
      {:ok, view} = mount(conn, Misuse.DivLive)
      attrs = attrs_of(view, "#item-1")
      params = %{"id" => "1", "__sig" => attrs["phx-value-__sig"], "value" => 0}

      assert {:handled, html} = push(view, "pick", params)
      assert html =~ "picked 1"
    end

    test "F9: nil, false and true are never signed as present, truthy strings (blocked)" do
      # Raising (current lib) or leaving the param out like plain HEEx does
      # (R2-6 patch) are both secure; "" or "false" arriving is not.
      ctx = ctx_all()

      for v <- [false, nil, true] do
        result =
          try do
            {:ok, signed_attrs(ctx, "delete", id: 1, confirmed: v)}
          rescue
            ArgumentError -> :refused
          end

        case result do
          :refused ->
            :ok

          {:ok, attrs} ->
            refute Map.has_key?(attrs, "phx-value-confirmed"),
                   "#{inspect(v)} was signed as #{inspect(attrs["phx-value-confirmed"])}"

            assert attrs["phx-value-__sig"] =~ ~r/^id\./
        end
      end
    end

    test "R2-6: a nil field from the database doesn't crash rendering, and can't be forged",
         %{conn: conn} do
      # F9's fix raises on nil, which turns optional associations into a
      # data-dependent 500 that fixtures with every field set won't catch.
      # Plain HEEx omits phx-value-x={nil}; doing the same is safe under :deny
      # (and under :allow, where :signed now covers the key).
      case mount(conn, Misuse.OptionalFieldLive) do
        {:error, error} ->
          flunk("rendering crashed on a nil value: #{Exception.message(error)}")

        {:ok, view} ->
          assert view |> element("#open-2") |> render_click() =~ "opened 2 manager=none"
          attrs = attrs_of(view, "#open-2")
          refute Map.has_key?(attrs, "phx-value-manager_id")

          params = %{"id" => "2", "__sig" => attrs["phx-value-__sig"], "manager_id" => "9"}
          assert {:rejected, {:unsigned_params, ["manager_id"]}} = push(view, "open", params)
      end
    end
  end

  ## 5. Key leakage

  describe "key leakage" do
    test "F12: inspect/2 (any options) and Erlang ~p don't print key material (blocked)" do
      ctx = ctx_all()
      secrets = secrets(self(), ctx)
      assert inspect(ctx) == "#LiveViewSecure.Context<redacted>"
      refute leaks?(inspect(ctx, structs: false, limit: :infinity), secrets)
      refute leaks?(IO.iodata_to_binary(:io_lib.format(~c"~p", [ctx])), secrets)

      # The process dictionary holds only references to the key.
      dict = Process.get()

      refute leaks?(
               inspect(dict, structs: false, limit: :infinity, printable_limit: :infinity),
               secrets
             )

      refute leaks?(IO.iodata_to_binary(:io_lib.format(~c"~tp", [dict])), secrets)
      refute leaks?(:erlang.term_to_binary(dict), secrets)
      refute leaks?(:erlang.term_to_binary(ctx), secrets)
    end

    test "F12: JSON, String.Chars, Phoenix.HTML.Safe and HEEx refuse the context (blocked)" do
      ctx = ctx_all()
      secrets = secrets(self(), ctx)
      assigns = %{ctx: ctx}

      for fun <- [
            fn -> Jason.encode!(%{secure: ctx}) end,
            fn -> JSON.encode!(%{secure: ctx}) end,
            fn -> apply(String.Chars, :to_string, [ctx]) end,
            fn -> apply(Phoenix.HTML.Safe, :to_iodata, [ctx]) end,
            fn -> Query.encode(%{secure: ctx}) end,
            fn -> rendered_to_string(~H"<div>{@ctx}</div>") end,
            fn -> rendered_to_string(~H"<div data-secure={@ctx}></div>") end
          ] do
        error = assert_raise(Protocol.UndefinedError, fun)
        refute leaks?(Exception.message(error), secrets)
      end

      error = assert_raise ArgumentError, fn -> signed_attrs(ctx, "go", ctx: ctx) end
      refute leaks?(Exception.message(error), secrets)
    end

    test "F12: crash reports, :sys.get_status and process info don't contain key material (blocked)",
         %{conn: conn} do
      {:ok, view} = mount(conn, Misuse.CrashLive)
      secrets = live_secrets(view)

      status = :sys.get_status(view.pid)
      {:dictionary, dict} = Process.info(view.pid, :dictionary)
      refute leaks?(inspect(status, structs: false, limit: :infinity), secrets)
      refute leaks?(IO.iodata_to_binary(:io_lib.format(~c"~p", [status])), secrets)
      refute leaks?(IO.iodata_to_binary(:io_lib.format(~c"~p", [dict])), secrets)
      refute leaks?(inspect(:sys.get_state(view.pid), structs: false, limit: :infinity), secrets)

      log =
        capture_log([level: :debug], fn ->
          catch_exit(render_click(view, "anything", %{"__sig" => "x"}))
          Process.sleep(50)
        end)

      assert log =~ "LiveViewSecure rejected"
      refute leaks?(log, secrets)
    end

    test "F12: telemetry metadata doesn't carry key material (blocked)", %{conn: conn} do
      telemetry([[:live_view_secure, :event, :rejected], [:live_view_secure, :verify, :stop]])
      {:ok, view} = mount(conn, Misuse.CrashLive)
      secrets = live_secrets(view)
      catch_exit(render_click(view, "anything", %{}))

      for event <- [[:live_view_secure, :event, :rejected], [:live_view_secure, :verify, :stop]] do
        assert_received {:telemetry, ^event, meta}
        refute leaks?(inspect(meta, structs: false, limit: :infinity), secrets)
        refute leaks?(:erlang.term_to_binary(meta), secrets)
      end
    end

    test "F2: the context in a nested LiveView's session gives the browser nothing to forge with (blocked)",
         %{conn: conn} do
      {:ok, view} = mount(conn, Misuse.SessionLeakLive)
      secrets = live_secrets(view)

      [token] =
        view
        |> render()
        |> LazyHTML.from_fragment()
        |> LazyHTML.query("#child")
        |> LazyHTML.attribute("data-phx-session")

      [_, payload, _] = String.split(token, ".")
      payload = Base.url_decode64!(payload, padding: false)
      term = :erlang.binary_to_term(payload)

      # The browser can read the term: try every 32-byte binary as a key, and
      # as a root key with every 16-byte id it can see.
      roots = binaries_of_size(term, 32)
      ids = binaries_of_size(term, 16)
      candidates = roots ++ for(r <- roots, i <- ids, do: derive(r, i))

      for key <- candidates do
        forged = forge_token(key, "delete_user", %{"id" => "1"})

        refute match?(
                 {:handled, _},
                 push(view, "delete_user", %{"id" => "1", "__sig" => forged})
               ),
               "a token forged with material from data-phx-session was accepted"
      end

      refute leaks?(payload, secrets)
    end
  end

  ## 6. Rejection output and ergonomics

  describe "rejection output" do
    test "rejection logs escape attacker-chosen names and don't echo the token (blocked)",
         %{conn: conn} do
      {:ok, view} = mount(conn, LiveViewSecure.Test.StrictLive)
      event = "inc\n12:00:00.000 [info] admin logged in\e[0m"
      params = %{"x\n[error] forged" => "1", "__sig" => String.duplicate("A", 10_000)}

      log = capture_log([level: :warning], fn -> render_click(view, event, params) end)

      assert log =~ "LiveViewSecure rejected"
      refute log =~ "\n12:00:00.000 [info] admin logged in"
      refute log =~ "\e["
      refute log =~ String.duplicate("A", 100)
      assert view |> element("#count") |> render() =~ ">0<"
    end
  end

  describe "ergonomics" do
    test "F11: forgetting the brackets around values doesn't silently sign :target (blocked)" do
      assert_raise ArgumentError, ~r/@myself|target/, fn ->
        signed_attrs(ctx_all(), "remove", item: "a", target: %Phoenix.LiveComponent.CID{cid: 1})
      end
    end

    test "misconfiguration raises with guidance (blocked)" do
      socket = bare_socket()

      assert_raise ArgumentError, ~r/which events/, fn ->
        LiveViewSecure.attach(socket, :default)
      end

      assert_raise ArgumentError, fn ->
        LiveViewSecure.attach(socket, events: ["x"], on_failure: :log)
      end

      assert_raise ArgumentError, fn ->
        LiveViewSecure.attach(socket, events: ["x"], except: ["y"])
      end

      assert_raise ArgumentError, fn -> LiveViewSecure.attach(socket, events: [{"x", :allow}]) end

      assert_raise ArgumentError, ~r/signed/, fn ->
        LiveViewSecure.attach(socket, events: [{"x", unsigned: :allow}])
      end
    end

    test "R2-7: every `on_mount {LiveViewSecure, ...}` example in the docs is a valid configuration" do
      # README.md and the signed_inputs docs showed `{"save", unsigned: :allow}`,
      # which now raises at mount because :allow requires :signed.
      root = Path.expand("../..", __DIR__)
      files = [Path.join(root, "README.md") | Path.wildcard(Path.join(root, "lib/**/*.ex"))]

      examples =
        for file <- files,
            text = File.read!(file),
            opts <- doc_examples(text),
            do: {Path.relative_to(file, root), opts}

      assert length(examples) >= 3

      for {file, opts} <- examples do
        {opts, _} = Code.eval_string("[" <> opts <> "]")

        try do
          LiveViewSecure.attach(bare_socket(), opts)
        rescue
          e in ArgumentError ->
            flunk(
              "#{file}: on_mount {LiveViewSecure, #{inspect(opts)}} raises: " <>
                String.slice(Exception.message(e), 0, 120)
            )
        end
      end
    end
  end
end
