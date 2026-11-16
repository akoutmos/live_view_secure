defmodule LiveViewSecure.Test.Protocol.Layouts do
  @moduledoc false
  use Phoenix.Component

  def root(assigns) do
    ~H"""
    <!DOCTYPE html>
    <html>
      <head><meta name="csrf-token" content={Phoenix.Controller.get_csrf_token()} /></head>
      <body>{@inner_content}</body>
    </html>
    """
  end
end

defmodule LiveViewSecure.Test.Protocol.ErrorHTML do
  @moduledoc false
  # So a crashed request renders a plain 500 and the original exception is
  # what gets logged.
  def render(template, _assigns), do: Phoenix.Controller.status_message_from_template(template)
end

defmodule LiveViewSecure.Test.Protocol.Router do
  @moduledoc false
  # A production-shaped router: session, CSRF protection, a root layout with the
  # CSRF meta tag, and `live` routes, so the wire tests get real session tokens
  # from a real dead render.
  use Phoenix.Router
  import Phoenix.Controller
  import Phoenix.LiveView.Router

  alias LiveViewSecure.Test
  alias LiveViewSecure.Test.Protocol

  pipeline :browser do
    plug(:accepts, ["html"])
    plug(:fetch_session)
    plug(:protect_from_forgery)
    plug(:put_root_layout, html: {Protocol.Layouts, :root})
  end

  scope "/" do
    pipe_through(:browser)

    # Existing fixtures from test/support/live.ex (module-level on_mount).
    live("/users", Test.UsersLive)
    live("/strict", Test.StrictLive)
    live("/cart", Test.CartLive)

    # Fixtures for the wire tests.
    live("/admin", Protocol.AdminLive)
    live("/hook", Protocol.HookLive)
    live("/components", Protocol.ComponentsLive)
    live("/nested", Protocol.NestedParentLive)
    live("/upload", Protocol.UploadLive)
    live("/patch", Protocol.PatchLive)
    live("/exact", Protocol.ExactLive)

    live("/bank", Protocol.BankLive)
    live("/foreign-nested", Protocol.ForeignParentLive)

    # Round-1 F1: LiveViewSecure only in a live_session. Round 2: refused at mount.
    live_session :guarded,
      on_mount: [{LiveViewSecure, events: ["delete_user", "view_user"]}] do
      live("/session-guarded", Protocol.SessionGuardedLive)
    end

    # An app hook in a live_session (attached before LiveViewSecure runs), with
    # LiveViewSecure declared in the modules.
    live_session :app_hooks, on_mount: [Protocol.SessionHook] do
      live("/hooked", Protocol.HookedLive)
      live("/app-hooked", Protocol.AppHookedLive)
    end

    # The live_session declares LiveViewSecure with other opts than the module.
    live_session :mismatch, on_mount: [{LiveViewSecure, events: ["view_user"]}] do
      live("/mismatch", Protocol.MismatchLive)
    end

    # The live_session declares exactly the module's own opts.
    live_session :same_opts,
      on_mount: [{LiveViewSecure, events: ["delete_user"], on_failure: :halt}] do
      live("/same-opts", Protocol.SameOptsLive)
    end
  end
end

defmodule LiveViewSecure.Test.Protocol.Endpoint do
  @moduledoc false
  use Phoenix.Endpoint, otp_app: :live_view_secure

  @session_options [
    store: :cookie,
    key: "_lvs_protocol_key",
    signing_salt: "protocol_salt",
    same_site: "Lax"
  ]

  socket("/live", Phoenix.LiveView.Socket,
    websocket: [connect_info: [session: @session_options]],
    longpoll: false
  )

  plug(Plug.Session, @session_options)
  plug(LiveViewSecure.Test.Protocol.Router)

  @doc false
  def start!(test_supervisor_start) do
    Application.put_env(:live_view_secure, __MODULE__,
      adapter: Bandit.PhoenixAdapter,
      http: [ip: {127, 0, 0, 1}, port: 0],
      server: true,
      url: [host: "localhost"],
      check_origin: false,
      render_errors: [formats: [html: LiveViewSecure.Test.Protocol.ErrorHTML], layout: false],
      secret_key_base: String.duplicate("p", 64),
      live_view: [signing_salt: "protocol_lv_salt"],
      pubsub_server: LiveViewSecure.Test.Protocol.PubSub
    )

    test_supervisor_start.({Phoenix.PubSub, name: LiveViewSecure.Test.Protocol.PubSub})
    test_supervisor_start.(__MODULE__)
    {:ok, {_ip, port}} = server_info(:http)
    port
  end
end
