defmodule LiveViewSecure do
  @moduledoc """
  Makes sure the event params a LiveView receives are exactly what it rendered.

  Anyone can send any event with any params over the LiveView websocket.
  Hiding the delete button doesn't stop someone from pushing `"delete"`
  with any id they like. LiveViewSecure signs the event name together with
  its values when you render them, and rejects any declared event whose
  params don't match a signature this LiveView process issued.

  This is defense in depth. It proves "this LiveView rendered exactly this
  event with exactly these values". It does not prove "this user may do this
  right now", so keep authorizing in your contexts. It earns its keep where
  the server no longer has what it rendered (streams, temporary assigns) and
  as a backstop against forgotten checks.

  ## Usage

      defmodule MyAppWeb.UsersLive do
        use MyAppWeb, :live_view
        import LiveViewSecure.HTML

        on_mount {LiveViewSecure, events: ["delete_user", "archive", {"save", unsigned: ["post"]}]}

        def render(assigns) do
          ~H\"\"\"
          <div :for={user <- @users}>
            {user.name}
            <button {signed_attrs(@live_view_secure, "delete_user", id: user.id)}>Delete</button>
            <button phx-click={signed_push(@live_view_secure, "archive", value: %{id: user.id, scope: "mine"})}>
              Archive
            </button>
          </div>

          <.form for={@form} phx-submit="save">
            <.signed_inputs secure={@live_view_secure} event="save" values={%{id: @post.id}} />
            <.input field={@form[:title]} />
          </.form>
          \"\"\"
        end

        # Unchanged handlers. Signed values arrive as strings, next to a "__sig" param.
        def handle_event("delete_user", %{"id" => id}, socket), do: ...
      end

  ## Options

    * `:events` (required) - which events must be signed:
        * a list of event names, each optionally given as `{name, opts}`;
        * `:all`, every event except those in `:except`;
        * `[:all, {name, opts}, ...]`, every event, with per-event options
          for the ones listed.
    * `:except` - with `:all`, events that don't need a signature (typically
      `phx-change` validation).
    * `:unsigned` - what to do with params that arrive but weren't signed.
      Can also be set per event.
        * `:deny` (default) - reject the event. The one exception is the
          element's empty DOM value (`"value" => ""` from a `<button>`,
          `"value" => 0` from an `<li>`), which browsers send with every click.
        * a list of param names to let through, e.g. `["key"]` for key events,
          or `["post"]` for a form built with `to_form(changeset)`.
        * `:allow` - let anything else through. Requires `:signed`.
    * `:signed` - params that must be covered by the signature whenever they
      arrive, whatever `:unsigned` allows. Required with `unsigned: :allow`,
      because without it a token this LiveView issued for the same event with
      fewer values (a "new" form next to an "edit" form) would verify, and the
      client could add the rest. Can also be set per event.
    * `:on_failure` - `:raise` (default) raises `LiveViewSecure.InvalidEventError`,
      which crashes the LiveView and makes the client remount. `:halt` drops the
      event and keeps the LiveView running.

  Every rejection emits `[:live_view_secure, :event, :rejected]` telemetry and
  is logged by the default logger, if you attach it with
  `LiveViewSecure.Telemetry.attach_default_logger/1`. See `LiveViewSecure.Telemetry` for all events
  and for metric definitions.

  ## Ordering

  LiveViewSecure verifies before your `handle_event/3`, and before any
  `:handle_event` hook, including ones attached earlier (say by a
  `live_session` `on_mount`): `attach/2` moves its hook to the front.

  ## Revoking tokens

  Every LiveView process gets a fresh random key on mount, so tokens never
  outlive the process that rendered them. To revoke the ones it has already
  rendered (say a user's permissions just changed), call `rotate/1`. Every
  expression that signs with `@live_view_secure` re-renders with new tokens.
  Content LiveView doesn't re-render (stream items you don't re-insert,
  `phx-update="ignore"` regions) keeps its old tokens, which now fail closed.
  """

  alias LiveViewSecure.{Context, InvalidEventError, Signer, Telemetry}
  alias Phoenix.LiveView.Socket

  @assign :live_view_secure
  @hook :live_view_secure

  @type unsigned :: :deny | :allow | [String.t() | atom()]
  @type event_opts :: [unsigned: unsigned(), signed: [String.t() | atom()], single_use: boolean()]
  @type event_spec :: String.t() | atom() | {String.t() | atom(), event_opts()}
  @type option ::
          {:events, :all | [event_spec() | :all]}
          | {:except, [String.t() | atom()]}
          | {:unsigned, unsigned()}
          | {:signed, [String.t() | atom()]}
          | {:on_failure, :raise | :halt}

  @doc """
  `on_mount/4` callback. Declare it in the LiveView module itself (directly,
  or in the `live_view` block of your `MyAppWeb` module):

      on_mount {LiveViewSecure, events: ["delete_user"]}

  Declaring it in a `live_session` raises: each LiveView that relies on
  LiveViewSecure declares it itself.

  See the module docs for options.
  """
  @spec on_mount([option()] | :default, map() | :not_mounted_at_router, map(), Socket.t()) ::
          {:cont, Socket.t()}
  def on_mount(opts, _params, _session, %Socket{} = socket) do
    ensure_declared_in_view!(socket, opts)
    {:cont, attach(socket, opts)}
  end

  defp ensure_declared_in_view!(%Socket{view: view}, opts) do
    declared_in_view? =
      Enum.any?(view.__live__().lifecycle.mount, &match?(%{id: {__MODULE__, ^opts}}, &1))

    if not declared_in_view? do
      raise ArgumentError, """
      on_mount {LiveViewSecure, ...} must be declared in #{inspect(view)} itself, \
      not in a live_session.

      Move the on_mount into the LiveView module, or into the `live_view` block \
      of your MyAppWeb module.
      """
    end
  end

  @doc """
  Assigns a new `@live_view_secure` context and attaches the `:handle_event`
  hook that verifies signatures, in front of any `:handle_event` hooks already
  attached.

  `on_mount/4` calls this for LiveViews. You can also call it from `mount/3`.
  LiveComponents have their own lifecycle, so a LiveView's hook never sees
  events sent to a component (`phx-target={@myself}`). Call this from the
  component's `mount/1`:

      def mount(socket) do
        {:ok, LiveViewSecure.attach(socket, events: ["remove_item"])}
      end

  The component then signs with its own `@live_view_secure`. A context is
  bound to the LiveView or component that created it, so passing a parent's
  `@live_view_secure` into a component (or a nested LiveView) gets every event
  there rejected with `:foreign_context`.
  """
  @spec attach(Socket.t(), [option()] | :default) :: Socket.t()
  def attach(%Socket{} = socket, opts) do
    ensure_not_from_live_session!(socket)
    config = config!(opts)
    cid = socket.assigns[:myself]

    # A LiveView mounting starts a new root key for its process; a component
    # mounting inside it shares that root (so the LiveView's rotate/1 revokes it).
    context =
      Context.new(cid, config.verifies, fresh_root: is_nil(cid), signable: signable(config))

    socket
    |> Phoenix.Component.assign(@assign, context)
    |> attach_first(fn event, params, socket -> verify_event(config, event, params, socket) end)
  end

  # The same rule as in on_mount/4, one level removed: a policy module whose
  # on_mount calls attach/2 has to be declared in the view itself, not in a
  # live_session. Its on_mount/4 frame is on the stack while it runs, so refuse
  # unless that module is declared in the view. Best effort: a wrapper that
  # tail-calls into a helper leaves no frame.
  defp ensure_not_from_live_session!(%Socket{view: view}) when is_atom(view) and view != nil do
    if function_exported?(view, :__live__, 0) do
      own =
        for %{id: {module, _}} <- view.__live__().lifecycle.mount, into: MapSet.new(), do: module

      {:current_stacktrace, stack} = Process.info(self(), :current_stacktrace)

      foreign =
        for {module, :on_mount, 4, _location} <- stack,
            module != __MODULE__,
            not MapSet.member?(own, module),
            do: module

      if foreign != [] do
        raise ArgumentError, """
        LiveViewSecure.attach/2 was called from #{inspect(hd(foreign))}.on_mount/4, which \
        isn't declared in #{inspect(view)} itself (a live_session's on_mount?). Declare \
        `on_mount #{inspect(hd(foreign))}` in the LiveView module (or its `live_view` block \
        in MyAppWeb), or call attach/2 from mount/3.\
        """
      end
    end
  end

  defp ensure_not_from_live_session!(_socket), do: :ok

  # LiveView runs :handle_event hooks in the order they were attached. Detach
  # any that are already there and re-attach them after ours, so nothing sees
  # an event before it's verified.
  defp attach_first(socket, fun) do
    earlier =
      case socket.private do
        %{lifecycle: %{handle_event: hooks}} when is_list(hooks) ->
          hooks

        _ ->
          raise "LiveViewSecure couldn't read this socket's lifecycle hooks, so it can't " <>
                  "make sure it verifies events first. Is this a LiveView or LiveComponent socket?"
      end

    if Enum.any?(earlier, &(&1.id == @hook)) do
      raise ArgumentError, "LiveViewSecure.attach/2 was called twice on the same socket"
    end

    socket = Enum.reduce(earlier, socket, &Phoenix.LiveView.detach_hook(&2, &1.id, :handle_event))
    socket = Phoenix.LiveView.attach_hook(socket, @hook, :handle_event, fun)

    Enum.reduce(earlier, socket, fn %{id: id, function: hook_fun}, socket ->
      Phoenix.LiveView.attach_hook(socket, id, :handle_event, hook_fun)
    end)
  end

  @doc """
  Revokes every token issued so far and re-renders with new ones.

  On a LiveView socket this replaces the process's root key, which also revokes
  the tokens of every LiveComponent in it. (Each component re-renders with fresh
  tokens on its next event; that first event is dropped as `:revoked`.) On a
  component socket it only revokes that component's tokens.

  Emits `[:live_view_secure, :key, :rotate]` telemetry.
  """
  @spec rotate(Socket.t()) :: Socket.t()
  def rotate(%Socket{} = socket) do
    case socket.assigns[@assign] do
      %Context{} = context ->
        Telemetry.rotated(socket)
        scope = if socket.assigns[:myself], do: :local, else: :process
        Phoenix.Component.assign(socket, @assign, Context.rotate(context, scope))

      _ ->
        raise ArgumentError,
              "LiveViewSecure.rotate/1 needs a socket with a @live_view_secure assign"
    end
  end

  ## Hook

  defp verify_event(config, event, params, socket) do
    meta = Telemetry.metadata(socket, event)

    case rule(config, event) do
      nil ->
        Telemetry.unverified(meta, params)
        {:cont, socket}

      %{unsigned: unsigned, signed: signed} = rule ->
        context = socket.assigns[@assign]

        result =
          :telemetry.span([:live_view_secure, :verify], meta, fn ->
            result =
              case context do
                %Context{} ->
                  if Context.owned_by?(context, self(), socket.assigns[:myself]),
                    do: Signer.check(context, event, params, unsigned, signed),
                    else: {:error, :foreign_context}

                _ ->
                  {:error, :no_context}
              end

            {result, Telemetry.stop_metadata(meta, with({:ok, _} <- result, do: :ok))}
          end)

        case result do
          {:ok, base} ->
            # Single-use: re-issue this pair's token before the handler runs,
            # so a replay or a double click arrives as :revoked. Other pairs
            # (other rows, stream items, in-flight clicks) keep their tokens.
            # A stale component re-issues everything anyway.
            socket =
              cond do
                Context.stale?(context) ->
                  refresh(socket, context)

                rule.single_use ->
                  Phoenix.Component.assign(socket, @assign, Context.consume(context, base))

                true ->
                  socket
              end

            {:cont, socket}

          {:error, :revoked} ->
            # Not an attack signature: a click that was in flight during a
            # rotation looks exactly like this. Drop it without raising.
            reject(:halt, meta, refresh_if_stale(socket, context), :revoked)

          # A stale component (its LiveView rotated since it last rendered)
          # only has dead tokens on the page. After two or more rotations they
          # no longer match a revoked key either, so without this it would
          # never refresh: its buttons would stay dead under :halt, and every
          # click would crash the LiveView under :raise. Treat it like
          # :revoked. Bounded: once refreshed, it isn't stale any more.
          {:error, :invalid_signature} when is_struct(context, Context) ->
            if Context.stale?(context),
              do: reject(:halt, meta, refresh(socket, context), :revoked),
              else: reject(config.on_failure, meta, socket, :invalid_signature)

          {:error, reason} ->
            reject(config.on_failure, meta, socket, reason)
        end
    end
  end

  # The LiveView rotated the process root after this component last rendered:
  # its tokens on the page are dead, so give it a new id to re-render them.
  defp refresh_if_stale(socket, context) do
    if Context.stale?(context), do: refresh(socket, context), else: socket
  end

  defp refresh(socket, context),
    do: Phoenix.Component.assign(socket, @assign, Context.rotate(context, :local))

  defp rule(%{mode: :all, except: except, rules: rules, default_rule: default}, event) do
    if MapSet.member?(except, event), do: nil, else: Map.get(rules, event, default)
  end

  defp rule(%{mode: :only, rules: rules}, event), do: Map.get(rules, event)

  # What the context needs to refuse signing keys the policy would also accept
  # unsigned (see Context.check_signable!/3).
  defp signable(%{rules: rules, default_rule: default}) do
    policy = &Map.take(&1, [:unsigned, :signed])
    {Map.new(rules, fn {event, rule} -> {event, policy.(rule)} end), default && policy.(default)}
  end

  defp reject(action, meta, socket, reason) do
    Telemetry.rejected(meta, reason, action)

    case action do
      :raise -> raise InvalidEventError, view: socket.view, event: meta.event, reason: reason
      :halt -> {:halt, socket}
    end
  end

  ## Config

  defp config!(:default) do
    raise ArgumentError, """
    LiveViewSecure needs to know which events to verify, e.g.

        on_mount {LiveViewSecure, events: ["delete_user"]}
        on_mount {LiveViewSecure, events: :all, except: ["validate"]}
    """
  end

  defp config!(opts) when is_list(opts) do
    opts =
      Keyword.validate!(opts, [:events, :signed, except: [], unsigned: :deny, on_failure: :raise])

    # Only an explicitly given :signed list counts for the `unsigned: :allow` check.
    defaults = Keyword.take(opts, [:unsigned, :signed])

    {mode, specs} =
      case opts[:events] do
        nil -> config!(:default)
        :all -> {:all, []}
        [:all | specs] -> {:all, specs}
        specs when is_list(specs) -> {:only, specs}
        other -> raise ArgumentError, ":events must be a list or :all, got: #{inspect(other)}"
      end

    if :all in specs do
      raise ArgumentError,
            "`:all` can only come first in the :events list, e.g. " <>
              ~s|events: [:all, {"save", unsigned: ["post"]}]. | <>
              ~s|Use the string "all" for an event named "all".|
    end

    rules = Enum.map(specs, &event_spec!(&1, defaults))

    case rules -- Enum.uniq_by(rules, &elem(&1, 0)) do
      [] -> :ok
      [{event, _} | _] -> raise ArgumentError, "#{inspect(event)} is declared more than once"
    end

    rules = Map.new(rules)
    except = MapSet.new(opts[:except], &Signer.event_name!/1)

    cond do
      mode == :only and opts[:except] != [] ->
        raise ArgumentError, ":except only applies to `events: :all`"

      (both = Enum.filter(Map.keys(rules), &MapSet.member?(except, &1))) != [] ->
        raise ArgumentError, "#{inspect(both)} are both declared and listed in :except"

      true ->
        :ok
    end

    on_failure =
      case opts[:on_failure] do
        mode when mode in [:raise, :halt] ->
          mode

        other ->
          raise ArgumentError, ":on_failure must be :raise or :halt, got: #{inspect(other)}"
      end

    %{
      mode: mode,
      rules: rules,
      except: except,
      default_rule: if(mode == :all, do: rule!("events: :all", defaults)),
      verifies:
        if(mode == :all,
          do: {:all_except, except},
          else: {:only, rules |> Map.keys() |> MapSet.new()}
        ),
      on_failure: on_failure
    }
  end

  defp config!(other) do
    raise ArgumentError,
          "expected LiveViewSecure options as a keyword list, got: #{inspect(other)}"
  end

  defp event_spec!({event, event_opts}, defaults) when is_list(event_opts) do
    event = Signer.event_name!(event)
    event_opts = Keyword.validate!(event_opts, [:unsigned, :signed, :single_use])
    {event, rule!(inspect(event), Keyword.merge(defaults, event_opts))}
  end

  defp event_spec!(event, defaults) do
    event = Signer.event_name!(event)
    {event, rule!(inspect(event), defaults)}
  end

  defp rule!(label, opts) do
    unsigned = unsigned!(Keyword.get(opts, :unsigned, :deny))

    signed =
      case Keyword.fetch(opts, :signed) do
        {:ok, keys} when is_list(keys) ->
          Enum.map(keys, &param_name!/1)

        {:ok, other} ->
          raise ArgumentError, ":signed must be a list of param names, got: #{inspect(other)}"

        :error when unsigned == :allow ->
          raise ArgumentError, """
          #{label} uses `unsigned: :allow`, which also needs a `:signed` list: the \
          params that must be covered by the signature whenever they're present, e.g.

              {"save", unsigned: :allow, signed: ["id"]}

          Without it, a token this LiveView issued for the same event with fewer \
          values (say, a "new" form next to an "edit" form) would verify, and the \
          client could add `"id"` as an ordinary unsigned param. Use `signed: []` \
          if the event has no server-provided values. For Phoenix forms, a list \
          policy such as `unsigned: ["post"]` is tighter still.
          """

        :error ->
          []
      end

    overlap = if is_list(unsigned), do: Enum.filter(unsigned, &(&1 in signed)), else: []

    if overlap != [] do
      raise ArgumentError, "#{label} lists #{inspect(overlap)} in both :unsigned and :signed"
    end

    single_use =
      case Keyword.get(opts, :single_use, false) do
        flag when is_boolean(flag) -> flag
        other -> raise ArgumentError, ":single_use must be a boolean, got: #{inspect(other)}"
      end

    %{unsigned: unsigned, signed: signed, single_use: single_use}
  end

  defp unsigned!(policy) when policy in [:deny, :allow], do: policy
  defp unsigned!(keys) when is_list(keys), do: Enum.map(keys, &param_name!/1)

  defp unsigned!(other) do
    raise ArgumentError,
          ":unsigned must be :deny, :allow or a list of param names, got: #{inspect(other)}"
  end

  defp param_name!(name) when is_atom(name) and not is_nil(name),
    do: param_name!(Atom.to_string(name))

  defp param_name!(name) when is_binary(name) do
    if String.contains?(name, ["[", "]"]) do
      raise ArgumentError, """
      param names in :signed and :unsigned are top-level keys, got: #{inspect(name)}. \
      Params arrive decoded, so "post[author_id]" is %{"post" => %{"author_id" => ...}} \
      and that name would never match. List the top-level name ("post"), and sign \
      server-provided values with <.signed_inputs> as top-level inputs.\
      """
    end

    name
  end

  defp param_name!(other) do
    raise ArgumentError, "param names must be strings or atoms, got: #{inspect(other)}"
  end
end
