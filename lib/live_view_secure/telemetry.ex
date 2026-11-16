defmodule LiveViewSecure.Telemetry do
  @moduledoc """
  Telemetry events emitted by LiveViewSecure, and an optional default logger.

  ## Verification span

  Emitted around signature verification for every declared event, using
  `:telemetry.span/3`:

    * `[:live_view_secure, :verify, :start]`
      * Measurements: `%{system_time: integer, monotonic_time: integer}`
      * Metadata: `%{view: module, source: :view | :component, event: String.t(), socket: Phoenix.LiveView.Socket.t()}`

    * `[:live_view_secure, :verify, :stop]`
      * Measurements: `%{duration: integer, monotonic_time: integer}` (native time units)
      * Metadata: the start metadata, plus
        * `:result` - `:ok` or `:rejected`
        * `:reason` - `nil`, or the rejection reason (see `LiveViewSecure.InvalidEventError`)
        * `:reason_type` - `nil`, or the reason without its details:
          `:missing_signature`, `:malformed_signature`, `:invalid_signature`,
          `:revoked`, `:missing_params`, `:unsigned_params`, `:foreign_context`
          or `:no_context`

    * `[:live_view_secure, :verify, :exception]` - verification itself raised.
      That's a bug in LiveViewSecure (rejections are not exceptions), so please
      report it. Standard `:telemetry.span/3` measurements and metadata.

  ## Discrete events

    * `[:live_view_secure, :event, :rejected]` - a declared event failed
      verification. Emitted after the `:stop` event and before the LiveView
      raises or halts.
      * Measurements: `%{count: 1}`
      * Metadata: `%{view, source, event, reason, reason_type, action, socket}`.
        `:action` is what happened: `:raise` or `:halt`. It follows the
        `:on_failure` option, except that `:revoked` tokens are always halted.
        Those are what a click in flight during a rotation looks like, and a
        replayed single-use token, so a steady trickle is normal. A burst of
        anything else isn't.

    * `[:live_view_secure, :event, :unverified]` - an event reached a handler
      without verification: it isn't declared, or (with the default logger
      attached, see below) the LiveView or LiveComponent that handled it has no
      LiveViewSecure hook at all.
      * Measurements: `%{count: 1}`
      * Metadata: `%{view, source, event, signed, socket}`. `:signed` is `true`
        when the event carried a `"__sig"` param anyway, which means something
        signed it expecting it to be verified. Usually that's a typo in
        `:events`, a form whose `phx-submit` isn't the event `<.signed_inputs>`
        signs, a LiveComponent that never called `LiveViewSecure.attach/2`, or a
        nested LiveView without its own `on_mount`. Form `phx-change` events
        (which carry `"_target"`) are left out, because they normally carry the
        form's signed inputs without being declared. The default logger warns
        about every `signed: true` event.

    * `[:live_view_secure, :key, :rotate]` - `LiveViewSecure.rotate/1` replaced
      a key.
      * Measurements: `%{count: 1}`
      * Metadata: `%{view, source, socket}`

  `:view` is always the LiveView module, including for events handled by a
  LiveComponent (`source: :component`). To see the component module, correlate
  with LiveView's own `[:phoenix, :live_component, :handle_event, :start]`
  event, which carries the component and the full params.

  ## Metrics

  With `Telemetry.Metrics`, e.g. in your `MyAppWeb.Telemetry` module:

      counter("live_view_secure.event.rejected.count", tags: [:view, :reason_type]),
      counter("live_view_secure.event.unverified.count", tags: [:view, :signed]),
      counter("live_view_secure.key.rotate.count", tags: [:view]),
      distribution("live_view_secure.verify.stop.duration",
        unit: {:native, :microsecond},
        tags: [:result]
      )

  > #### Don't tag metrics by `:event` blindly {: .warning}
  >
  > The event name comes from the client. With `events: :all`, and for
  > `:unverified` events, an attacker can send as many distinct names as they
  > like, which gives you unbounded metric cardinality. Every other field above
  > is bounded. If you need per-event metrics, map unknown names to a single
  > value with `:tag_values`.

  ## Default logger

  Attach it when your application starts:

      # lib/my_app/application.ex
      def start(_type, _args) do
        :ok = LiveViewSecure.Telemetry.attach_default_logger()
        # ...
      end

  * **What it logs.** One `:warning` line per rejection, and one per
    `:unverified` event with `signed: true`. The client's values are escaped
    and truncated.
  * **The watch.** It also watches LiveView's own
    `[:phoenix, :live_view | :live_component, :handle_event, :start]` events.
    When a signed event reaches a LiveView or component with no LiveViewSecure
    hook at all, it's reported as `:unverified` too. Without the watch, nothing
    sees those: say, a nested LiveView without `on_mount`, or a component that
    never called `LiveViewSecure.attach/2`.
  * **On a crash.** With `on_failure: :raise`, the LiveView crash is logged as
    well.
  """

  require Logger

  @logger_id {__MODULE__, :default_logger}
  @watch_id {__MODULE__, :watch}

  @doc """
  Attaches the default logger, plus the watch for signed events reaching
  LiveViews and components without a hook (see the module docs). Call it from
  your `Application.start/2`.

  ## Options

    * `:level` - the log level, `:warning` by default.
  """
  @spec attach_default_logger(keyword()) :: :ok | {:error, :already_exists}
  def attach_default_logger(opts \\ []) do
    opts = Keyword.validate!(opts, level: :warning)

    with :ok <-
           :telemetry.attach_many(
             @logger_id,
             [[:live_view_secure, :event, :rejected], [:live_view_secure, :event, :unverified]],
             &__MODULE__.log_event/4,
             %{level: opts[:level]}
           ) do
      attach_watch()
    end
  end

  @doc "Detaches the default logger and the watch."
  @spec detach_default_logger() :: :ok | {:error, :not_found}
  def detach_default_logger do
    :telemetry.detach(@watch_id)
    :telemetry.detach(@logger_id)
  end

  @doc false
  def log_event([:live_view_secure, :event, :rejected] = event, measurements, meta, config),
    do: log_rejection(event, measurements, meta, config)

  def log_event([:live_view_secure, :event, :unverified], _measurements, meta, %{level: level}) do
    if meta.signed do
      Logger.log(level, fn ->
        "LiveViewSecure: event #{safe_inspect(meta.event)} in #{inspect(meta.view)} " <>
          "(#{meta.source}) carries a signature but was NOT verified. Check :events for " <>
          "typos, that a form's phx-submit is the event <.signed_inputs> signs, that " <>
          "LiveComponents call LiveViewSecure.attach/2 themselves, and that nested " <>
          "LiveViews declare their own on_mount."
      end)
    end
  end

  @doc false
  def log_rejection(_event, _measurements, meta, %{level: level}) do
    # Everything here can be chosen by the client, so it's inspected (escaping
    # newlines and control characters) and truncated.
    Logger.log(level, fn ->
      "LiveViewSecure rejected event #{safe_inspect(meta.event)} in #{inspect(meta.view)} " <>
        "(#{meta.source}): #{safe_inspect(meta.reason)} [action: #{meta.action}]"
    end)
  end

  @doc false
  def safe_inspect(term), do: inspect(term, limit: 10, printable_limit: 100)

  ## Emitting (internal)

  @doc false
  def metadata(socket, event) do
    %{view: socket.view, source: source(socket), event: event, socket: socket}
  end

  @doc false
  def rotated(socket) do
    meta = socket |> metadata(nil) |> Map.delete(:event)
    :telemetry.execute([:live_view_secure, :key, :rotate], %{count: 1}, meta)
  end

  @doc false
  def unverified(meta, params) do
    :telemetry.execute(
      [:live_view_secure, :event, :unverified],
      %{count: 1},
      Map.put(meta, :signed, signed?(params))
    )
  end

  # Carries a signature, and isn't a form's phx-change (those carry "_target"
  # and normally include the form's signed inputs without being declared).
  defp signed?(params) do
    is_map(params) and Map.has_key?(params, LiveViewSecure.Signer.sig_param()) and
      not Map.has_key?(params, "_target")
  end

  ## Sockets without a hook (internal)

  # A LiveView's hook never sees events sent to a LiveComponent, and a LiveView
  # without `on_mount {LiveViewSecure, ...}` has no hook at all. When a signed
  # event reaches one of those, nothing verifies it: report it as :unverified
  # with signed: true, like an undeclared event.
  defp attach_watch do
    :telemetry.attach_many(
      @watch_id,
      [
        [:phoenix, :live_view, :handle_event, :start],
        [:phoenix, :live_component, :handle_event, :start]
      ],
      &__MODULE__.watch_event/4,
      nil
    )
  end

  @doc false
  def watch_event(_event, _measurements, %{socket: socket, event: event, params: params}, _) do
    hooks =
      case socket.private do
        %{lifecycle: %{handle_event: hooks}} when is_list(hooks) -> hooks
        _ -> []
      end

    if signed?(params) and not Enum.any?(hooks, &(&1.id == :live_view_secure)) do
      socket |> metadata(event) |> unverified(params)
    end
  end

  def watch_event(_event, _measurements, _meta, _config), do: :ok

  @doc false
  def rejected(meta, reason, action) do
    meta = Map.merge(meta, %{reason: reason, reason_type: reason_type(reason), action: action})

    :telemetry.execute([:live_view_secure, :event, :rejected], %{count: 1}, meta)
  end

  @doc false
  def stop_metadata(meta, :ok), do: Map.merge(meta, %{result: :ok, reason: nil, reason_type: nil})

  def stop_metadata(meta, {:error, reason}),
    do: Map.merge(meta, %{result: :rejected, reason: reason, reason_type: reason_type(reason)})

  defp reason_type({type, _details}) when is_atom(type), do: type
  defp reason_type(type) when is_atom(type), do: type

  defp source(%{assigns: %{myself: %Phoenix.LiveComponent.CID{}}}), do: :component
  defp source(_socket), do: :view
end
