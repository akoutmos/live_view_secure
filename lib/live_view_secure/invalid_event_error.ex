defmodule LiveViewSecure.InvalidEventError do
  @moduledoc """
  Raised (with `on_failure: :raise`, the default) when a declared event
  arrives without a valid signature.

  `:reason` is one of:

    * `:missing_signature` - no `"__sig"` param
    * `:malformed_signature` - a `"__sig"` param that isn't a token LiveViewSecure issues
    * `:invalid_signature` - the token doesn't match this event and these values,
      or it was issued by another process, or more than one rotation ago
    * `:revoked` - the token was valid until the last rotation (or it's a
      single-use token that was already used). Always halted, never raised.
    * `{:missing_params, keys}` - signed params that didn't arrive
    * `{:unsigned_params, keys}` - params that arrived without being signed
    * `:foreign_context` - the socket's `@live_view_secure` was created by another
      LiveView or component (for example, passed in from a parent)
    * `:no_context` - the socket has no `@live_view_secure` assign
  """

  defexception [:view, :event, :reason]

  @impl true
  def message(%__MODULE__{view: view, event: event, reason: reason}) do
    """
    LiveViewSecure rejected #{safe_inspect(event)} in #{inspect(view)}: #{describe(reason)}

    If you rendered this event with LiveViewSecure.HTML, someone is probably \
    sending crafted events to your LiveView.\
    """
  end

  defp describe(:missing_signature),
    do:
      ~s(no "__sig" param. Render the event with signed_attrs/4, signed_push/3 or ) <>
        "<.signed_inputs>, or take it out of :events if it shouldn't be signed."

  defp describe(:malformed_signature), do: ~s(the "__sig" param is not a LiveViewSecure token.)

  defp describe(:invalid_signature),
    do:
      "the signature doesn't match this event and its values. Either the values were " <>
        "tampered with or swapped in from another element, or the token is stale (another " <>
        "process issued it, or it predates LiveViewSecure.rotate/1)."

  defp describe({:missing_params, keys}),
    do: "signed params #{safe_inspect(keys)} were removed from the payload."

  defp describe({:unsigned_params, keys}),
    do:
      "params #{safe_inspect(keys)} weren't signed. Sign them, or let them through with " <>
        "the :unsigned option (e.g. form fields or key events)."

  defp describe(:revoked),
    do: "the token was revoked by LiveViewSecure.rotate/1 or a single-use event."

  defp describe(:foreign_context),
    do:
      "the socket's @live_view_secure belongs to another LiveView or component. " <>
        "Don't pass @live_view_secure into components or nested LiveViews; " <>
        "each one calls LiveViewSecure.attach/2 (or on_mount) for its own."

  defp describe(:no_context),
    do: "the socket has no @live_view_secure assign. Was it reassigned or removed?"

  defp describe(other), do: safe_inspect(other)

  # The event name and param names come from the client.
  defp safe_inspect(term), do: LiveViewSecure.Telemetry.safe_inspect(term)
end
