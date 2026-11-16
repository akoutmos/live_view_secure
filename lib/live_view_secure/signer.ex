defmodule LiveViewSecure.Signer do
  @moduledoc false
  # Token format (the value of the `__sig` param):
  #
  #     "<key>,<key>,....<base64url MAC>"      e.g. "id,scope.3q2-7wQ8n1J0d9mXyY1Zpg"
  #
  # The key list says which params were signed. It is covered by the MAC, so a
  # client cannot add keys to it or drop keys from it. The MAC is
  # HMAC-SHA256 truncated to 128 bits (RFC 2104 §5 allows truncating to half
  # the hash length). Forging one means guessing online against one process's
  # key, and every miss is rejected.
  #
  # The MAC input is length-prefixed so that no two (event, params) pairs encode
  # the same bytes:
  #
  #     "live_view_secure/v1" <> lp(event) <> <<count::32>> <> lp(k1) <> lp(v1) <> ...
  #
  # where lp(x) = <<byte_size(x)::64>> <> x.
  #
  # Keys are sorted, and signed values are always strings, because that's what
  # `phx-value-*` attributes and form fields come back as anyway.

  alias LiveViewSecure.Context

  @sig_param "__sig"
  @domain "live_view_secure/v1"
  @use_domain "live_view_secure/use/v1"
  @mac_bytes 16
  @max_keys 32
  @max_key_bytes 64
  @max_token_bytes 4096
  @max_reported_keys 20

  @type values :: %{optional(String.t()) => String.t()}
  @type unsigned_policy :: :deny | :allow | [String.t()]
  @type reason ::
          :no_context
          | :missing_signature
          | :malformed_signature
          | :invalid_signature
          | :revoked
          | :foreign_context
          | {:missing_params, [String.t()]}
          | {:unsigned_params, [String.t()]}

  def sig_param, do: @sig_param

  ## Signing

  @spec sign(Context.t(), String.t(), values()) :: String.t()
  def sign(%Context{} = context, event, values) when is_binary(event) and is_map(values) do
    key = Context.key(context)
    keys = values |> Map.keys() |> Enum.sort()
    Context.check_signable!(context, event, keys)
    base = mac(key, event, keys, values)
    tag = with_uses(key, base, Context.uses(context, base))

    Enum.join(keys, ",") <> "." <> Base.url_encode64(tag, padding: false)
  end

  def sign(other, _event, _values) do
    raise ArgumentError,
          "expected a %LiveViewSecure.Context{} (the @live_view_secure assign), got: " <>
            inspect(other) <>
            ". Did you add `on_mount {LiveViewSecure, ...}` (or call LiveViewSecure.attach/2) " <>
            "and pass @live_view_secure through to this component?"
  end

  @doc """
  Turns developer-supplied values (map or keyword list) into the string-to-string
  map that gets signed and sent. Raises `ArgumentError` for anything that can't
  make it to the client and back unchanged.

  `channel` is one of:

    * `:attrs` - rendered as `phx-value-*` attributes
    * `:push`  - sent as a `JS.push/2` value
    * `:form`  - rendered as hidden form inputs
  """
  @spec normalize_values!(map() | keyword(), :attrs | :push | :form) :: values()
  def normalize_values!(values, channel) when is_map(values) or is_list(values) do
    normalized =
      Enum.reduce(values, %{}, fn
        {key, value}, acc ->
          key = normalize_key!(key, channel)

          if Map.has_key?(acc, key) do
            raise ArgumentError, "duplicate signed key #{inspect(key)}"
          end

          # Like a plain phx-value-* attribute, nil and false leave the param
          # out (it isn't signed, and a client can't add it: it's either
          # rejected as unsigned, or listed in :signed). Signing them as "" or
          # "false" would hand the handler a present, truthy string.
          if value in [nil, false],
            do: Map.put(acc, key, :omit),
            else: Map.put(acc, key, normalize_value!(key, value, channel))

        other, _acc ->
          raise ArgumentError, "expected {key, value} pairs, got: #{inspect(other)}"
      end)

    normalized = for {key, value} <- normalized, value != :omit, into: %{}, do: {key, value}

    if map_size(normalized) > @max_keys do
      raise ArgumentError, "at most #{@max_keys} values can be signed per event"
    end

    normalized
  end

  def normalize_values!(other, _channel) do
    raise ArgumentError, "expected signed values as a map or keyword list, got: #{inspect(other)}"
  end

  defp normalize_key!(key, channel) when is_atom(key) and not is_nil(key) and not is_boolean(key),
    do: normalize_key!(Atom.to_string(key), channel)

  defp normalize_key!(@sig_param, _channel) do
    raise ArgumentError, "#{inspect(@sig_param)} is reserved by LiveViewSecure"
  end

  defp normalize_key!("value", :attrs) do
    raise ArgumentError, """
    the key "value" can't be signed as a phx-value-* attribute: the LiveView client \
    overwrites params["value"] with the element's DOM value (always "" for a <button>). \
    Use another key name, or use signed_push/3.\
    """
  end

  defp normalize_key!(key, :attrs) when is_binary(key) do
    if attr_key?(key) do
      key
    else
      raise ArgumentError, """
      invalid signed key #{inspect(key)}. phx-value-* keys must be 1-#{@max_key_bytes} \
      lowercase letters, digits, "_" or "-" (browsers lowercase attribute names, so a \
      key like "userId" would arrive as "userid" and fail verification).\
      """
    end
  end

  defp normalize_key!(key, _channel) when is_binary(key) do
    if key?(key) do
      key
    else
      raise ArgumentError,
            "invalid signed key #{inspect(key)}. Keys must be 1-#{@max_key_bytes} " <>
              ~s(letters, digits, "_" or "-".)
    end
  end

  defp normalize_key!(key, _channel) do
    raise ArgumentError, "signed keys must be atoms or strings, got: #{inspect(key)}"
  end

  defp normalize_value!(key, value, channel) when is_binary(value) do
    if not String.valid?(value) do
      raise ArgumentError,
            "can't sign #{inspect(key)}: the value is not valid UTF-8, so it can't be " <>
              "sent to the browser unchanged"
    end

    html_normalize(value, channel)
  end

  defp normalize_value!(key, true, _channel) do
    raise ArgumentError, """
    can't sign #{inspect(key)} = true. A plain phx-value-* attribute would send "" \
    for it and to_string/1 would give "true", so pass the string you want the \
    handler to receive.\
    """
  end

  defp normalize_value!(key, %Phoenix.LiveComponent.CID{} = value, _channel) do
    raise ArgumentError, """
    can't sign #{inspect(key)} = #{inspect(value)}. A component's @myself ended up \
    among the signed values, which usually means the values weren't wrapped in a \
    list: signed_attrs(ctx, "remove", [id: id], target: @myself)\
    """
  end

  # Structs (Date, Decimal, ...) fall through to the String.Chars check below.
  defp normalize_value!(key, value, _channel)
       when is_list(value) or is_tuple(value) or (is_map(value) and not is_struct(value)) do
    raise ArgumentError,
          "can't sign #{inspect(key)}: values must be scalars that convert with " <>
            "to_string/1 (strings, numbers, atoms, dates, ...), got: #{inspect(value)}. " <>
            "Sign an identifier and load the data on the server instead."
  end

  defp normalize_value!(key, value, channel) do
    if String.Chars.impl_for(value) do
      normalize_value!(key, to_string(value), channel)
    else
      raise ArgumentError,
            "can't sign #{inspect(key)}: #{inspect(value)} does not implement String.Chars"
    end
  end

  # Values rendered into HTML attributes come back the way the browser's HTML
  # parser leaves them: CR and CRLF become LF, and NUL becomes U+FFFD. Sign
  # (and render) them in that form, so the handler receives exactly what a plain
  # phx-value-* attribute would have delivered, and the signature still matches.
  # JS.push values travel as JSON, which escapes these characters, so they're untouched.
  defp html_normalize(value, channel) when channel in [:attrs, :form] do
    value
    |> String.replace(["\r\n", "\r"], "\n")
    |> String.replace(<<0>>, "\uFFFD")
  end

  defp html_normalize(value, :push), do: value

  @doc """
  Validates an event name for rendering. The LiveView client runs a binding
  value that starts with "[" as JS commands, so an event name taken from data
  must never look like one.
  """
  @spec event_name!(String.t() | atom()) :: String.t()
  def event_name!(event) when is_atom(event) and not is_nil(event) and not is_boolean(event),
    do: event_name!(Atom.to_string(event))

  def event_name!(event) when is_binary(event) do
    cond do
      event == "" ->
        raise ArgumentError, "event names can't be empty"

      not String.valid?(event) or String.match?(event, ~r/[\x00-\x1F\x7F]/) ->
        raise ArgumentError,
              "event names must be valid UTF-8 without control characters, got: " <>
                inspect(event)

      String.starts_with?(event, "[") ->
        raise ArgumentError,
              "event names can't start with \"[\", because the LiveView client would " <>
                "run them as JS commands, got: #{inspect(event)}"

      true ->
        event
    end
  end

  def event_name!(other) do
    raise ArgumentError, "event names must be strings or atoms, got: #{inspect(other)}"
  end

  ## Verification

  @doc """
  `signed` lists param names that must be covered by the token whenever they're
  present, whatever the `unsigned` policy says. Without it, a token issued for
  the same event with fewer keys (a "new" form next to an "edit" form) would
  verify, and the client could supply the missing keys as unsigned params.
  """
  @spec verify(Context.t() | nil, String.t(), term(), unsigned_policy(), [String.t()]) ::
          :ok | {:error, reason()}
  def verify(context, event, params, unsigned, signed \\ []) do
    with {:ok, _base} <- check(context, event, params, unsigned, signed), do: :ok
  end

  @doc false
  # Like verify/5, but returns the base MAC of the verified (event, values)
  # pair, which identifies it for single-use counting (Context.consume/2).
  @spec check(Context.t() | nil, String.t(), term(), unsigned_policy(), [String.t()]) ::
          {:ok, binary()} | {:error, reason()}
  def check(%Context{} = context, event, params, unsigned, signed) when is_map(params) do
    with {:ok, token} <- fetch_token(params),
         {:ok, keys, given_mac} <- parse(token),
         {:ok, values} <- fetch_signed_values(params, keys),
         mac_result = check_mac(context, event, keys, values, given_mac),
         :ok <- authentic(mac_result),
         :ok <- check_unsigned(params, keys, unsigned),
         :ok <- check_signed(params, keys, signed) do
      # {:ok, base}, or {:error, :revoked}. :revoked is only reported for an
      # otherwise clean payload: a genuine old token carrying injected params
      # is tampering, not a click that was in flight, and mustn't be quietly
      # dropped as one.
      mac_result
    end
  end

  def check(%Context{}, _event, _params, _unsigned, _signed), do: {:error, :missing_signature}
  def check(_no_context, _event, _params, _unsigned, _signed), do: {:error, :no_context}

  defp fetch_token(params) do
    case params do
      %{@sig_param => token} when is_binary(token) -> {:ok, token}
      %{@sig_param => _} -> {:error, :malformed_signature}
      _ -> {:error, :missing_signature}
    end
  end

  defp parse(token) when byte_size(token) > @max_token_bytes, do: {:error, :malformed_signature}

  defp parse(token) do
    with [keys_part, mac_part] <- String.split(token, "."),
         {:ok, <<given_mac::binary-size(@mac_bytes)>>} <-
           Base.url_decode64(mac_part, padding: false),
         # The last base64 character carries unused bits that the decoder
         # ignores, so several strings decode to the same MAC. Only accept the
         # one we emit, so a token has exactly one valid spelling.
         ^mac_part <- Base.url_encode64(given_mac, padding: false),
         {:ok, keys} <- parse_keys(keys_part) do
      {:ok, keys, given_mac}
    else
      _ -> {:error, :malformed_signature}
    end
  end

  defp parse_keys(""), do: {:ok, []}

  defp parse_keys(keys_part) do
    keys = String.split(keys_part, ",")

    # Strictly ascending implies unique, and it's the only order sign/3 emits.
    if length(keys) <= @max_keys and Enum.all?(keys, &key?/1) and
         strictly_ascending?(keys) do
      {:ok, keys}
    else
      :error
    end
  end

  defp strictly_ascending?([a, b | rest]) when a < b, do: strictly_ascending?([b | rest])
  defp strictly_ascending?([_, _ | _]), do: false
  defp strictly_ascending?(_), do: true

  defp fetch_signed_values(params, keys) do
    {values, missing} =
      Enum.reduce(keys, {%{}, []}, fn key, {values, missing} ->
        case params do
          %{^key => value} -> {Map.put(values, key, value), missing}
          _ -> {values, [key | missing]}
        end
      end)

    case missing do
      [] -> {:ok, values}
      missing -> {:error, {:missing_params, Enum.reverse(missing)}}
    end
  end

  defp authentic({:ok, _base}), do: :ok
  defp authentic({:error, :revoked}), do: :ok
  defp authentic(error), do: error

  defp check_mac(context, event, keys, values, given_mac) do
    matches? = &Plug.Crypto.secure_compare(&1, given_mac)

    # A signed value that comes back as anything other than a string was
    # tampered with (we only ever sign strings).
    if not is_binary(event) or not Enum.all?(keys, &is_binary(Map.fetch!(values, &1))) do
      {:error, :invalid_signature}
    else
      key = Context.key(context)
      base = mac(key, event, keys, values)
      uses = Context.uses(context, base)

      cond do
        matches?.(with_uses(key, base, uses)) ->
          {:ok, base}

        # This pair's token from one use ago: a double click, or a replay of a
        # single-use token. Other pairs' tokens are untouched.
        uses > 0 and matches?.(with_uses(key, base, uses - 1)) ->
          {:error, :revoked}

        # Signed before the last rotation: what a click in flight during the
        # rotation looks like.
        Enum.any?(Context.revoked_keys(context), fn revoked ->
          base = mac(revoked, event, keys, values)
          matches?.(base) or matches?.(with_uses(revoked, base, Context.prev_uses(context, base)))
        end) ->
          {:error, :revoked}

        true ->
          {:error, :invalid_signature}
      end
    end
  end

  # A pair that was never consumed gets exactly the v1 MAC. After n accepted
  # single-use events its MAC is re-keyed over the base MAC and n.
  defp with_uses(_key, base, 0), do: base

  defp with_uses(key, base, n),
    do:
      :crypto.mac(:hmac, :sha256, key, [@use_domain, base, <<n::64>>])
      |> binary_part(0, @mac_bytes)

  defp check_unsigned(_params, _keys, :allow), do: :ok

  defp check_unsigned(params, keys, policy) do
    allowed = if is_list(policy), do: policy, else: []

    extras =
      for {key, value} <- params,
          key != @sig_param,
          key not in keys,
          key not in allowed,
          # Browsers send the element's DOM `value` with every click. Without
          # a value attribute that's "" (<button>) or 0 (<li>, <meter>,
          # <progress>), which carries nothing.
          not (key == "value" and (value === "" or value === 0)),
          do: key

    unsigned_params_error(extras)
  end

  defp check_signed(_params, _keys, []), do: :ok

  defp check_signed(params, keys, signed) do
    signed
    |> Enum.filter(&(Map.has_key?(params, &1) and &1 not in keys))
    |> unsigned_params_error()
  end

  defp unsigned_params_error([]), do: :ok

  # The keys come from the client, so report a bounded number of them.
  defp unsigned_params_error(keys),
    do: {:error, {:unsigned_params, keys |> Enum.sort() |> Enum.take(@max_reported_keys)}}

  defp mac(key, event, keys, values) do
    data = [
      @domain,
      lp(event),
      <<length(keys)::32>>,
      Enum.map(keys, fn k -> [lp(k), lp(Map.fetch!(values, k))] end)
    ]

    :crypto.mac(:hmac, :sha256, key, data) |> binary_part(0, @mac_bytes)
  end

  defp lp(binary), do: [<<byte_size(binary)::64>>, binary]

  # Keys that may be signed: 1-64 letters, digits, "_" or "-". Lowercase only
  # for `phx-value-*` attributes, because HTML parsers lowercase attribute names.
  defp key?(key), do: Regex.match?(~r/\A[A-Za-z0-9_\-]{1,64}\z/, key)
  defp attr_key?(key), do: Regex.match?(~r/\A[a-z0-9_\-]{1,64}\z/, key)
end
