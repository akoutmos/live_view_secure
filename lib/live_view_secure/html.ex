defmodule LiveViewSecure.HTML do
  @moduledoc """
  Template helpers that render signed events. Import them where you import
  your other HTML helpers:

      import LiveViewSecure.HTML

  Every helper takes the `@live_view_secure` assign as its first argument.
  Because they read it as an assign, LiveView re-renders them (with new
  tokens) when `LiveViewSecure.rotate/1` replaces it.

  Signed values are converted with `to_string/1` and arrive in `handle_event/3`
  as strings, the same as plain `phx-value-*` attributes. Sign identifiers,
  not data structures.
  """

  use Phoenix.Component

  alias LiveViewSecure.{Context, Signer}
  alias Phoenix.LiveView.JS

  @doc """
  Returns the attributes for a signed `phx-click` (or another binding):

      <button {signed_attrs(@live_view_secure, "delete_user", id: user.id)}>Delete</button>

  renders

      <button phx-click="delete_user" phx-value-id="42" phx-value-__sig="id.AbC...">

  Keys must be lowercase, because browsers lowercase attribute names, and
  `value` is reserved, because LiveView replaces it with the element's DOM
  value. Use `signed_push/3` if you need either.

  ## Options

    * `:binding` - the attribute that carries the event. Defaults to
      `"phx-click"`. Use `"phx-blur"`, `"phx-keydown"` and so on for other
      bindings, and remember that those send extra unsigned params (`"value"`,
      `"key"`, ...) that the event's `:unsigned` option needs to allow.
    * `:target` - rendered as `phx-target`, e.g. `@myself`.
  """
  @spec signed_attrs(Context.t(), String.t() | atom(), map() | keyword(), keyword()) :: map()
  def signed_attrs(secure, event, values \\ [], opts \\ []) do
    opts = Keyword.validate!(opts, binding: "phx-click", target: nil)
    binding = binding!(opts[:binding])
    event = event!(secure, event, opts[:target])
    values = Signer.normalize_values!(values, :attrs)
    token = Signer.sign(secure, event, values)

    attrs = %{binding => event, "phx-value-#{Signer.sig_param()}" => token}
    attrs = Enum.reduce(values, attrs, fn {k, v}, acc -> Map.put(acc, "phx-value-" <> k, v) end)

    if opts[:target], do: Map.put(attrs, "phx-target", opts[:target]), else: attrs
  end

  @doc """
  A signed `Phoenix.LiveView.JS.push/3`. Takes the same options as `JS.push/3`,
  and signs the map passed as `:value`:

      <button phx-click={signed_push(@live_view_secure, "archive", value: %{id: user.id})}>
      <button phx-click={JS.hide("#row") |> signed_push(@live_view_secure, "archive", value: %{id: 1})}>

  Keys here are case-sensitive and may be `"value"`.
  """
  @spec signed_push(Context.t(), String.t() | atom()) :: JS.t()
  def signed_push(secure, event), do: signed_push(secure, event, [])

  @doc """
  `signed_push(js, secure, event)` or `signed_push(secure, event, opts)`.
  See `signed_push/2`.
  """
  @spec signed_push(JS.t(), Context.t(), String.t() | atom()) :: JS.t()
  @spec signed_push(Context.t(), String.t() | atom(), keyword()) :: JS.t()
  def signed_push(%JS{} = js, secure, event), do: signed_push(js, secure, event, [])

  def signed_push(secure, event, opts) when is_list(opts) do
    {event, opts} = push_args(secure, event, opts)
    JS.push(event, opts)
  end

  @doc """
  `signed_push(js, secure, event, opts)`: adds the signed push to `js`. See
  `signed_push/2`.
  """
  @spec signed_push(JS.t(), Context.t(), String.t() | atom(), keyword()) :: JS.t()
  def signed_push(%JS{} = js, secure, event, opts) when is_list(opts) do
    {event, opts} = push_args(secure, event, opts)
    JS.push(js, event, opts)
  end

  # Shared by signed_push/3 and /4. Without a JS to add to, JS.push/2 builds
  # one itself, since a %JS{}'s ops are opaque.
  defp push_args(secure, event, opts) do
    event = event!(secure, event, opts[:target])
    {values, opts} = Keyword.pop(opts, :value, %{})
    values = Signer.normalize_values!(values, :push)
    token = Signer.sign(secure, event, values)

    {event, Keyword.put(opts, :value, Map.put(values, Signer.sig_param(), token))}
  end

  @doc """
  Signed hidden inputs for a form. The signature covers the event name and
  these inputs only, so declare the submit event with an `:unsigned` policy
  that lets the fields the user filled in through. For a `to_form(changeset)`
  form, those are all nested under one param:

      on_mount {LiveViewSecure, events: [{"save", unsigned: ["post"]}]}

      <.form for={@form} phx-change="validate" phx-submit="save">
        <.signed_inputs secure={@live_view_secure} event="save" values={%{id: @post.id}} />
        ...
      </.form>

  * **Event binding.** A token is bound to one event, so sign for the event
    that changes data (`phx-submit`) and leave `phx-change` unverified.
  * **Matching names.** Make sure the form's `phx-submit` matches `event`. A
    mismatch submits an undeclared event, which isn't verified.
  * **User input.** The submit button's name and value are user input, like
    every other unsigned field.
  """
  attr(:secure, Context, required: true, doc: "the `@live_view_secure` assign")
  attr(:event, :string, required: true, doc: "the event these values are signed for")
  attr(:values, :any, default: [], doc: "map or keyword list of values to sign")

  def signed_inputs(assigns) do
    values = Signer.normalize_values!(assigns.values, :form)
    token = Signer.sign(assigns.secure, event!(assigns.secure, assigns.event, nil), values)
    assigns = assign(assigns, :inputs, Enum.sort(values) ++ [{Signer.sig_param(), token}])

    ~H"""
    <input :for={{name, value} <- @inputs} type="hidden" name={name} value={value} />
    """
  end

  # Bindings whose value is an event name. Anything else (an `on*` handler,
  # `href`, `phx-value-*`, `phx-target`, `phx-hook`, ...) would put the event name
  # somewhere it means something else.
  # (phx-viewport-top/bottom aren't here: the client sends its own "id" and
  # "_overran" with them, which is user input by nature.)
  @bindings ~w(phx-click phx-click-away phx-blur phx-focus phx-window-blur phx-window-focus
               phx-keydown phx-keyup phx-window-keydown phx-window-keyup phx-change phx-submit)

  defp binding!(binding) when binding in @bindings, do: binding

  defp binding!(other) do
    raise ArgumentError,
          ":binding must be one of #{Enum.join(@bindings, ", ")}, got: #{inspect(other)}. " <>
            "Use signed_push/3 inside other JS commands."
  end

  # Refuse to sign what the hook would never check: an event this LiveView
  # (or component) doesn't verify, or one aimed at a component this context
  # doesn't belong to.
  defp event!(secure, event, target) do
    event = Signer.event_name!(event)

    with %Context{} <- secure do
      if not Context.verifies?(secure, event) do
        raise ArgumentError, """
        refusing to sign #{inspect(event)}: the LiveViewSecure hook for this context \
        doesn't verify it, so the event would be accepted with any params. Add it to \
        the :events option (and check for typos), or don't sign it.\
        """
      end

      case {target, secure.owner} do
        {%Phoenix.LiveComponent.CID{} = cid, {_pid, owner}} when cid != owner ->
          raise ArgumentError, """
          refusing to sign #{inspect(event)} for component #{inspect(cid)} with a context \
          that belongs to #{if owner, do: "component #{inspect(owner)}", else: "the LiveView"}. \
          Events sent to a component skip the LiveView's hook, so call \
          LiveViewSecure.attach/2 in the component's mount/1 and sign with the \
          component's own @live_view_secure.\
          """

        _ ->
          :ok
      end
    end

    event
  end
end
