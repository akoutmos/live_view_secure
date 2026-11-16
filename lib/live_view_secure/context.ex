defmodule LiveViewSecure.Context do
  @moduledoc """
  The signing context for one LiveView (or one LiveComponent).

  `LiveViewSecure.attach/2` puts one of these in the `@live_view_secure` assign.

  ## Keys

  Each LiveView process gets a random 256-bit **root key** when it mounts. It
  lives in an `:atomics` array referenced from the process dictionary, and never
  in an assign. Each context has a random, non-secret `id`, and signs with
  `HMAC(root, id)`. So:

    * a token is only valid in the process that rendered it. A reconnect, a fresh
      page load, another tab or another user means another root.
    * the struct holds no key material. It can't leak through `inspect/2` (with
      any options), Erlang's `~p` formatting, crash reports or
      `:erlang.term_to_binary/1`. That last one covers putting it into a nested
      LiveView's session, which Phoenix sends to the browser signed but not
      encrypted.
    * a context only signs in the process that created it. Used anywhere else
      (say, handed to a nested LiveView through `assign_new/3`), it raises.

  ## Rotation

  `LiveViewSecure.rotate/1` on a LiveView replaces the root, which revokes every
  token the process has issued, including its LiveComponents'. On a component,
  it gives just that component a new id. Either way the struct changes, so
  LiveView re-renders every expression that signs with it.

  Tokens from the generation just before a rotation are recognized as
  `:revoked`. They're always dropped, never raised: they're what a legitimate
  click looks like when it was in flight during the rotation. A component whose
  tokens were revoked by its LiveView's rotation refreshes itself on its next
  event.
  """

  @enforce_keys [:id, :prev_id, :root_gen, :owner, :verifies]
  defstruct [
    :id,
    :prev_id,
    :root_gen,
    :owner,
    :verifies,
    uses: %{},
    prev_uses: %{},
    signable: nil
  ]

  @typedoc false
  @type verifies :: {:only, MapSet.t(String.t())} | {:all_except, MapSet.t(String.t())}

  @type t :: %__MODULE__{
          id: binary(),
          prev_id: binary() | nil,
          root_gen: pos_integer(),
          owner: {pid(), Phoenix.LiveComponent.CID.t() | nil},
          verifies: verifies(),
          uses: %{optional(binary()) => pos_integer()},
          prev_uses: %{optional(binary()) => pos_integer()}
        }

  @root {__MODULE__, :root}
  @domain "live_view_secure/context-key/v1"

  ## Creating and rotating

  @doc false
  # `fresh_root: true` starts a new root for the process (a LiveView mounting).
  # Otherwise the current root is reused (a component mounting inside one).
  @spec new(Phoenix.LiveComponent.CID.t() | nil, verifies(), keyword()) :: t()
  def new(cid \\ nil, verifies \\ {:all_except, MapSet.new()}, opts \\ []) do
    {gen, _current, _previous} =
      if Keyword.get(opts, :fresh_root, false), do: fresh_root(), else: ensure_root()

    %__MODULE__{
      id: new_id(),
      prev_id: nil,
      root_gen: gen,
      owner: {self(), cid},
      verifies: verifies,
      signable: Keyword.get(opts, :signable)
    }
  end

  @doc false
  # A key that the event's :unsigned policy would also accept unsigned (not
  # listed in :signed under `unsigned: :allow`, or listed in an :unsigned list)
  # isn't protected by signing it: any token this context issues for the same
  # event without that key lets the client add it with any value. Refuse to sign
  # it, so a mismatch between the config and the templates shows up at render.
  @spec check_signable!(t(), String.t(), [String.t()]) :: :ok
  def check_signable!(%__MODULE__{signable: {rules, default}}, event, keys) do
    unprotected =
      case Map.get(rules, event, default) do
        %{unsigned: :allow, signed: signed} -> keys -- signed
        %{unsigned: allowed} when is_list(allowed) -> Enum.filter(keys, &(&1 in allowed))
        _ -> []
      end

    if unprotected != [] do
      raise ArgumentError, """
      refusing to sign #{inspect(unprotected)} for #{inspect(event)}: the event's \
      :unsigned policy also accepts #{if length(unprotected) == 1, do: "it", else: "them"} \
      unsigned, so a token for the same event without #{if length(unprotected) == 1, do: "it", else: "them"} \
      would let the client send any value. List #{inspect(unprotected)} in the event's \
      :signed option, and not in :unsigned.\
      """
    end

    :ok
  end

  def check_signable!(%__MODULE__{}, _event, _keys), do: :ok

  @doc false
  # :process replaces the root (revoking every context in this process);
  # :local only replaces this context's id.
  @spec rotate(t(), :process | :local) :: t()
  def rotate(%__MODULE__{} = context, scope) do
    ensure_owner!(context)

    {gen, _current, _previous} =
      case scope do
        :process -> put_root(root())
        :local -> root()
      end

    %{
      context
      | prev_id: context.id,
        id: new_id(),
        root_gen: gen,
        uses: %{},
        prev_uses: context.uses
    }
  end

  @doc false
  # How many times the signed (event, values) pair whose base MAC is `base` has
  # been accepted as a single-use event. Tokens carry the count they were
  # rendered with, so accepting one re-issues only that pair's token.
  @spec uses(t(), binary()) :: non_neg_integer()
  def uses(%__MODULE__{uses: uses}, base), do: Map.get(uses, base, 0)

  @doc false
  # The same, for the generation before the last rotation (keyed by base MACs
  # under the revoked key), so a used token from then is still :revoked.
  @spec prev_uses(t(), binary()) :: non_neg_integer()
  def prev_uses(%__MODULE__{prev_uses: uses}, base), do: Map.get(uses, base, 0)

  @doc false
  @spec consume(t(), binary()) :: t()
  def consume(%__MODULE__{uses: uses} = context, base),
    do: %{context | uses: Map.update(uses, base, 1, &(&1 + 1))}

  @doc false
  # True when the process root changed after this context last rendered, so
  # its tokens in the page are revoked and it should re-render.
  @spec stale?(t()) :: boolean()
  def stale?(%__MODULE__{root_gen: gen}) do
    {current_gen, _, _} = root()
    gen != current_gen
  end

  ## Keys

  @doc false
  @spec key(t()) :: binary()
  def key(%__MODULE__{id: id} = context) do
    ensure_owner!(context)
    {_gen, current, _previous} = root()
    derive(current, id)
  end

  @doc false
  # Keys that signed tokens which are now revoked: the previous root and/or the
  # previous id. Only consulted when the current key doesn't match.
  @spec revoked_keys(t()) :: [binary()]
  def revoked_keys(%__MODULE__{id: id, prev_id: prev_id} = context) do
    ensure_owner!(context)
    {_gen, current, previous} = root()

    for root_ref <- [current, previous],
        key_id <- [id, prev_id],
        root_ref != nil and key_id != nil,
        {root_ref, key_id} != {current, id},
        do: derive(root_ref, key_id)
  end

  ## Ownership and declared events

  @doc false
  @spec owned_by?(t(), pid(), Phoenix.LiveComponent.CID.t() | nil) :: boolean()
  def owned_by?(%__MODULE__{owner: {pid, cid}}, owner_pid, owner_cid),
    do: pid == owner_pid and cid == owner_cid

  @doc false
  @spec verifies?(t(), String.t()) :: boolean()
  def verifies?(%__MODULE__{verifies: {:only, events}}, event), do: MapSet.member?(events, event)

  def verifies?(%__MODULE__{verifies: {:all_except, except}}, event),
    do: not MapSet.member?(except, event)

  ## Internals

  defp ensure_owner!(%__MODULE__{owner: {pid, _cid}}) when pid == self(), do: :ok

  defp ensure_owner!(%__MODULE__{owner: {pid, _cid}}) do
    raise ArgumentError, """
    this @live_view_secure context belongs to #{inspect(pid)}, but it's being used in \
    #{inspect(self())}. A context only works in the LiveView process that created it, \
    so don't share it with nested LiveViews (through their session or assign_new/3). \
    Give each LiveView its own `on_mount {LiveViewSecure, ...}`.\
    """
  end

  defp root do
    case Process.get(@root) do
      {_gen, _current, _previous} = root ->
        root

      nil ->
        raise ArgumentError,
              "no LiveViewSecure root key in this process. Contexts are created by " <>
                "LiveViewSecure.attach/2 (or on_mount) in the LiveView process."
    end
  end

  defp ensure_root do
    case Process.get(@root) do
      {_gen, _current, _previous} = root -> root
      nil -> put_root(nil)
    end
  end

  # A new root with no "previous" one: tokens from whatever this process
  # rendered before (another LiveView in a dead render, say) are just invalid,
  # not :revoked. The generation still moves forward, so contexts created
  # before it count as stale.
  defp fresh_root do
    gen =
      case Process.get(@root) do
        {gen, _current, _previous} -> gen + 1
        nil -> 1
      end

    root = {gen, new_root_ref(), nil}
    Process.put(@root, root)
    root
  end

  defp put_root(previous) do
    {gen, previous_ref} =
      case previous do
        {gen, current, _} -> {gen + 1, current}
        nil -> {1, nil}
      end

    root = {gen, new_root_ref(), previous_ref}
    Process.put(@root, root)
    root
  end

  defp new_root_ref do
    <<a::64, b::64, c::64, d::64>> = :crypto.strong_rand_bytes(32)
    ref = :atomics.new(4, signed: false)
    for {word, index} <- Enum.with_index([a, b, c, d], 1), do: :atomics.put(ref, index, word)
    ref
  end

  defp derive(root_ref, id) do
    root =
      <<:atomics.get(root_ref, 1)::64, :atomics.get(root_ref, 2)::64,
        :atomics.get(root_ref, 3)::64, :atomics.get(root_ref, 4)::64>>

    :crypto.mac(:hmac, :sha256, root, [@domain, id])
  end

  defp new_id, do: :crypto.strong_rand_bytes(16)

  defimpl Inspect do
    def inspect(_context, _opts), do: "#LiveViewSecure.Context<redacted>"
  end
end
