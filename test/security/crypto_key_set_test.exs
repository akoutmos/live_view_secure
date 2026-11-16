defmodule LiveViewSecure.Security.CryptoPostsLive do
  @moduledoc false
  # Round-1 F1 scenario with the round-2 fix: a "new post" form (nothing to
  # sign) and an "edit post" form (signed id), both submitting "save".
  use Phoenix.LiveView
  import LiveViewSecure.HTML

  on_mount({LiveViewSecure, events: [{"save", unsigned: :allow, signed: ["id"]}]})

  def mount(_params, _session, socket), do: {:ok, assign(socket, post_id: 1, log: [])}

  def render(assigns) do
    ~H"""
    <form id="new-post" phx-submit="save">
      <.signed_inputs secure={@live_view_secure} event="save" />
      <input type="text" name="title" value="" />
    </form>
    <form id="edit-post" phx-submit="save">
      <.signed_inputs secure={@live_view_secure} event="save" values={%{id: @post_id}} />
      <input type="text" name="title" value="" />
    </form>
    <ul id="log">
      <li :for={entry <- @log}>{entry}</li>
    </ul>
    """
  end

  def handle_event("save", %{"id" => id, "title" => title}, socket),
    do: {:noreply, update(socket, :log, &(&1 ++ ["updated post #{id} title=#{title}"]))}

  def handle_event("save", %{"title" => title}, socket),
    do: {:noreply, update(socket, :log, &(&1 ++ ["created post title=#{title}"]))}
end

defmodule LiveViewSecure.Security.CryptoLaxPostsLive do
  @moduledoc false
  # The same page, but `signed: []` — what the config error message suggests
  # "if the event has no server-provided values" — while the edit form does sign
  # an id. Nothing ties the :signed list to what the templates actually sign.
  use Phoenix.LiveView

  on_mount({LiveViewSecure, events: [{"save", unsigned: :allow, signed: []}]})

  defdelegate mount(params, session, socket), to: LiveViewSecure.Security.CryptoPostsLive
  defdelegate render(assigns), to: LiveViewSecure.Security.CryptoPostsLive
  defdelegate handle_event(event, params, socket), to: LiveViewSecure.Security.CryptoPostsLive
end

defmodule LiveViewSecure.Security.CryptoListPolicyPostsLive do
  @moduledoc false
  # Same mistake with a list policy: "id" is listed as user input, and the edit
  # form also signs it.
  use Phoenix.LiveView

  on_mount({LiveViewSecure, events: [{"save", unsigned: ["id", "title"]}]})

  defdelegate mount(params, session, socket), to: LiveViewSecure.Security.CryptoPostsLive
  defdelegate render(assigns), to: LiveViewSecure.Security.CryptoPostsLive
  defdelegate handle_event(event, params, socket), to: LiveViewSecure.Security.CryptoPostsLive
end

defmodule LiveViewSecure.Security.CryptoKeySetTest do
  @moduledoc """
  Round-1 F1, ported: a token proves which keys *it* covers. Under a permissive
  `:unsigned` policy a client could pick a narrower token for the same event
  and supply the "signed" params itself. Round 2 adds `:signed` (required with
  `unsigned: :allow`).

  Every test asserts the SECURE behaviour, so a failing test is a vulnerability.
  """
  use ExUnit.Case, async: false

  import Phoenix.ConnTest
  import Phoenix.LiveViewTest

  alias LiveViewSecure.{Context, Signer}

  alias LiveViewSecure.Security.{
    CryptoLaxPostsLive,
    CryptoListPolicyPostsLive,
    CryptoPostsLive
  }

  @endpoint LiveViewSecure.Test.Endpoint
  @moduletag :capture_log

  setup do
    Process.flag(:trap_exit, true)
    {:ok, conn: build_conn()}
  end

  defp hidden(view, form, name) do
    [value] =
      view
      |> element("##{form} input[name=#{name}]")
      |> render()
      |> LazyHTML.from_fragment()
      |> LazyHTML.attribute("value")

    value
  end

  defp submit(view, params) do
    render_submit(view, "save", params)
  catch
    :exit, {{%LiveViewSecure.InvalidEventError{reason: reason}, _}, _} -> {:rejected, reason}
  end

  # The attack from round 1: the new-post token, plus an id of the attacker's choosing.
  # The attack from round 1: the new-post token, plus an id of the attacker's
  # choosing. Returns the rendered page if the handler ran, or why it didn't.
  defp attack(conn, live) do
    {:ok, view, _html} = live_isolated(conn, live)
    token = hidden(view, "new-post", "__sig")
    submit(view, %{"__sig" => token, "id" => "999", "title" => "pwned"})
  rescue
    # Secure too: the LiveView refuses to render a token it can't protect.
    e in ArgumentError -> {:refused_at_render, Exception.message(e)}
  catch
    :exit, reason -> {:mount_failed, reason}
  end

  describe "round-1 F1 (fixed): unsigned: :allow requires :signed" do
    for opts <- [
          [events: [{"save", unsigned: :allow}]],
          [events: ["save"], unsigned: :allow],
          [events: :all, unsigned: :allow],
          [events: [:all, {"save", unsigned: :allow}]],
          [events: [{"save", unsigned: :allow, signed: nil}]]
        ] do
      test "config #{inspect(opts)} raises" do
        assert_raise ArgumentError, ~r/signed/, fn ->
          LiveViewSecure.attach(%Phoenix.LiveView.Socket{}, unquote(Macro.escape(opts)))
        end
      end
    end

    test "with signed: [\"id\"] the legitimate forms work", %{conn: conn} do
      {:ok, view, _html} = live_isolated(conn, CryptoPostsLive)

      assert view |> form("#edit-post", %{"title" => "a"}) |> render_submit() =~
               "updated post 1 title=a"

      assert view |> form("#new-post", %{"title" => "b"}) |> render_submit() =~
               "created post title=b"
    end

    test "with signed: [\"id\"] the new-post token can't carry an id", %{conn: conn} do
      assert {:rejected, {:unsigned_params, ["id"]}} = attack(conn, CryptoPostsLive)
    end

    test "verify/5 rejects protected names that arrive unsigned, under every policy" do
      ctx = Context.new()
      narrow = Signer.sign(ctx, "save", %{"org" => "acme"})
      wide = Signer.sign(ctx, "save", %{"org" => "acme", "id" => "1"})
      params = %{"__sig" => narrow, "org" => "acme", "id" => "999"}

      for policy <- [:allow, :deny, ["title"]] do
        assert {:error, {:unsigned_params, ["id"]}} =
                 Signer.verify(ctx, "save", params, policy, ["id"])
      end

      # protected even when it's the benign empty DOM value
      for benign <- ["", 0] do
        assert {:error, {:unsigned_params, ["value"]}} =
                 Signer.verify(
                   ctx,
                   "save",
                   %{"__sig" => narrow, "org" => "acme", "value" => benign},
                   :deny,
                   ["value"]
                 )
      end

      assert :ok =
               Signer.verify(ctx, "save", %{params | "__sig" => wide, "id" => "1"}, :allow, ["id"])

      # tampering with a protected, signed value is still caught by the MAC
      assert {:error, :invalid_signature} =
               Signer.verify(ctx, "save", %{params | "__sig" => wide}, :allow, ["id"])
    end
  end

  describe "[FINDING] a signed key the policy also accepts unsigned" do
    # Nothing ties :signed (or the :unsigned list) to the keys templates actually
    # sign. Secure behaviour: refuse to sign such a key at render time, or reject
    # the attack. Today the handler receives the attacker's id.

    test "unsigned: :allow, signed: [] while a template signs id", %{conn: conn} do
      result = attack(conn, CryptoLaxPostsLive)

      refute is_binary(result) and result =~ "updated post 999",
             "handler received an id this process never signed: #{inspect(result)}"
    end

    test ~S(unsigned: ["id", "title"] while a template signs id), %{conn: conn} do
      result = attack(conn, CryptoListPolicyPostsLive)

      refute is_binary(result) and result =~ "updated post 999",
             "handler received an id this process never signed: #{inspect(result)}"
    end
  end
end
