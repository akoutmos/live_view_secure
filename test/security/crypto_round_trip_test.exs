defmodule LiveViewSecure.Security.CryptoRoundTripTest do
  @moduledoc """
  Round-1 F2, ported: values containing CR or NUL used to sign fine and then
  never verify after the browser parsed them. Round 2 normalizes them on the
  HTML channels (`:attrs`, `:form`) before signing *and* rendering, the way the
  browser's HTML tokenizer would (CR/CRLF -> LF, NUL -> U+FFFD), and raises on
  invalid UTF-8 everywhere.

  The browser is modelled with lexbor (via LazyHTML), a WHATWG-conformant HTML
  parser, after a UTF-8 decode. LiveView's client parses server HTML the same
  way, on the dead render and for diffs.

  Every test asserts the SECURE behaviour.
  """
  use ExUnit.Case, async: true
  use ExUnitProperties

  import Phoenix.Component, only: [sigil_H: 2]
  import Phoenix.LiveViewTest, only: [rendered_to_string: 1]
  import LiveViewSecure.HTML

  alias LiveViewSecure.{Context, Signer}

  # What a browser does with server HTML before LiveView reads it back:
  # decode UTF-8, then run the HTML tokenizer.
  defp browser_parse(html), do: html |> String.replace_invalid() |> LazyHTML.from_fragment()

  defp render_signed(ctx, channel, v) do
    assigns = %{ctx: ctx, v: v}

    case channel do
      :attrs ->
        ~H|<button {signed_attrs(@ctx, "go", note: @v)}>x</button>|

      :form ->
        ~H|<form><.signed_inputs secure={@ctx} event="go" values={%{note: @v}} /></form>|

      :push ->
        ~H|<button phx-click={signed_push(@ctx, "go", value: %{note: @v})}>x</button>|
    end
    |> rendered_to_string()
  end

  # What the handler would receive from a plain, unsigned phx-value-* attribute.
  defp plain_phx_value(v) do
    assigns = %{v: v}

    [value] =
      ~H|<button phx-click="go" phx-value-note={@v}>x</button>|
      |> rendered_to_string()
      |> browser_parse()
      |> LazyHTML.query("button")
      |> LazyHTML.attribute("phx-value-note")

    value
  end

  # The params LiveView's client would send for that DOM.
  defp params_from_dom(doc, :attrs) do
    [attrs] = LazyHTML.attributes(LazyHTML.query(doc, "button"))
    for {"phx-value-" <> k, v} <- attrs, into: %{"value" => ""}, do: {k, v}
  end

  defp params_from_dom(doc, :form) do
    names = LazyHTML.attribute(LazyHTML.query(doc, "input"), "name")
    values = LazyHTML.attribute(LazyHTML.query(doc, "input"), "value")
    names |> Enum.zip(values) |> URI.encode_query(:www_form) |> Plug.Conn.Query.decode()
  end

  defp params_from_dom(doc, :push) do
    [json] = LazyHTML.attribute(LazyHTML.query(doc, "button"), "phx-click")
    [["push", %{"value" => value}]] = Jason.decode!(json)
    Map.put(value, "value", "")
  end

  # {verify result, the params the handler would get}
  defp round_trip(channel, v) do
    ctx = Context.new()
    params = ctx |> render_signed(channel, v) |> browser_parse() |> params_from_dom(channel)
    {Signer.verify(ctx, "go", params, :deny), params}
  end

  @html_rewrites ["line\r\nbreak", "carriage\rreturn", "nul\0byte", "\r", "\0", "\r\r\n\n\0�"]
  @fine [
    "",
    "plain",
    "line\nbreak",
    "tab\there",
    "  spaced  ",
    "é ✓ 日本",
    ~s(<"&'>),
    <<0x2028::utf8>>,
    "\x01\x7F",
    "�"
  ]

  describe "round-1 F2 (fixed): values the HTML parser rewrites" do
    for channel <- [:attrs, :form], v <- @html_rewrites do
      test "#{channel}: #{inspect(v)} verifies after the browser, as a plain phx-value would deliver it" do
        v = unquote(v)
        {result, params} = round_trip(unquote(channel), v)
        assert result == :ok
        assert params["note"] == plain_phx_value(v)
      end
    end

    for v <- @html_rewrites do
      test "push: #{inspect(v)} round-trips unchanged (JSON escapes it)" do
        assert {:ok, %{"note" => unquote(v)}} = round_trip(:push, unquote(v))
      end
    end

    for channel <- [:attrs, :form, :push], v <- @fine do
      test "#{channel}: #{inspect(v)} round-trips unchanged" do
        assert {:ok, %{"note" => unquote(v)}} = round_trip(unquote(channel), unquote(v))
      end
    end

    test "invalid UTF-8 is refused on every channel (it can't reach the browser intact)" do
      for channel <- [:attrs, :form, :push],
          v <- [<<0xFF>>, <<?a, 0xC3>>, <<0xED, 0xA0, 0x80>>] do
        assert_raise ArgumentError, ~r/UTF-8/, fn ->
          Signer.normalize_values!([note: v], channel)
        end
      end
    end
  end

  describe "normalization only collapses what HTML collapses" do
    defp html_norm(s), do: s |> String.replace(["\r\n", "\r"], "\n") |> String.replace(<<0>>, "�")

    property "the signed value is exactly the browser's view of the plain attribute" do
      check all(
              v <- string([?a, ?\r, ?\n, 0, 0xFFFD, ?é], max_length: 12),
              channel <- member_of([:attrs, :form]),
              max_runs: 300
            ) do
        assert %{"note" => signed} = Signer.normalize_values!([note: v], channel)
        assert signed == plain_phx_value(v)
        assert signed == html_norm(v)
        # idempotent, and the identity on values without CR or NUL
        assert Signer.normalize_values!([note: signed], channel) == %{"note" => signed}
        if not String.contains?(v, ["\r", <<0>>]), do: assert(signed == v)
        # JS.push values are never rewritten
        assert Signer.normalize_values!([note: v], :push) == %{"note" => v}
      end
    end

    property "two server values share a token only if the browser couldn't tell them apart either" do
      ctx = Context.new()
      alphabet = [?a, ?\r, ?\n, 0, 0xFFFD]

      check all(
              v1 <- string(alphabet, max_length: 6),
              v2 <- string(alphabet, max_length: 6),
              v1 != v2,
              channel <- member_of([:attrs, :form]),
              max_runs: 500
            ) do
        p1 = Signer.normalize_values!([note: v1], channel)
        p2 = Signer.normalize_values!([note: v2], channel)
        same_token = Signer.sign(ctx, "go", p1) == Signer.sign(ctx, "go", p2)

        assert same_token == (plain_phx_value(v1) == plain_phx_value(v2))
      end
    end
  end
end
