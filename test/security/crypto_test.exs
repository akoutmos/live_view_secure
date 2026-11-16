defmodule LiveViewSecure.Security.CryptoTest do
  @moduledoc """
  Red-team coverage for the token format and the signer (round 1, ported to
  the round-2 API). The key model (root/derived keys, rotation, `:revoked`,
  single use, leakage) is covered in `crypto_key_model_test.exs`.

  Every test asserts the SECURE behaviour, so a failing test is a vulnerability.
  """
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias LiveViewSecure.{Context, Signer}
  alias Plug.Conn.Query

  @key_chars [?a..?z, ?A..?Z, ?0..?9, ?_, ?-]
  @policies [:deny, :allow, [], ["value"], ["key", "id"]]

  ## Helpers

  defp signed(ctx, event, values), do: Map.put(values, "__sig", Signer.sign(ctx, event, values))
  defp verify(ctx, event, params, policy \\ :deny), do: Signer.verify(ctx, event, params, policy)
  defp ok?(ctx, event, params, policy \\ :deny), do: verify(ctx, event, params, policy) == :ok

  # The MAC input's length prefix is 64-bit since round 1 (I1). lp32 is the old
  # 32-bit encoding, kept to build collision attempts against both.
  defp lp(bin), do: <<byte_size(bin)::64>> <> bin
  defp lp32(bin), do: <<byte_size(bin)::32>> <> bin

  defp mac_part(token), do: token |> String.split(".") |> List.last()

  defp splice(bin, at, len, with),
    do: binary_part(bin, 0, at) <> with <> binary_part(bin, at + len, byte_size(bin) - at - len)

  defp never_raises(fun) do
    fun.()
  rescue
    e -> flunk("verify/4 raised #{inspect(e.__struct__)}: #{Exception.message(e)}")
  end

  ## Generators

  # term() unbounded is very slow to generate; this keeps maps/lists/tuples small.
  defp small_term, do: resize(term(), 12)

  # map_of/3 needs unique keys and gives up on small key spaces; duplicates are fine here.
  defp loose_map(key, value, max),
    do: map(list_of(tuple({key, value}), max_length: max), &Map.new/1)

  defp key_gen, do: string(@key_chars, min_length: 1, max_length: 64)
  defp values_gen(value_gen), do: map_of(key_gen(), value_gen, max_length: 32)

  # Everything that can come out of a JSON or urlencoded payload.
  defp json_gen do
    leaf =
      one_of([
        string(:utf8, max_length: 12),
        binary(max_length: 12),
        integer(),
        float(),
        boolean(),
        constant(nil)
      ])

    leaf
    |> tree(fn child ->
      one_of([
        list_of(child, max_length: 4),
        loose_map(one_of([string(:utf8, max_length: 6), key_gen()]), child, 4)
      ])
    end)
    |> resize(10)
  end

  describe "sign -> verify round trip" do
    property "any event and any byte-string values verify under every policy" do
      ctx = Context.new()

      check all(
              event <- binary(max_length: 64),
              values <- values_gen(binary(max_length: 64)),
              policy <- member_of(@policies),
              max_runs: 500
            ) do
        assert :ok = verify(ctx, event, signed(ctx, event, values), policy)
      end
    end

    property "developer-side scalars survive normalize_values!/2 + sign + verify (no transport)" do
      ctx = Context.new()

      # nil and booleans raise since round 2 (on purpose); CR and NUL are
      # normalized on the HTML channels (see crypto_round_trip_test.exs).
      scalar =
        one_of([
          string(:printable, max_length: 20),
          integer(),
          float(),
          member_of([:ok, :foo, ~D[2026-11-16], ~U[2026-11-16 10:00:00Z]])
        ])

      check all(
              values <-
                map_of(string([?a..?z, ?0..?9, ?_], min_length: 1, max_length: 10), scalar,
                  max_length: 32
                ),
              channel <- member_of([:attrs, :push, :form]),
              values = Map.drop(values, ["value", "__sig"]),
              max_runs: 300
            ) do
        normalized = Signer.normalize_values!(values, channel)
        assert Enum.all?(normalized, fn {k, v} -> is_binary(k) and is_binary(v) end)
        assert :ok = verify(ctx, "ev", signed(ctx, "ev", normalized))
      end
    end

    test "the documented maximum (32 keys of 64 bytes each) round-trips well under the token cap" do
      ctx = Context.new()
      values = for i <- 1..32, into: %{}, do: {String.pad_leading("#{i}", 64, "k"), "v#{i}"}
      params = signed(ctx, "ev", values)

      assert byte_size(params["__sig"]) == 32 * 64 + 31 + 1 + 22
      assert byte_size(params["__sig"]) < 4096
      assert :ok = verify(ctx, "ev", params)
    end

    test "the MAC is exactly 128 bits, encoded as 22 base64url chars" do
      ctx = Context.new()

      for _ <- 1..200 do
        mac = ctx |> Signer.sign("e", %{"id" => "#{:rand.uniform(1_000_000)}"}) |> mac_part()
        assert byte_size(mac) == 22
        assert {:ok, <<_::binary-size(16)>>} = Base.url_decode64(mac, padding: false)
      end
    end
  end

  describe "forgery without the key" do
    test "20k random MACs never verify (a 128-bit MAC can't be guessed online)" do
      ctx = Context.new()
      values = %{"id" => "7"}

      for _ <- 1..20_000 do
        token = "id." <> Base.url_encode64(:crypto.strong_rand_bytes(16), padding: false)
        refute ok?(ctx, "delete", Map.put(values, "__sig", token))
      end
    end

    test "degenerate MACs (all zero, all one, HMAC with an empty/zero key) don't verify" do
      ctx = Context.new()
      values = %{"id" => "7"}
      data = ["live_view_secure/v1", lp("delete"), <<1::32>>, lp("id"), lp("7")]
      data32 = ["live_view_secure/v1", lp32("delete"), <<1::32>>, lp32("id"), lp32("7")]

      macs = [
        :binary.copy(<<0>>, 16),
        :binary.copy(<<255>>, 16),
        :crypto.mac(:hmac, :sha256, "", data) |> binary_part(0, 16),
        :crypto.mac(:hmac, :sha256, :binary.copy(<<0>>, 32), data) |> binary_part(0, 16),
        :crypto.hash(:sha256, data) |> binary_part(0, 16),
        # the last 16 bytes instead of the first 16
        :crypto.mac(:hmac, :sha256, Context.key(ctx), data) |> binary_part(16, 16),
        # the round-1 encoding (32-bit length prefixes) under the real key
        :crypto.mac(:hmac, :sha256, Context.key(ctx), data32) |> binary_part(0, 16)
      ]

      for mac <- macs do
        token = "id." <> Base.url_encode64(mac, padding: false)
        refute ok?(ctx, "delete", Map.put(values, "__sig", token))
      end

      # Sanity check that `data` is the real encoding (64-bit length prefixes,
      # round-1 I1 fixed): with the real key it verifies.
      real = :crypto.mac(:hmac, :sha256, Context.key(ctx), data) |> binary_part(0, 16)

      assert ok?(
               ctx,
               "delete",
               Map.put(values, "__sig", "id." <> Base.url_encode64(real, padding: false))
             )
    end

    property "a token from another context (tab, user, reconnect) never verifies" do
      check all(
              event <- string(:printable, max_length: 20),
              values <- values_gen(string(:printable, max_length: 20)),
              max_runs: 300
            ) do
        params = signed(Context.new(), event, values)
        assert {:error, :invalid_signature} = verify(Context.new(), event, params)
      end
    end

    test "the key is what's MAC'd with: another id, or one flipped root bit, never accepts" do
      ctx = Context.new()
      params = signed(ctx, "e", %{"id" => "1"})
      assert :ok = verify(ctx, "e", params)

      # Same process (same root), different id.
      other_id = %{ctx | id: :crypto.strong_rand_bytes(16)}
      assert {:error, :invalid_signature} = verify(other_id, "e", params)

      # Flip one bit of the root key in place.
      {_gen, root, _prev} = Process.get({Context, :root})
      word = :atomics.get(root, 4)
      :atomics.put(root, 4, Bitwise.bxor(word, 1))
      assert {:error, :invalid_signature} = verify(ctx, "e", params)
      :atomics.put(root, 4, word)
      assert :ok = verify(ctx, "e", params)
    end
  end

  describe "canonical encoding (no two (event, values) pairs share a MAC input)" do
    test "hand-built boundary-shift collisions don't verify" do
      ctx = Context.new()

      # {event, values} that the token is issued for, {event, values} the attacker submits.
      pairs = [
        {{"ab", %{}}, {"a", %{"b" => ""}}},
        {{"x", %{"a" => "bc"}}, {"x", %{"ab" => "c"}}},
        {{"x", %{"a" => "bc"}}, {"xa", %{"b" => "c"}}},
        {{"x", %{"a" => "1", "b" => "2"}}, {"x", %{"a" => "1" <> lp("b") <> lp("2")}}},
        {{"x", %{"a" => "1", "b" => "2"}},
         {"x" <> <<2::32>> <> lp("a") <> lp("1"), %{"b" => "2"}}},
        {{"e", %{"k" => "v"}}, {"e" <> <<1::32>> <> lp("k") <> "v", %{}}},
        {{"e", %{"k" => "v"}}, {"e" <> <<1::32>> <> lp("k") <> lp("v"), %{}}},
        {{"e", %{"k" => ""}}, {"e", %{"k" => <<0, 0, 0, 0>>}}},
        {{"e", %{"k" => "v"}}, {"e", %{"k" => "v" <> <<0>>}}},
        {{"e", %{"a" => "", "b" => ""}}, {"e", %{"a" => <<0, 0, 0, 1, ?b, 0, 0, 0, 0>>}}},
        {{"", %{}}, {<<0>>, %{}}},
        {{"live_view_secure/v1", %{}}, {"", %{}}},
        # the same shifts built with the round-1 32-bit prefixes
        {{"x", %{"a" => "1", "b" => "2"}}, {"x", %{"a" => "1" <> lp32("b") <> lp32("2")}}},
        {{"e", %{"k" => "v"}}, {"e" <> <<1::32>> <> lp32("k") <> lp32("v"), %{}}},
        {{"e", %{"k" => ""}}, {"e", %{"k" => <<0, 0, 0, 0, 0, 0, 0, 0>>}}}
      ]

      for {{e1, v1}, {e2, v2}} <- pairs do
        token = Signer.sign(ctx, e1, v1)

        refute token == Signer.sign(ctx, e2, v2),
               "tokens collide for #{inspect({e1, v1})} / #{inspect({e2, v2})}"

        # Tokens list the keys they cover, so splice the MAC under the other key list too.
        forged = "#{v2 |> Map.keys() |> Enum.sort() |> Enum.join(",")}.#{mac_part(token)}"
        refute ok?(ctx, e2, Map.put(v2, "__sig", forged), :allow)
        refute ok?(ctx, e2, Map.put(v2, "__sig", token), :allow)
      end
    end

    property "re-splitting the same bytes into a different event/keys/values never collides" do
      ctx = Context.new()

      check all(
              s <- string(@key_chars, min_length: 1, max_length: 40),
              cuts_a <- list_of(integer(0..byte_size(s)), max_length: 8),
              cuts_b <- list_of(integer(0..byte_size(s)), max_length: 8),
              max_runs: 1000
            ) do
        {ea, va} = split_into_pair(s, cuts_a)
        {eb, vb} = split_into_pair(s, cuts_b)

        if {ea, va} != {eb, vb} do
          token = Signer.sign(ctx, ea, va)
          refute token == Signer.sign(ctx, eb, vb)
          forged = "#{vb |> Map.keys() |> Enum.sort() |> Enum.join(",")}.#{mac_part(token)}"
          refute ok?(ctx, eb, Map.put(vb, "__sig", forged), :allow)
        end
      end
    end

    defp split_into_pair(s, cuts) do
      cuts = Enum.sort(cuts)
      cuts = if rem(length(cuts), 2) == 1, do: tl(cuts), else: cuts
      bounds = [0 | cuts] ++ [byte_size(s)]

      [event | rest] =
        bounds
        |> Enum.chunk_every(2, 1, :discard)
        |> Enum.map(fn [a, b] -> binary_part(s, a, b - a) end)

      values =
        rest
        |> Enum.chunk_every(2)
        |> Enum.reject(fn [k, _] -> k == "" end)
        |> Map.new(fn [k, v] -> {k, v} end)

      {event, values}
    end
  end

  describe "token malleability (exactly one valid spelling)" do
    test "every single-byte substitution, insertion and deletion (all 256 byte values) is rejected" do
      ctx = Context.new()
      values = %{"id" => "7", "scope" => "mine", "Z-9_" => ""}
      token = Signer.sign(ctx, "archive", values)
      assert ok?(ctx, "archive", Map.put(values, "__sig", token))

      for i <- 0..(byte_size(token) - 1), b <- 0..255, b != :binary.at(token, i) do
        refute ok?(ctx, "archive", Map.put(values, "__sig", splice(token, i, 1, <<b>>)), :allow)
      end

      for i <- 0..byte_size(token), b <- 0..255 do
        refute ok?(ctx, "archive", Map.put(values, "__sig", splice(token, i, 0, <<b>>)), :allow)
      end

      for i <- 0..(byte_size(token) - 1) do
        refute ok?(ctx, "archive", Map.put(values, "__sig", splice(token, i, 1, "")), :allow)
      end
    end

    test "for any MAC, exactly one of the 64 possible last characters verifies" do
      ctx = Context.new()
      alphabet = ~c"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

      for i <- 1..100 do
        values = %{"id" => "#{i}"}
        token = Signer.sign(ctx, "e", values)
        prefix = binary_part(token, 0, byte_size(token) - 1)

        accepted =
          for c <- alphabet, ok?(ctx, "e", Map.put(values, "__sig", prefix <> <<c>>)), do: c

        assert accepted == [:binary.last(token)]
      end
    end

    test "alternative spellings of a valid token are all malformed" do
      ctx = Context.new()
      values = %{"a" => "1", "b" => "2"}
      token = Signer.sign(ctx, "e", values)
      "a,b." <> mac = token
      std_mac = mac |> String.replace("-", "+") |> String.replace("_", "/")

      spellings = [
        token <> "==",
        token <> "=",
        "a,b." <> mac <> "\n",
        " " <> token,
        token <> " ",
        "a, b." <> mac,
        "a,b ." <> mac,
        "a,b.." <> mac,
        "a,b." <> mac <> ".",
        "a,b,." <> mac,
        ",a,b." <> mac,
        "a,,b." <> mac,
        "b,a." <> mac,
        "a,a,b." <> mac,
        "A,b." <> mac,
        "a,B." <> mac,
        "ａ,b." <> mac,
        "a\0,b." <> mac,
        "a\n,b." <> mac,
        "a,b\n." <> mac,
        "a%2Cb." <> mac,
        "a;b." <> mac,
        "a,b:" <> mac,
        "a,b." <> String.upcase(mac),
        "a,b." <> String.downcase(mac),
        "a,b." <> Base.encode16(Base.url_decode64!(mac, padding: false)),
        "a,b." <> Base.url_encode64(Base.url_decode64!(mac, padding: false), padding: true),
        "a,b." <> mac <> "A",
        "a,b." <> binary_part(mac, 0, 21)
      ]

      spellings =
        if std_mac != mac, do: ["a,b." <> std_mac | spellings], else: spellings

      for spelling <- spellings, spelling != token do
        refute ok?(ctx, "e", Map.put(values, "__sig", spelling), :allow),
               "#{inspect(spelling)} verified"
      end
    end

    test "key lists: boundaries and characters outside the key alphabet" do
      ctx = Context.new()
      mac = Base.url_encode64(:crypto.strong_rand_bytes(16), padding: false)

      malformed = [
        String.duplicate("k", 65),
        "a.b",
        "a b",
        "é",
        "a/b",
        "a+b",
        "a=b",
        "a\0",
        "a\n",
        "\na",
        "a\r",
        "[a]",
        "a[]"
      ]

      for key <- malformed do
        assert {:error, :malformed_signature} =
                 verify(ctx, "e", %{key => "1", "__sig" => key <> "." <> mac}, :allow),
               "#{inspect(key)} wasn't rejected as malformed"
      end

      # 33 strictly ascending valid keys
      keys = for i <- 1..33, do: "k" <> String.pad_leading("#{i}", 2, "0")
      params = Map.new(keys, &{&1, "1"}) |> Map.put("__sig", Enum.join(keys, ",") <> "." <> mac)
      assert {:error, :malformed_signature} = verify(ctx, "e", params, :allow)

      # 64 bytes is fine (and then only the MAC is wrong)
      k64 = String.duplicate("k", 64)

      assert {:error, :invalid_signature} =
               verify(ctx, "e", %{k64 => "1", "__sig" => k64 <> "." <> mac})
    end
  end

  describe "params that aren't what the signer expects" do
    test "signed values that come back as any non-string term are rejected" do
      ctx = Context.new()
      p = signed(ctx, "e", %{"id" => "7"})

      for bad <- [
            7,
            7.0,
            -0.0,
            nil,
            true,
            false,
            [],
            ["7"],
            [?7],
            %{},
            %{"id" => "7"},
            %{"" => "7"},
            {"7"},
            :"7"
          ] do
        assert {:error, :invalid_signature} = verify(ctx, "e", %{p | "id" => bad}, :allow)
      end
    end

    test "a valid token arriving as a non-string (list, map, number) is malformed" do
      ctx = Context.new()
      p = signed(ctx, "e", %{"id" => "7"})

      for bad <- [
            [p["__sig"]],
            %{"0" => p["__sig"]},
            1,
            nil,
            true,
            String.to_charlist(p["__sig"])
          ] do
        assert {:error, :malformed_signature} = verify(ctx, "e", %{p | "__sig" => bad}, :allow)
      end
    end

    test "NFC and NFD spellings of a signed value are different values" do
      ctx = Context.new()
      nfc = :unicode.characters_to_nfc_binary("café-Å")
      nfd = :unicode.characters_to_nfd_binary("café-Å")
      refute nfc == nfd

      p = signed(ctx, "e", %{"name" => nfc})
      assert :ok = verify(ctx, "e", p)
      assert {:error, :invalid_signature} = verify(ctx, "e", %{p | "name" => nfd})
      # and the other way around for the event name
      p = signed(ctx, nfc, %{})
      assert {:error, :invalid_signature} = verify(ctx, nfd, p)
    end

    test "NUL bytes, invalid UTF-8 and lookalikes are compared byte for byte" do
      ctx = Context.new()

      for {signed_v, sent_v} <- [
            {"7", "7\0"},
            {"7", "\0" <> "7"},
            {"7", "７"},
            {"7", " 7"},
            {"7", "7 "},
            {<<255>>, "�"},
            {"admin", "ADMIN"},
            {"1", "01"},
            {"1", "1.0"}
          ] do
        p = signed(ctx, "e", %{"id" => signed_v})
        assert {:error, :invalid_signature} = verify(ctx, "e", %{p | "id" => sent_v}, :allow)
      end
    end

    test "urlencoded (form) payloads: nested and list shapes can't stand in for signed strings" do
      ctx = Context.new()
      token = Signer.sign(ctx, "save", %{"id" => "99"})
      enc = URI.encode_www_form(token)

      for query <- [
            "id[]=99&__sig=#{enc}",
            "id[x]=99&__sig=#{enc}",
            "id=99&id[]=100&__sig=#{enc}",
            "id=99&id=100&__sig=#{enc}",
            "id=99&__sig[]=#{enc}",
            "id=99&__sig[a]=#{enc}",
            "id=99&__sig=#{enc}&__sig[]=#{enc}",
            "id=99%00&__sig=#{enc}",
            "ID=99&__sig=#{enc}",
            "__sig=#{enc}"
          ] do
        params = Query.decode(query)
        refute ok?(ctx, "save", params, :allow), "#{query} -> #{inspect(params)} verified"
      end

      # Duplicates resolve to the last value, and that's what gets verified and handled.
      assert :ok = verify(ctx, "save", Query.decode("id=1&id=99&__sig=#{enc}"), :deny)
    end

    test ~S(the empty-DOM-value exemption covers exactly `"value" => ""` and `=> 0`) do
      ctx = Context.new()
      p = signed(ctx, "e", %{"id" => "7"})
      assert :ok = verify(ctx, "e", Map.put(p, "value", ""))
      # <li>/<meter>/<progress> send the number 0 (round 2, on purpose)
      assert :ok = verify(ctx, "e", Map.put(p, "value", 0))

      for bad <- [" ", "\0", nil, [], [""], [0], %{}, %{"" => ""}, 0.0, -0.0, 1, -1, false, "0"] do
        assert {:error, {:unsigned_params, ["value"]}} =
                 verify(ctx, "e", Map.put(p, "value", bad))
      end

      for key <- ["Value", "VALUE", "value ", " value", "value\0", "values", "phx-value-value"] do
        assert {:error, {:unsigned_params, [^key]}} = verify(ctx, "e", Map.put(p, key, ""))
      end
    end
  end

  describe "verify/4 never raises on attacker-controlled input" do
    property "arbitrary terms as params, event and token" do
      ctx = Context.new()

      check all(
              params <- small_term(),
              event <- one_of([binary(), small_term()]),
              token <-
                one_of([
                  small_term(),
                  binary(max_length: 80),
                  string(@key_chars ++ [?., ?,, ?=], max_length: 80)
                ]),
              policy <- member_of(@policies),
              max_runs: 1000
            ) do
        params =
          if is_map(params) and not is_struct(params),
            do: Map.put(params, "__sig", token),
            else: params

        result = never_raises(fn -> verify(ctx, event, params, policy) end)
        assert match?({:error, _}, result)
      end
    end

    property "JSON/urlencoded-shaped params around a real token" do
      ctx = Context.new()

      check all(
              event <- member_of(["save", "delete", ""]),
              values <- values_gen(string(:printable, max_length: 10)),
              extra <-
                loose_map(
                  one_of([
                    key_gen(),
                    string(:utf8, max_length: 8),
                    constant("value"),
                    constant("__sig")
                  ]),
                  json_gen(),
                  6
                ),
              overwrite <-
                loose_map(member_of(Map.keys(values) ++ ["__sig", "x"]), json_gen(), 3),
              policy <- member_of(@policies),
              max_runs: 1000
            ) do
        params = signed(ctx, event, values) |> Map.merge(extra) |> Map.merge(overwrite)
        result = never_raises(fn -> verify(ctx, event, params, policy) end)
        assert result == :ok or match?({:error, _}, result)
      end
    end

    property "random urlencoded bodies through Plug's decoder" do
      ctx = Context.new()
      token = Signer.sign(ctx, "save", %{"id" => "1"})

      piece =
        one_of([
          string(@key_chars, max_length: 4),
          member_of([
            "[",
            "]",
            "[]",
            "=",
            "&",
            "%",
            "%00",
            "__sig",
            "id",
            URI.encode_www_form(token)
          ])
        ])

      check all(
              parts <- list_of(piece, max_length: 20),
              policy <- member_of(@policies),
              max_runs: 1000
            ) do
        query = Enum.join(parts)

        case (try do
                {:ok, Query.decode(query)}
              rescue
                _ -> :decoder_rejected
              end) do
          {:ok, params} -> never_raises(fn -> verify(ctx, "save", params, policy) end)
          :decoder_rejected -> :ok
        end
      end
    end

    test "no context, a context-less socket, or a non-map payload" do
      for ctx <- [nil, %{}, "key", %{key: "k"}],
          params <- [%{"__sig" => "a.b"}, nil, [], "x"] do
        assert {:error, reason} = never_raises(fn -> verify(ctx, "e", params) end)
        assert reason in [:no_context, :missing_signature]
      end
    end
  end

  describe "the security claim, checked against a reference model" do
    # The claim: a declared event passes iff the token was issued by this
    # context for this exact event, every key it covers arrived with exactly the
    # signed string, and every other param is allowed by the policy (or is
    # `"value" => ""`).
    defp model_ok?(issued, event, params, policy) do
      with %{"__sig" => token} when is_binary(token) <- params,
           {:ok, candidates} <- Map.fetch(issued, token) do
        Enum.any?(candidates, fn {e, v} ->
          e == event and Enum.all?(v, fn {k, val} -> Map.fetch(params, k) == {:ok, val} end) and
            Enum.all?(params, fn {k, val} ->
              k == "__sig" or Map.has_key?(v, k) or policy == :allow or
                (is_list(policy) and k in policy) or
                (k == "value" and (val === "" or val === 0))
            end)
        end)
      else
        _ -> false
      end
    end

    property "verify/4 agrees with the model on mixed-and-matched tokens and values" do
      small_key = member_of(["a", "b", "id", "value", "key", "scope"])
      small_val = member_of(["", "1", "2", "x"])
      evil_val = one_of([small_val, member_of([0, 0.0, 1, nil, ["1"], %{"a" => "1"}, true])])
      event = member_of(["save", "delete", "x"])

      check all(
              issued_list <-
                list_of(tuple({event, loose_map(small_key, small_val, 4)}),
                  min_length: 1,
                  max_length: 6
                ),
              ctx = Context.new(),
              issued = Enum.group_by(issued_list, fn {e, v} -> Signer.sign(ctx, e, v) end),
              tokens = Map.keys(issued),
              token <-
                one_of([
                  member_of(tokens),
                  map(member_of(tokens), &splice(&1, 0, 0, "a,")),
                  binary(max_length: 30)
                ]),
              {_, base} <- member_of(issued_list),
              drop <- list_of(small_key, max_length: 2),
              add <- loose_map(small_key, evil_val, 3),
              sent_event <- event,
              policy <- member_of(@policies),
              max_runs: 3000
            ) do
        params = base |> Map.drop(drop) |> Map.merge(add) |> Map.put("__sig", token)

        assert verify(ctx, sent_event, params, policy) == :ok ==
                 model_ok?(issued, sent_event, params, policy),
               "disagreement for #{inspect({sent_event, params, policy})}, issued #{inspect(issued_list)}"
      end
    end

    property "any single mutation of a signed payload is rejected (:deny)" do
      ctx = Context.new()

      check all(
              event <- string(:printable, max_length: 16),
              values <- values_gen(string(:printable, max_length: 16)),
              mutation <-
                member_of([:event, :value, :drop, :add, :rename, :swap_token, :foreign_ctx]),
              noise <- string(:printable, min_length: 1, max_length: 8),
              new_key <- key_gen(),
              max_runs: 1500
            ) do
        params = signed(ctx, event, values)
        keys = Map.keys(values)

        mutated =
          case {mutation, keys} do
            {:event, _} ->
              {event <> noise, params}

            {:value, [k | _]} ->
              {event, Map.update!(params, k, &(&1 <> noise))}

            {:drop, [k | _]} ->
              {event, Map.delete(params, k)}

            {:add, _} when new_key in ["value"] ->
              {event, Map.put(params, "value", noise)}

            {:add, _} ->
              if Map.has_key?(values, new_key),
                do: :skip,
                else: {event, Map.put(params, new_key, noise)}

            {:rename, [k | _]} ->
              if Map.has_key?(values, new_key),
                do: :skip,
                else: {event, params |> Map.delete(k) |> Map.put(new_key, values[k])}

            {:swap_token, _} ->
              other = Map.put(values, new_key, noise)

              if other == values,
                do: :skip,
                else: {event, Map.put(params, "__sig", Signer.sign(ctx, event, other))}

            {:foreign_ctx, _} ->
              {event, signed(Context.new(), event, values)}

            {_, []} ->
              :skip
          end

        with {e, p} <- mutated do
          refute verify(ctx, e, p) == :ok, "#{mutation} verified: #{inspect(p)}"
        end
      end
    end
  end

  describe "CPU / memory bounds (measured, generous limits)" do
    defp time_ms(fun) do
      {us, result} = :timer.tc(fun)
      {us / 1000, result}
    end

    test "an oversized token is rejected before it is scanned" do
      ctx = Context.new()
      huge = :binary.copy("a,", 25_000_000) <> "." <> :binary.copy("A", 22)
      {ms, result} = time_ms(fn -> verify(ctx, "e", %{"__sig" => huge}) end)
      assert result == {:error, :malformed_signature}
      assert ms < 50
    end

    test "worst-case token parsing (4096 bytes of separators / short keys) is cheap" do
      ctx = Context.new()

      for token <- [
            String.duplicate(".", 4096),
            String.duplicate(",", 4096),
            String.duplicate("a,", 2048),
            String.duplicate("a,", 2036) <> "a." <> String.duplicate("A", 22)
          ] do
        {ms, result} = time_ms(fn -> verify(ctx, "e", %{"__sig" => token}) end)
        assert {:error, :malformed_signature} = result
        assert ms < 20
      end
    end

    test "MAC cost is linear in payload size (no amplification over decoding it)" do
      ctx = Context.new()
      big = :binary.copy("a", 20_000_000)
      bad = "id." <> String.duplicate("A", 22)
      {ms, result} = time_ms(fn -> verify(ctx, "e", %{"id" => big, "__sig" => bad}) end)
      assert result == {:error, :invalid_signature}
      # ~8 ms measured in development; Jason.decode of the same payload took ~20 ms.
      assert ms < 1_000
    end

    test "a valid token plus 200k unsigned params is rejected in roughly linear time" do
      ctx = Context.new()

      params =
        Map.new(1..200_000, &{"p#{&1}", "v"}) |> Map.merge(signed(ctx, "e", %{"id" => "1"}))

      {ms, result} = time_ms(fn -> verify(ctx, "e", params, ["z1", "z2", "z3"]) end)
      assert {:error, {:unsigned_params, extras}} = result
      # round 2: the reported list is bounded (the names come from the client)
      assert length(extras) == 20
      assert ms < 3_000
    end

    test "deeply nested values cost nothing (verify never walks them)" do
      ctx = Context.new()
      deep = Enum.reduce(1..200_000, "x", fn _, acc -> %{"a" => [acc]} end)
      valid = signed(ctx, "e", %{"id" => "1"})

      for params <- [
            Map.put(valid, "n", deep),
            %{valid | "id" => deep},
            %{valid | "__sig" => deep},
            Map.put(valid, "value", deep)
          ] do
        {ms, result} = time_ms(fn -> verify(ctx, "e", params, :deny) end)
        assert {:error, _} = result
        assert ms < 20
      end
    end
  end

  # Key generation, derivation, rotation and leakage: crypto_key_model_test.exs.
end
