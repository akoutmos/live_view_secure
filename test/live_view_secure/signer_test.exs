defmodule LiveViewSecure.SignerTest do
  use ExUnit.Case, async: true

  alias LiveViewSecure.{Context, Signer}

  setup do
    {:ok, ctx: Context.new()}
  end

  defp params(ctx, event, values) do
    Map.put(values, "__sig", Signer.sign(ctx, event, values))
  end

  describe "verify/4" do
    test "accepts exactly what was signed", %{ctx: ctx} do
      values = %{"id" => "7", "scope" => "mine"}
      assert :ok = Signer.verify(ctx, "archive", params(ctx, "archive", values), :deny)
    end

    test "accepts an event with no values", %{ctx: ctx} do
      assert "." <> _ = token = Signer.sign(ctx, "inc", %{})
      assert :ok = Signer.verify(ctx, "inc", %{"__sig" => token}, :deny)
    end

    test "binds the event name", %{ctx: ctx} do
      p = params(ctx, "view_user", %{"id" => "5"})
      assert {:error, :invalid_signature} = Signer.verify(ctx, "delete_user", p, :deny)
    end

    test "binds every value", %{ctx: ctx} do
      p = params(ctx, "archive", %{"id" => "7", "scope" => "mine"})

      assert {:error, :invalid_signature} =
               Signer.verify(ctx, "archive", %{p | "scope" => "everything"}, :deny)

      assert {:error, :invalid_signature} =
               Signer.verify(ctx, "archive", %{p | "id" => "8"}, :deny)
    end

    test "binds the key", %{ctx: ctx} do
      assert {:error, :invalid_signature} =
               Signer.verify(Context.new(), "x", params(ctx, "x", %{"id" => "1"}), :deny)
    end

    test "reports signed params that were dropped", %{ctx: ctx} do
      p = params(ctx, "archive", %{"id" => "7", "scope" => "mine", "a" => "1"})

      assert {:error, {:missing_params, ["a", "scope"]}} =
               Signer.verify(ctx, "archive", Map.drop(p, ["scope", "a"]), :deny)
    end

    test "signed values that come back as non-strings are rejected, not crashed on", %{ctx: ctx} do
      p = params(ctx, "x", %{"id" => "7"})

      for bad <- [7, nil, true, %{"a" => 1}, ["7"]] do
        assert {:error, :invalid_signature} = Signer.verify(ctx, "x", %{p | "id" => bad}, :deny)
      end
    end

    test "unsigned policy :deny rejects extra params", %{ctx: ctx} do
      p = params(ctx, "x", %{"id" => "7"}) |> Map.merge(%{"b" => "1", "a" => "2"})
      assert {:error, {:unsigned_params, ["a", "b"]}} = Signer.verify(ctx, "x", p, :deny)
    end

    test "unsigned policy :deny tolerates the empty button value only", %{ctx: ctx} do
      p = params(ctx, "x", %{"id" => "7"})
      assert :ok = Signer.verify(ctx, "x", Map.put(p, "value", ""), :deny)

      assert {:error, {:unsigned_params, ["value"]}} =
               Signer.verify(ctx, "x", Map.put(p, "value", "1"), :deny)
    end

    test "unsigned policy list allows just those keys", %{ctx: ctx} do
      p = params(ctx, "x", %{"id" => "7"}) |> Map.merge(%{"key" => "Enter", "evil" => "1"})
      assert {:error, {:unsigned_params, ["evil"]}} = Signer.verify(ctx, "x", p, ["key"])
      assert :ok = Signer.verify(ctx, "x", Map.delete(p, "evil"), ["key"])
    end

    test "unsigned policy :allow still verifies the signed keys", %{ctx: ctx} do
      p = params(ctx, "save", %{"id" => "99"}) |> Map.put("title", "anything")
      assert :ok = Signer.verify(ctx, "save", p, :allow)
      assert {:error, :invalid_signature} = Signer.verify(ctx, "save", %{p | "id" => "1"}, :allow)
    end

    test "missing or malformed tokens", %{ctx: ctx} do
      assert {:error, :missing_signature} = Signer.verify(ctx, "x", %{"id" => "7"}, :deny)
      assert {:error, :missing_signature} = Signer.verify(ctx, "x", "not a map", :deny)
      assert {:error, :no_context} = Signer.verify(nil, "x", %{"__sig" => "a"}, :deny)

      valid_mac =
        ctx |> Signer.sign("x", %{"a" => "1", "b" => "2"}) |> String.split(".") |> List.last()

      for token <- [
            nil,
            123,
            %{},
            "",
            ".",
            "..",
            "a",
            "a.b",
            "a.",
            "a.b.c",
            "a." <> valid_mac <> "x",
            "b,a." <> valid_mac,
            "a,a." <> valid_mac,
            "a,,b." <> valid_mac,
            "a b." <> valid_mac,
            "a.!!!!!!!!!!!!!!!!!!!!!!",
            String.duplicate("a,", 40) <> "a." <> valid_mac,
            String.duplicate("a", 5000) <> "." <> valid_mac
          ] do
        assert {:error, :malformed_signature} =
                 Signer.verify(ctx, "x", %{"a" => "1", "b" => "2", "__sig" => token}, :deny),
               "expected #{inspect(token)} to be malformed"
      end
    end

    test "flipping any single character of a token never verifies", %{ctx: ctx} do
      values = %{"id" => "7", "scope" => "mine"}
      token = Signer.sign(ctx, "archive", values)
      alphabet = ~c"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.,"

      for i <- 0..(byte_size(token) - 1), c <- alphabet, c != :binary.at(token, i) do
        tampered =
          binary_part(token, 0, i) <> <<c>> <> binary_part(token, i + 1, byte_size(token) - i - 1)

        refute Signer.verify(ctx, "archive", Map.put(values, "__sig", tampered), :deny) == :ok
      end
    end

    test "the encoding is unambiguous", %{ctx: ctx} do
      # Same concatenated bytes, different structure.
      refute Signer.sign(ctx, "ab", %{}) == Signer.sign(ctx, "a", %{"b" => ""})
      refute Signer.sign(ctx, "x", %{"a" => "bc"}) == Signer.sign(ctx, "x", %{"ab" => "c"})
    end

    test "tokens are deterministic for a given key (so LiveView diffs stay small)", %{ctx: ctx} do
      assert Signer.sign(ctx, "x", %{"id" => "1"}) == Signer.sign(ctx, "x", %{"id" => "1"})

      refute Signer.sign(ctx, "x", %{"id" => "1"}) ==
               Signer.sign(Context.new(), "x", %{"id" => "1"})
    end

    test "unicode and newlines round-trip", %{ctx: ctx} do
      values = %{"note" => "line one\nline two ✓ 日本"}
      assert :ok = Signer.verify(ctx, "x", params(ctx, "x", values), :deny)
    end
  end

  describe "normalize_values!/2" do
    test "stringifies keys and scalar values" do
      assert %{"id" => "7", "kind" => "admin", "at" => "2026-11-16", "x" => "1.5"} =
               Signer.normalize_values!([id: 7, kind: :admin, at: ~D[2026-11-16], x: 1.5], :attrs)
    end

    test "leaves out nil and false like plain phx-value-*, and refuses true" do
      for channel <- [:attrs, :push, :form] do
        assert %{"id" => "1"} ==
                 Signer.normalize_values!([id: 1, manager_id: nil, archived: false], channel)
      end

      assert_raise ArgumentError, ~r/= true/, fn ->
        Signer.normalize_values!([flag: true], :attrs)
      end
    end

    test "refuses a component's @myself (values not wrapped in a list)" do
      assert_raise ArgumentError, ~r/wrapped in a/, fn ->
        Signer.normalize_values!([item: "a", target: %Phoenix.LiveComponent.CID{cid: 1}], :attrs)
      end
    end

    test "applies the browser's attribute normalization on the HTML channels" do
      for channel <- [:attrs, :form] do
        assert %{"v" => "a\nb\nc\uFFFDd"} =
                 Signer.normalize_values!([v: "a\r\nb\rc" <> <<0>> <> "d"], channel)
      end

      # JSON escapes them, so JS.push values are left alone.
      assert %{"v" => "a\r\nb"} = Signer.normalize_values!([v: "a\r\nb"], :push)
    end

    test "refuses invalid UTF-8" do
      assert_raise ArgumentError, ~r/UTF-8/, fn ->
        Signer.normalize_values!([v: <<0xFF>>], :push)
      end
    end

    test "rejects keys that can't survive the trip" do
      assert_raise ArgumentError, ~r/lowercase/, fn ->
        Signer.normalize_values!([userId: 1], :attrs)
      end

      assert_raise ArgumentError, ~r/overwrites/, fn ->
        Signer.normalize_values!([value: 1], :attrs)
      end

      assert_raise ArgumentError, ~r/reserved/, fn ->
        Signer.normalize_values!(%{"__sig" => 1}, :push)
      end

      assert_raise ArgumentError, ~r/invalid signed key/, fn ->
        Signer.normalize_values!(%{"a.b" => 1}, :push)
      end

      assert_raise ArgumentError, ~r/invalid signed key/, fn ->
        Signer.normalize_values!(%{"post[id]" => 1}, :form)
      end

      assert_raise ArgumentError, ~r/duplicate/, fn ->
        Signer.normalize_values!([id: 1, id: 2], :push)
      end

      assert_raise ArgumentError, ~r/duplicate/, fn ->
        Signer.normalize_values!(%{:id => 1, "id" => 2}, :push)
      end

      # Mixed case and "value" are fine outside of attributes.
      assert %{"userId" => "1", "value" => "2"} =
               Signer.normalize_values!([userId: 1, value: 2], :push)
    end

    test "rejects values that aren't scalars" do
      for bad <- [%{a: 1}, [1, 2], {1, 2}, self(), MapSet.new([1])] do
        assert_raise ArgumentError, fn -> Signer.normalize_values!([id: bad], :push) end
      end
    end

    test "limits the number of signed keys" do
      too_many = for i <- 1..33, do: {"k#{i}", i}

      assert_raise ArgumentError, ~r/at most 32/, fn ->
        Signer.normalize_values!(too_many, :push)
      end
    end
  end

  test "sign/3 explains a missing context" do
    assert_raise ArgumentError, ~r/@live_view_secure/, fn -> Signer.sign(nil, "x", %{}) end
  end

  test "the context never holds its key" do
    ctx = Context.new()
    key = Context.key(ctx)
    assert inspect(ctx) == "#LiveViewSecure.Context<redacted>"
    assert inspect(%{assigns: %{live_view_secure: ctx}}) =~ "redacted"

    # Not even in the raw term: no inspect options, Erlang formatting or
    # serialization can show it.
    for dump <- [
          inspect(ctx, structs: false),
          :io_lib.format(~c"~p", [ctx]) |> IO.iodata_to_binary(),
          :erlang.term_to_binary(ctx)
        ] do
      refute :binary.match(dump, key) != :nomatch
      refute dump =~ Base.encode16(key)
      refute dump =~ Base.encode16(key, case: :lower)
    end
  end

  test "a context only signs in the process that created it" do
    ctx = Context.new()

    parent = self()

    spawn(fn ->
      result =
        try do
          Signer.sign(ctx, "x", %{})
        rescue
          error -> error
        end

      send(parent, {:result, result})
    end)

    assert_receive {:result, %ArgumentError{message: message}}
    assert message =~ "only works in the LiveView process that created it"
  end
end
