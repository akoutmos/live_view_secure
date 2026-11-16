defmodule LiveViewSecure.HTMLTest do
  use ExUnit.Case, async: true

  import Phoenix.Component, only: [sigil_H: 2]
  import Phoenix.LiveViewTest, only: [rendered_to_string: 1]
  import LiveViewSecure.HTML

  alias LiveViewSecure.{Context, Signer}
  alias Phoenix.LiveView.JS

  setup do
    {:ok, ctx: Context.new()}
  end

  describe "signed_attrs/4" do
    test "builds phx-click + phx-value-* + one signature", %{ctx: ctx} do
      attrs = signed_attrs(ctx, "delete_user", id: 7, "user-name": "bob")

      assert %{
               "phx-click" => "delete_user",
               "phx-value-id" => "7",
               "phx-value-user-name" => "bob",
               "phx-value-__sig" => "id,user-name." <> _
             } = attrs

      params = %{"id" => "7", "user-name" => "bob", "__sig" => attrs["phx-value-__sig"]}
      assert :ok = Signer.verify(ctx, "delete_user", params, :deny)
    end

    test "supports other bindings and phx-target", %{ctx: ctx} do
      attrs = signed_attrs(ctx, :save, [], binding: "phx-blur", target: "#form")
      assert %{"phx-blur" => "save", "phx-target" => "#form"} = attrs
      refute Map.has_key?(attrs, "phx-click")
    end

    test "renders as HTML attributes", %{ctx: ctx} do
      assigns = %{ctx: ctx}

      html =
        rendered_to_string(~H"""
        <button {signed_attrs(@ctx, "go", id: ~s(a"b<c))}>Go</button>
        """)

      assert html =~ ~s(phx-click="go")
      assert html =~ ~s(phx-value-id="a&quot;b&lt;c")
      assert html =~ ~s(phx-value-__sig="id.)
    end

    test "rejects unknown options", %{ctx: ctx} do
      assert_raise ArgumentError, fn -> signed_attrs(ctx, "go", [], targett: "#x") end
    end
  end

  describe "signed_push" do
    test "signs the :value map and keeps other JS.push options", %{ctx: ctx} do
      %JS{ops: [["push", args]]} = signed_push(ctx, "archive", value: %{id: 7}, target: "#t")

      assert %{event: "archive", target: "#t", value: %{"id" => "7", "__sig" => sig}} = args
      assert :ok = Signer.verify(ctx, "archive", %{"id" => "7", "__sig" => sig}, :deny)
    end

    test "pipes after other JS commands", %{ctx: ctx} do
      %JS{ops: [["hide", _], ["push", %{event: "go"}]]} =
        JS.hide(to: "#row") |> signed_push(ctx, "go")

      %JS{ops: [["hide", _], ["push", %{value: %{"id" => "1"}}]]} =
        JS.hide(to: "#row") |> signed_push(ctx, "go", value: [id: 1])
    end
  end

  describe "signed_inputs/1" do
    test "renders hidden inputs plus the signature", %{ctx: ctx} do
      assigns = %{ctx: ctx}

      html =
        rendered_to_string(~H"""
        <.signed_inputs secure={@ctx} event="save" values={%{id: 99, kind: "post"}} />
        """)

      doc = LazyHTML.from_fragment(html)
      names = doc |> LazyHTML.query("input[type=hidden]") |> LazyHTML.attribute("name")
      values = doc |> LazyHTML.query("input[type=hidden]") |> LazyHTML.attribute("value")
      params = Map.new(Enum.zip(names, values))

      assert names == ["id", "kind", "__sig"]
      assert :ok = Signer.verify(ctx, "save", params, :deny)
    end
  end
end
