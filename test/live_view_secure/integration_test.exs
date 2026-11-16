defmodule LiveViewSecure.IntegrationTest do
  # Telemetry handlers are global, so keep these synchronous.
  use ExUnit.Case, async: false

  import Phoenix.ConnTest
  import Phoenix.LiveViewTest

  alias LiveViewSecure.Test.{CartLive, StrictLive, UsersLive}

  @endpoint LiveViewSecure.Test.Endpoint
  @moduletag :capture_log

  setup do
    test_pid = self()
    handler_id = {__MODULE__, make_ref()}

    :telemetry.attach(
      handler_id,
      [:live_view_secure, :event, :rejected],
      fn _event, _measurements, meta, _ ->
        send(test_pid, {:rejected, meta.event, meta.reason})
      end,
      nil
    )

    on_exit(fn -> :telemetry.detach(handler_id) end)
    Process.flag(:trap_exit, true)

    {:ok, conn: build_conn()}
  end

  # Pushes a raw event the way a malicious client would and asserts that
  # LiveViewSecure rejected it (and so crashed the LiveView before the handler ran).
  defp assert_rejected(view, event, params, reason) do
    assert {{%LiveViewSecure.InvalidEventError{event: ^event, reason: ^reason}, _}, _} =
             catch_exit(render_click(view, event, params))

    assert_received {:rejected, ^event, ^reason}
  end

  defp attr(view, selector, name) do
    [value] =
      view
      |> element(selector)
      |> render()
      |> LazyHTML.from_fragment()
      |> LazyHTML.attribute(name)

    value
  end

  defp sig(view, selector), do: attr(view, selector, "phx-value-__sig")

  defp pushed_value(view, selector) do
    [["push", %{"value" => value}]] = view |> attr(selector, "phx-click") |> Jason.decode!()
    value
  end

  describe "signed phx-click" do
    test "the rendered buttons work", %{conn: conn} do
      {:ok, view, _html} = live_isolated(conn, UsersLive)

      view |> element("#view-5") |> render_click()
      html = view |> element("#delete-7") |> render_click()

      assert html =~ "viewed 5"
      assert html =~ "deleted 7"
      refute_received {:rejected, _, _}
    end

    test "renders one token over event + values", %{conn: conn} do
      {:ok, view, _html} = live_isolated(conn, UsersLive)

      assert attr(view, "#delete-7", "phx-click") == "delete_user"
      assert attr(view, "#delete-7", "phx-value-id") == "7"
      assert "id." <> _mac = sig(view, "#delete-7")
    end

    test "an unsigned push is rejected", %{conn: conn} do
      {:ok, view, _html} = live_isolated(conn, UsersLive)
      assert_rejected(view, "delete_user", %{"id" => "7"}, :missing_signature)
    end

    test "garbage in __sig is rejected", %{conn: conn} do
      {:ok, view, _html} = live_isolated(conn, UsersLive)

      assert_rejected(
        view,
        "delete_user",
        %{"id" => "7", "__sig" => "nope"},
        :malformed_signature
      )
    end

    test "PoC attack: a value signed for one event can't be replayed into another", %{conn: conn} do
      # Ann (5) only has a *view* button. Take its signed id and send it as a delete.
      {:ok, view, _html} = live_isolated(conn, UsersLive)
      view_5 = sig(view, "#view-5")

      assert_rejected(view, "delete_user", %{"id" => "5", "__sig" => view_5}, :invalid_signature)
    end

    test "PoC attack: a signature can't be moved to another row's values", %{conn: conn} do
      # Use Bob's (7) delete signature with Ann's id.
      {:ok, view, _html} = live_isolated(conn, UsersLive)
      delete_7 = sig(view, "#delete-7")

      assert_rejected(
        view,
        "delete_user",
        %{"id" => "5", "__sig" => delete_7},
        :invalid_signature
      )
    end

    test "params that weren't signed are rejected", %{conn: conn} do
      {:ok, view, _html} = live_isolated(conn, UsersLive)
      params = %{"id" => "7", "__sig" => sig(view, "#delete-7"), "force" => "true"}

      assert_rejected(view, "delete_user", params, {:unsigned_params, ["force"]})
    end

    test "the empty value browsers send with every <button> click is allowed", %{conn: conn} do
      {:ok, view, _html} = live_isolated(conn, UsersLive)
      params = %{"id" => "7", "__sig" => sig(view, "#delete-7"), "value" => ""}

      assert render_click(view, "delete_user", params) =~ "deleted 7"
    end

    test "a non-empty unsigned value is not", %{conn: conn} do
      {:ok, view, _html} = live_isolated(conn, UsersLive)
      params = %{"id" => "7", "__sig" => sig(view, "#delete-7"), "value" => "5"}

      assert_rejected(view, "delete_user", params, {:unsigned_params, ["value"]})
    end

    test "events that aren't declared pass through untouched", %{conn: conn} do
      {:ok, view, _html} = live_isolated(conn, UsersLive)
      assert view |> element("#demote") |> render_click() =~ "demoted"
    end
  end

  describe "signed JS.push" do
    test "works when clicked", %{conn: conn} do
      {:ok, view, _html} = live_isolated(conn, UsersLive)
      assert view |> element("#archive-7") |> render_click() =~ "archived 7 scope=mine"
    end

    test "values are stringified and signed together", %{conn: conn} do
      {:ok, view, _html} = live_isolated(conn, UsersLive)

      assert %{"id" => "7", "scope" => "mine", "__sig" => "id,scope." <> _} =
               pushed_value(view, "#archive-7")
    end

    test "PoC attack: dropping a signed param (to fall back to a default) is rejected",
         %{conn: conn} do
      {:ok, view, _html} = live_isolated(conn, UsersLive)
      params = view |> pushed_value("#archive-7") |> Map.delete("scope")

      assert_rejected(view, "archive", params, {:missing_params, ["scope"]})
    end

    test "changing a signed param is rejected", %{conn: conn} do
      {:ok, view, _html} = live_isolated(conn, UsersLive)
      params = view |> pushed_value("#archive-7") |> Map.put("scope", "everything")

      assert_rejected(view, "archive", params, :invalid_signature)
    end
  end

  describe "signed form inputs" do
    test "submits with the signed hidden id and free user input", %{conn: conn} do
      {:ok, view, _html} = live_isolated(conn, UsersLive)

      html = view |> form("#post-form", %{"title" => "Hello"}) |> render_submit()
      assert html =~ "saved 99 title=Hello"
    end

    test "tampering with the hidden id is rejected", %{conn: conn} do
      {:ok, view, _html} = live_isolated(conn, UsersLive)
      token = attr(view, "#post-form input[name=__sig]", "value")
      params = %{"id" => "100", "__sig" => token, "title" => "Hello"}

      assert {{%LiveViewSecure.InvalidEventError{reason: :invalid_signature}, _}, _} =
               catch_exit(render_submit(view, "save", params))
    end
  end

  describe "token lifetime" do
    test "rotate/1 revokes tokens that were already rendered", %{conn: conn} do
      {:ok, view, _html} = live_isolated(conn, UsersLive)
      old_delete_7 = sig(view, "#delete-7")
      old_view_5 = sig(view, "#view-5")

      view |> element("#demote") |> render_click()

      # The delete button is gone and the view button was re-rendered with a fresh token.
      refute has_element?(view, "#delete-7")
      assert sig(view, "#view-5") != old_view_5
      assert view |> element("#view-5") |> render_click() =~ "viewed 5"

      # A saved copy of the old delete button no longer verifies. One rotation
      # back it's recognized as :revoked and dropped (never raised: a click in
      # flight during the rotation looks the same).
      html = render_click(view, "delete_user", %{"id" => "7", "__sig" => old_delete_7})
      refute html =~ "deleted 7"
      assert_received {:rejected, "delete_user", :revoked}

      # Two rotations back it's just an invalid signature, and :raise applies.
      view |> element("#demote") |> render_click()

      assert_rejected(
        view,
        "delete_user",
        %{"id" => "7", "__sig" => old_delete_7},
        :invalid_signature
      )
    end

    test "tokens from another LiveView process don't verify", %{conn: conn} do
      {:ok, view_a, _html} = live_isolated(conn, UsersLive)
      {:ok, view_b, _html} = live_isolated(conn, UsersLive)

      # Same page, same user, but a different process (another tab, a reconnect,
      # or the disconnected render) means a different key.
      params = %{"id" => "7", "__sig" => sig(view_a, "#delete-7")}
      assert_rejected(view_b, "delete_user", params, :invalid_signature)
    end
  end

  describe "events: :all with on_failure: :halt" do
    test "signed events work, everything else is dropped", %{conn: conn} do
      {:ok, view, _html} = live_isolated(conn, StrictLive)

      view |> element("#inc") |> render_click()
      assert view |> element("#count") |> render() =~ ">1<"

      # Halted: the LiveView keeps running and the handlers never ran.
      render_click(view, "inc", %{"by" => "50"})
      assert_received {:rejected, "inc", :missing_signature}

      render_click(view, "anything", %{})
      assert_received {:rejected, "anything", :missing_signature}

      assert view |> element("#count") |> render() =~ ">1<"
    end

    test "events listed in :except aren't verified", %{conn: conn} do
      {:ok, view, _html} = live_isolated(conn, StrictLive)
      render_click(view, "validate", %{})

      assert view |> element("#count") |> render() =~ ">100<"
      refute_received {:rejected, _, _}
    end
  end

  describe "LiveComponents" do
    test "attach/2 in mount verifies events targeted at the component", %{conn: conn} do
      {:ok, view, _html} = live_isolated(conn, CartLive)

      view |> element("#remove-a") |> render_click()
      assert view |> element("#removed") |> render() =~ ">a<"
    end

    test "a component's signature can't be reused for another value", %{conn: conn} do
      {:ok, view, _html} = live_isolated(conn, CartLive)

      assert {{%LiveViewSecure.InvalidEventError{event: "remove", reason: :invalid_signature}, _},
              _} =
               catch_exit(view |> element("#remove-b") |> render_click(%{"item" => "z"}))
    end
  end
end
