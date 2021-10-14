defmodule LiveViewSecure do
  @moduledoc """
  This library provides a way to securely sign Phoenix LiveView events and
  values associated with those events. The problem that this library solves
  is that with LiveView, you can modify the HTML attributes and invoke events
  and populate parameters that the application did not produce. This can be
  a security concern as you may be working with data that you did not intend
  in your handle_event functions.

  Under the hood, LiveViewSecure uses HMAC hashes to ensure that the data
  was signed has not been tampered with by the client when it makes its way
  to the backend.

  ## Example usage

  ### LiveView Module
  ```elixir
  secure_handle_event("delete_user", fn %{"user-id" => user_id}, socket ->
    socket =
      user_id
      |> Users.delete_user(user_id)
      |> case do
        {:ok, %User{} = user} ->
          all_users = Users.list_users()
          assign(socket, all_users: all_users)

        error ->
          Logger.warning("Failed to delete user with ID #{inspect(user_id)}")

          socket
      end

    {:noreply, socket}
  end)
  ```

  ### LiveView template
  ```html
  <%= for user <- @all_users do %>
    <div>
      <%= user.first_name %> <%= user.last_name %>
      <button
        phx-click="<%= sign_event(@socket, "delete_user") %>"
        phx-value-user-id="<%= sign_phx_value(@socket, "user-id", user.id) %>"
      >
        <%= gettext "Delete user" %>
      </button>
    </div>
  <% end %>
  ```
  """

  # TODO: Replace with a configurable key
  @dummy_key "abcd1234"

  def sign_event(socket, event) do
    hmac =
      :hmac
      |> :crypto.mac(:sha256, @dummy_key, "#{socket.id}:#{event}")
      |> Base.encode16()

    "#{event}:#{hmac}"
  end

  def sign_phx_value(socket, key, value) do
    hmac =
      :hmac
      |> :crypto.mac(:sha256, @dummy_key, "#{socket.id}:#{key}:#{value}")
      |> Base.encode16()

    "#{value}::::#{hmac}"
  end

  defmacro secure_handle_event(event, handler) do
    quote do
      @impl true
      def handle_event(unquote(event), _params, _socket) do
        LiveViewSecure.raise_event_error(unquote(event))
      end

      def handle_event("#{unquote(event)}:" <> hmac_hash, params, socket) do
        with true <- LiveViewSecure.valid_signature?(socket, unquote(event), hmac_hash),
             {:ok, verified_params} <-
               LiveViewSecure.verify_params(socket, unquote(event), params) do
          unquote(handler).(verified_params, socket)
        else
          false ->
            LiveViewSecure.raise_event_error(unquote(event))
        end
      end
    end
  end

  # ---- Internal library functions ----

  @doc false
  def valid_signature?(socket, value, hmac) do
    socket
    |> sign_event(value)
    |> Plug.Crypto.secure_compare("#{value}:#{hmac}")
  end

  @doc false
  def verify_params(socket, event, params) do
    verified_params =
      params
      |> Enum.map(fn {key, value} ->
        with %{"hmac" => hmac, "value" => value} <-
               Regex.named_captures(~r/(?<value>.*)::::(?<hmac>.*)/, value),
             {:ok, verified_value} <- verify_param(socket, key, value, hmac) do
          {key, verified_value}
        else
          _ ->
            raise_params_error(event, key)
        end
      end)
      |> Map.new()

    {:ok, verified_params}
  end

  @doc false
  def verify_param(socket, key, value, hmac) do
    valid_param =
      socket
      |> sign_phx_value(key, value)
      |> Plug.Crypto.secure_compare("#{value}::::#{hmac}")

    if valid_param do
      {:ok, value}
    else
      :error
    end
  end

  @doc false
  def raise_event_error(event) do
    raise """
    The handle_event callback #{event} was marked as secure and was attempted to be called
    in an insecure fashion. Ensure that your LiveView template makes use of the
    gen_signature/2 function. If you already make use of gen_signature/2, then it is
    fair to assume that someone is attempting to probe at your application.
    """
  end

  @doc false
  def raise_params_error(event, key) do
    raise """
    The handle_event callback #{event} was marked as secure and was attempted to be called
    in an insecure fashion by way of the phx-value "#{key}". Please make sure that you call
    sign_phx_value/3 on all signed event values. If you already make use of sign_phx_value/2,
    then it is fair to assume that someone is attempting to probe at your application.
    """
  end
end
