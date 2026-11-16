defmodule LiveViewSecure.Test.Endpoint do
  use Phoenix.Endpoint, otp_app: :live_view_secure

  socket("/live", Phoenix.LiveView.Socket)
end
