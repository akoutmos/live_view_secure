Application.put_env(:live_view_secure, LiveViewSecure.Test.Endpoint,
  secret_key_base: String.duplicate("s", 64),
  live_view: [signing_salt: "live_view_secure_test"]
)

{:ok, _} = LiveViewSecure.Test.Endpoint.start_link()

# What an app does in its Application.start/2.
:ok = LiveViewSecure.Telemetry.attach_default_logger()

# Tests tagged :known_limitation assert secure behavior the library can't
# provide (documented in the README). Run them with --include known_limitation.
ExUnit.start(exclude: [:known_limitation])
