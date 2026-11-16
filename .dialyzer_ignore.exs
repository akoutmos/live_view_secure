[
  # Context.new/3's default `verifies` argument builds an empty MapSet. Elixir
  # compiles that default into a %MapSet{} literal, which OTP 28's Dialyzer
  # reports as breaking MapSet's opacity in the generated new/0 and new/1. Only
  # the defaults are affected; the library always passes `verifies` itself.
  {"lib/live_view_secure/context.ex", :call_without_opaque},
  # signed_push/2-4 return what Phoenix.LiveView.JS.push builds, and are specced
  # with JS.t(), whose ops are opaque. JS.push has no spec, so Dialyzer sees the
  # plain list it builds and reports the JS.t() return as a broken contract.
  {"lib/live_view_secure/html.ex", :contract_with_opaque}
]
