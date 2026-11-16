defmodule LiveViewSecure.MixProject do
  use Mix.Project

  @version "0.1.0"

  def project do
    [
      app: :live_view_secure,
      version: @version,
      elixir: "~> 1.15",
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      description: "Tamper-proof phx-click / JS.push / form values for Phoenix LiveView events",
      docs: [main: "LiveViewSecure", extras: ["README.md"]]
    ]
  end

  def application do
    [extra_applications: [:logger, :crypto]]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  defp deps do
    [
      {:phoenix_live_view, "~> 1.0"},
      {:plug_crypto, "~> 2.0"},
      {:telemetry, "~> 1.0"},
      {:jason, "~> 1.4", only: :test},
      {:lazy_html, ">= 0.1.0", only: :test},
      {:stream_data, "~> 1.0", only: :test},
      # A real HTTP + websocket endpoint for the wire-protocol security tests.
      {:bandit, "~> 1.0", only: :test},
      {:websockex, "~> 0.4", only: :test}
    ]
  end
end
