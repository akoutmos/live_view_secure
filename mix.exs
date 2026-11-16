defmodule LiveViewSecure.MixProject do
  use Mix.Project

  @version "0.1.0"
  @source_url "https://github.com/akoutmos/live_view_secure"

  def project do
    [
      app: :live_view_secure,
      version: @version,
      elixir: "~> 1.15",
      elixirc_paths: elixirc_paths(Mix.env()),
      name: "LiveViewSecure",
      source_url: @source_url,
      homepage_url: "https://hex.pm/packages/live_view_secure",
      description: "Tamper-proof phx-click / JS.push / form values for Phoenix LiveView events",
      start_permanent: Mix.env() == :prod,
      package: package(),
      deps: deps(),
      docs: docs()
    ]
  end

  def application do
    [extra_applications: [:logger, :crypto]]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  defp package do
    [
      files: ~w(lib mix.exs .formatter.exs README.md SECURITY.md CHANGELOG.md LICENSE),
      licenses: ["MIT"],
      maintainers: ["Alex Koutmos"],
      links: %{
        "GitHub" => @source_url,
        "Sponsor" => "https://github.com/sponsors/akoutmos"
      }
    ]
  end

  defp docs do
    [
      main: "readme",
      # Releases are tagged with their version, such as 0.1.0
      source_ref: @version,
      extras: ["README.md", "SECURITY.md", "CHANGELOG.md"]
    ]
  end

  defp deps do
    [
      # The test suite's raw-websocket harness needs LiveView 1.1's diff format.
      {:phoenix_live_view, "~> 1.1"},
      {:plug_crypto, "~> 2.0"},
      {:telemetry, "~> 1.0"},
      {:ex_doc, "~> 0.40", only: :dev, runtime: false},
      {:jason, "~> 1.4", only: :test},
      {:lazy_html, ">= 0.1.0", only: :test},
      {:stream_data, "~> 1.0", only: :test},
      # A real HTTP + websocket endpoint for the wire-protocol security tests.
      {:bandit, "~> 1.0", only: :test},
      {:websockex, "~> 0.4", only: :test}
    ]
  end
end
