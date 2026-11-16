defmodule LiveViewSecure.MixProject do
  use Mix.Project

  @version "0.1.0"
  @source_url "https://github.com/akoutmos/live_view_secure"

  def project do
    [
      app: :live_view_secure,
      version: @version,
      elixir: "~> 1.18",
      elixirc_paths: elixirc_paths(Mix.env()),
      name: "LiveViewSecure",
      source_url: @source_url,
      homepage_url: "https://hex.pm/packages/live_view_secure",
      description: "Tamper-proof phx-click / JS.push / form values for Phoenix LiveView events",
      start_permanent: Mix.env() == :prod,
      package: package(),
      deps: deps(),
      docs: docs(),
      dialyzer: dialyzer()
    ]
  end

  def application do
    [extra_applications: [:logger, :crypto]]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  defp package do
    [
      # hex.pm shows the README from the package, so the images it references are packaged too.
      files: ~w(lib images mix.exs .formatter.exs README.md SECURITY.md CHANGELOG.md LICENSE),
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
      # The README references its images as images/..., which works on GitHub, hex.pm and in the docs
      assets: %{"images" => "images"},
      extras: ["README.md", "SECURITY.md", "CHANGELOG.md"]
    ]
  end

  defp dialyzer do
    [
      plt_file: {:no_warn, "priv/plts/dialyzer.plt"},
      # Some entries only apply to some OTP versions, so unused ones aren't an error.
      ignore_warnings: ".dialyzer_ignore.exs"
    ]
  end

  defp deps do
    [
      # The test suite's raw-websocket harness needs LiveView 1.1's diff format.
      {:phoenix_live_view, "~> 1.1"},
      {:plug_crypto, "~> 2.0"},
      {:telemetry, "~> 1.0"},
      {:ex_doc, "~> 0.40", only: :dev, runtime: false},
      {:credo, "~> 1.7", only: :dev, runtime: false},
      {:doctor, "~> 0.23", only: :dev, runtime: false},
      {:dialyxir, "~> 1.4", only: :dev, runtime: false},
      {:jason, "~> 1.4", only: [:dev, :test]},
      {:lazy_html, ">= 0.1.0", only: :test},
      {:stream_data, "~> 1.0", only: :test},
      # A real HTTP + websocket endpoint for the wire-protocol security tests.
      {:bandit, "~> 1.0", only: :test},
      {:websockex, "~> 0.4", only: :test}
    ]
  end
end
