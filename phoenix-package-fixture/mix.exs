defmodule BmsclPhoenixFixture.MixProject do
  use Mix.Project

  def project do
    [
      app: :bmscl_phoenix_fixture,
      version: "0.1.0",
      elixir: "~> 1.18",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      releases: [
        bmscl_phoenix_fixture: [
          include_executables_for: [:unix]
        ]
      ]
    ]
  end

  def application do
    [
      mod: {BmsclPhoenixFixture.Application, []},
      extra_applications: [:logger]
    ]
  end

  defp deps do
    [
      {:phoenix, "~> 1.8"},
      {:phoenix_live_view, "~> 1.0"}
    ]
  end
end
