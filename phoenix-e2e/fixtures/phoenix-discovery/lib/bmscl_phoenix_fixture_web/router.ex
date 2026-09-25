defmodule BmsclPhoenixFixtureWeb.Router do
  use Phoenix.Router
  import Phoenix.LiveView.Router

  get "/health", BmsclPhoenixFixtureWeb.HealthController, :show
  get "/dashboard", BmsclPhoenixFixtureWeb.DashboardController, :index
  live "/live-dashboard", BmsclPhoenixFixtureWeb.DashboardLive
  post "/api/users", BmsclPhoenixFixtureWeb.UserController, :create
end
