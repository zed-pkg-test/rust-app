defmodule BmsclPhoenixFixtureWeb.Router do
  use Phoenix.Router

  get "/health", BmsclPhoenixFixtureWeb.HealthController, :show
  get "/dashboard", BmsclPhoenixFixtureWeb.DashboardController, :index
  post "/api/users", BmsclPhoenixFixtureWeb.UserController, :create
end
