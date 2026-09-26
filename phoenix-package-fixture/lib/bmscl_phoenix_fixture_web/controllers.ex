defmodule BmsclPhoenixFixtureWeb.HealthController do
  use Phoenix.Controller

  def show(conn, _params), do: text(conn, "ok")
end

defmodule BmsclPhoenixFixtureWeb.DashboardController do
  use Phoenix.Controller

  def index(conn, _params), do: html(conn, "<main id=\"dashboard\">dashboard</main>")
end

defmodule BmsclPhoenixFixtureWeb.UserController do
  use Phoenix.Controller

  def create(conn, _params), do: json(conn, %{created: true})
end
