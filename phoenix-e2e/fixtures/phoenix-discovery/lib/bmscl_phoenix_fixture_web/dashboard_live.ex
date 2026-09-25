defmodule BmsclPhoenixFixtureWeb.DashboardLive do
  use Phoenix.LiveView

  @impl true
  def mount(_params, _session, socket) do
    {:ok, assign(socket, :message, "phoenix-live")}
  end

  @impl true
  def render(assigns) do
    ~H"""
    <main id="dashboard-live"><%= @message %></main>
    """
  end
end
