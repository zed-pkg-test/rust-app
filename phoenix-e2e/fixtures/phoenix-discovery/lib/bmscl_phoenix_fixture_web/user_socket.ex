defmodule BmsclPhoenixFixtureWeb.UserSocket do
  use Phoenix.Socket

  channel "room:*", BmsclPhoenixFixtureWeb.RoomChannel

  @impl true
  def connect(_params, socket, _connect_info), do: {:ok, socket}

  @impl true
  def id(_socket), do: nil
end

defmodule BmsclPhoenixFixtureWeb.RoomChannel do
  use Phoenix.Channel

  @impl true
  def join("room:" <> _room, _payload, socket), do: {:ok, socket}
end
