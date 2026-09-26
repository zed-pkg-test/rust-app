defmodule BmsclPhoenixFixtureWeb.Endpoint do
  use Phoenix.Endpoint, otp_app: :bmscl_phoenix_fixture

  socket "/socket", BmsclPhoenixFixtureWeb.UserSocket,
    websocket: true,
    longpoll: false

  socket "/live", Phoenix.LiveView.Socket,
    websocket: [connect_info: [:peer_data]],
    longpoll: false
end
