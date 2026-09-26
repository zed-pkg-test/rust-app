import Config

config :bmscl_phoenix_fixture, BmsclPhoenixFixtureWeb.Endpoint,
  secret_key_base: String.duplicate("a", 64),
  server: false
