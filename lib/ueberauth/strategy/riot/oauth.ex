defmodule Ueberauth.Strategy.Riot.OAuth do
  @moduledoc """
  OAuth2 for Riot.

  Add `client_id` and `client_secret` to your configuration:

  config :ueberauth, Ueberauth.Strategy.Riot.OAuth,
    client_id: System.get_env("RSO_CLIENT_ID"),
    client_secret: System.get_env("RSO_CLIENT_SECRET")
  """
  use OAuth2.Strategy

  @defaults [
    strategy: __MODULE__,
    site: "https://auth.riotgames.com",
    authorize_url: "https://auth.riotgames.com/authorize",
    token_url: "https://auth.riotgames.com/token"
  ]

  @doc """
  Construct a client for requests to Twitch.

  This will be setup automatically for you in `Ueberauth.Strategy.Twitch`.

  These options are only useful for usage outside the normal callback phase of Ueberauth.
  """
  def client(opts \\ []) do
    opts =
      @defaults
      |> Keyword.merge(config())
      |> Keyword.merge(opts)

    opts
    |> OAuth2.Client.new()
    |> OAuth2.Client.put_serializer("application/json", Jason)
  end

  @doc """
  Provides the authorize url for the request phase of Ueberauth. No need to call this usually.
  """
  def authorize_url!(params \\ [], opts \\ []) do
    opts
    |> client
    |> OAuth2.Client.authorize_url!(params)
  end

  def get(token, url, headers \\ [], opts \\ []) do
    headers = headers ++ [{"Client-ID", config()[:client_id]}]

    client(token: token)
    |> OAuth2.Client.put_param(:client_secret, config()[:client_secret])
    |> OAuth2.Client.get(url, headers, opts)
  end

  def get_token!(params \\ [], opts \\ []) do
    opts
    |> client
    |> OAuth2.Client.put_header("content-type", "application/x-www-form-urlencoded")
    |> OAuth2.Client.put_param("form", [client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", client_assertion: config()[:client_assertion], grant_type: "authorization_code", code: params.code, redirect_uri: opts.redirect_uri])
    |> OAuth2.Client.get_token!(params)
  end

  defp config do
    Application.get_env(:ueberauth, Ueberauth.Strategy.Riot.OAuth)
  end

  # Strategy Callbacks

  def authorize_url(client, params) do
    OAuth2.Strategy.AuthCode.authorize_url(client, params)
  end

  def get_token(client, params, headers) do
    client
    |> put_header("Accept", "application/json")
    |> OAuth2.Strategy.AuthCode.get_token(params, headers)
  end
end
