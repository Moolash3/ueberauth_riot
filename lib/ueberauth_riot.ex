defmodule UeberauthRiot do
  @moduledoc """
  Documentation for `UeberauthRiot`.
  """

  @doc """
  """
  def client_id do
    Application.get_env(:ueberauth, Ueberauth.Strategy.Riot.OAuth)[:client_id]
  end

  def client_secret do
    Application.get_env(:ueberauth, Ueberauth.Strategy.Riot.OAuth)[:client_secret]
  end

  def client_assertion do
    Application.get_env(:ueberauth, Ueberauth.Strategy.Riot.OAuth)[:client_assertion]
  end
end
