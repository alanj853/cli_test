defmodule CLI.Password.SecondNMC do
  @moduledoc """
  Verify the Username / Password for the SFTP Server for the second NMC
  """
  require Logger
  @interfaces Application.compile_env(:common_core, CLI)[:interfaces]
  @max_sessions 1

  @doc """
  Only allow the second NMC credentials to be used to log into the Second NMC SSH/SFTP Account
  """
  def pwdfun(username, password, _peer_addr = {_ip, _port}, _state) do
    current_sessions = Ssh.Monitor.session_count(:second_nmc_server)

    if current_sessions >= @max_sessions do
      Logger.error("Max Second NMC SFTP sessions reached")
      :disconnect
    else
      stored_username = get_username()
      stored_password = get_password()

      if stored_username == username && stored_password == password do
        Logger.notice("Second NMC SFTP session logged in")
        Ssh.Monitor.monitor(self(), nil, :second_nmc_server)
        true
      else
        false
      end
    end
  end

  defp get_username(), do: get_item(:username)
  defp get_password(), do: get_item(:password)

  defp get_item(key) do
    [second_nmc_server_config] = Enum.filter(@interfaces, fn x -> x[:name] == :second_nmc_server end)
    second_nmc_server_config[key]
  end
end
