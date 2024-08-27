defmodule CLI.Password.Tuner do
  @moduledoc """
  Verify the Username / Password for the SFTP Server for the Tuner SFTP/SSH interface
  """
  require Logger
  @max_sessions 1

  def pwdfun("Tuner", "STO2017", _peer_addr = {{169, 254, 5, _x}, _port}, _state) do
    current_sessions = Ssh.Monitor.session_count(:service)

    cond do
      CacheManager.get(:"fwu.status") == :uploading ->
        Logger.error("Tuner login failed: Remote FWU upload currently in progress")
        :disconnect

      current_sessions >= @max_sessions ->
        Logger.error("Tuner login failed: Max Tuner SFTP sessions reached")
        :disconnect

      true ->
        Logger.notice("Tuner session logged in")
        Ssh.Monitor.monitor(self(), nil, :service)
        true
    end
  end

  def pwdfun(_username, _password, _peer_addr = {_ip, _port}, _state), do: false
end
