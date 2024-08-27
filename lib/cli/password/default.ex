defmodule CLI.Password.Default do
  require Logger

  @moduledoc """
  Verify the Username / Password.
  """

  def pwdfun(user, password, addr, state) do
    AppModuleManager.get_build_flavour()
    |> pwdfun(user, password, addr, state)
  end

  ## on dev and qa builds, user "eng" with password "eng" will bring you to the iex prompt
  defp pwdfun(flavour, "eng", "eng", _, _state) when flavour in [:dev, :qa] do
    Ssh.Monitor.monitor(self(), nil, :diagnostic)
    true
  end

  defp pwdfun(_, user, password, {remote_ip, _port}, _state) do
    current_sessions = Ssh.Monitor.session_count()
    max_sessions = UserManager.Session.get_max_sessions("SSH/SFTP")

    if current_sessions >= max_sessions do
      Logger.error("Max SSH/SFTP sessions reached")
      :disconnect
    else
      case UserManager.login(
             user,
             password,
             interface: "SSH/SFTP",
             address: remote_ip,
             auto_close: true
           ) do
        {:ok, session_id, user} ->
          Ssh.Monitor.monitor(self(), session_id, user)
          true

        # A separate check had to be implemented for users logging in using SSH. To allow
        # the user to change the password, they need to be logged in to the CLI, so login
        # is allowed here, and the password is changed in CLI.Shell.run
        {:error, :password_expired, _user} ->
          true

        _ ->
          false
      end
    end
  end
end
