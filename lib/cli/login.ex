defmodule CLI.Login do
  @moduledoc """
  Prompt for Username / Password
  """
  alias CLI.Password.Change
  @main_app Application.compile_env(:common_data, ConfigManager)[:app_name]

  @login_pompt "login as: "
  @password_prompt "password: "
  @invalid_password "Invalid Password"
  @auth_server_timeout "Authorisation Server Timeout"
  @invalid_server_response "Invalid Server Response"
  @invalid_server_setup "Incorrect Server Setup"
  @no_server_reply "No Reply From Authorisation Server(s)"
  @unknown_error "Unknown Authorisation Error"
  @account_locked """
  Account is Locked.
  A super user or a user with administrator rights must re-enable the user account.
  """
  @max_sessions_reached """
  Maximum number of sessions has been reached.
  """

  @max_retries 3
  @system_monitor_registry_wait_ms 667

  # Waits for SystemMonitor's registry to be started by either Shoehorn or CommonBootstrap
  defp wait_for_system_monitor_registry() do
    if not SystemMonitor.started?() do
      :timer.sleep(@system_monitor_registry_wait_ms)
      wait_for_system_monitor_registry()
    else
      :ok
    end
  end

  @doc """
  The function is being invoked by the :iex's initialisation hook. The :iex initialisation is being invoked at the veary early stage of the boostrap process -
  :iex is :kernel's dependecy whereas :kernel is laoded as a dependency for Shoehorn module.
  Returns `{:ok, _}` or `{:error, reason}` or `{:error, :reason, user_name}`.

  ## Parameters

  ## Examples

  """
  def prompt() do
    # There is a mminimal chance for a race condition so we MUST ensure the minimal dependency of systemMonitor's registry is started.
    # The function either returns with an `:ok` or blocks indefinitely.
    :ok = wait_for_system_monitor_registry()

    # So we could wait for :common_data application using the SystemMonitor's registry
    SystemMonitor.wait_for_app(@main_app, :started)

    # Disable any tab-complete function that is already registered
    :io.setopts(Process.group_leader(), encoding: :latin1, expand_fun: &disable_expand(&1))

    prompt(user_name: nil, retries: 0)
  end

  def prompt(user_name: nil, retries: _) do
    IO.write(@login_pompt)

    user_name =
      :line
      |> IO.read()
      |> String.trim()

    case user_name do
      "" ->
        prompt(user_name: nil, retries: 0)

      _ ->
        prompt(user_name: user_name, retries: 0)
    end
  end

  def prompt(user_name: user_name, retries: retries) when retries < @max_retries do
    IO.write(@password_prompt)
    password = :io.get_password() |> to_string()

    case login(user_name, password) do
      {:ok, session_id, user} ->
        {user_name, session_id, user}

      {:error, :max_sessions_reached} ->
        IO.puts(@max_sessions_reached)
        prompt(user_name: nil, retries: 0)

      {:error, :account_locked} ->
        IO.puts(@account_locked)
        prompt(user_name: nil, retries: 0)

      {:error, :password_expired, user} ->
        case Change.run([user, password]) do
          {:ok, new_password} ->
            {:ok, session_id, _user} = login(user_name, new_password)
            {user_name, session_id}

          {:error, reason} ->
            IO.puts(reason <> "\n")
            prompt(user_name: user_name, retries: 0)

          {:error, reason, _} ->
            IO.puts(reason <> "\n")
            prompt(user_name: user_name, retries: 0)
        end

      {:error, :invalid_password} ->
        IO.puts(@invalid_password)
        prompt(user_name: user_name, retries: retries + 1)

      {:error, :timeout} ->
        IO.puts(@auth_server_timeout)
        prompt(user_name: user_name, retries: 0)

      # A malformed RADIUS reply packet i.e. packet size, message authenticator
      {:error, :bad_server_response} ->
        IO.puts(@invalid_server_response)
        prompt(user_name: user_name, retries: 0)

      # This clause will match if unparseable RADIUS Server's IP would end-up int the Config-DB
      {:error, :einval} ->
        IO.puts(@invalid_server_setup)
        prompt(user_name: user_name, retries: 0)

      # Clause matching when message authenticator does not allow to decode RADIUS reply i.e.
      # MIM attack or mismatching shared-secret.
      {:error, :noreply} ->
        IO.puts(@no_server_reply)
        prompt(user_name: user_name, retries: 0)

      # It is safer to print-out an unknown error than fallback into iex> prompt giving
      # an unauthorised user root acces
      other ->
        IO.puts(@unknown_error <> "#{inspect other}" <> "\n")
        prompt(user_name: user_name, retries: 0)
    end
  end

  def prompt(user_name: _user_name, retries: _retries) do
    prompt(user_name: nil, retries: 0)
  end

  def login(user_name, password) do
    UserManager.login(user_name, password, interface: "Console", auto_close: true)
  end

  def disable_expand(_text) do
    {:no, '', []}
  end
end
