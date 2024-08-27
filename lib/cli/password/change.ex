defmodule CLI.Password.Change do
  use CLI.PromptCommand, input_type: :hidden

  @password_change_fail """
  Password Change Failed
  """

  @password_expired """
  Your password is expired and must be changed.
  """

  @password_first_logon """
  Please update your password in order to proceed.
  """

  def init([%{user_type: :read_only}, _]) do
    IO.puts("""
    Password is Expired.
    A super user or a user with administrator rights must re-enable the user account.
    """)

    {:error, :read_only}
  end

  def init([%{user_name: user_name}, existing_password]) do
    if ConfigManager.get(:"security.user_management.super_user.first_sign_on") do
      IO.puts(@password_first_logon)
    else
      IO.puts(@password_expired)
    end

    {:ok, %{user_name: user_name, existing_password: existing_password, new_password: nil}}
  end

  def init([%{user_name: user_name}]) do
    if ConfigManager.get(:"security.user_management.super_user.first_sign_on") do
      IO.puts(@password_first_logon)
    else
      IO.puts(@password_expired)
    end

    {:ok, %{user_name: user_name, existing_password: nil, new_password: nil}}
  end

  def handle_prompt(%{existing_password: nil}) do
    "Please enter your current password:  "
  end

  def handle_prompt(%{new_password: nil}) do
    "Please Enter a new password: "
  end

  def handle_prompt(%{new_password: new_password}) when not is_nil(new_password) do
    "Please re-enter new password: "
  end

  def handle_command(current_password, %{existing_password: nil} = state) do
    {:ok, %{state | existing_password: current_password}}
  end

  def handle_command(new_password, %{new_password: nil} = state) do
    {:ok, %{state | new_password: new_password}}
  end

  def handle_command(confirmation, %{new_password: new_password} = state)
      when confirmation != new_password do
    IO.puts(@password_change_fail)
    {:exit, {:error, "Confirm Password must match New Password"}, state}
  end

  def handle_command(
        new_password,
        %{user_name: user_name, existing_password: existing_password, new_password: new_password} = state
      ) do
    UserManager.change_password(user_name, existing_password, new_password)
    |> case do
      :ok ->
        {:exit, {:ok, new_password}, state}

      error ->
        IO.puts(@password_change_fail)
        {:exit, error, state}
    end
  end
end
