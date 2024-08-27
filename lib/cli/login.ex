defmodule CLI.Login do
  @moduledoc """
  Prompt for Username / Password
  """

  @login_pompt "login as: "
  @password_prompt "password: "
  @max_retries 3

  def prompt() do
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

    {:ok, session_id, user} = login(user_name, password)
    {user_name, session_id, user}
  end

  def prompt(user_name: _user_name, retries: _retries) do
    prompt(user_name: nil, retries: 0)
  end

  def login(user_name, _password) do
    {:ok, "sessionid1", user_name}
  end

  def disable_expand(_text) do
    {:no, ~c"", []}
  end
end
