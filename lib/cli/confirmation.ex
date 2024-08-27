defmodule CLI.Confirmation do
  @moduledoc """
  Creates a confirmation dialog for the shell

  Returns the confirmation callback return

  A confirmation callback needs to handle two different inputs.
  When the user types "yes" the callback receives `:confirmed`.
  When the user enters nothing the callback receives `:unconfirmed`.
  """
  use CLI.PromptCommand,
    timeout: :infinity,
    prompt: "Enter 'YES' to continue or <ENTER> to cancel :"

  @type confirmation_choice :: :confirmed | :unconfirmed
  @type callback :: (confirmation_choice -> term())

  @spec init(callback | any()) :: {:ok, callback | any()}
  def init(callback) do
    {:ok, callback}
  end

  @spec handle_command(String.t(), callback | any()) :: {:ok, callback | any()} | {:exit, term, nil}
  def handle_command(command, callback) do
    command
    |> String.upcase()
    |> case do
      "YES" ->
        {:exit, callback.(:confirmed), nil}

      "" ->
        {:exit, callback.(:unconfirmed), nil}

      _ ->
        IO.puts("#{command} is not valid")
        {:ok, callback}
    end
  end
end
