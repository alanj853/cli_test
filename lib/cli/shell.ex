defmodule CLI.Shell do
  use CLI.PromptCommand
  require Logger
  require Integer
  alias CLI.Commands
  alias CLI.PromptCommand

  defstruct mods: [],
            prompt: ~c"myprompt> ",
            before_exit: &__MODULE__.noop/0,
            user: nil

  def run(user, peer, mods, schema, options \\ [])

  def run(user, peer, mods, schema, options) when is_list(user) do
    {to_string(user), nil}
    |> run(peer, mods, schema, options)
  end

  def run(user, peer, mods, schema, options) when is_binary(user),
    do: run({user, nil}, peer, mods, schema, options)

  def run({_username, session, user}, peer, mods, schema, options) do
    PromptCommand.run(__MODULE__, [{user, session}, peer, mods, schema, options], timeout: 60000)
  end

  def init([user, peer, mods, schema, options]) do
    Process.put(:user, user)
    Process.put(:cwd, "/")
    Process.put(:peer_name, peer)
    Process.put(:schema, schema)

    gl = Process.group_leader()
    command_list = [~c"help"]
    :io.setopts(gl, encoding: :latin1, expand_fun: &expand(&1, command_list))

    {current_banner, current_bannerlerss_options} =
      case Keyword.pop(options, :banner) do
        {nil, bannerlerss_options} -> {&banner/1, bannerlerss_options}
        {popped_banner, popped_bannerlerss_options} -> {popped_banner, popped_bannerlerss_options}
      end

    shell = List.foldl(current_bannerlerss_options, %__MODULE__{mods: mods}, &add_option/2)

    :io.format(current_banner.(user))

    {:ok, shell}
  rescue
    error ->
      Logger.error("Got this error #{inspect(error)}")
      {:error, error}
  end

  def handle_prompt(%{prompt: prompt}) do
    prompt
  end

  def handle_command(command, state) do
    command
    |> eval_cli()
    |> handle_command_status(state)
  end

  def eval_cli(line) when is_list(line) do
    eval_cli(to_string(line))
  end

  def eval_cli(line) do
    if contains_unclosed_quotes(line) do
      IO.puts(~s(E102: Parameter Error - unclosed " or '))
    else
      try do
        case line |> Kernel.<>(" \"\"") |> String.trim() |> OptionParser.split() do
          [] ->
            ""

          [command | arg_strings] ->
            Commands.run(command, arg_strings)
        end
      rescue
        e in RuntimeError -> IO.puts("Error: Runtime Error: #{inspect(e)}")
      catch
        :exit, error ->
          Logger.error("Caught exit for command: #{inspect(line)}: #{inspect(error)}")
          IO.puts("E100: Command Failed\n")
      end
    end
  end

  defp contains_unclosed_quotes(line) do
    line
    |> String.split(~s('))
    |> Enum.count()
    |> Integer.is_even() or
      line
      |> String.split(~s("))
      |> Enum.count()
      |> Integer.is_even()
  end

  def noop do
  end

  defp add_option({:before_exit, before_exit}, state) do
    %{state | before_exit: before_exit}
  end

  defp add_option({:prompt, prompt}, state) do
    %{state | prompt: to_charlist(prompt)}
  end

  defp add_option(unknown_option, state) do
    Logger.error(fn -> "Unknown CLI.Shell Option #{inspect(unknown_option)}" end)
    state
  end

  defp handle_command_status(result, %{before_exit: before_exit} = state) do
    case result do
      :exit ->
        before_exit.()
        {:exit, :ok, state}

      :ok ->
        {:ok, state}

      {:error, message} ->
        Logger.debug(fn -> "An Error Occured: #{inspect(message)} \n" end)
        {:ok, state}

      "" ->
        {:ok, state}

      _ ->
        Logger.debug(fn -> "'--> #{inspect(result)}\n" end)
        {:ok, state}
    end
  end

  def expand(char_list, command_list) when is_list(char_list) do
    prefix = :lists.reverse(char_list)

    case longest_prefix(command_list, prefix) do
      {:prefix, p, [_]} ->
        {:yes, p ++ ~c" ", []}

      {:prefix, ~c"", m} ->
        {:yes, ~c"", m}

      {:prefix, p, m} ->
        {:yes, p, m}

      {:none, _m} ->
        {:no, ~c"", []}
    end
  end

  @doc """
  longest prefix in a list, given a prefix.  Taken from the SSH example module
  """
  def longest_prefix(list, prefix) do
    match_command_list =
      for command <- list, :lists.prefix(prefix, command) do
        command
      end

    case match_command_list do
      [] ->
        {:none, list}

      [s | rest] ->
        new_prefix_0 =
          :lists.foldl(
            fn a, p ->
              common_prefix(a, p, [])
            end,
            s,
            rest
          )

        new_prefix = nthtail(length(prefix), new_prefix_0)
        {:prefix, new_prefix, [s | rest]}
    end
  end

  @doc """
  the longest common prefix of two strings.  Taken from the SSH example module
  """
  def common_prefix([c | r1], [c | r2], acc) do
    common_prefix(r1, r2, [c | acc])
  end

  def common_prefix(_, _, acc) do
    :lists.reverse(acc)
  end

  @doc """
  nthtail as in lists, but no badarg if n > the length of list
  """
  def nthtail(0, a), do: a
  def nthtail(n, [_ | a]), do: nthtail(n - 1, a)
  def nthtail(_, _), do: []

  def banner(_user) do
    ["\nWelcome to the CLI\n"]
  end
end
