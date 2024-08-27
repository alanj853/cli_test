defmodule CLI.IExHook do
  @moduledoc """
    Override IEx session

    This starts our own CLI instead of the standard iex> prompt.
  """
  alias CLI.Login
  alias CLI.Shell
  alias IEx.Autocomplete

  def shell() do
    IO.write(IO.ANSI.clear())
    IO.write(IO.ANSI.home())

    user = Login.prompt()

    peer = "Terminal"

    env = Application.get_env(:common_core, CLI.IExHook)
    cli_mods = add_iex_command(env)

    try do
      Task.async(fn ->
        Shell.run(
          user,
          peer,
          cli_mods,
          CommonCore.CommonSocket.schema()
        )
      end)
      |> Task.await(:infinity)
    catch
      :exit, _ -> :ok
    end

    receive do
      :iex_exit ->
        gl = Process.group_leader()
        :io.setopts(gl, expand_fun: &Autocomplete.expand(&1))
        :io.setopts(gl, binary: true, encoding: :unicode)
        :ok
    after
      0 ->
        shell()
    end
  end

  @spec generate_iex_command() :: ([<<_::32>>] -> :exit | :ok)
  defp generate_iex_command() do
    pid = self()

    fn
      [] ->
        send(pid, :iex_exit)
        :exit

      ["help"] ->
        IO.puts("Exits to IEx")
        :ok
    end
  end

  defp add_iex_command(env) do
    mods = Keyword.get(env, :cli_mods, [])

    if Keyword.get(env, :allow_iex_command, false) do
      [{"iex", generate_iex_command()} | mods]
    else
      mods
    end
  end
end
