defmodule CLI.IExHook do
  @moduledoc """
    Override IEx session

    This starts our own CLI instead of the standard iex> prompt.
  """
  alias CLI.Shell
  alias IEx.Autocomplete

  def shell() do
    IO.write(IO.ANSI.clear())
    IO.write(IO.ANSI.home())

    user = {:ok, "sessionid1", "user1"}

    peer = "Terminal"

    try do
      Task.async(fn ->
        Shell.run(
          user,
          peer,
          [],
          %{}
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

end
