defmodule CLI.Commands do
  def init do
    :ok
  end

  def run(_command, _args) do
    IO.puts("world")
  end
end
