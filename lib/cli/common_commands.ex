defmodule CLI.CommonCommands do
  @moduledoc """
    Module for CLI commands
  """
  require Logger

  def exit([]) do
    :exit
  end

  def exit(args) do
    unless args == ["help"] or args == ["?"] do
      IO.write("E102: Parameter Error\n")
    end

    """
    Usage:  exit -- Exit Session
    """
    |> IO.write()
  end

  def bye([]) do
    :exit
  end

  def bye(args) do
    unless args == ["help"] or args == ["?"] do
      IO.write("E102: Parameter Error\n")
    end

    """
    Usage:  bye -- Exit Session
    """
    |> IO.write()
  end

  def quit([]) do
    :exit
  end

  def quit(args) do
    unless args == ["help"] or args == ["?"] do
      IO.write("E102: Parameter Error\n")
    end

    """
    Usage:  quit -- Exit Session
    """
    |> IO.write()
  end
end
