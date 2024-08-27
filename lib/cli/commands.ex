defmodule CLI.Commands do
  @moduledoc """
  Handles storing and registration of possible cli commands

  The commands are stored based on the pid of the calling process.
  """
  alias CLI.Commands
  require Logger
  defstruct pid: nil

  @opaque t :: %__MODULE__{}

  @typedoc """
  The name of the available command
  """
  @type name :: String.t()

  @typedoc """
  A list of arguments to be passed to a command
  """
  @type args :: [String.t()]

  @typedoc """
  Determines the functions to add to the available commands

  They can be in the form of `{name, function}` where the name is
  the name of the command and the function is a single arity function
  taking a list of string arguments.

  The id can also be a module. All single arity functions will be
  exported from the module. If the module supports `__cmd_list/0`
  and `__cmd/2` it will export each function in the command list,
  and they will be called through the `__cmd(name, args)`.
  """
  @type id :: {name, (args -> term)} | module

  @doc """
  Starts the command registry
  """
  def start_command_registry(user_type, route) do
    # Second registry to map pid to usertype
    # User type to be queried for access rights within commands & add_function(s) call
    # Route is either :exec of :shell
    pid = self()
    Registry.register(AccessControl, {pid, :usertype}, {user_type, route})
    :ok
  end

  @doc """
  Initializes the starting state of the command registry
  """
  def init do
    %__MODULE__{pid: self()}
  end

  @doc """
  List all cli commands that the calling process has available
  """
  @spec list() :: [name] | [] | [any()]
  def list() do
    __MODULE__
    |> Registry.keys(self())
    |> Enum.map(&elem(&1, 1))
  end

  @doc """
  Runs a command with the given arguments

  ## Example

       iex> CLI.Commnads.run("whoami", [])
  """
  @spec run(name | any(), args | any()) :: term
  def run(command, args) do
    pid = self()
    command_pair = Registry.lookup(__MODULE__, {pid, to_string(command)})

    if command_pair == [] do
      IO.puts("E101: Command Not Found\n")
      :error
    else
      [{^pid, function}] = command_pair
      function.(args)
    end
  end

  @doc """
  Gets available help for a command

  The first argument is the base command that help is needed for. The
  second is the list of arguments for the help command.

  ## Example

  iex> CLI.Commands.help("help", [])
  """
  @spec help(name | any(), args | any()) :: String.t() | [String.t()] | any()
  def help(command, args) do
    case run(command, ["help" | args]) do
      :not_found ->
        "No help available\n"

      :ok ->
        ""

      help ->
        help
    end
  rescue
    error ->
      Logger.debug(fn -> "Help for #{inspect([command, args])} failed with #{inspect(error)}" end)
      "No help available\n"
  end

  @doc """
  Adds command(s) to the registry

  Commands can come in a few forms.

  ## Command Types

  t:module/0
  t:command
  """
  @spec add_functions(t | any(), atom | id | {any(), any()}) :: t | any()
  def add_functions(%{pid: pid} = registry, {name, func}) do
    _ =
      if AccessControl.command_accessible(to_string(name)) do
        Registry.register(__MODULE__, {pid, to_string(name)}, func)
      end

    registry
  end

  def add_functions(registry, module) when is_atom(module) do
    module.__info__(:functions)
    |> Enum.each(&add_function(&1, module, registry))

    registry
  end

  # Adds seperate file defined commands
  @spec add_function({atom, non_neg_integer} | any(), module | any(), t | any()) :: t | any()
  def add_function({command, 1}, module, %{pid: pid}) do
    if AccessControl.command_accessible(to_string(command)) do
      Registry.register(__MODULE__, {pid, to_string(command)}, &apply(module, command, [&1]))
    end
  end

  def add_function({:__cmd_list, 0}, module, registry) do
    Enum.each(module.__cmd_list(), fn command ->
      add_functions(registry, {command, &apply(module, :__cmd, [command, &1])})
    end)
  end

  def add_function(_, _, registry) do
    registry
  end

  defimpl Collectable do
    def into(original) do
      func = fn
        commands, {:cont, command_module} ->
          Commands.add_functions(commands, command_module)

        commands, :done ->
          commands

        _, :halt ->
          :ok
      end

      {original, func}
    end
  end
end
