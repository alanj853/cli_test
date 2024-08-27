defmodule CLI.PromptCommand do
  @moduledoc """
  An OTP behaviour for creating interactive shell commands

  The behaviour is used to create commands that ask the user
  for input and then respond to those inputs.

  # Callbacks that are required:

  * c:init/1
  * c:handle_prompt/1 (optional)
  * c:handle_command/2

  # Examples

       defmodule MyCommand do
         use CLI.PromptCommand

         def init(stack) do
           {:ok, stack}
         end

         def handle_command(<<"push ", value::binary()>>, stack) do
           {:ok, [value | stack]}
         end

         def handle_command("pop", [head | stack]) do
           IO.puts(head)
           {:ok, stack}
         end

        def handle_command("exit", stack) do
          {:exit, :ok, stack}
        end

        def handle_prompt([]) do
          "empty>"
        end

        def handle_prompt(stack) do
          to_string(length(stack)) <> ">"
        end
      end

      MyCommand.run([1])

  # `use` can take a few options

  * :timeout - default 30 seconds
  * :input_type - default :visible
  * :prompt - default is empty and can be used instead of implementing c:handle_prompt
  """

  require Logger

  defmacro __using__(opts) do
    quote location: :keep, bind_quoted: [opts: opts] do
      @behaviour CLI.PromptCommand

      def run(args) do
        options = unquote(Macro.escape(opts))
        input_type = Keyword.get(options, :input_type, :visible)
        CLI.PromptCommand.run(__MODULE__, args, input_type: input_type)
      end

      defoverridable run: 1

      def handle_prompt(_) do
        unquote(Macro.escape(opts))
        |> Keyword.get(:prompt, "")
      end

      defoverridable handle_prompt: 1
    end
  end

  @optional_callbacks handle_prompt: 1

  @typedoc """
  The state of the command
  """
  @type command_state :: term()

  @typedoc """
  A trimmed string of what the user typed
  """
  @type command :: String.t()

  @typedoc """
  options values for input type

  * `:hidden` - user input is not displayed
  * `:visible` - the user input is shown as the user types (default)
  """
  @type input_type :: :hidden | :visible

  @typedoc """
  Option values used to configure the command

  `:timeout` - defaults to 30 seconds
  """
  @type option :: {:timeout, timeout} | {:input_type, input_type}

  @typedoc """
  Options used by the command
  """
  @type options :: [option]

  # @typep internal_state :: %{timeout: timeout, input_type: input_type, command_state: command_state}

  @default_input_type :visible

  @doc """
  (Optional Callback) Determines the prompt to use

  Returns t:String.t/0 or an IO List

  The handle prompt receives c:command_state/0 and returns a
  prompt suitable for printing. The default callback has no prompt
  """
  @callback handle_prompt(command_state) :: String.t() | [String.t()]

  @doc """
  Sets up the initial state of the Prompt Command
  This callbaack receives the arguments that were passed to
  `CLI.PromptCommand.run/3`.

  Any return value other than `{:ok, state}` will result in an exception.
  """
  @callback init(term) :: {:ok, command_state} | {:error, term}

  @doc """
  Processes incoming commands

  When the user responds to a prompt the response is processed by
  `CLI.PromptCommand.handle_command/2`. The first argument is the
  command that the user sent in by typing and ending with a `\n`.

  The return value tells the prompt how to respond and updates the
  current state. Possible return values:

  * `{:ok, new_state}` - Causes the prompt to loop back around
  * `{:exit, response, new_state}` - Halts the returning of the prompt
  with the response as the status
  """
  @callback handle_command(String.t(), state) ::
              {:ok, state}
              | {:exit, term, state}
            when state: var

  @doc """
  Starts the command

  Returns the response from the last `CLI.PromptCommand.handle_command/2`
  that returns `{:exit, response, c:command_state/0}`.

  Inputs

  * c:module/0 - a module that implements the callbacks
  * c:term/0 - argument to be passed to `CLI.PromptCommand.init/1`
  * c:options/0 - (optional) default: `[]`
  """
  def run(module, args, options \\ []) do
    case apply(module, :init, [args]) do
      {:ok, command_state} ->
        _run(module, command_state, options)

      error ->
        error
    end
  end

  defp _run(module, command_state, options) do
    default_timeout =
      :"security.user_management.super_user.session_timeout"
      |> DataDictionary.default_val()
      |> :timer.minutes()

    internal_state = %{
      command_state: command_state,
      input_type: Keyword.get(options, :input_type, @default_input_type),
      timeout: Keyword.get(options, :timeout, default_timeout)
    }

    loop(module, internal_state)
  end

  defp loop(module, %{command_state: command_state} = internal_state) do
    apply(module, :handle_prompt, [command_state])
    |> prompt(internal_state)

    {_, internal_state} =
      Map.get_and_update(internal_state, :timeout, fn x ->
        {x,
         unless is_atom(x) do
           Kernel.trunc(x)
         else
           x
         end}
      end)

    wait_for_command(module, internal_state)
  end

  defp prompt(message, internal_state) do
    listener = self()

    spawn(fn ->
      send(listener, process_user_command(message, internal_state))
    end)
  end

  defp process_user_command(message, internal_state) do
    message
    |> get_input(internal_state)
    |> parse_command()
  rescue
    error ->
      {:command_error, error}
  end

  defp get_input(message, %{input_type: :visible}) do
    ensure_string_result(message, &IO.gets/1)
  end

  defp get_input(message, %{input_type: :hidden}) do
    ensure_string_result(message, &get_hidden_input/1)
  end

  def get_hidden_input(message) do
    IO.puts(message)
    :io.get_password()
  end

  defp wait_for_command(
         module,
         %{command_state: command_state, timeout: timeout} = internal_state
       ) do
    receive do
      :terminate ->
        Logger.warning("Terminating CLI session")
        close_session()
        {:exit, "terminate", command_state}

      {:command_error, error} ->
        Logger.error(fn -> "An error caused #{__MODULE__} to crash #{inspect(error)}" end)
        next({:exit, "Command Error", internal_state}, module, internal_state)

      command ->
        apply(module, :handle_command, [command, command_state])
        |> next(module, internal_state)
    after
      timeout ->
        close_session()
        {:exit, "timeout", command_state}
    end
  end

  defp close_session() do
    case Process.get(:session_id) do
      nil -> :ok
      session_id -> UserManager.Session.close(session_id)
    end
  end

  @spec parse_command(String.t()) :: String.t()
  defp parse_command(input) when is_binary(input), do: String.trim_trailing(input)

  defp next({:ok, command_state}, module, internal_state) do
    loop(module, %{internal_state | command_state: command_state})
  end

  defp next({:exit, response, _}, _, _) do
    close_session()
    UserManager.SessionMonitor.trigger_session_check()
    response
  end

  # `IO.gets/x` and the `:io` functions can return either a `String.t` or
  # a chardata. It depends on the configuration of `:io.setopts/x`. To keep
  # a consistent interface we want to always return a `String.t`.
  defp ensure_string_result(message, io_getter) do
    io_getter.(message) |> to_string()
  end
end
