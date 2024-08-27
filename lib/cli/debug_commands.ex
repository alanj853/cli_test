defmodule CLI.DebugCommands do
  @doc """
  Prints engineering logs
  """
  def diagnostics(args) when is_list(args) do
    case OptionParser.parse(
           args,
           strict: [limit: :integer, help: :boolean],
           aliases: [l: :limit, h: :help]
         ) do
      {options, [], []} ->
        if Keyword.get(options, :help) do
          doDiagnostics(:help)
        else
          doDiagnostics(Keyword.get(options, :limit, :default))
        end

      _ ->
        IO.puts("Invalid arguments\n")
        doDiagnostics(:help)
    end
  end

  defp doDiagnostics(:default), do: EngineeringLogger.logs() |> Enum.join("\n") |> IO.puts()

  defp doDiagnostics(:help) do
    """
    Usage:
      diagnostics [OPTION]

    Options:
      -l, --limit <limit> output the last log messages up to the limit default: 50
      -h, --help          print this message
    """
    |> IO.puts()
  end

  defp doDiagnostics(limit), do: EngineeringLogger.logs(limit) |> Enum.join("\n") |> IO.puts()

  # @doc """
  # Starts the Event Log Test. Will only work from AppAlpha or from an NMC
  # """
  @doc false
  def startEventLogPerf([]) do
    case Code.ensure_compiled(EventLogPerformance) do
      {:module, EventLogPerformance} ->
        IO.puts("Events will now be sent from the UC.")

        IO.puts("Run the following command to stop the event log performance test and generate the event log report:")

        IO.puts("   stopEventLogPerformance")
        EventLogPerformance.start_test()
      {:error, _reason} ->
        IO.puts("This command only works from AppAlpha or from an NMC.")
    end
  end

  def gen_config_ini([]) do
    Process.get(:user)
    |> ConfigIniManager.generate_ini_file()
  end

  # @doc """
  # Stops the Event Log Test and prints out the event log information: Below is a sample output
  #   Generating Report...
  #   Here is the event log performance report:
  #   First 10 'Slow Events Results'
  #     Max Transfer Time = 10 ms
  #     Min Transfer Time = 2 ms
  #     Average Transfer Time = 5 ms
  #     Missing Events = 0
  #     Events Rate = 200 events/sec
  #   Remaining 'Fast Events Results'
  #     Max Transfer Time = 10 ms
  #     Min Transfer Time = 2 ms
  #     Average Transfer Time = 5 ms
  #     Missing Events = 0
  #     Events Rate = 200 events/sec
  # """
  @doc false
  def stopEventLogPerf([]) do
    case Code.ensure_compiled(EventLogPerformance) do
      {:module, EventLogPerformance} ->
        IO.puts("Generating Report...")
        EventLogPerformance.stop_test()
        report = EventLogPerformance.generate_report()
        IO.puts("Here is the event log performance report:")
        IO.puts("#{report}")
      {:error, _reason} ->
        IO.puts("This command only works from AppAlpha or from an NMC.")
    end
  end

  # def event_log_performance(_args) do
  #   IO.puts "To start get the event log performance test, run the following command:"
  #   IO.puts "   event_log_performance --start"
  #   IO.puts "To stop the event log performance test and generate a report, run the following command:"
  #   IO.puts "   event_log_performance --stop"
  #   IO.puts "If the event log performance test is not stopped by the user after 5 minutes, it will be stopped automatically."
  # end

  def eval(string_parts) do
    string_parts
    |> Enum.join(" ")
    |> Code.eval_string()
    |> elem(0)
    |> IO.inspect()

    :ok
  end
end
