defmodule CLI.Alarmcount do
  @moduledoc """
    Run the alarmcount command

    # Valid options

      -p all
      View the total number of active alarms.

      -p critical
      View the number of active critical alarms

      -p warning
      View the number of active warning alarms

      -p informational
      View the number of active informational alarms
  """
  alias Modbus.Bridge
  require Logger

  @usage "Usage: alarmcount -- Alarm severity \n    alarmcount [-p <all | warning | critical | informational>]"
  @alarm_count "Alarmcount:"
  @warning_count "Warning Alarm Count:"
  @critical_count "Critical Alarm Count:"
  @info_count "Informational Alarm Count:"

  @success "E000: Success\n"
  @parameter_error "E102: Parameter Error\n"

  @doc """
  executes the alarm count and returns an IO List ready for printing
  """
  @spec run([any()] | any()) :: [any()]
  def run(args) do
    args
    |> OptionParser.parse(aliases: [p: :level], strict: [level: :string])
    |> execute()
    rescue
      error ->
        Logger.error("Error parsing #{inspect args}. Reason: #{inspect error}")
        [@parameter_error, @usage]
  end

  #Usage: "alarmcount help"
  defp execute({_, [arg], _}) when arg in ["help", "?"] do
    [@usage]
  end

  #Expected option: "alarmcount -p 'level'"
  defp execute({[level: level], [], []}) do
    alarm_map = Bridge.get_alarm_count_by_severity()

    case level do
      "all" ->
        [
          @success,
          @alarm_count,
          Integer.to_string(alarm_map.critical + alarm_map.info + alarm_map.warning)
        ]

      "warning" ->
        [@success, @warning_count, Integer.to_string(alarm_map.warning)]

      "critical" ->
        [@success, @critical_count, Integer.to_string(alarm_map.critical)]

      "informational" ->
        [@success, @info_count, Integer.to_string(alarm_map.info)]

      _ ->
        [@parameter_error, @usage]
    end
    |> Enum.intersperse(" ")
  end

  #Unknown option: "alarmcount -X all"
  defp execute({_, [], [{_, _}]}) do
    [@parameter_error, @usage]
  end

  #No option: "alarmcount"
  defp execute({[], [], []}) do
    alarm_map = Bridge.get_alarm_count_by_severity()
    [
      @success,
      @alarm_count,
      Integer.to_string(alarm_map.critical + alarm_map.info + alarm_map.warning)
    ]
    |> Enum.intersperse(" ")
  end

  defp execute(_) do
    [@parameter_error, @usage]
  end
end
