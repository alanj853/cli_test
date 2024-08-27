defmodule CLI.Eventlog.Formatter do
  @moduledoc """

  EventLog

  """
  alias TableRex.Table

  @short_line "---------------------------------------------------\n"
  @table_header ~w[Date Time User Event]

  defp format_date_time({date, time}, page) do
    ["\nDate: ", format_date(date), "       ", "Time: ", format_time(time), "       Page: #{page}\n"]
  end

  defp format_date({year, month, day}) do
    "#{day}/#{month}/#{year}"
  end

  def pad(int) do
    if int < 10 do
      "0#{int}"
    else
      "#{int}"
    end
  end

  def format_time({hour, min, sec}) do
    hour = pad(hour)
    min = pad(min)
    sec = pad(sec)
    "#{hour}:#{min}:#{sec}"
  end

  defp format_record(%{"description" => description, "user" => user, "time_stamp" => time_stamp}) do
    [date, time_ext] = String.split(time_stamp, "T")

    [time, _] =
      if String.contains?(time_ext, ".") do
       #"00:16:30.353+01:00" -> "00:16:30"
       String.split(time_ext, ".")
      else
        #"00:16:31+01:00" -> "00:16:31" (1 time out of 1000, no ms)
        String.split(time_ext, "+")
      end

    [date, time, user, description]
  end

  def datetime_to_iso8601({{y, m, d}, {h, mn, s}}) do
    [y, m, d, h, mn, s] = Enum.map([y, m, d, h, mn, s], fn x -> pad(x) end)
    "#{y}-#{m}-#{d}T#{h}-#{mn}-#{s}.000000Z"
  end

  defp body([]), do: []

  defp body(log) do
    log
    |> Enum.map(&format_record/1)
    |> Table.new(@table_header)
    |> Table.render!(
      horizontal_style: :off,
      vertical_style: :off,
      bottom_frame_symbol: " ",
      top_frame_symbol: " "
    )
  end

  def format(log, current_date_time, page) do
    [
      [format_date_time(current_date_time, page), @short_line],
      body(log)
    ]
  end
end
