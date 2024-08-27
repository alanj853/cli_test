defmodule CLI.Netstat do
  @moduledoc """
  Run the Netstat command
  """

  def run() do
    # Shows all ESTABLISHED tcp connections
    cmd = "-tn"

    ip_list = ~w[:1883 :8883 169.254.0. 169.254.2. 169.254.3. 169.254.4. 169.254.5. 169.254.6. 169.254.7. 169.254.8. 169.254.9.]

    MuonTrap.cmd("netstat", [cmd])
    |> elem(0)
    |> String.split("\n")
    # Removes IPs that are in ip_list
    |> Enum.each(fn line ->
      unless String.contains?(line, ip_list) do
        IO.puts(line)
      end
    end)
  end
end
