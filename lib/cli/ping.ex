defmodule CLI.Ping do
  use GenServer
  require Logger

  alias Utils.Ping

  @moduledoc """
      Run the PING command
  """

  @doc """
      Performs a ping command

      Argument 1: The address you want to ping (default: "127.0.0.1")
      Argument 2: The number of times you want to ping it (default: 2)

      ===========================================
      Example 1: Without any arguments passed in
      ===========================================

      CLI.Ping.start_link

      ===========================================
      Example 2: With both arguments passed in
      ===========================================

      CLI.Ping.start_link [addr: "192.168.1.23", count: 5]

      ===========================================
      Example 3: With one argument passed in.
                 (Will ping that address 2 times)
      ===========================================

      CLI.Ping.start_link [addr: "192.168.1.23"]

      ===========================================
      Example 4: With one argument passed in.
                 (Will ping 127.0.0.1 5 times)
      ===========================================

      CLI.Ping.start_link [count: 5]
  """

  def start_link(args) do
    GenServer.start_link(__MODULE__, args)
  end

  def init(args) do
    host  =  Keyword.get(args, :host, "127.0.0.1")
    count =  Keyword.get(args, :count, 4)

    {:ok, %{count: count, host: host, status: :ok}}
  end

  def run(pid) do
    # There might be up to three resolvers specified for either IPv4 or IPv6.
    # Each can be attempted 2 times (default) and each attempt can take up to 5[s] (default).
    # 3*2*5 = ~30[s]. In addition to that  On lces2 timeout, for non-resolvable host name' with two resolvers takes 19[s].
    # Multiplied by the ping attempts = 4 gives circa 60[s] with three (maximum supported resolvers) 30*4 = 120[s].
    # We shall allow twice as much time for the ping command's completion.
    GenServer.call(pid, :run, 240_000)
  end

  def handle_call(:run, from, state = %{count: count, host: host}) do
    new_state = Map.put(%{state | count: count - 1}, :reply, from)
    ping_results = Ping.ping(host)

    Process.send(self(), {from, {:data, ping_results}}, [])
    Process.send_after(self(), :ping, 1_000, [])

    {:noreply, new_state}
  end

  defp address_tuple_to_string(_ipv4 = {a, b, c, d}) do
    "#{a}.#{b}.#{c}.#{d}"
  end

  defp address_tuple_to_string(address) do
    Logger.warning("Unsupported IP address format: #{inspect(address)}")
    ""
  end

  def handle_info({_port, {:exit_status, status}}, state = %{reply: from}) do
    case status do
      :ok ->
        Logger.debug("PING status: #{status}")
        IO.puts("")

      :timeout ->
        Logger.error("Ping status: #{status}:\tPing request timed out.")

        IO.puts("E100: Command Failed\nPing request timed out\nUsage: \tping -- Configuration Options\n\tping <IP or DNS Address>")

      :nxdomain ->
        Logger.error("PING status: #{status}:\tIP/Domain does not exist.")

        IO.puts("E100: Command Failed\nIP/Domain does not exist.\nUsage: \tping -- Configuration Options\n\tping <IP or DNS Address> [count]")

      :unreach_net ->
        Logger.error("PING status: #{status}:\tIP/Network unreachable.")
        IO.puts("E100: Command Failed\nIP/Network unreachable.\nUsage: \tping -- Configuration Options\n\tping <IP or DNS Address> [count]")

      :unreach_host ->
        Logger.error("PING status: #{status}:\tIP/Network unreachable.")
        IO.puts("E100: Command Failed\nIP/Host unreachable.\nUsage: \tping -- Configuration Options\n\tping <IP or DNS Address> [count]")

      _ ->
        Logger.error("PING Exited: #{status}")
        IO.puts("E100: Command Failed")
    end

    GenServer.reply(from, :ok)

    {:stop, :normal, state}
  end

  #  Response = {ok, Host, Address, ReplyAddr, Details, Payload}
  #              | {error, ICMPError, Host, Address, ReplyAddr, Details, Payload}
  #              | {error, Error, Host, Address}
  #          Details = {Id, Sequence, TTL, Elapsed}
  #          Elapsed = int() | undefined
  #          Payload = binary()
  #          ICMPError = unreach_host | timxceed_intrans
  #          Error = timeout | inet:posix()
  def handle_info(
        {_port,
         {:data,
          response = {
            :ok,
            _host,
            address,
            _reply_address,
            _details = {_id, _sequence, _ttl, elapsed},
            _payload
          }}},
        state
      ) do
    Logger.debug("PING: #{inspect(response)}")

    # DESIRED OUTPUT Message Format to SSH Console:
    #    Reply from 10.216.254.84: time(ms)= <10
    if is_integer(elapsed) do
      cond do
        elapsed <= 10 ->
          IO.puts("Reply from #{address_tuple_to_string(address)}: time(ms)= <10")

        elapsed > 10 and elapsed < 50 ->
          IO.puts("Reply from #{address_tuple_to_string(address)}: time(ms)= >10")

        elapsed >= 50 ->
          IO.puts("Reply from #{address_tuple_to_string(address)}: time(ms)= #{elapsed}")
      end
    end

    {:noreply, %{state | status: :ok}}
  end

  # Handling errors like for example:
  #   {:error, :timeout, 'www.google6.com', {95, 211, 117, 215}}
  #   {:error, :nxdomain, 'hep', :undefined}
  def handle_info({_port, {:data, response = {:error, error, _host, _address}}}, state) do
    Logger.debug("Ping response: #{inspect(response)}")

    {:noreply, %{state | status: error}}
  end

  # Handling errors like for example:
  #   {:error, unreach_net, '0.1.1.1', {0, 1, 1, 1}, {192, 168, 237, 2}, {60820, 0, 128, :undefined}, <<69, 0, 0, ...>>}
  def handle_info(
        {_port,
         {:data,
          response = {
            :error,
            icmp_error,
            _host,
            _address,
            _reply_address,
            _details = {_id, _sequence, _ttl, _elapsed},
            _payload
          }}},
        state
      ) do
    Logger.debug("Ping response: #{inspect(response)}")

    {:noreply, %{state | status: icmp_error}}
  end

  def handle_info({_port, {:data, response}}, state) do
    Logger.warning("PING - Unknown response #{inspect(response)}")

    {:noreply, state}
  end

  def handle_info(:ping, state = %{reply: from, count: 0, host: _host, status: status}) do
    Process.send(self(), {from, {:exit_status, status}}, [])

    {:noreply, state}
  end

  def handle_info(:ping, state = %{reply: from, count: count, host: host}) do
    ping_results = Ping.ping(host)
    Process.send(self(), {from, {:data, ping_results}}, [])
    Process.send_after(self(), :ping, 1_000, [])

    {:noreply, %{state | count: count - 1}}
  end
end
