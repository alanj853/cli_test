#
#  Copyright (c) Schneider Electric 2017, All Rights Reserved.
#
#    $ID$
#
#    @author "Michael Schmidt <michael.k.schmidt@.schneider-electric.com>"
#
defmodule CLI do
  @moduledoc """
    Thin Wrapper over the SSH Daemon module.  Heavily based on example SSH module in the
    erlang docs
    args:
      iex_port - only spawn iex on this port
      cli_port - spawn cli.  will spawn sftp if dir is specified
      sftp_port - only spawn sftp on this port
      cli_mods - List of modules to fetch commands from
      pwdfun - Password function to call

    CLI Process Variables:
      :user - the user who logged in
      :peer_name - the peer who connected
      :prompt - the prompt that should be displayed
      :cwd - the Current working directory
  """
  require Logger
  require Integer
  use GenServer
  alias CLI.Commands
  alias CLI.CommonCommands
  alias CLI.Shell

  @server_name __MODULE__

  @time_to_kill :timer.seconds(1)
  @exit_delay_in_seconds 2
  @kill_attempts 10

  @doc """
  Starts the CLI.
  """
  def start_link(_args \\ []) do
    GenServer.start_link(__MODULE__, [], name: @server_name)
  end

  @doc """
  Starts the diagnostic SSH Daemon on port 3022. Will provide IEx Access.
  """
  def start_diagnostic() do
    config =
      Application.get_env(:common_core, __MODULE__)
      |> Keyword.put(:start_diagnostic, true)

    Application.put_env(:common_core, __MODULE__, config)
    start_interface(:diagnostic)
  end

  @doc """
  Stops the diagnostic SSH Daemon on port 3022.
  """
  def stop_diagnostic() do
    config =
      Application.get_env(:common_core, __MODULE__)
      |> Keyword.put(:start_diagnostic, false)

    Application.put_env(:common_core, __MODULE__, config)
    stop_interface(:diagnostic)
  end

  @doc """
  Function to check if diagnostic can be started
  """
  def can_start_diagnostic?() do
    Application.get_env(:common_core, __MODULE__)[:start_diagnostic]
  end

  def init(_) do
    _ = :ssh.start(:permanent)
    interfaces = CLI.start()
    {:ok, %{interfaces: interfaces, restart_delay_ref: nil}}
  end

  def get_state() do
    GenServer.call(@server_name, :get_state)
  end

  def start_interface(interface, port \\ nil) do
    GenServer.call(@server_name, {:start_interface, interface, port})
  end

  def restart_interface(interface, port \\ nil) do
    GenServer.cast(@server_name, {:restart_interface, interface, port})
  end

  def stop_interface(daemon_name) do
    timeout = @time_to_kill * (@kill_attempts + 1)
    GenServer.call(@server_name, {:stop_interface, daemon_name}, timeout)
  end

  def ssh_process_alive?(), do: Process.whereis(@server_name) != nil

  def ssh_daemon_alive?(daemon) do
    if Process.whereis(@server_name) != nil do
      GenServer.call(@server_name, {:ssh_daemon_alive, daemon}, 15_000)
    else
      false
    end
  end

  @doc """
  Starts the SSH application.  Note as an application it does not need outside supervision
  """
  def start() do
    interfaces_to_start = get_config()
    for interface_config <- interfaces_to_start[:interfaces], do: listen(interface_config, nil)
  end

  @doc """
  Function to return the config for CLI. Allows to only have to configure eth0 SSH/CLI
  settings once in the .exs file, as the same settings are copied for ipv4 as ipv6 for
  that interface.
  """
  def get_config() do
    {interfaces, interfaces_to_start} =
      case Application.fetch_env(:common_core, CLI) do
        {:ok, interfaces_to_start} ->
          {interfaces_to_start[:interfaces], interfaces_to_start}

        :error ->
          Logger.error("Unable to fetch_env :common_core, CLI!!")
          {[], []}
      end

    [eth0_config] =
      Enum.filter(interfaces, fn interface_config ->
        interface_config[:name] == :eth0
      end)

    ipv4_config =
      eth0_config
      |> Keyword.put(:name, :eth0_ipv4)
      |> Keyword.put(:ip_address, :eth0)

    ipv6_config =
      eth0_config
      |> Keyword.put(:name, :eth0_ipv6)
      ## ipv6 address can run on all interfaces
      |> Keyword.put(:ip_address, "::")

    new_interfaces =
      Enum.filter(interfaces, fn interface_config ->
        interface_config[:name] != :eth0
      end)

    new_interfaces = [ipv4_config, ipv6_config] ++ new_interfaces

    Keyword.replace!(interfaces_to_start, :interfaces, new_interfaces)
  end

  def handle_cast({:restart_interface, interface, port}, state) do
    Logger.notice("Attemping to restart #{inspect(interface)}")
    {:reply, _result, new_state} = handle_call({:stop_interface, interface}, :ok, state)

    {:reply, _result, new_state} = handle_call({:start_interface, interface, port}, :ok, %{new_state | restart_delay_ref: nil})

    {:noreply, new_state}
  end

  def handle_call({:ssh_daemon_alive, daemon}, _from, state = %{interfaces: interfaces}) do
    result =
      Enum.any?(interfaces, fn [name: n, daemon_ref: d] ->
        n == daemon && d != nil && daemon_alive?(d)
      end)

    {:reply, result, state}
  end

  def handle_call(:get_state, _from, state) do
    {:reply, state, state}
  end

  @doc """
  Handler to start SSH on an `interface`
  """
  def handle_call({:start_interface, interface, port}, _from, state = %{interfaces: interfaces}) do
    _ = :ssh.start(:permanent)
    ## get list of interfaces from config
    interfaces_to_start = get_config()

    {result, new_interfaces} =
      if interface_exists?(interface, interfaces) do
        [return_value] =
          for interface_config <- interfaces_to_start[:interfaces] do
            name = interface_config[:name]

            if name == interface do
              ref = get_daemon_ref(name, interfaces)

              if ref == nil do
                ## start only the interface `interface`
                listen(interface_config, port)
              else
                Logger.notice("SSH already started on interface '#{inspect(name)}'.")
                [name: name, daemon_ref: ref]
              end
            else
              ## otherwise return :ok
              :ok
            end
          end
          ## filter out the :ok entries from the list
          |> Enum.reject(fn x -> x == :ok end)

        list_of_interfaces =
          for item = [name: name, daemon_ref: _old_ref] <- interfaces do
            ## replace old entry in the interfaces for this interface
            if interface == name do
              return_value
            else
              ## return the rest of the interfaces
              item
            end
          end

        {:ok, list_of_interfaces}
      else
        Logger.warning(
          "Did not start ssh daemon #{inspect(interface)} because there is no configuration specified in the config for this interface."
        )

        {:interface_does_not_exist, interfaces}
      end

    {:reply, result, %{state | interfaces: new_interfaces}}
  end

  # Handler to stop SSH from running on an `interface`
  def handle_call({:stop_interface, interface}, _from, state = %{interfaces: interfaces}) do
    {result, new_interfaces} =
      if interface_exists?(interface, interfaces) do
        list_of_interfaces =
          for daemon = [name: name, daemon_ref: daemon_ref] <- interfaces do
            if name == interface do
              if daemon_ref == nil do
                Logger.warning("ssh daemon #{inspect(name)} is already stopped.")
              else
                stop_daemon(daemon_ref, @kill_attempts)
              end

              [name: name, daemon_ref: nil]
            else
              daemon
            end
          end

        {:ok, list_of_interfaces}
      else
        Logger.warning("Not stopping interface #{inspect(interface)} as it does not exist in this configuration")

        {:interface_does_not_exist, interfaces}
      end

    {:reply, result, %{state | interfaces: new_interfaces}}
  end

  def stop_daemon(daemon_ref, repeat_count \\ 0) do
    if daemon_alive?(daemon_ref) do
      :ssh.stop_daemon(daemon_ref)
      wait(@time_to_kill)

      ## check if daemon is still alive
      if daemon_alive?(daemon_ref) do
        Logger.warning("SSH Daemon kill was unsuccessful. Will try again #{repeat_count} more times.")

        if repeat_count > 0 do
          stop_daemon(daemon_ref, repeat_count - 1)
        else
          Logger.error("Count not kill SSH daemon after #{@kill_attempts} attempts. This could mean ssh will not work")

          false
        end
      else
        Logger.notice("SSH Daemon was killed")
        true
      end
    else
      Logger.notice("SSH Daemon already killed")
      true
    end
  end

  @doc """
  Listen to the specified interface. Port can either be specified as part of `args` or explicitily as the second argument,
  where the value specified in the second argument takes priority if it is not `nil`.
  """
  def listen(args, port \\ nil) do
    name = args[:name] || :no_name
    options = args[:options] || []
    cli_mods = args[:cli_mods] || CommonCommands

    pwdfun =
      case name do
        :second_nmc_server -> &CLI.Password.SecondNMC.pwdfun/4
        :service -> &CLI.Password.Tuner.pwdfun/4
        _ -> &CLI.Password.Default.pwdfun/4
      end

    self_gen_dir = args[:self_gen_dir]
    system_dir = args[:system_dir] || self_gen_dir

    system_dir =
      if !File.exists?("#{system_dir}/ssh_host_rsa_key") or !File.exists?("#{system_dir}/ssh_host_rsa_key.pub") do
        Logger.notice("One or more ssh key(s) does not exist in the #{system_dir} directory. Using self generated key pair in #{self_gen_dir}.")

        unless File.exists?("#{self_gen_dir}/ssh_host_rsa_key") and File.exists?("#{self_gen_dir}/ssh_host_rsa_key.pub") do
          Logger.notice("Generating new RSA key pair...")

          with {:file, {:ok, _}} <- {:file, File.rm_rf(self_gen_dir)},
               {:path, :ok} <- {:path, File.mkdir_p(self_gen_dir)} do
            Utils.SSH.generate_ssh_key_pair(self_gen_dir)
            self_gen_dir
          else
            {:file, {:error, reason, _}} ->
              Logger.error("Unable to delete #{self_gen_dir} directory: #{inspect(reason)}")
              system_dir

            {:path, {:error, reason}} ->
              Logger.error("Unable to create #{self_gen_dir} directory: #{inspect(reason)}")
              system_dir
          end
        else
          self_gen_dir
        end
      else
        system_dir
      end

    if name == :eth0_ipv4 or name == :eth0_ipv6 do
      if system_dir == self_gen_dir do
        Logger.debug("SSH on #{inspect(name)} is using a self-generated RSA key pair (#{inspect(system_dir)}).")

        ## don't show fingerprint for self generated keys
        ConfigManager.set(:"network.console.ssh_key_fingerprint", nil)
      else
        Logger.debug("SSH on #{inspect(name)} is using a customer's own RSA key pair (#{inspect(system_dir)}).")

        ## Set fingerprint for the customer key pair we're using, but only when starting ssh on eth0
        current_fingerprint = Utils.SSH.get_fingerprint("#{system_dir}/ssh_host_rsa_key.pub")
        ConfigManager.set(:"network.console.ssh_key_fingerprint", current_fingerprint)
      end
    end

    system_dir = Path.absname(system_dir) |> to_charlist()
    File.mkdir_p!(system_dir)

    subsystems =
      case args[:sftp_dir] do
        nil ->
          []

        sftp_dir ->
          sftp_dir =
            sftp_dir
            |> to_charlist()

          cwd =
            (args[:sftp_cwd] || "/")
            |> to_charlist()

          file_handler =
            case args[:file_handler] do
              {FileManager, _initial_state} -> {FileManager, %{parent: nil, user: name, session: nil}}
              _ -> {:ssh_sftpd_file, %{}}
            end

          [
            :se_ssh_sftpd.subsystem_spec(
              root: sftp_dir,
              cwd: cwd,
              file_handler: file_handler
            )
          ]
      end

    args_map =
      args
      |> Enum.into(%{})
      |> Map.merge(%{cli_mods: cli_mods, pwdfun: pwdfun, system_dir: system_dir})

    port =
      cond do
        ## force to use port specified, if present
        port != nil ->
          port

        args[:cli_port] != nil ->
          args[:cli_port]

        args[:iex_port] != nil ->
          args[:iex_port]

        args[:sftp_port] != nil ->
          args[:sftp_port]
      end

    port =
      case port do
        port when is_integer(port) and port >= 0 and port < 65_536 ->
          port

        {module, fun, args} ->
          apply(module, fun, args)
      end

    shell_options =
      cond do
        args[:cli_port] != nil ->
          [shell: &CLI.start_shell(&1, &2, args_map), exec: &CLI.start_exec(&1, &2, &3, args_map)]

        args[:iex_port] != nil ->
          [shell: {IEx, :start, []}]

        :else ->
          []
      end

    interface_options =
      case args[:interface] do
        nil ->
          []

        intf ->
          [bind_to_device: intf]
      end

    ipv6_options =
      if name == :eth0_ipv6 do
        [ipv6_v6only: true]
      else
        []
      end

    default_algos = :ssh.default_algorithms()

    {_public_keys, updated_algos} =
      Keyword.get_and_update(default_algos, :public_key, fn
        values when is_list(values) ->
          {values, values ++ [:"ssh-rsa"]}

        values ->
          {values, values}
      end)

    full_options =
      options ++
        interface_options ++
        shell_options ++
        ipv6_options ++
        [
          system_dir: system_dir,
          pwdfun: &CLI.password_func(&1, &2, &3, &4, args_map),
          subsystems: subsystems,
          key_cb: SshCallback,
          preferred_algorithms: updated_algos,
          modify_algorithms: [
            {
              :rm,
              [
                {:cipher, [:"3des-cbc", :"aes256-cbc", :"aes192-cbc", :"aes128-cbc"]},
                {:kex, [:"diffie-hellman-group-exchange-sha1"]},
                {:mac, [:"hmac-sha1-etm@openssh.com", :"hmac-sha1"]}
              ]
            }
          ]
        ]

    # NOTE about `ip_addr`. We really don't want this value to every be set to :any, as this will mean that
    # an SSH daemon will start on 0.0.0.0:<port_no>, which blocks all other ssh daemons on other interfaces
    # starting, if they have the same port number (which is quite likely, as it's normally 22 for all interfaces).
    # So if someone decides to make a change with IPs, please keep the above in mind.

    ip_addr =
      case args[:ip_address] do
        nil ->
          # Implement interface via lookup for now
          # TODO: bind to interface once we are on OTP20
          case args[:interface] do
            nil ->
              :any

            intf ->
              ip_addr =
                :inet.getifaddrs()
                |> elem(1)
                |> List.keyfind(to_charlist(intf), 0)
                |> elem(1)
                |> Keyword.get(:addr)

              ip_addr
          end

        ip_addr when is_binary(ip_addr) ->
          {:ok, ip_addr} =
            ip_addr
            |> to_charlist()
            |> :inet.parse_address()

          ip_addr

        raw_ip when is_tuple(raw_ip) ->
          raw_ip

        :eth0 ->
          case NetworkManager.Ipv4.get_ip("eth0") do
            {:ok, ip_addr} ->
              {:ok, ip_addr} =
                ip_addr
                |> to_charlist()
                |> :inet.parse_address()

              ip_addr

            {:error, error} ->
              Logger.error("Could not get an IPv4 Address to start the SSH Daemon for #{inspect(name)}. Reason: #{inspect(error)}")
          end

        :any ->
          :any
      end

    cond do
      name == :diagnostic and !can_start_diagnostic?() ->
        [name: name, daemon_ref: nil]

      ## only start on eth0 if enabled
      (name == :eth0_ipv4 or name == :eth0_ipv6) && ConfigManager.get(:"network.console.ssh_enable") == :disable ->
        Logger.error("Could not start SSH Daemon for #{inspect(name)} on #{inspect(ip_addr)} on port #{inspect(port)}. Reason: :not_enabled")

        [name: name, daemon_ref: nil]

      true ->
        case :ssh.daemon(ip_addr, port, full_options) do
          {:ok, daemon_ref} ->
            Logger.notice("Successfully started SSH daemon on interface #{inspect(name)}.")
            ## store the daemon reference, provided it is not the diagnostic SSH daemon.
            ## We don't store this as it's not directly part of common_core (or firmware)
            if name != :diagnostic, do: SshTable.set(name, daemon_ref)
            [name: name, daemon_ref: daemon_ref]

          {:error, :eaddrinuse} ->
            Logger.warning("Address is in use for #{inspect(name)}. Attempting to use old daemon ref...")

            ## if address is in use, chances are that the an old daemon is still running. So we try to use that daemon reference
            daemon_ref = SshTable.get(name)
            [name: name, daemon_ref: daemon_ref]

          {:error, error} ->
            Logger.error(
              "Could not start SSH Daemon for #{inspect(name)} on #{inspect(ip_addr)} on port #{inspect(port)}. Reason: #{inspect(error)}"
            )

            ## we need to call this here as there is a bug in erlang ssh where a tcp socket can remain
            ## open even when the daemon crashes/ doesn't start:
            kill_rogue_socket(ip_addr, port)
            ## store the daemon reference as `nil`
            if name != :diagnostic, do: SshTable.set(name, nil)
            [name: name, daemon_ref: nil]
        end
    end
  end

  ## Function to check if an `interface exists in the given list of `interfaces`. Is useful because `interfaces` is actually a list of lists.
  defp interface_exists?(interface, interfaces) do
    new_list =
      for [name: name, daemon_ref: _ref] <- interfaces do
        if name == interface do
          true
        else
          :ok
        end
      end
      ## filter out the :ok entries from the list
      |> Enum.reject(fn x -> x == :ok end)

    case new_list do
      [] -> false
      _not_empty_list -> true
    end
  end

  ## Function to return the :ssh.daemon reference for a given `interface` in a list of `interfaces`
  defp get_daemon_ref(interface, interfaces) do
    new_list =
      for [name: name, daemon_ref: ref] <- interfaces do
        if name == interface do
          ref
        else
          :ok
        end
      end
      ## filter out the :ok entries from the list
      |> Enum.reject(fn x -> x == :ok end)

    case new_list do
      [] -> nil
      [result] -> result
    end
  end

  # function to wait for `time_to_wait` milliseconds. `target_time` set to -1 acts as a trigger to start the wait
  defp wait(time_to_wait) do
    wait_until(time_to_wait + :os.system_time(:millisecond))
  end

  defp wait_until(target_time) do
    current_time = :os.system_time(:millisecond)

    if current_time < target_time do
      wait_until(target_time)
    else
      :ok
    end
  end

  # This may look like a strange way to check if the daemon is runnning, but that is how erlang does it
  # https://github.com/erlang/otp/blob/master/lib/ssh/src/sshd_sup.erl . I would have used erlangs function if it was not private.
  # Doing this initial check is just stop a FunctionClauseError being spat out in the sshd_sup file when it's stop_child function
  # gets an atom as an argument.
  # We also check if the Process is alive ourselves because we trust no one anymore!

  # Note, that from testing, the :list.keyfind/3 function appears very expensive because it take a long time to run, but seems to be effective
  # Maybe we could just switch to Process.alive?/1
  defp daemon_alive?(daemon_ref),
    ## Previous code:
    # do: :lists.keyfind(daemon_ref, 2, Supervisor.which_children(:sshd_sup)) != false or Process.alive?(daemon_ref)

    ## New Code: 08/05/2019 AJ
    ## :lists.keyfind was too computationaly expensive and unnessary, as we were using Process.alive? as backup anyways
    ## if it returned false
    do: Process.alive?(daemon_ref)

  # Map the password_func to the configured function
  def password_func(user, password, peer_addr, state, _args = %{pwdfun: pwdfun}) do
    pwdfun.(to_string(user), to_string(password), peer_addr, state)
  end

  def start_exec(cmd, user_name, peer, %{cli_mods: cli_mods, schema: schema, sftp_dir: base_dir}) do
    user = UserManager.find_user_in_sessions(user_name)

    spawn(fn ->
      # Save the module list in the process dictionary.
      # This is to be used by any command that needs
      # the module list
      Commands.start_command_registry(user.user_type, :exec)
      Enum.into(cli_mods, Commands.init())
      Process.put(:user, user)
      Process.put(:peer_name, peer)
      Process.put(:schema, schema)
      Process.put(:base_dir, base_dir)

      eval_cli(cmd)
    end)
  end

  def start_shell(user, peer, args = %{cli_mods: cli_mods, schema: schema}) do
    spawn(fn ->
      Shell.run(
        user,
        peer,
        cli_mods,
        schema,
        banner: args[:banner],
        before_exit: &delay_exit/0
      )
    end)
  end

  def delay_exit do
    IO.puts("Closing in #{@exit_delay_in_seconds} seconds")

    @exit_delay_in_seconds
    |> :timer.seconds()
    |> :timer.sleep()
  end

  defp contains_unclosed_quotes(line) do
    line
    |> String.split(~s('))
    |> Enum.count()
    |> Integer.is_even() or
      line
      |> String.split(~s("))
      |> Enum.count()
      |> Integer.is_even()
  end

  @doc """
    built in commands are also implemented here
  """
  def eval_cli(line) when is_list(line) do
    eval_cli(to_string(line))
  end

  def eval_cli(line) do
    if contains_unclosed_quotes(line) do
      IO.puts(~s(E102: Parameter Error - unclosed " or '))
    else
      try do
        case line |> Kernel.<>(" \"\"") |> String.trim() |> OptionParser.split() do
          [] ->
            ""

          [command | arg_strings] ->
            if ConfigManager.get(:"security.user_management.super_user.first_sign_on") do
              """
              Please log into the NMC and change the password before executing an SSH command.
              """
              |> IO.puts()
            else
              Commands.run(command, arg_strings)
            end
        end
      rescue
        e in RuntimeError -> IO.puts("Error: Runtime Error: #{inspect(e)}")
      catch
        :exit, error ->
          Logger.error("Caught exit for command: #{inspect(line)}: #{inspect(error)}")
          IO.puts("E100: Command Failed\n")
      end
    end
  end

  ## Will Kill a tcp socket based on ip and port, if it finds one.
  defp kill_rogue_socket(:any, port), do: kill_rogue_socket({0, 0, 0, 0}, port)

  defp kill_rogue_socket(ip, port) do
    ports = :erlang.ports()

    tcp_sockets =
      Enum.filter(ports, fn port ->
        port_info = :erlang.port_info(port)

        unless port_info == :undefined do
          Access.get(port_info, :name) == 'tcp_inet'
        else
          false
        end
      end)

    socket =
      Enum.find(tcp_sockets, fn s ->
        {:ok, {i, p}} = :prim_inet.sockname(s)
        i == ip && p == port
      end)

    unless socket == nil, do: :gen_tcp.close(socket)
  end
end
