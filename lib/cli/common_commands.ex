defmodule CLI.CommonCommands do
  @moduledoc """
    Module for CLI commands
  """
  require Logger
  alias TableRex.Table, as: Table
  alias UserManager.User

  @dd_ups_model_name :"ups_system.identity.setting.model_number"
  @dd_ups_serial_number :"ups_system.identity.setting.serial_number"
  @dd_ups_scalable_status :"ups_system.status.scalable_ups_status"
  @query_power_rating "query{hardware{factory{powerRating}}}"
  @query_product_name "query{hardware{factory{productName}} system{device_name_setting}}"
  @query_scalable_power """
  query{
    upsSystem{
      outputSystem{
        general{
          currentApparentPowerRatingKva(includeUnits:true, decimalDigits: 0)
        }
        setting{
          apparentPowerRatingSettingKVa(includeUnits:true, decimalDigits: 0)
        }
      }
    }
  }
  """

  def scp(args) do
    CLI.SCP.run(args)
  end

  def help([arg]) when arg in ["help", "?"] do
    """
    Usage:  help - The list of supported cli commands
            help <command> - equivalent to: <command> help
    """
    |> IO.write()
  end

  def help([command | args]) do
    if String.starts_with?(command, ["?", "-"]) do
      IO.puts("E102: Parameter Error")
      help(["help"])
    else
      Logger.debug(fn -> "help for #{inspect(command)}" end)
      CLI.Commands.help(command, args)
    end
  end

  def help([]) do
    # Split the list of commands in list of maximum 6 elements
    # Put the leftover (last elements) inside an empty list
    rows =
      CLI.Commands.list()
      |> Enum.sort()
      |> Enum.chunk_every(4, 4, ["", "", "", "", ""])

    header = ["System Commands:"]

    # Display the commands in a basic array
    Table.new(rows, header)
    |> Table.render!(vertical_style: :off, horizontal_style: :off)
    |> IO.puts()
  end

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

  def ping([arg]) when arg in ["help", "?"] do
    """
    Usage:  ping <remote_address> -- Run echo request on <remote_address>
    """
    |> IO.write()
  end

  def ping(args) do
    {:ok, pid} =
      Keyword.new(args, fn x -> {:host, x} end)
      |> CLI.Ping.start_link()
    CLI.Ping.run(pid)
  end

  def pwd([]) do
    wd = Process.get(:cwd)

    """
    #{wd}

    """
    |> IO.write()
  end

  def pwd(args) do
    unless args == ["help"] or args == ["?"] do
      IO.write("E102: Parameter Error\n")
    end

    """
    Usage: pwd -- Configuration Options
        pwd

    """
    |> IO.write()
  end

  ## should be the same as dir command
  def ls(args) do
    dir(args, "ls")
  end

  ## command will be either "dir" or "ls".
  def dir(args, command \\ "dir")

  def dir([], command) do
    dir = Process.get(:cwd)
    user_type = Process.get(:user_type)
    path = CommonCore.VFSManager.root_dir(user_type) <> "/#{dir}"

    if FileManager.allowed_to_view?(path, user_type) do
      case File.ls(path) do
        {:ok, listings} ->
          """
          E000: Success
          """
          |> IO.write()

          listings
          |> Enum.sort()
          |> Enum.filter(fn f -> FileManager.allowed_to_view?(path <> "/#{f}", user_type) end)
          |> add_pre_set_dirs()
          |> Enum.filter(fn f -> FileManager.exists?(path <> "/#{f}") end)
          |> Enum.map(fn f -> encode_file_info(path <> "/#{f}") end)
          |> Enum.map(fn f -> IO.write("#{f}\n") end)

          IO.write("\n")

        _ ->
          dir(:error, command)
      end
    else
      dir(:error, command)
    end
  end

  def dir(:error, command) do
    IO.write("E102: Parameter Error\n")
    dir(:help, command)
  end

  def dir(:help, command) do
    """
    Usage: #{command} -- Configuration Options
        #{command}

    """
    |> IO.write()
  end

  def dir(args, command) do
    if args == ["help"] or args == ["?"] do
      dir(:help, command)
    else
      dir(:error, command)
    end
  end

  def cd([]) do
    cd(["help"])
  end

  def cd(["?"]) do
    cd(["help"])
  end

  def cd(["help"]) do
    """
    Usage: cd -- Configuration Options
        cd <directory name>

    """
    |> IO.write()
  end

  def cd(args) do
    if Enum.count(args) > 1 do
      IO.write("E102: Parameter Error\n")
      cd(["help"])
    else
      [dir] = args
      dir = Path.expand(dir, "/")
      user_type = Process.get(:user_type)
      cwd = Process.get(:cwd)
      path =
      user_type
      |> CommonCore.VFSManager.root_dir()
      |> Path.join(cwd)
      |> Path.join(dir)

      if FileManager.allowed_to_view?(path, user_type) and File.dir?(path) do
        Process.put(:cwd, dir)

        """
        E000: Success\n
        """
        |> IO.write()
      else
        IO.write("E102: Parameter Error\n")
        cd(["help"])
      end
    end
  end

  def delete([]) do
    delete(["help"])
  end

  def delete(["?"]) do
    delete(["help"])
  end

  def delete(["help"]) do
    """
    Usage: delete -- Configuration Options
        delete <file name>

    """
    |> IO.write()
  end

  def delete([file = "/"]) do
    Logger.error("Failed to delete #{file}. Reason: #{inspect({:error, :eperm})}")
    IO.write("E100: Command Failed\n")
  end

  def delete(args) do
    if Enum.count(args) > 1 do
      IO.write("E102: Parameter Error\n")
      delete(["help"])
    else
      [file] = args
      cwd = Process.get(:cwd)
      file = Path.expand(file, cwd)
      user_type = Process.get(:user_type)
      path = CommonCore.VFSManager.root_dir(user_type) <> "/#{file}"
      can_delete = FileManager.allowed_to_delete?(path, user_type)
      exists = FileManager.exists?(path)
      deleting_cwd = file == cwd
      is_dir = File.dir?(path)

      if can_delete and exists and !deleting_cwd and !is_dir do
        {:ok, path} = File.read_link(path)
        case File.rm(path) do
          :ok ->
            """
            E000: Success\n
            """
            |> IO.write()

          error ->
            Logger.error("Failed to delete #{file} (real_path=#{path}). Reason: #{inspect(error)}")
            IO.write("E100: Command Failed\n")
        end
      else
        Logger.error("Failed to delete #{file} (real_path=#{path}). can_delete: #{can_delete} exists: #{exists} deleting_cwd: #{deleting_cwd} is_dir: #{is_dir}")
        IO.write("E100: Command Failed\n")
      end
    end
  end

  def eventlog(args) do
    if args == [] do
      CLI.Eventlog.run(args)
    else
      if args != ["help"] and args != ["?"] do
        IO.write("E102: Parameter Error\n")
      end

      """
      Usage eventlog -- Displays the first page of eventlog.
                        The user can then use the following to navigate:
                        E: Exit the eventlog prompt. Return to regular CLI shell
                        R: Refresh the eventlog. Go back to first page
                        N: Next page of the eventlog
                        B: Previous page of the eventlog
                        D: Delete the eventlog (Confirmation required)
      """
      |> IO.write()
    end
  end

  @doc """
    Displays the number of warning/critical/info/total alarms

    Displays the parameter error and usage with an unknown argument

    ## Examples
      iex> CLI.CommonCommands.alarmcount(["-p", "all"])
      E000: Success
       Alarmcount: 0
      :ok
      iex> CLI.CommonCommands.alarmcount(["-p", "warnings"])
      E102: Parameter Error
       Usage: alarmcount -- Alarm severity
          alarmcount [-p <all | warning | critical | informational>]
      :ok
      iex> CLI.CommonCommands.alarmcount(["-p", "warning"])
      E000: Success
       WarningAlarmCount: 0
      :ok

  """
  def alarmcount(args) do
    CLI.Alarmcount.run(args)
    |> IO.puts()
  end

  def about([]) do
    hwf_map = HwFactoryManager.get_hardware_factory_data()
    app_map = AppModuleManager.get_app_module_data()
    management_uptime = TimeManager.uptime_str()

    model_number = hwf_map.nmc_model_number
    hardware_rev = hwf_map.hardware_revision
    manufacturing_date = hwf_map.manufacturing_date
    mac_addr = hwf_map.mac_address
    serial_num = hwf_map.nmc_serial_number

    date = app_map.date
    name = app_map.name
    time = app_map.time
    version = app_map.version

    ups_model_num = CacheManager.get(@dd_ups_model_name)
    ups_serial_num = CacheManager.get(@dd_ups_serial_number)

    product_name_map =
      @query_product_name
      |> Absinthe.run!(CommonCore.CommonSocket.schema())

    product_name = product_name_map[:data]["hardware"]["factory"]["productName"]
    device_name_setting = product_name_map[:data]["system"]["device_name_setting"]

    model_num_label = model_number_label(name)

    scalable_ups_status = CacheManager.get(@dd_ups_scalable_status)

    nmc_core_version = CoreManager.nmc_core_version()

    power_string =
      case scalable_ups_status do
        :enabled ->
          scalable_power_map =
            @query_scalable_power
            |> Absinthe.run!(CommonCore.CommonSocket.schema())

          installed_power = scalable_power_map[:data]["upsSystem"]["outputSystem"]["general"]["currentApparentPowerRatingKva"]
          nominal_power = scalable_power_map[:data]["upsSystem"]["outputSystem"]["setting"]["apparentPowerRatingSettingKVa"]

          """
          Power Rating:           #{nominal_power}
          Installed Power Rating: #{installed_power}
          """

        _ ->
          power_rating_map =
            @query_power_rating
            |> Absinthe.run!(CommonCore.Schema)

          # Add a space between the power rating and "kW" to maintain consistency.
          power_rating =
            String.split_at(power_rating_map[:data]["hardware"]["factory"]["powerRating"], -2)
            |> Tuple.to_list()
            |> Enum.join(" ")

          """
          Power Rating:           #{power_rating}
          """
      end

    ("""
     E000: Success

     Hardware Factory
     ----------------
     Model Number:           #{model_number}
     Serial Number:          #{serial_num}
     Hardware Revision:      #{hardware_rev}
     Manufacture Date:       #{manufacturing_date}
     MAC Address:            #{String.upcase(mac_addr)}
     Management Uptime:      #{management_uptime}

     Application Module
     ------------------
     Name:                   #{name}
     Version:                #{version}
     Core Version:           #{nmc_core_version}
     Date:                   #{date}
     Time:                   #{time}

     UPS Information
     ---------------
     UPS Name:               #{device_name_setting}
     Product Name:           #{product_name}
     """ <>
       power_string <>
       """
       UPS Serial Number:      #{ups_serial_num}
       #{model_num_label}   #{ups_model_num}
       """)
    |> IO.puts()
  end

  def about(args) do
    unless args == ["help"] or args == ["?"] do
      IO.write("E102: Parameter Error\n")
    end

    """
    Usage:  about -- Displays Hardware / Application / UPS Configuration
    """
    |> IO.write()
  end

  defp model_number_label("Galaxy VL"), do: "Commercial Reference:"
  defp model_number_label(_ups_family), do: "UPS Model Number:    "

  def whoami([]) do
    username =
      Process.get(:user)
      |> User.username()

    """
    E000: Success
    #{username}
    """
    |> IO.puts()
  end

  def whoami(args) do
    unless args == ["help"] or args == ["?"] do
      IO.write("E102: Parameter Error\n")
    end

    """
    Usage: whoami --  Display Current User
    """
    |> IO.write()
  end

  def netstat([]) do
    CLI.Netstat.run()
  end

  def netstat(args) do
    unless args == ["help"] or args == ["?"] do
      IO.write("E102: Parameter Error\n")
    end

    """
    Usage: netstat -- Shows all established tcp connections
    """
    |> IO.write()
  end

  @doc """
  -- Generates a self-signed certificate and key pair. Will only work when a customer certifcate and key pair is not in use
  """

  # Generates a self-signed certificate and key pair
  def gencert([]) do
    output =
      unless ConfigManager.get(:"web.cert.type") == :customer do
        WebManager.clear_self_signed_pair()

        result =
          case Utils.SSL.generate_self_signed_cert_and_key() do
            :ok ->
              EventDispatcher.dispatch(:e_ssl_new_ss_cert, time_stamp: {:log_time, DateTime.utc_now()})
              Logger.warning("Successfully regenerated a new self-signed cert and key pair")

              """
              E000: Success
              Successfully regenerated a new self-signed cert and key pair\n
              """

            error ->
              ## Should on ever get here
              Logger.error("Failed to regenerate a new self-signed cert and key pair: Error: #{inspect(error)}")
              nil
          end

        WebManager.restart_endpoint()
        result
      else
        Logger.warning("Customer cert-key pair in use, not generating self-signed pair")

        """
        E101: Did not generate self-signed certificate and key pair.
        Customer certificate and key pair in use.\n
        """
      end

    unless output == nil, do: IO.write(output)
  end

  # Help and error message for gencert command
  def gencert(args) do
    unless args == ["help"] or args == ["?"] do
      IO.write("E102: Parameter Error\n")
    end

    """
    Usage:  gencert -- Generates a self-signed certificate and key pair. Will only work when a customer certificate and key pair is not in use.\n
    """
    |> IO.write()
  end

  defp encode_file_info(file) do
    case File.stat(file) do
      {:ok, %{type: :directory, mtime: {{year, month, date}, {_hour, _min, _sec}}, access: _, size: _size}} ->
        # size is treated as 0 for dirs on Rhodes 2
        size = 0
        size = size |> to_string() |> String.pad_leading(12)
        date = date |> to_string() |> String.pad_leading(2, "0")
        month = month |> as_string()

        # Copy Rhodes II formatting
        file_name =
          case Path.basename(file) do
            ".." -> "../"
            "." -> "./"
            file_name -> file_name
          end

        "#{size} #{month} #{date}  #{year}  #{file_name}"

      {:ok, %{type: _, mtime: {{_year, month, date}, {hour, min, _sec}}, access: _, size: size}} ->
        size = size |> to_string() |> String.pad_leading(12)
        date = date |> to_string() |> String.pad_leading(2, "0")
        hour = hour |> to_string() |> String.pad_leading(2, "0")
        min = min |> to_string() |> String.pad_leading(2, "0")
        month = month |> as_string()
        "#{size} #{month} #{date} #{hour}:#{min}  #{Path.basename(file)}"

      {:error, _reason} ->
        ## File might be a symbolic link
        case :file.read_link_info(file) do
          {:ok,
           {_, size, _type, _access, _atime, {{_year, month, date}, {hour, min, _sec}}, _ctime, _mode, _links, _major_device, _minor_device,
            _inode, _uid, _gid}} ->
            size = size |> to_string() |> String.pad_leading(12)
            date = date |> to_string() |> String.pad_leading(2, "0")
            hour = hour |> to_string() |> String.pad_leading(2, "0")
            min = min |> to_string() |> String.pad_leading(2, "0")
            month = month |> as_string()
            "#{size} #{month} #{date} #{hour}:#{min}  #{Path.basename(file)}"

          {:error, _reason} ->
            ""
        end
    end
  end

  defp as_string(1), do: "Jan"
  defp as_string(2), do: "Feb"
  defp as_string(3), do: "Mar"
  defp as_string(4), do: "Apr"
  defp as_string(5), do: "May"
  defp as_string(6), do: "Jun"
  defp as_string(7), do: "Jul"
  defp as_string(8), do: "Aug"
  defp as_string(9), do: "Sep"
  defp as_string(10), do: "Oct"
  defp as_string(11), do: "Nov"
  defp as_string(12), do: "Dec"

  defp add_pre_set_dirs(list), do: ["./", "../"] ++ list
end
