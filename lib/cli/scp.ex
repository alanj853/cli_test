defmodule CLI.SCP do
  @moduledoc """
  A module to handle the execution of SCP commands.

  The module only handles the download of files from the NMC. User upload of files to the NMC is not supported

  Only the '-f' option is supported for this command. All additional options
  raise an warning error, and are then ignored during the file tranfer.
  """

  require Logger
  import Utils.File

  @typedoc """
  The scp step atoms
  """
  @type(scp_step :: :start_download, :start_upload, :file_details, :file_contents, :acknowledge, :end)

  @typedoc """
  The SCP state map
  """
  @type scp_state :: %{
          :cm => pid(),
          :id => :ssh.channel_id(),
          :base_dir => binary(),
          :error_state => :ok | {:error, binary()},
          optional(:step) => scp_step,
          optional(:file_path) => binary(),
          optional(:file_name) => binary()
        }

  @doc """
   Runs the scp command. Entry point to the module
   Takes a list of the options of the scp command
  """
  def run(args) do
    init(args)
    |> exec()
  end

  @doc """
    Initialises the state map, and parses the scp command option.

    Gets the ConnectionManager PID and the channel id - used for sending messages
    to the SSH connection - and the base directory to be used for SCP from
    process variables.

    The base directory is the same base directory set in the ssh daemon for
    the SFTP subsystem.
  """
  def init(args) do
    with {:ok, dir} <- read_from_process(:base_dir),
         {:ok, user} <- read_from_process(:user),
         {cm, id} <- get_ssh_channel() do
      %{error_state: :ok, cm: cm, id: id, base_dir: dir, user: user}
      |> parse_args(args)
    else
      _ ->
        Logger.error("SCP: Connection channel info not found")
        %{error_state: {:error, "Connection channel info not found"}}
    end
  end

  @doc """
  Reads required keys from the process dictionary. If any key does not exist in
  the process dictionary, the function returns an error.

  ## Examples
      iex> Process.put(:base_dir, "/var/system/pub")
      iex> CLI.SCP.read_from_process(:base_dir)
      {:ok, "/var/system/pub"}

      iex> CLI.SCP.read_from_process(:base_dir)
      :error
  """
  @spec read_from_process(atom() | any()) :: {:ok, any()} | :error
  def read_from_process(key) do
    value = Process.get(key)
    if value == nil, do: :error, else: {:ok, value}
  end

  @doc """
  Parses the arguments passed into the module from the SCP command,
  and adds the data to the state map.

  OpenSSH places all optional arguments at the beginning of the command, so
  the function loops through the list, and ends by parsing the remaining two
  elements in the list as the direction of the file transfer and the file path

  ## Examples
      iex> CLI.SCP.parse_args(%{error_state: :ok, base_dir: "/var/system/pub", user: %{user_type: :admin}}, ["-v", "-f", "ddf.zip"])
      %{
        base_dir: "/var/system/pub/admin",
        error_state: :ok,
        file_path: "/var/system/pub/admin/ddf.zip",
        step: :start_download,
        file_name: "ddf.zip",
        user: %{user_type: :admin}
      }

  """
  @spec parse_args(scp_state() | any(), [binary()] | any()) :: scp_state() | map()
  def parse_args(state, [direction, path]) do
    parse_arg(state, direction)
    |> parse_file_path(path)
  end

  def parse_args(state, [head | rest]) when rest != [] do
    parse_arg(state, head)
    |> parse_args(rest)
  end

  def parse_args(state, args) do
    %{state | error_state: {:error, "SCP: Invalid arguments in SCP command: #{inspect(args)}"}}
  end

  @doc """
  Parses individual scp command options.
  The "-f" and "-t" options are currently supported.
  The "-v" option (verbose) is ignored.
  The "-r" option (recursive copy of a directory) is not supported,
    and returns an error message to inform the user that it is not supported.
  All other options log a warninng and are ignored.

  ## Examples
      iex> CLI.SCP.parse_arg(%{error_state: :ok}, "-f")
      %{error_state: :ok, step: :start_download}

      iex> CLI.SCP.parse_arg(%{error_state: :ok}, "-t")
      %{error_state: :ok, step: :start_upload}

      iex> CLI.SCP.parse_arg(%{error_state: :ok}, "-v")
      %{error_state: :ok}

      iex> CLI.SCP.parse_arg(%{error_state: :ok}, "-r")
      %{error_state: {:error, "SCP: Recursive directory copy is not supported"}}

      iex> CLI.SCP.parse_arg(%{error_state: :ok}, "-nonsense")
      %{error_state: :ok}
  """
  @spec parse_arg(scp_state() | any(), binary() | any()) :: scp_state() | any()
  def parse_arg(state, "-f"), do: Map.put(state, :step, :start_download)
  def parse_arg(state, "-t"), do: Map.put(state, :step, :start_upload)
  def parse_arg(state, "-v"), do: state
  def parse_arg(state, "-r"), do: Map.put(state, :error_state, {:error, "SCP: Recursive directory copy is not supported"})

  def parse_arg(state, option) do
    Logger.warning("SCP: Command called with unsupported option: #{option}")
    state
  end

  @doc """
  Parses the file path, and adjusts the file path based on the user type to get the correct VFS file path

  The function sets an error state if the filename is not "ddf.zip"

  ## Example
      iex> CLI.SCP.parse_file_path(%{error_state: :ok, base_dir: "/var/system/pub", user: %{user_type: :admin}}, "ddf.zip")
      %{
        base_dir: "/var/system/pub/admin",
        error_state: :ok,
        file_path: "/var/system/pub/admin/ddf.zip",
        file_name: "ddf.zip",
        user: %{user_type: :admin}
      }

      iex> CLI.SCP.parse_file_path(%{error_state: :ok, base_dir: "/var/system/pub", user: %{user_type: :admin}}, "other_file_name")
      %{
        base_dir: "/var/system/pub/admin",
        error_state: :ok,
        user: %{user_type: :admin},
        file_name: "other_file_name",
        file_path: "/var/system/pub/admin/other_file_name"
      }
  """
  @spec parse_file_path(scp_state() | map(), binary() | any()) :: scp_state() | map()
  def parse_file_path(state = %{base_dir: dir, user: %{user_type: user_type}}, path) do
    base_dir = dir <> "/#{user_type}"
    file_path = Path.join(base_dir, path)

    state
    |> Map.put(:base_dir, base_dir)
    |> Map.put(:file_path, file_path)
    |> Map.put(:file_name, path)
  end

  def parse_file_path(state, path) do
    Logger.warning("SCP: command called with file #{inspect(path)}. Permission denied")
    Map.put(state, :error_state, {:error, "SCP: Permission Denied"})
  end

  @doc """
  Executes the scp command with the state map from the init() function

  Routes the execution to either the download or upload, and halts execution
  if an error is detected, or if no valid :step value is detected

  """
  def exec(state) do
    EventDispatcher.dispatch(:e_scp_transfer_start, time_stamp: {:log_time, DateTime.utc_now()})

    case state do
      %{error_state: {:error, message}} ->
        send_error(state, message)

      %{step: :start_download} ->
        download_step(%{state | step: :file_details})

      %{step: :start_upload} ->
        upload_loop(%{state | step: :file_details})

      _ ->
        Logger.error("SCP: File direction not specified")
        send_error(state, "SCP Server Error")
    end
  end

  @doc """
  Initiates the execution loop for SCP download of a file from the NMC.
  For a single file (not a directory), there are three stages of sending information:
  1 - Send the file permissions, file length and file name
    e.g. "C0622 23316 ddf.zip"
  2 - Send the file data
  3 - Send an end-of-file

  After each stage, the client should acknowledge receipt of the data with a binary 0

  Each loop consists of checking the error state of the state map, and reading
  an acknowledgement from the client. Once these two conditions are met, the
  download_step function is called, and the output state looped back into another
  iteration of download_loop

  ## Examples:
      iex> CLI.SCP.download_loop(%{step: :end, file_name: "ddf.zip"})
      :ok
  """
  def download_loop(%{step: :end, file_name: file_name}) do
    EventDispatcher.dispatch(:e_file_download_success, file: file_name, interface: "SCP", time_stamp: {:log_time, DateTime.utc_now()})
    Process.sleep(10)
  end

  def download_loop(state = %{file_name: file_name}) do
    with :ok <- state[:error_state],
         [0] <- read(state) do
      state
      |> download_step()
      |> download_loop()
    else
      {:error, msg} ->
        EventDispatcher.dispatch(:e_file_download_failure, file: file_name, interface: "SCP", time_stamp: {:log_time, DateTime.utc_now()})
        send_error(state, msg)

      :timeout ->
        Logger.error("SCP: Timeout in reading from client.")
        send_error(state, "SCP: Client Error")

      message ->
        Logger.error("SCP: Received unexpected message from client: #{inspect(message)}")
        send_error(state, "SCP: Client Error")
    end
  end

  @doc """
  The download step executes single steps in the SCP file download process.
  The three steps are:
   - :file_details - send file details
   - :file_contents - send file contents
   - :acknowledge - acknowledge file transfer
  """
  def download_step(state = %{step: :file_details, file_path: file_path, user: user}) do
    user_type = get_user_type(user)
    user_name = get_user_name(user)

    state =
      if FileManager.allowed_to_read?(file_path, user_type, :scp) do
        ## if the requested file is the config.ini, it will first need to be generated
        FileManager.maybe_generate_config_ini_file(file_path, :scp, %{user_type: user_type, user_name: user_name})

        case File.stat(file_path) do
          {:ok, %{size: file_length}} ->
            file = Path.basename(file_path)
            details = "C0644 " <> Integer.to_string(file_length) <> " " <> file <> "\n"
            write(state, String.to_charlist(details))
            Map.merge(state, %{step: :file_contents, file_length: file_length})

          {:error, reason} ->
            Logger.error("SCP: Requested file was not found: #{inspect(reason)}")
            %{state | error_state: {:error, "Requested file was not found"}}
        end
      else
        Logger.error("SCP download: Permission Denied")
        %{state | error_state: {:error, "SCP download: Permission Denied"}}
      end

    download_loop(state)
  end

  def download_step(state = %{step: :file_contents, file_path: file_path}) do
    File.stream!(file_path, [], 1024)
    |> Stream.map(&write(state, &1))
    |> Stream.run()

    acknowledge(state)
    %{state | step: :acknowledge}
  end

  def download_step(state = %{step: :acknowledge}) do
    %{state | step: :end}
  end

  @doc """
  Initiates the execution loop for SCP upload of a file to the NMC.
  For a single file (not a directory), there are five stages of sending/receiving information:
  1 - Acknowledge the scp command
  2 - Receive the file permissions, e.g. "C0622 23316 ddf.zip"
  3 - Send acknowledge
  4 - Receive the file contents
  5 - Send acknowledge

  Each loop consists of checking the error state of the state map, and sending an
  an acknowledgement to the client. Once these two conditions are met, the
  upload_step function is called, and the output state looped back into another
  iteration of upload_loop

  ## Examples:
      iex> CLI.SCP.upload_loop(%{step: :end, file_name: "file.txt", user: %UserManager.User{}})
      :ok
  """
  def upload_loop(%{step: :end, file_name: file_name, user: user}) do
    user = CommonCore.AuditLogger.Helper.get_user_from_token(user.gql_token)
    FileManager.UploadMonitor.demonitor(self())
    CommonCore.AuditLogger.log(:e_file_upload_successful, %{user: user, filename: Path.basename(file_name)})
  end

  def upload_loop(state) do
    case state[:error_state] do
      :ok ->
        acknowledge(state)

        upload_step(state)
        |> upload_loop()

      {:error, error} ->
        send_error(state, error)
    end
  end

  @doc """
  The upload step executes single steps in the SCP file upload process.
  The three steps are:
   - :file_details - send file details
   - :file_contents - send file contents
   - :acknowledge - acknowledge file transfer
  """
  def upload_step(state = %{step: :file_details, user: user, file_name: file_name}) do
    file_details = read(state, :line)
    audit_user = CommonCore.AuditLogger.Helper.get_user_from_token(user.gql_token)


    state =
      case parse_file_details(file_details) do
        {_permissions, length, origin_filename} ->
          # If the upload directory is specified, but not the target file name, then use the origin file name.
          state = maybe_update_file_name(state, origin_filename)
          file_name = state.file_name
          user_type = get_user_type(user)

          if FileManager.allowed_to_write?(state[:file_path], user_type, :scp) do
            if length <= FileManager.max_file_size() do
              Map.put(state, :length, length)
            else
              CommonCore.AuditLogger.log(:e_file_upload_rejected, %{user: audit_user, filename: Path.basename(file_name)})
              Logger.error("SCP: File #{inspect(state[:file_path])} is too large.")
              %{state | error_state: {:error, "SCP upload: File exceeds the maximum file size of 200 MB."}}
            end
          else
            CommonCore.AuditLogger.log(:e_file_upload_rejected, %{user: audit_user, filename: Path.basename(file_name)})
            Logger.error("SCP: No write permissions for file: #{inspect(state[:file_path])}")
            %{state | error_state: {:error, "SCP upload: Permission Denied"}}
          end

        :timeout ->
          CommonCore.AuditLogger.log(:e_file_upload_unsuccessful, %{user: audit_user, filename: Path.basename(file_name)})
          %{state | error_state: {:error, "SCP Error: Timeout"}}

        {:error, msg} ->
          # In the case of the client sending an error message, do not return an error message,
          # as the client has already printed one.
          CommonCore.AuditLogger.log(:e_file_upload_unsuccessful, %{user: audit_user, filename: Path.basename(file_name)})
          Logger.error("SCP: Received error message from client: #{msg}")
          %{state | error_state: {:error, ""}}

        _ ->
          CommonCore.AuditLogger.log(:e_file_upload_unsuccessful, %{user: audit_user, filename: Path.basename(file_name)})
          %{state | error_state: {:error, "SCP Error: Unknown file details format"}}
      end

    %{state | step: :file_contents}
  end

  def upload_step(state = %{step: :file_contents, file_path: working_path, user: user, file_name: file_name}) do
    file_contents = read(state, state[:length])
    audit_user = CommonCore.AuditLogger.Helper.get_user_from_token(user.gql_token)

    state =
      if file_contents != :timeout do
        working_path = FileManager.update_path(working_path, user.user_type, Map.put(state, :protocol, :scp)) |> to_string()
        real_location = String.trim_leading(working_path, state.base_dir) |> CommonCore.VFSManager.get_real_location()

        if real_location != nil do
          maybe_delete_file(real_location)

          case receive_file(real_location, :write, file_contents, state) do
            :ok ->
              if FileManager.is_config_ini_file?(working_path) do
                ConfigIniManager.file_location() |> ConfigIniManager.read_ini_file(user)
              end

              file_size =
                case File.lstat(real_location) do
                  {:ok, %File.Stat{size: size}} ->
                    size

                  error ->
                    Logger.warning("Error running lstat on #{inspect(real_location)}: #{inspect(error)}")
                    :unknown
                end

              Logger.info("Received #{inspect(file_size)} bytes ::: #{inspect(self())}.")
              state

            :error ->
              CommonCore.AuditLogger.log(:e_file_upload_unsuccessful, %{user: audit_user, filename: Path.basename(file_name)})
              %{state | error_state: {:error, "SCP Error: Server Error"}}
          end
        else
          CommonCore.AuditLogger.log(:e_file_upload_unsuccessful, %{user: audit_user, filename: Path.basename(file_name)})
          %{state | error_state: {:error, "SCP Error: Server Error"}}
        end
      else
        CommonCore.AuditLogger.log(:e_file_upload_unsuccessful, %{user: audit_user, filename: Path.basename(file_name)})
        %{state | error_state: {:error, "SCP Error: Timeout"}}
      end

    Map.merge(state, %{step: :acknowledge, file_contents: file_contents})
  end

  def upload_step(state = %{step: :acknowledge}) do
    %{state | step: :end}
  end

  defp maybe_delete_file(working_path) do
    case exists?(working_path) do
      true ->
        if FileManager.is_symbolic_link?(working_path) do
          case File.read_link(working_path) do
            {:ok, real_location} ->
              rm(real_location)

            error ->
              Logger.error("Error removing symbolic link: #{inspect(error)}")
          end
        else
          rm(working_path)
        end

      false ->
        :ok
    end
  end

  # Error messages from the client begins with "1"
  defp parse_file_details([1 | error_msg]) do
    {:error, to_string(error_msg)}
  end

  defp parse_file_details(input) when is_list(input) do
    file_details =
      input
      |> to_string()
      |> String.trim("\n")
      |> String.split()

    with [permissions, length_string, file_name] <- file_details,
         {length, _remainder} <- Integer.parse(length_string) do
      {permissions, length, file_name}
    else
      :error ->
        Logger.error("SCP: error parsing file length: #{file_details}")
        :error

      _ ->
        Logger.error("SCP: error reading file details: #{file_details}")
        :error
    end
  end

  defp parse_file_details(input) do
    input
  end

  @doc """
    Function to handle cases where the target file name on the NMC is not specified (only the write directory is specified).
    e.g. "scp customer_cert.pem apc@10.216.251.24:ssl/"
    In these cases, join the origin file name to the file path and file name.

    ## Examples:
    iex> CLI.SCP.maybe_update_file_name(%{file_name: "target.txt", file_path: "dir/target.txt"}, "origin.txt")
    %{file_name: "target.txt", file_path: "dir/target.txt"}
    iex> CLI.SCP.maybe_update_file_name(%{file_name: ".", file_path: "dir/."}, "origin.txt")
    %{file_name: "origin.txt", file_path: "dir/origin.txt"}
    iex> CLI.SCP.maybe_update_file_name(%{file_name: "target_dir/", file_path: "target_dir/"}, "origin.txt")
    %{file_name: "target_dir/origin.txt", file_path: "target_dir/origin.txt"}
  """
  def maybe_update_file_name(state = %{file_path: file_path, file_name: file_name}, origin_file_name) do
    cond do
      String.ends_with?(file_name, ".") ->
        state
        |> Map.put(:file_path, String.replace_suffix(file_path, ".", origin_file_name))
        |> Map.put(:file_name, String.replace_suffix(file_name, ".", origin_file_name))

      String.ends_with?(file_name, "/") ->
        state
        |> Map.put(:file_path, Path.join(file_path, origin_file_name))
        |> Map.put(:file_name, Path.join(file_name, origin_file_name))

      true ->
        state
    end
  end

  def receive_file(to_path, mode, recv_data, state) when is_map(state) do
    with {:ok, io_dev} <- FileManager.open_for_write(to_path, [mode, :binary], state, self()) do
      receive_file(to_path, mode, recv_data, io_dev)
    else
      {:error, reason} ->
        Logger.error("Error opening #{inspect(to_path)} to write! reason = #{inspect(reason)}")
        :error
    end
  end

  def receive_file(to_path, _mode, recv_data, io_dev) do
    result =
      case IO.binwrite(io_dev, recv_data) do
        :ok ->
          :ok

        {:error, reason} ->
          Logger.error("Error writing to #{inspect(to_path)} reason = #{inspect(reason)}")
          :error
      end

    _ = File.close(io_dev)
    result
  end

  defp acknowledge(state) do
    write(state, <<0>>)
  end

  defp send_error(state, error) do
    write(state, error <> "\n", 1)
  end

  defp read(state, length \\ 1) when is_integer(length) or length == :line do
    task = Task.async(fn -> IO.binread(length) end)
    Task.await(task, send_receive_timeout())
  catch
    :exit, _ ->
      Logger.error("SCP read timeout. State: #{inspect(state)}")
      :timeout
  end

  # Write binary data or charlist data to the ssh connection
  # Requires the connection manager PID, the channel ID from the state,
  # the message (binary or charlist) and an optional argument of the
  # message type:
  # 0 -> Standard Message
  # 1 -> Error Message
  defp write(state, msg, type \\ 0)

  defp write(%{cm: cm, id: id}, msg, type) when is_list(msg) or is_bitstring(msg) do
    :ssh_connection.send(cm, id, type, msg, send_receive_timeout())
    :ok
  end

  defp send_receive_timeout() do
    with {:ok, list} <- Application.fetch_env(:common_core, CLI.SCP),
         {:ok, value} <- Keyword.fetch(list, :send_receive_timeout) do
      value
    else
      _ ->
        Logger.warning("SCP: Using default value of SCP send/receive timeout")
        10_000
    end
  end

  defp get_ssh_channel() do
    with {:group_leader, exec_pid} <- Process.info(self(), :group_leader),
         {:dictionary, dict} <- Process.info(exec_pid, :dictionary),
         connection_pid <- Keyword.get(dict, :user_drv),
         {{connection_manager, channel_id}, _callback_info} <- :ssh_server_channel.get_print_info(connection_pid) do
      {connection_manager, channel_id}
    else
      _ ->
        Logger.error("SCP: Error getting connection information")
        nil
    end
  end

  defp get_user_type(user) when is_map(user) do
    Map.get(user, :user_type, default_scp_privilege())
  end

  defp get_user_type(_) do
    default_scp_privilege()
  end

  defp get_user_name(user) when is_map(user) do
    Map.get(user, :user_name, default_scp_user_name())
  end

  defp get_user_name(_) do
    default_scp_privilege()
  end

  defp default_scp_privilege() do
    :super_user
  end

  defp default_scp_user_name() do
    "apc"
  end
end
