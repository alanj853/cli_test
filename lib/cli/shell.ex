defmodule CLI.Shell do
  use CLI.PromptCommand
  require Logger
  alias CLI.Commands
  alias CLI.Password.Change, as: PasswordChange
  alias CLI.PromptCommand
  alias CLI.SerialShellMonitor
  alias TableRex.Table
  alias UserManager.Policy
  alias UserManager.User

  @typedoc """
  Options available to the shell

  * `prompt` - The prompt that will be displayed to the user
  * `before_exit` - a 0-arity function that will be run right before the shell exits
  * `banner` - a function taking t:User.t/0 and returning a String to display when
               the shell starts
  """
  @type option ::
          {:before_exit, (() -> term)}
          | {:prompt, charlist() | String.t()}
          | {:banner, (User.t() -> String.t())}
  @type username :: charlist() | binary()
  @type session :: String.t()
  @type peer :: String.t()

  defstruct mods: [],
            prompt: 'apc> ',
            before_exit: &__MODULE__.noop/0,
            user: nil

  # spec run(username() | {username(), session()} | {username(), session(), UserManager.User(), peer(), [Commands.id()], Absinthe.Schema.t(), keyword(option)) :: {:error, any()} | any()
  def run(user, peer, mods, schema, options \\ [])

  def run(user, peer, mods, schema, options) when is_list(user) do
    {to_string(user), nil}
    |> run(peer, mods, schema, options)
  end

  def run(user, peer, mods, schema, options) when is_binary(user),
    do: run({user, nil}, peer, mods, schema, options)

  # this function clause if for not breaking the SSH shell authorisation. Once SSH shall invoke
  # run({username, session, user}, peer, mods, schema, options) clause, where user is of type %UserManager.User, this function
  # clause would not be needed.
  # ToDo: alter the CLI.start_shell() so it'd accepts %UserManager.User struct, that is returned by UserManager.login() as user parameter.
  def run({user_name, nil}, peer, mods, schema, options) do
    # We shall now attempt finding user on the list of already established SSH sessions.
    # At this stage the user has already been authorised.
    user = UserManager.find_user_in_sessions(user_name)

    run({user_name, nil, user}, peer, mods, schema, options)
    {:error, :invalid_user}
  end

  def run({username, session, user}, peer, mods, schema, options) do
    if is_nil(user) do
      {:error, :invalid_user}
    else
      user_type = Map.get(user, :user_type)

      # Not using Map.get(user, :first_sign_on): Users that are not super_user do not hava a :first_sign_on element
      first_sign_on = ConfigManager.get(:"security.user_management.super_user.first_sign_on")
      current_password = Map.get(user, :current_password)

      if user_type == :super_user and first_sign_on and
           Bcrypt.verify_pass("apc", current_password) do
        case PasswordChange.run([user, "apc"]) do
          {:error, reason, _} ->
            IO.puts("Reason: #{reason}\n")
            Logger.warning("Failed to change password #{reason}")
            run(username, peer, mods, schema, options)
            :error

          {:error, reason} ->
            IO.puts("Reason: #{reason}\n")
            Logger.warning("Failed to change password #{reason}")
            run(username, peer, mods, schema, options)
            :error

          {:ok, _} ->
            ConfigManager.set(:"security.user_management.super_user.first_sign_on", false)

            PromptCommand.run(__MODULE__, [{user, session}, peer, mods, schema, options],
              timeout: User.session_timeout(user)
            )

          _ ->
            # This should be unreachable with the current implemenation of CLI.Password.Change
            Logger.warning("Failed to change password")
            :error
        end
      else
        if Policy.password_expired?(user) do
          case PasswordChange.run([user]) do
            {:ok, _new_password} ->
              IO.puts("Password successfully changed")

              PromptCommand.run(__MODULE__, [{user, session}, peer, mods, schema, options],
                timeout: User.session_timeout(user)
              )

            {:error, reason} ->
              IO.puts("Reason: #{reason}\n")
              :error

            {:error, reason, _} ->
              IO.puts("Reason: #{reason}\n")
              :error
          end
        else
          PromptCommand.run(__MODULE__, [{user, session}, peer, mods, schema, options],
            timeout: User.session_timeout(user)
          )
        end
      end
    end
  end

  def init([user, peer, mods, schema, options]) do
    ## This is only necessary with Terminal (a.k.a Serial). SSH has its own monitoring
    if peer == "Terminal" do
      self() |> SerialShellMonitor.set_serial_shell_pid()
    end

    # Save the module list in the process dictionary.
    # This is to be used by any command that needs
    # the module list
    user =
      case user do
        {user, session_id} ->
          ## should go here when run from serial CLI
          Process.put(:session_id, session_id)
          user

        user ->
          ## should go here when run from ssh CLI (SSH starts CLI in different way to Serial)
          user
      end

    Commands.start_command_registry(user.user_type, :shell)
    Process.put(:user, user)
    Process.put(:user_type, user.user_type)
    Process.put(:cwd, "/")
    Process.put(:peer_name, peer)
    Process.put(:schema, schema)

    # Adds commands to registry, see: common_core/lib/cli/commands.ex - defimpl Collectable
    Enum.into(mods, Commands.init())

    gl = Process.group_leader()
    command_list = Commands.list() |> Enum.map(&to_charlist/1)
    :io.setopts(gl, encoding: :latin1, expand_fun: &expand(&1, command_list))

    {current_banner, current_bannerlerss_options} =
      case Keyword.pop(options, :banner) do
        {nil, bannerlerss_options} -> {&banner/1, bannerlerss_options}
        {popped_banner, popped_bannerlerss_options} -> {popped_banner, popped_bannerlerss_options}
      end

    shell = List.foldl(current_bannerlerss_options, %__MODULE__{mods: mods}, &add_option/2)

    :io.format(current_banner.(user))

    {:ok, shell}
  rescue
    error ->
      {:error, error}
  end

  def handle_prompt(%{prompt: prompt}) do
    prompt
  end

  def handle_command(command, state) do
    command
    |> CLI.eval_cli()
    |> handle_command_status(state)
  end

  def noop do
  end

  defp add_option({:before_exit, before_exit}, state) do
    %{state | before_exit: before_exit}
  end

  defp add_option({:prompt, prompt}, state) do
    %{state | prompt: to_charlist(prompt)}
  end

  defp add_option(unknown_option, state) do
    Logger.error(fn -> "Unknown CLI.Shell Option #{inspect(unknown_option)}" end)
    state
  end

  defp handle_command_status(result, %{before_exit: before_exit} = state) do
    case result do
      :exit ->
        before_exit.()
        {:exit, :ok, state}

      :ok ->
        {:ok, state}

      {:error, message} ->
        Logger.debug(fn -> "An Error Occured: #{inspect(message)} \n" end)
        {:ok, state}

      "" ->
        {:ok, state}

      _ ->
        Logger.debug(fn -> "'--> #{inspect(result)}\n" end)
        {:ok, state}
    end
  end

  def expand(char_list, command_list) when is_list(char_list) do
    prefix = :lists.reverse(char_list)

    case longest_prefix(command_list, prefix) do
      {:prefix, p, [_]} ->
        {:yes, p ++ ' ', []}

      {:prefix, '', m} ->
        {:yes, '', m}

      {:prefix, p, m} ->
        {:yes, p, m}

      {:none, _m} ->
        {:no, '', []}
    end
  end

  @doc """
  longest prefix in a list, given a prefix.  Taken from the SSH example module
  """
  def longest_prefix(list, prefix) do
    match_command_list =
      for command <- list, :lists.prefix(prefix, command) do
        command
      end

    case match_command_list do
      [] ->
        {:none, list}

      [s | rest] ->
        new_prefix_0 =
          :lists.foldl(
            fn a, p ->
              common_prefix(a, p, [])
            end,
            s,
            rest
          )

        new_prefix = nthtail(length(prefix), new_prefix_0)
        {:prefix, new_prefix, [s | rest]}
    end
  end

  @doc """
  the longest common prefix of two strings.  Taken from the SSH example module
  """
  def common_prefix([c | r1], [c | r2], acc) do
    common_prefix(r1, r2, [c | acc])
  end

  def common_prefix(_, _, acc) do
    :lists.reverse(acc)
  end

  @doc """
  nthtail as in lists, but no badarg if n > the length of list
  """
  def nthtail(0, a), do: a
  def nthtail(n, [_ | a]), do: nthtail(n - 1, a)
  def nthtail(_, _), do: []

  defp bool_to_enabled_disabled(true), do: "enabled"
  defp bool_to_enabled_disabled(_false), do: "disabled"

  defp top_table(version, product_name) do
    year = AppModuleManager.get_app_module_data() |> Map.get(:copyright_year)

    [
      ["Schneider Electric", "Network Management Card 4", version],
      ["(c) Copyright #{year}", "All Rights Reserved", product_name]
    ]
    |> Table.new()
    |> Table.put_column_meta(2, align: :right)
    |> Table.render!(vertical_style: :off, bottom_frame_symbol: "-", top_frame_symbol: "")
  rescue
    TableRex.Error ->
      Logger.warning("Failed to render CLI Table heading")
  end

  defp protocol_table() do
    header = ["Protocol", "Status", "Protocol", "Status", "Protocol", "Status"]

    [
      [
        "IPv6",
        bool_to_enabled_disabled(ConfigManager.get("network.ipv6.enable")),
        "IPv4",
        bool_to_enabled_disabled(ConfigManager.get("network.ipv4.enable")),
        "Ping",
        Atom.to_string(ConfigManager.get("security.ping.enable_ipv4_ping_response")) <> "d"
      ],
      [
        "HTTP",
        Atom.to_string(ConfigManager.get("web.settings.http_enable")) <> "d",
        "HTTPS",
        Atom.to_string(ConfigManager.get("web.settings.https_enable")) <> "d",
        "FTP",
        Atom.to_string(ConfigManager.get("ftp.server_active")) <> "d"
      ],
      [
        "SSH/SFTP/SCP",
        Atom.to_string(ConfigManager.get("network.console.ssh_enable")) <> "d",
        "SNMPv1",
        Atom.to_string(ConfigManager.get("snmp.v1_enable")) <> "d",
        "SNMPv3",
        Atom.to_string(ConfigManager.get("snmp.v3_enable")) <> "d"
      ],
      [
        "Modbus TCP",
        bool_to_enabled_disabled(ConfigManager.get("modbus.tcp.access")),
        "EAPoL",
        Atom.to_string(ConfigManager.get("network.eapol.status")) <> "d",
        "",
        ""
      ]
    ]
    |> TableRex.quick_render!(header)
  rescue
    RuntimeError ->
      Logger.warning("Failed to render Protocol Table")
  end

  @query """
  query {
    system {
      version
      description
      contact
      device_name_setting
      location
    },
    hardware{
      factory{
        product_name
      }
    }
  }
  """
  @spec banner(User.t() | any) :: [String.t() | any()]
  def banner(user) do
    app_map = AppModuleManager.get_app_module_data()
    version = app_map.version

    %{
      data: %{
        "system" => %{
          "description" => _app_name,
          "contact" => sys_contact,
          "device_name_setting" => device_name,
          "location" => sys_location
        },
        "hardware" => %{
          "factory" => %{
            "product_name" => product_name
          }
        }
      }
    } = Absinthe.run!(@query, CommonCore.Schema, context: %{user: user})

    # Schneider Electric        Network Management Card 4      Unknown Version
    # (c) Copyright 2020 All Rights Reserved               Galaxy VS 100kW
    # -------------------------------------------------------------------------------
    # Name      : Unknown Name                              Date : 01/31/2020
    # Contact   : Unknown Contact                           Time : 15:53:58
    # Location  : Unknown Location                          User : apc
    # Up Time   : 0 Days 0 Hours 1 Minutes                  Type : super_user
    #
    #
    # Type help for command listing

    rows =
      [
        ["UPS Name", device_name, "Date", TimeManager.date_str()],
        ["Contact", sys_contact, "Time", TimeManager.time_str()],
        ["Location", sys_location, "User", User.username(user)],
        ["Up Time", TimeManager.uptime_str(), "Type", User.usertype(user)]
      ]

        [
          top_table(version, product_name)
        ] ++
        for row <- rows do
          :io_lib.format("~.10s: ~.41s ~.5s: ~.16s~n", row)
        end ++
        [
          "\n" <> protocol_table()
        ] ++
        [
          "\nType help for command listing\n"
        ]
  rescue
    error ->
      Logger.error("Couldn't execute Absinthe query: #{inspect(error)}")
      []
  end
end
