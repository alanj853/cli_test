defmodule CLI.Rhodes2 do
  import GraphQL.CLIUtil

  alias NetworkManager.EAPoL, as: EAPoL
  require Logger

  def __cmd_list() do
    [
      "user",
      "system",
      "userdflt",
      "web",
      "ssh",
      "boot",
      "dns",
      "eapol",
      "tcpip",
      "tcpip6",
      "snmp",
      "snmpv3",
      "smtp",
      "modbus",
      "email",
      "date",
      "snmptrap",
      "session",
      "resetToDef",
      "uio"
    ]
  end

  @success "E000: Success"

  defp all(:get, data, next) do
    data
    |> Enum.map(next)
  end

  def up_the_atom(value) when is_atom(value),
    do:
      value
      |> Atom.to_string()
      |> String.upcase()
      |> String.to_atom()

  def up_the_atom(value), do: value

  # 1. Get the user defaults settings
  # 2. Transform them from Map to Keyword list
  #     This is clunky, because:
  #       a- The keys in the map are snake_case and need to be camelCase in the Keyword
  #       b- The atom values in the map are lower case need to be upper case in the Keyword
  # 3  Overwrite the default Keyword list with the keypairs entered on the CLI
  #      (password and confirm password need to be there and need to be indentical)
  def add_defaults(parsed) do
    if Keyword.has_key?(parsed, :newPassword) and Keyword.has_key?(parsed, :confirmPassword) and
         Keyword.fetch(parsed, :newPassword) == Keyword.fetch(parsed, :confirmPassword) do
      defaults_map = ConfigManager.get(:"security.user_management.defaults")

      # sessionTimeout is stored either as a number or {number, "minutes}
      {sessionTimeout, _} = UserManager.session_timeout(:dontcare)

      defaults_keywords =
        Keyword.new([
          {:accessEnable, get_in(defaults_map, [:access_enable]) |> up_the_atom()},
          {:logExportFormat, get_in(defaults_map, [:log_export_format]) |> up_the_atom()},
          {:sessionTimeout, sessionTimeout},
          {:temperatureScale, get_in(defaults_map, [:temperature_scale]) |> up_the_atom()},
          {:userDescription, get_in(defaults_map, [:user_description])},
          {:userType, get_in(defaults_map, [:user_type]) |> up_the_atom()}
        ])

      Keyword.merge(defaults_keywords, parsed)
    else
      """
      E102: Parameter Error
      To create a new user, or to change the password of an existing one:
      Both the new password (-p) and confirm password (-c) need to be present and need to match
      """
      |> IO.puts()

      :error
    end
  end

  def check_password(parsed) do
    if Keyword.has_key?(parsed, :password) do
      if Keyword.has_key?(parsed, :confirm_password) and Keyword.fetch(parsed, :password) == Keyword.fetch(parsed, :confirm_password) do
        :ok
      else
        """
        E102: Parameter Error
        To change the password:
        Both the new password (-w) and confirm password (-d) need to be present and need to match
        """
        |> IO.puts()

        :error
      end
    end
  end

  # takes in ISO8601 format string from time.date_time data
  # dictionary query and splits into a tuple of format:
  # {date, time, utc_offset}
  # Note time only keeps the HH:MM:SS part.
  # def parse_date_time(<<date :: binary-size(10)>> <> "T" <> <<time :: binary-size(8)>> <> << _microseconds :: binary-size(7)>> <> utc_offset) do
  #   {date, time, utc_offset}
  # end
  def parse_date_time(<<date::binary-size(10)>> <> "T" <> <<time::binary-size(8)>> <> rest) do
    # This part is needed to handle the fact that the milliseconds portion of the date_time string is not
    # a constant number of characters long, so the separation of the utc_offset from the ms value requires
    # a split at one of the characters found at the start of the utc_offset
    char_list = String.graphemes(rest)

    {_ms, utc_offset} =
      cond do
        String.contains?(rest, "+") ->
          String.split_at(rest, Enum.find_index(char_list, fn x -> x == "+" end))

        String.contains?(rest, "-") ->
          String.split_at(rest, Enum.find_index(char_list, fn x -> x == "-" end))

        # this is the returned utc_offset when offset is 00:00
        String.contains?(rest, "Z") ->
          String.split_at(rest, Enum.find_index(char_list, fn x -> x == "Z" end))
      end

    {date, time, utc_offset}
  end

  # Function to convert the database time (which is stored as a local time)
  # to a new local time, if the UTC offset is being changed in the CLI command.
  # Otherwise, return the stored local time
  defp get_updated_local_time(parsed) do
    user_map =
      """
        query{
          time{
            date_time
          }
        }
      """
      |> Absinthe.run!(CommonCore.Schema)

    iso_date_time = get_in(user_map, [:data, "time", "date_time"])

    if parsed[:utc_offset] do
      {:ok, date_time, _offset} = DateTime.from_iso8601(iso_date_time)

      case Timex.Timezone.convert(date_time, parsed[:utc_offset]) do
        local_date_time = %DateTime{} ->
          {:ok, DateTime.to_iso8601(local_date_time)}

        _ ->
          :error
      end
    else
      {:ok, iso_date_time}
    end
  end

  def user_index2name(index) do
    user_map =
      """
        query {
          security {
            userManagement{
              users(instance:#{index}){
                userName
              }
            }
          }
        }
      """
      |> Absinthe.run!(CommonCore.Schema)

    [%{"userName" => user_name}] = user_map[:data]["security"]["userManagement"]["users"]
    user_name
  end

  defp user_name2index(name) do
    Enum.find(0..8, fn i -> name == user_index2name(i) end)
  end

  def user_superusername() do
    userMap =
      """
      query{
        security {
          userManagement {
            superUser {
              userName
            }
          }
        }
      }
      """
      |> Absinthe.run!(CommonCore.Schema)

    %{"userName" => userName} = userMap[:data]["security"]["userManagement"]["superUser"]
    userName
  end

  def available_user_index() do
    user_map =
      """
      query{
        security {
          userManagement {
            users {
              userName
              userType
              accessEnable
              visible
            }
          }
        }
      }
      """
      |> Absinthe.run!(CommonCore.Schema)

    get_in(user_map, [:data, "security", "userManagement", "users", &all/3, "visible"])
    |> Enum.find_index(fn x -> x == "FALSE" end)
  end

  @email_help """
  Usage: email -- Configure and display email recipient parameters
        email
        OR
        email help
        OR
        email -i <n> (Instance)
              [-g <enable | disable>] (Email Generation)
              [-t <to address>]
              [-o <long | short>] (Email Format)
              [-l <language code>]
              [-r <local | custom>] (Route)
              [-D] (Delete Recipient)
              ([n] 1,2,3,4 or 5)

         --- Custom Route Options
              [-f <from address>]
              [-s <smtp server>]
              [-p <port>] (1 - 65535)
              [-a <enable | disable>] (Authentication)
              [-u <user name>]
              [-w <password>]
              [-d <confirm password>]
  """

  # TODO add in encryption options when functionality is included
  # [-e <none | if_supported | always | implicit>] (Authentication)
  # [-c <enable | disable>] (Require Certificate)
  # [-i <Certificate File Name>]

  @smtp_help """
  Usage: smtp -- Configure and display SMTP server parameters
        smtp
        OR
        smtp help
        OR
        smtp [-f <from address>]
             [-s <smtp server>]
             [-p <port>] (1 - 65535)
             [-a <enable | disable>] (Authentication)
             [-u <user name>]
             [-w <password>]
             [-d <confirm password>] (This must be included to change the password)
  """

  # TODO Add back in when funcitonality for encryptred emails is added
  #           [-e <none | ifavail | always | implicit>] (Encryption)
  #           [-c <enable | disable>] (Require Certificate)
  #           [-i <Certificate File Name>]
  # """

  @snmp_help """
  Usage: snmp -- Configuration Options
        snmp
        OR
        snmp help
        OR
        snmp [-S <disable | enable>]
        OR
        snmp -i <n> (Instance)
             [-c <community>]
             [-a <READ_ACCESS | WRITE_ACCESS | DISABLE>]
             [-n <ip or domain name>]
             ([n] = 1,2,3 or 4)
  """

  @snmptrap_help """
  Usage: snmptrap -- Configure and display SNMP trap receiver settings
        snmptrap
        OR
        snmptrap help
        OR
        snmptrap -i <n> (Instance)
                 [-c <community>]
                 [-r <receiver NMS IP>]
                 [-p <receiver port>] (162 and 5000-55162)
                 [-l <language>]
                 [-t <snmpV1 | snmpV3>] (Trap Receiver Type)
                 [-g <enable | disable>] (Generation)
                 [-a <enable | disable>] (Authentication)
                 [-u <user name>] (User Profile)
                 [-D] (Delete Trap)
                 ([n] 1,2,3,4,5 or 6)
  """

  @user_usage """
  Usage: user -- Configure and display user settings
        user
        OR
        user help
        OR
        user -n <user>  (User)
             [-P  <current password>] (Req. For Super User Account)
             [-a  <Admin | Device | Read_Only | Network_Only>]
                      (User Permission)
             [-d  <user description>]
             [-e  <enable | disable>] (Access Enable)
             [-t  <session timout>] (Minutes)
             [-l  <tab | csv>] (Export Log Format)
             [-s  <us | metric>] (Temperature Scale)
        OR
        user -n <user> (User)
             [-p  <new password>] (Required for User creation)
             [-c  <confirm password>] (Required for User creation)
             [-D] (Deletes user. Does not work on Super User)
        OR
        user -n <user> (User)
            [-P <current password> (Required for changing the password of the current user)
            [-p <new password>] (Required for changing the password of the current user)
            [-c <confirm password>] (Required for changing the password of the current user)
  """

  @user_usage_unprivileged """
  Usage: user -- Configure and display user settings
        user
        OR
        user help
        OR
        user -P <current password>
             -p <new password>
             -c <confirm password>
  """

  @userdflt_help """
  Usage: userdflt -- Configuration Options
        userdflt
        OR
        userdflt help
        OR
        userdflt [-e <enable | disable>] (Access Enable)
                 [-a <admin | device | read_only | network_only>] (User Permission)
                 [-d <user description>]
                 [-t <session timout>] (Minutes)
                 [-b <bad login attempts>]
                 [-l <tab | csv>] (Export Log Format)
                 [-s <us | metric>] (Temperature Scale)
        OR
        userdflt [-q <enable | disable>] (Strong Passwords)
                 [-i <interval in days>] (Required Password Change Interval)
  """

  @date_help """
  Usage: date -- Configure Date & Time Settings
        date
        OR
        date help
        OR
        date [-d <datestring>] (Format YYYY-MM-DD)
             [-t <timestring>] (24-hour format, 00:00:00)
             [-z <utc offset>] (Format +/-HH:MM, in the range -12:00 to +14:00)

  """

  @uio_help """
  Usage: uio -- Display sensor type and data
        uio
        OR
        uio help
        OR
        uio [-d] (Discover Probe)
            [-s] (Probe Status)

  """

  @snmpv3_help """
  Usage: snmpv3 -- Configuration Options
        snmpv3
        OR
        snmpv3 help
        OR
        snmpv3 [-S <disable | enable>]
        OR
        snmpv3 -i <n> (Instance)
               [-u <user name>]
               [-a <auth phrase>]
               [-p <crypt phrase>]
               [-A <sha | md5 | none>]
                       (Authentication Protocol)
               [-P <aes | des | none>]
                       (Privacy Protocol)
        OR
        snmpv3 -i <n> (Instance)
               [-e <enable | disable>] (Access)
               [-u <user name>] (Access User Profile)
               ([n]= 1,2,3 or 4)

  """

  @boot_help """
  Usage: boot -- Configuration Options
        boot
        OR
        boot help
        OR
        boot [-b <dhcp | manual | bootp>] (IPv4 Boot Mode)
             [-c <enable | disable>] (Require DHCPv4 Cookie)
             [-v <vendor class>]
             [-i <client id>]
             [-u <user class>]
  Note:
    Please run the tcpip command with the desired static ip, subnet
    and default gateway before running "boot -b manual"

  """

  @ssh_usage """
  Usage: ssh -- Configuration Options
        ssh
        OR
        ssh help
        OR
        ssh [-s <enable | disable>] (ssh/sftp/scp)
            [-ps <ssh-port>] (22 and 5000-32768)
  """

  @web_usage """
  Usage: web -- Configuration Options
        web
        OR
        web help
        OR
        web [-h <enable | disable> (http)]
            [-s <enable | disable> (https)]
            [-ph <http-port-number>] (80 and 5000-32768 except 8000 and 8883)
            [-ps <https-port-number>] (443 and 5000-32768 except 8000 and 8883)
            [-mp <minimum protocol>] (TLS1.1 | TLS1.2 | TLS1.3)
  """

  @session_usage """
  Usage: session -- Display and delete user sessions
        session
        OR
        session help
        OR
        session [-d <user name>] (Delete User Session)
                [-i <interface>]
  """

  @system_usage """
  Usage: system -- Configuration Options
        system
        OR
        system help
        OR
        system [-n <system-name>]
               [-c <system-contact>]
               [-l <system-location>]
               [-m <system-message>]
  """

  @dns_help """
  Usage: dns  -- Configure and display DNS parameters
        dns
        OR
        dns help
        OR
        dns [-OM <override manual DNS settings>[enable | disable]]
            [-p <primary DNS server>]
            [-s <secondary DNS server>]
            [-d <domain name>]
            [-n <domain name IPv6>]
            [-h <host name>]
            [-y <enable | disable>] (system-hostname sync)
  """

  @tcpip_usage """
  Usage: tcpip -- Configure and display TCP/IP v4 parameters
        tcpip
        OR
        tcpip help
        OR
        tcpip [-S <enable | disable>]
              [-i <ipv4 address>]
              [-s <subnet mask>]
              [-g <gateway>]
              [-b <dhcp | manual | bootp>] (IPv4 Boot Mode)
  """

  @tcpip6_usage """
  Usage: tcpip6 -- Configure and display Tcpip v6 parameters
        tcpip6
        OR
        tcpip6 help
        OR
        tcpip6 [-S    <enable | disable>] (enables IPv6)
               [-i    <ipv6 address>]     (sets manual IPv6 address)
               [-g    <ipv6 gateway>]     (sets IPv6 gateway)
               [-man  <enable | disable>] (enables IPv6 manual address)
               [-auto <enable | disable>] (enables IPv6 autoconfiguation)
               [-d6   <stateful | stateless | never>] (sets DHCPv6 mode)
  """

  @eapol_usage """
  Usage: eapol  -- Configure and display EAPoL parameters
        eapol [-S <enable | disable>]
              [-n <supplicant name>]
              [-p <private key passphrase>]
              OR
              [-r] (force re-authentication)
  """

  @modbus_usage """
  Usage: modbus -- Configuration Options
        modbus
        OR
        modbus help
        OR
        modbus [-a <enable | disable>] (Modbus status)
               [-b <BAUD_2400 | BAUD_9600 | BAUD_19200 | BAUD_38400>] (baud rate)
               [-p <parity_even | parity_odd | parity_none>] (parity)
               [-s <1-247>] (slave address)
               [-S <1 | STOP_BITS_ONE | 2 | STOP_BITS_TWO>] (stop bits)
        OR
        modbus [-e <enable | disable>] (Modbus TCP status)
               [-n <502 | 5000-32768] (Modbus TCP port number)
        OR
        modbus [-R] (Reset to Defaults)
  """

  @resetToDef_usage """
  Usage: resetToDef -- Reset NMC settings
        resetToDef
        OR
        resetToDef help
        OR
        resetToDef [-p <all | keepip>] (reset all settings | reset all settings except TCP/IP settings)
  """

  # MIN and MAX Instances
  @snmptrap_max_instance 6
  @snmptrap_min_instance 0
  @email_max_instance 5
  @email_min_instance 0
  @snmp_max_instance 4
  @snmp_min_instance 0
  @snmpv3_max_instance 4
  @snmpv3_min_instance 0

  def convert_stop_bits_value(:"1"), do: :STOP_BITS_ONE
  def convert_stop_bits_value(:"2"), do: :STOP_BITS_TWO
  def convert_stop_bits_value("STOP_BITS_ONE"), do: "1"
  def convert_stop_bits_value("STOP_BITS_TWO"), do: "2"
  def convert_stop_bits_value(other), do: other

  # Administrative user roles will get the full list of users printed. Other user-roles will only see their own
  # user account summary.
  defp filter_based_on_user_permissions(list, _user_name, user_type) when user_type in [:super_user, :admin] do
    list
  end

  defp filter_based_on_user_permissions(list, user_name, user_type) do
    Enum.filter(list, fn [name, type, _enabled]  -> name == user_name and type == to_string(user_type) end)
  end

  defp get_current_user_name() do
    user = Process.get(:user)
    user.user_name
  end

  defp get_current_user_type() do
    user = Process.get(:user)
    user.user_type
  end

  defp filter_based_on_user_permissions(list) do
    filter_based_on_user_permissions(list, get_current_user_name(), get_current_user_type())
  end

  # uio
  def convert(_cli_args = ["uio"]) do
    IO.puts("E102: Parameter Error")
    IO.puts(@uio_help)
    :halt
  end


  def convert(_cli_args = ["uio", uio_arg]) do
    case uio_arg do
      arg when arg in ["help", "?"] ->
        IO.puts(@uio_help)
        :halt

      "-d" ->
        """
          query{
            sensor {
              type
            }
          }
        """

      "-s" ->
        """
        query{
          sensor{
            type temperature(decimalDigits:1) humidity(decimalDigits:0) alarm_status
          }
        }
        """

      _ ->
        IO.puts("E102: Parameter Error")
        IO.puts(@uio_help)
        :halt
    end
  end

  def convert(_cli_args = ["uio" | _args]) do
    IO.puts("E102: Parameter Error")
    IO.puts(@uio_help)
    :halt
  end

  # session
  def convert(_cli_args = ["session"]) do
    """
      query{
        security {
          active_sessions {
            user_name login_timestamp interface address auth_source active_flag
          }
        }
      }
    """
  end

  def convert(_cli_args = ["session" | session_args]) do
    switches = [
      delete: :string,
      interface: :string
    ]

    aliases = [
      d: :delete,
      i: :interface
    ]

    enums = []

    {parsed, bare, errors} = option_parse(session_args, switches: switches, aliases: aliases, enums: enums)

    if args_ok?(parsed, bare, errors) do
      if parsed[:delete] do
        sessions = UserManager.Session.all()

        if Enum.any?(sessions, fn {_id, %UserManager.Session{:user_name => x}} -> x == parsed[:delete] end) do
          indices =
            for {id, %UserManager.Session{:user_name => user, :interface => interface}} <- sessions do
              if parsed[:interface] do
                if user == parsed[:delete] && String.capitalize(interface) == String.capitalize(parsed[:interface]) do
                  Enum.find_index(sessions, fn {x, _struct} -> x == id end)
                end
              else
                if user == parsed[:delete] do
                  Enum.find_index(sessions, fn {x, _struct} -> x == id end)
                end
              end
            end
            |> Enum.filter(&(!is_nil(&1)))

          if length(indices) != 0 do
            for index <- Enum.sort(indices, &(&1 >= &2)) do
              with {jwt, _session} <- Enum.at(sessions, index),
                   {:ok, _claims} <- UserManager.Guardian.revoke(jwt) do
                UserManager.dispatch(jwt, :logout)
                UserManager.dispatch_auto_close(jwt)
              end

              :ok
            end

            IO.puts("E000: Success")
          else
            """

              No session found with the specified interface

            """
            |> IO.puts()
          end
        else
          """

            No session found with specified user

          """
          |> IO.puts()
        end
      else
        """
          Use the -d <User Name> switch to delete a user session
        """
        |> IO.puts()
      end
    else
      unless help_request?(bare) do
        IO.puts("E102: Parameter Error")
      end

      @session_usage
      |> IO.puts()
    end

    :halt
  end

  # SNMP Traps
  def convert(_cli_args = ["snmptrap"]) do
    """
      query{
        snmp{
          trap {
            receiver_ip receiver_port enable instance visible
          }
        }
      }
    """
  end

  def convert(_cli_args = ["snmptrap", arg]) when arg in ["help", "?"] do
    @snmptrap_help
    |> IO.puts()

    :halt
  end

  # # snmptrap - single query
  def convert(_cli_args = ["snmptrap" | snmptrap_args]) when length(snmptrap_args) == 3 and tl(tl(snmptrap_args)) !== ["-D"] do
    switches = [
      instance: :integer,
      community: :string,
      receiver_ip: :string,
      receiver_port: :string,
      language: :string,
      auth: :string,
      type: :string,
      enable: :string,
      user_profile_mapping: :string
    ]

    aliases = [
      i: :instance,
      c: :community,
      r: :receiver_ip,
      p: :receiver_port,
      l: :language,
      t: :type,
      g: :enable,
      a: :auth,
      u: :user_profile_mapping
    ]

    enums = [
      :community,
      :receiver_ip,
      :receiver_port,
      :language,
      :type,
      :enable,
      :auth,
      :user_profile_mapping
    ]

    # Throw away string to parse args
    snmptrap_args = snmptrap_args ++ ["string"]
    {parsed, bare, errors} = option_parse(snmptrap_args, switches: switches, aliases: aliases, enums: enums)

    # Sets instances to begin from 1
    parsed = adjust_instance(parsed)

    if args_ok?(parsed, bare, errors) do
      instance = Keyword.get(parsed, :instance)

      if instance && instance >= 0 && instance < 6 do
        """
          query{
            snmp{
              trap(instance: #{instance}){
                instance type visible #{parsed2select(parsed)}
              }
            }
          }
        """
      else
        IO.puts("E102: Parameter Error")

        @snmptrap_help
        |> IO.puts()

        :halt
      end
    else
      IO.puts("E102: Parameter Error")

      @snmptrap_help
      |> IO.puts()

      :halt
    end
  end

  # SNMPtrap Delete Operation
  def convert(_cli_args = ["snmptrap" | args]) when length(args) == 3 and tl(tl(args)) == ["-D"] do
    switches = [
      instance: :integer
    ]

    aliases = [
      i: :instance
    ]

    enums = []

    # Throws a param error here if the wrong
    # char is used as it will only remove '-D'
    args = args -- ["-D"]
    {parsed, bare, errors} = option_parse(args, switches: switches, aliases: aliases, enums: enums)

    # Sets instances to begin from 1
    parsed = adjust_instance(parsed)

    if args_ok?(parsed, bare, errors) do
      instance = Keyword.get(parsed, :instance)

      if instance && instance >= @snmptrap_min_instance && instance < @snmptrap_max_instance do
        """
        mutation {
          update(input: {
            clientMutationId: "snmptrap",
              snmp: {
                trap: {
                  instance: #{instance}, visible: TRAP_INVISIBLE
                }
              }
            })
          {
          clientMutationId
            snmp {
              trap {
                instance visible
              }
            }
          }
        }
        """
      else
        IO.puts("E102: Parameter Error")
        IO.puts(@snmptrap_help)
        :halt
      end
    else
      IO.puts("E102: Parameter Error")
      IO.puts(@snmptrap_help)
      :halt
    end
  end

  # snmptrap mutate function
  def convert(_cli_args = ["snmptrap" | snmptrap_args]) do
    switches = [
      instance: :integer,
      community: :string,
      receiver_ip: :string,
      receiver_port: :integer,
      language: :string,
      auth: :string,
      type: :string,
      enable: :string,
      user_profile_mapping: :string
    ]

    aliases = [
      i: :instance,
      c: :community,
      r: :receiver_ip,
      p: :receiver_port,
      l: :language,
      t: :type,
      g: :enable,
      a: :auth,
      u: :user_profile_mapping
    ]

    enums = [
      :language,
      :type,
      :enable,
      :auth
    ]

    {parsed, bare, errors} = option_parse(snmptrap_args, switches: switches, aliases: aliases, enums: enums)

    # pulls out the profile that matches the inputted name
    referenced_profile = matched_snmp_profile_by_name(parsed[:user_profile_mapping])

    valid_name = referenced_profile != 0

    c1 = parsed[:user_profile_mapping] && valid_name
    c2 = parsed[:user_profile_mapping] && !valid_name

    parsed =
      cond do
        c1 ->
          pointer = String.to_atom("PROFILE_#{referenced_profile[:instance]}")
          ret = List.keydelete(parsed, :user_profile_mapping, 0)
          ret = ret ++ [user_profile_mapping: pointer]
          map_snmptrap_arguments(ret)

        c2 ->
          """
          E102: Parameter Error
            User name must match a target profile

          """
          |> IO.puts()

          :halt

        true ->
          # The data dictionary items are not very intuitive or user friendly, so need to swap out the arguments
          # used on the command line for the arguments required for the GraphQL query
          # This also ensures that they are consistent with the other commands
          map_snmptrap_arguments(parsed)
      end

    # Sets instances to begin from 1
    parsed = adjust_instance(parsed)

    has_ip = parsed[:receiver_ip] != nil
    good_ip = check_ip?(has_ip, parsed[:receiver_ip])

    if args_ok?(parsed, bare, errors) do
      if good_ip do
        if parsed[:instance] != nil && parsed[:instance] >= @snmptrap_min_instance && parsed[:instance] < @snmptrap_max_instance do
          # Checks if length of args indicates a query or mutation
          is_query =
            parsed
            |> Keyword.to_list()
            |> Kernel.length()

          case is_query do
            1 ->
              """
                query{
                  snmp{
                    trap(instance: #{parsed[:instance]}){
                      instance community receiver_ip receiver_port auth type enable
                      user_profile_mapping visible language
                    }
                  }
                }
              """

            _ ->
              # Used for ensuring 'community' is entered when creating new trap with 'snmpv1' type
              check_map = ConfigManager.get(:"snmp.trap[]", parsed[:instance])

              # Ensures settings can't be changed on invisible traps
              missing_ip? = check_map[:visible] == :trap_invisible && !Keyword.has_key?(parsed, :receiver_ip)

              if missing_ip? do
                """
                E100: Command Failed

                    To create a new trap receiver, receiver ip must be set

                """
                |> IO.puts()

                :halt
              else
                # Mutation code past line 5200
                parsed
                |> snmptrap_mutate?(check_map)
                |> snmptrap_mutate(parsed)
              end
          end
        else
          IO.puts("E102: Parameter Error")
          IO.puts(@snmptrap_help)
          :halt
        end
      else
        IO.puts("E102: Parameter Error\n")

        :halt
      end
    else
      unless help_request?(bare) do
        IO.puts("E102: Parameter Error")
      end

      @snmptrap_help
      |> IO.puts()

      :halt
    end
  end

  # date
  def convert(_cli_args = ["date"]) do
    """
      query{
        time{
          date_time
          config{
            utc_offset time_source
          }
        }
      }
    """
  end

  # Capture commands to view a single setting
  def convert(_cli_args = ["date", arg]) when arg not in ["help", "?"] do
    # Can't do this with ConfigManager.get() as time.date_time returns an empty string
    user_map =
      """
        query{
          time{
            date_time
          }
        }
      """
      |> Absinthe.run!(CommonCore.Schema)

    {date, time, offset} = parse_date_time(get_in(user_map, [:data, "time", "date_time"]))

    offset = if offset == "Z", do: "00:00", else: offset

    case arg do
      "-z" ->
        """
        E000: Success

        UTC Offset:     #{offset}

        """

      "-d" ->
        """
        E000: Success

        Date:     #{date}

        """

      "-t" ->
        """
        E000: Success

        Time:     #{time}

        """

      _ ->
        """
        E102: Parameter Error")
        """ <> @date_help
    end
    |> IO.puts()

    :halt
  end

  def convert(_cli_args = ["date" | date_args]) do
    # The function being used to parse the options is from a standard library
    # (OptionParser.parse), and because the function sees everything that has
    # a '-' in front of it as a switch, need a cludge to handle the input of
    # negative UTC Offsets (remove '-' and add back in after parsing)
    {date_args, offset_neg?} =
      if Enum.member?(date_args, "-z") do
        index = Enum.find_index(date_args, fn x -> x == "-z" end) + 1
        <<sign::binary-size(1)>> <> rest = Enum.fetch!(date_args, index)

        case sign do
          "-" ->
            {List.replace_at(date_args, index, rest), true}

          _ ->
            {date_args, false}
        end
      else
        {date_args, false}
      end

    switches = [
      # z
      utc_offset: :string,
      # t
      time: :string,
      # d
      date: :string
    ]

    aliases = [
      z: :utc_offset,
      t: :time,
      d: :date
    ]

    enums = []

    {parsed, bare, errors} = option_parse(date_args, switches: switches, aliases: aliases, enums: enums)

    if args_ok?(parsed, bare, errors) do
      # Add back in the '-' sign if it was stripped out for parsing
      # Also the case when '00:00' is entered without a sign needs to be handled
      # as the lack of sign causes a parameter error. Replace '00:00' with '+00:00'
      # Could replace with 'Z' for the ISO8601, but cannot write 'Z' to date.config.utc_offset
      parsed =
        if offset_neg? do
          Keyword.update!(parsed, :utc_offset, fn x -> "-" <> x end)
        else
          if parsed[:utc_offset] == "00:00" do
            Keyword.update!(parsed, :utc_offset, fn x -> "+" <> x end)
          else
            parsed
          end
        end

      # If the timezone is being changed, then the time value needs to be updated,
      # as the data dictionary holds the local time. Updating the timezone only
      # would result in the 'UTC time' of the system changing, so the first
      # part of changing anything with the date command is to convert the UPS time
      # to the new offset, if it is included in the arguments.
      if offset_valid?(Keyword.get(parsed, :utc_offset)) do
        case get_updated_local_time(parsed) do
          {:ok, updated_iso_date_time} ->
            {date, time, offset} = parse_date_time(updated_iso_date_time)

            date = if parsed[:date], do: parsed[:date], else: date
            time = if parsed[:time], do: parsed[:time], else: time
            offset = if parsed[:utc_offset], do: parsed[:utc_offset], else: offset

            parsed = Keyword.drop(parsed, [:date, :time])

            # Need to write date_time in ISO8601 format
            date_time = [date_time: date <> "T" <> time <> ".000000" <> offset]

            parsed = Keyword.put_new(parsed, :time_source, :MANUAL)

            """
            mutation  {
              update(input: {
                clientMutationId: "date",
                time: {
                  #{parsed2args(date_time)}
                  config: {
                    #{parsed2args(parsed)}
                  }
                }
              })
              {
                clientMutationId
                time {
                  #{parsed2select(date_time)}
                  config{
                    #{parsed2select(parsed)}
                  }
                }
              }
            }
            """

          _ ->
            IO.puts("E102: Parameter Error")
            IO.puts(@date_help)
            :halt
        end
      else
        IO.puts("E102: Parameter Error")
        :halt
      end
    else
      unless help_request?(bare) do
        IO.puts("E102: Parameter Error")
      end

      IO.puts(@date_help)

      :halt
    end
  end

  # email
  def convert(_cli_args = ["email"]) do
    """
      query{
        email{
          recipients{
            instance enable address format language server visible
            custom{
              from_address smtp_server port
              authentication{
                enable user_name password
              }
            }
          }
        }
      }
    """
  end

  # email recipient delete and individual query function
  def convert(_cli_args = ["email" | email_args]) when length(email_args) == 3 do
    switches = [
      # i
      instance: :integer,
      # g
      generation: :string,
      # t
      address: :string,
      # o
      format: :string,
      # l
      language: :string,
      # r
      server: :string,
      # f
      from_address: :string,
      # s
      smtp_server: :string,
      # p
      port: :integer,
      # a
      enable: :string,
      # u
      user_name: :string,
      # w
      password: :string,
      # D
      delete: :string
    ]

    aliases = [
      i: :instance,
      g: :generation,
      t: :address,
      o: :format,
      l: :language,
      r: :server,
      f: :from_address,
      s: :smtp_server,
      p: :port,
      a: :enable,
      u: :user_name,
      w: :password,
      D: :delete
    ]

    # TODO - add in the advanced parameters into the aliases and switches
    #         when the functionality has been added. The framework for
    #         advanced option queries is already in place so the only
    #         change required is to add the options to the above lists.
    #         Cases will need to be added in the unit tests

    enums = []

    # Adds arbitrary string to pass the option_parse
    email_args = email_args ++ ["1"]
    {parsed, bare, errors} = option_parse(email_args, switches: switches, aliases: aliases, enums: enums)

    # Sets instances to begin from 1
    parsed = adjust_instance(parsed)

    is_del? = Keyword.has_key?(parsed, :delete)

    if args_ok?(parsed, bare, errors) do
      instance = Keyword.get(parsed, :instance)

      if instance && instance >= @email_min_instance && instance < @email_max_instance do
        # Check if is delete command
        if is_del? do
          """
          mutation {
            update(input: {
              clientMutationId: "email",
                email: {
                  recipients: {
                    visible: FALSE, instance: #{instance}
                  }
                }
              })
            {
            clientMutationId
              email {
                recipients {
                  instance visible
                }
              }
            }
          }
          """
        else
          recp_params = Keyword.take(parsed, [:generation, :address, :format, :language, :server])
          auth_params = Keyword.take(parsed, [:enable, :user_name, :password])
          serv_params = Keyword.take(parsed, [:from_address, :smtp_server, :port])
          adv_params = Keyword.take(parsed, [:use_ssl, :require_certificate, :selected_certificate])

          recp_len = length(recp_params)
          auth_len = length(auth_params)
          serv_len = length(serv_params)
          adv_len = length(adv_params)

          # Catches instance where '-i' is queried
          unless recp_len == 0 && auth_len == 0 && serv_len == 0 && adv_len == 0 do
            # Replaces 'generation' stand in with 'enable'
            recp_params =
              if Keyword.has_key?(recp_params, :generation) do
                Keyword.put_new(recp_params, :enable, Keyword.fetch!(recp_params, :generation))
                |> Keyword.delete(:generation)
              else
                recp_params
              end

            """
            query {
              email {
                recipients (instance: #{instance}) {
                  visible instance
                  #{case 1 do
              ^recp_len -> "#{parsed2select(recp_params)}"
              ^serv_len -> "custom {
                          #{parsed2select(serv_params)}
                        }"
              ^auth_len -> "custom {
                          authentication {
                            #{parsed2select(auth_params)}
                          }
                        }"
              ^adv_len -> "custom {
                          advanced {
                            #{parsed2select(adv_params)}
                          }
                        }"
            end}
                }
              }
            }
            """
          else
            IO.puts("E102: Parameter Error")
            IO.puts(@email_help)
            :halt
          end
        end
      else
        IO.puts("E102: Parameter Error")
        IO.puts(@email_help)
        :halt
      end
    else
      IO.puts("E102: Parameter Error")
      IO.puts(@email_help)
      :halt
    end
  end

  def convert(_cli_args = ["email" | email_args]) do
    # These must match the names in the Data Dictionary

    switches = [
      # i
      instance: :integer,
      # g
      generation: :string,
      # t
      address: :string,
      # o
      format: :string,
      # l
      language: :string,
      # r
      server: :string,
      # f
      from_address: :string,
      # s
      smtp_server: :string,
      # p
      port: :integer,
      # a
      enable: :string,
      # u
      user_name: :string,
      # w
      password: :string,
      # d
      confirm_password: :string
    ]

    aliases = [
      i: :instance,
      g: :generation,
      t: :address,
      o: :format,
      l: :language,
      r: :server,
      f: :from_address,
      s: :smtp_server,
      p: :port,
      a: :enable,
      u: :user_name,
      w: :password,
      d: :confirm_password
    ]

    enums = [
      :generation,
      :format,
      :language,
      :server,
      :enable
    ]

    # TODO Add back in when funcitonality for encryptred emails is added

    # switches:
    # use_ssl: :string,                 #e
    # require_certificate: :string,     #c
    # selected_certificate: :string     #h

    # aliases:
    # e: :use_ssl,
    # c: :require_certificate,
    # h: :selected_certificate

    # enums:
    # :use_ssl,
    # :require_certificate,
    # :selected_certificate

    {parsed, bare, errors} = option_parse(email_args, switches: switches, aliases: aliases, enums: enums)

    has_to_address = parsed[:address] != nil
    good_to_address = check_email?(has_to_address, parsed[:address])

    has_from_address = parsed[:from_address] != nil
    good_from_address = check_email?(has_from_address, parsed[:from_address])

    has_smtp_server = parsed[:smtp_server] != nil
    good_ip = check_smtp?(has_smtp_server, parsed[:smtp_server])

    # Sets instances to begin from 1
    parsed = adjust_instance(parsed)

    if args_ok?(parsed, bare, errors) do
      recp_params = Keyword.take(parsed, [:instance, :generation, :address, :format, :language, :server])
      auth_params = Keyword.take(parsed, [:enable, :user_name, :password, :confirm_password])
      serv_params = Keyword.take(parsed, [:from_address, :smtp_server, :port])
      adv_params = Keyword.take(parsed, [:use_ssl, :require_certificate, :selected_certificate])

      instance = Keyword.get(recp_params, :instance)

      if instance && instance >= @email_min_instance && instance < @email_max_instance do
        if good_to_address && good_from_address && good_ip do
          if check_password(parsed) == :error do
            :halt
          else
            # if there are no other options, the command is a recipient query
            case Kernel.length(Keyword.to_list(parsed)) do
              1 ->
                """
                  query{
                    email{
                      recipients(instance: #{instance}){
                        instance enable address format language server visible
                        custom{
                          from_address smtp_server port
                          authentication{
                            enable user_name password
                          }
                        }
                      }
                    }
                  }
                """

              _ ->
                # This is needed because there are two "enable" keys in the command, one for the email recipient,
                # and one for authentication when using custom server options. After the options have been split
                # into separate lists, the :generation keyword, which was used as placeholder, is replaced with
                # :enable so that the mutation is interpreted properly
                recp_params =
                  if Keyword.has_key?(recp_params, :generation) do
                    Keyword.put_new(recp_params, :enable, Keyword.fetch!(recp_params, :generation))
                    |> Keyword.delete(:generation)
                  else
                    recp_params
                  end

                # If the user changes any settings on an email recipient configuration, ensure that the
                # configuration is visible.
                recp_params = Keyword.put_new(recp_params, :visible, :TRUE)

                # This section is needed because if you try to send a GraphQL mutation to change just one
                # of the recipient custom server settings, for some reason all of the rest of the settings
                # are deleted, so this section grabs all of the current settings for the recipient
                # instance and merges with the list of new settings from the CLI, keeping the CLI values
                # in the case of a conflict. All atoms are then capitalised, as those from ConfigManager
                # are lower case, and GraphQL mutations require upper case. The merging also covers a
                # situation observed during development when fields are missing from the ConfigManager,
                # but this should not be possible outside development.
                recipient = ConfigManager.get(:"email.recipients[]", instance)

                auth_params =
                  Keyword.merge(auth_params, Map.to_list(recipient[:custom][:authentication]), fn _key, v1, _v2 -> v1 end)
                  |> Enum.map(fn {key, value} -> {key, up_the_atom(value)} end)

                serv_map = Map.drop(recipient[:custom], [:authentication, :advanced])
                serv_params = Keyword.merge(serv_params, Map.to_list(serv_map), fn _key, v1, _v2 -> v1 end)

                adv_params =
                  Keyword.merge(adv_params, Map.to_list(recipient[:custom][:advanced]), fn _key, v1, _v2 -> v1 end)
                  |> Enum.map(fn {key, value} -> {key, up_the_atom(value)} end)

                """
                  mutation  {
                    update(input: {
                      clientMutationId: "email",
                      email: {
                        recipients: {
                          #{unless recp_params == [] do
                  "#{parsed2args(recp_params)}"
                end}
                          custom: {
                            #{parsed2args(serv_params)}
                            authentication:{
                              #{parsed2args(auth_params)}
                            }
                            advanced:{
                              #{parsed2args(adv_params)}
                            }
                          }
                        }
                      }
                    })
                    {
                      email {
                        recipients {
                          #{unless recp_params == [] do
                  "#{parsed2select(recp_params)}"
                end}
                          custom {
                            #{parsed2select(serv_params)}
                            authentication {
                              #{parsed2select(auth_params)}
                            }
                            advanced {
                              #{parsed2select(adv_params)}
                            }
                          }
                        }
                      }
                    }
                  }
                """
            end
          end
        else
          IO.puts("E102: Parameter Error\n")

          :halt
        end
      else
        IO.puts("E102: Parameter Error")
        IO.puts(@email_help)
        :halt
      end
    else
      instance = Keyword.get(parsed, :instance)

      if instance == nil do
        unless help_request?(bare) do
          IO.puts("E102: Parameter Error")
        end

        IO.puts(@email_help)
        :halt
      else
        if errors != [] do
          [{inp, _nil}] = errors

          case inp do
            value when value in ["-g", "-t", "-o", "-l", "-r"] ->
              """
                query{
                  email{
                    recipients(instance: #{instance}){
                 instance #{case inp do
                "-g" -> "enable"
                "-t" -> "address"
                "-o" -> "format"
                "-l" -> "language"
                "-r" -> "server"
              end} visible
                      custom{
                        from_address smtp_server port
                        authentication{
                          enable user_name
                        }
                      }
                    }
                  }
                }
              """

            value when value in ["-f", "-s", "-p"] ->
              """
                query{
                  email{
                    recipients(instance: #{instance}){
                      instance server visible
                      custom{
                        #{case inp do
                "-f" -> "from_address"
                "-s" -> "smtp_server"
                "-p" -> "port"
              end}
                      }
                    }
                  }
                }
              """

            value when value in ["-a", "-u"] ->
              """
                query{
                  email{
                    recipients(instance: #{instance}){
                      instance server visible
                      custom{
                        authentication{
                    #{case inp do
                "-a" -> "enable"
                "-u" -> "user_name"
              end}
                        }
                      }
                    }
                  }
                }
              """

            _ ->
              IO.puts("E102: Parameter Error")
              IO.puts(@email_help)
              :halt
          end
        else
          @email_help
          |> IO.puts()

          :halt
        end
      end
    end
  end

  # smtp
  def convert(_cli_args = ["smtp"]) do
    # Query all settings
    """
    query{
      email{
        server{
          from_address
          smtp_server
          port
        }
        authentication{
          enable
          user_name
          password
        }
      }
    }
    """

    # TODO Add back in when functionality for encryptrd emails is added
    # advanced{
    #   use_ssl require_certificate selected_certificate
    # }
  end

  # smtp HELP catch
  def convert(_cli_args = ["smtp", arg]) when arg in ["help", "?"] do
    @smtp_help
    |> IO.puts()

    :halt
  end

  # smtp convert for QUERYING data in database
  def convert(_cli_args = ["smtp", arg]) do
    switches = [
      # f
      from_address: :string,
      # s
      smtp_server: :string,
      # p
      port: :integer,
      # a
      enable: :string,
      # u
      user_name: :string,
      # w
      password: :string
    ]

    aliases = [
      f: :from_address,
      s: :smtp_server,
      p: :port,
      a: :enable,
      # smtp
      u: :user_name,
      w: :password
    ]

    enums = []
    # Adds an arbitrary argument to the end of the
    # 'arg' list to be ignored later to get past
    # the 'option_parse' and parse the command
    arg = [arg] ++ ["1"]
    {parsed, bare, errors} = option_parse(arg, switches: switches, aliases: aliases, enums: enums)

    if args_ok?(parsed, bare, errors) do
      auth_params = Keyword.take(parsed, [:enable, :user_name, :password, :confirm_password])
      serv_params = Keyword.take(parsed, [:from_address, :smtp_server, :port])
      adv_params = Keyword.take(parsed, [:use_ssl, :require_certificate, :selected_certificate])

      # Length params for case check
      auth_len = length(auth_params)
      serv_len = length(serv_params)
      adv_len = length(adv_params)

      # Query with case to check which subtree is required
      """
      query {
        email {
          #{case 1 do
        ^auth_len -> "authentication {
                    #{parsed2select(auth_params)}
                  }"
        ^serv_len -> "server {
                    #{parsed2select(serv_params)}
                  }"
        ^adv_len -> "advanced {
                    #{parsed2select(adv_params)}
                  }"
      end}
        }
      }
      """
    else
      IO.puts("E102: Parameter Error")

      @smtp_help
      |> IO.puts()

      :halt
    end
  end

  # smtp convert for MUTATING data in database
  def convert(_cli_args = ["smtp" | smtp_args]) do
    # These must match the names in the Data Dictionary
    switches = [
      # f
      from_address: :string,
      # s
      smtp_server: :string,
      # p
      port: :integer,
      # a
      enable: :string,
      # u
      user_name: :string,
      # p
      password: :string,
      # d
      confirm_password: :string
    ]

    aliases = [
      f: :from_address,
      s: :smtp_server,
      p: :port,
      a: :enable,
      u: :user_name,
      w: :password,
      d: :confirm_password
    ]

    enums = [
      :enable
    ]

    # TODO Add back in when funcitonality for encrypted emails is added

    # switches:
    # use_ssl: :string,                 #e
    # require_certificate: :string,     #c
    # selected_certificate: :string     #h

    # aliases:
    # e: :use_ssl,
    # c: :require_certificate,
    # h: :selected_certificate

    # enums:
    # :use_ssl,
    # :require_certificate,
    # :selected_certificate

    {parsed, bare, errors} = option_parse(smtp_args, switches: switches, aliases: aliases, enums: enums)

    # Added backwards compatibility with Rhodes II.
    parsed =
      case parsed[:use_ssl] do
        :IFAVAIL ->
          Keyword.replace!(parsed, :use_ssl, :IF_SUPPORTED)

        :IMPLICIT ->
          Keyword.replace!(parsed, :use_ssl, :IMPLICITLY)

        _ ->
          parsed
      end

    has_from_address = parsed[:from_address] != nil
    good_email = check_email?(has_from_address, parsed[:from_address])

    has_smtp_server = parsed[:smtp_server] != nil
    good_ip = check_smtp?(has_smtp_server, parsed[:smtp_server])

    if args_ok?(parsed, bare, errors) do
      if good_email && good_ip do
        if check_password(parsed) == :error do
          :halt
        else
          auth_params = Keyword.take(parsed, [:enable, :user_name, :password, :confirm_password])
          serv_params = Keyword.take(parsed, [:from_address, :smtp_server, :port])
          adv_params = Keyword.take(parsed, [:use_ssl, :require_certificate, :selected_certificate])

          """
            mutation  {
              update(input: {
                clientMutationId: "email",
                email: {
          #{unless auth_params == [] do
            "authentication: {\n #{parsed2args(auth_params)}\n}"
          end}
          #{unless serv_params == [] do
            "server: {\n #{parsed2args(serv_params)}\n}"
          end}
          #{unless adv_params == [] do
            "advanced: {\n #{parsed2args(adv_params)}\n}"
          end}
                }
              })
              {
                email {
          #{unless auth_params == [] do
            "authentication {\n #{parsed2select(auth_params)}\n}"
          end}
          #{unless serv_params == [] do
            "server {\n\t #{parsed2select(serv_params)}\n\t}"
          end}
          #{unless adv_params == [] do
            "advanced {\n\t #{parsed2select(adv_params)}\n\t}"
          end}
                }
              }
            }
          """
        end
      else
        IO.puts("E102: Parameter Error\n")

        :halt
      end
    else
      IO.puts("E102: Parameter Error")

      @smtp_help
      |> IO.puts()

      :halt
    end
  end

  def convert(_cli_args = ["snmp", arg]) when arg in ["help", "?"] do
    @snmp_help
    |> IO.puts()

    :halt
  end

  def convert(_cli_args = ["snmp"]) do
    """
    query{
      snmp {
        v1Enable
        community {
          name
          access
          nmsIp
        }
      }
    }
    """
  end

  def convert(_cli_args = ["snmp", "-S"]) do
    ("\nSNMPv1 Access:\t" <> "#{ConfigManager.get(:"snmp.v1_enable")}" <> "\n")
    |> check_string_for_enable()
    |> IO.puts()

    :halt
  end

  def convert(_cli_args = ["snmp", "-S", "enable"]) do
    """
      mutation  {
        update(input: {
          clientMutationId: "snmp",
          snmp: {
              v1Enable: ENABLE
          }
        })
        {
          clientMutationId
          snmp {
            v1Enable
          }
        }
      }
    """
  end

  def convert(_cli_args = ["snmp", "-S", "disable"]) do
    """
      mutation  {
        update(input: {
          clientMutationId: "snmp",
          snmp: {
              v1Enable: DISABLE
          }
        })
        {
          clientMutationId
          snmp {
            v1Enable
          }
        }
      }
    """
  end

  # anything > 4 would do
  @illegal_instance 666

  # SNMP QUERY
  def convert(_cli_args = ["snmp" | arg]) when length(arg) == 3 do
    switches = [
      # c
      name: :string,
      # a
      access: :string,
      # n
      nmsIp: :string,
      # i
      instance: :integer
    ]

    aliases = [
      c: :name,
      a: :access,
      n: :nmsIp,
      i: :instance
    ]

    enums = []

    # Throw away sring to parse args
    arg = arg ++ ["string"]
    {parsed, bare, errors} = option_parse(arg, switches: switches, aliases: aliases, enums: enums)

    # Sets instances to begin from 1
    parsed = adjust_instance(parsed)

    {:instance, instance} = Enum.find(parsed, {:instance, @illegal_instance}, fn x -> Kernel.elem(x, 0) == :instance end)

    if instance < @snmp_max_instance and instance >= @snmp_min_instance and args_ok?(parsed, bare, errors) do
      """
      query {
        snmp {
          community(instance:#{instance}) {
            #{parsed2select(parsed)}
          }
        }
      }
      """
    else
      IO.puts("E102: Parameter Error")

      @snmp_help
      |> IO.puts()

      :halt
    end
  end

  # SNMP MUTATION
  def convert(_cli_args = ["snmp" | snmp_args]) do
    switches = [
      # -c
      name: :string,
      # -a
      access: :string,
      # -n
      nmsIp: :string,
      # -i
      instance: :integer
    ]

    # These map to the full switch names (ex system -l location )
    # They must match the arg names in cli.csv for the legacy system
    aliases = [
      c: :name,
      a: :access,
      n: :nmsIp,
      i: :instance
    ]

    enums = [
      :access
    ]

    {parsed, bare, errors} = option_parse(snmp_args, switches: switches, aliases: aliases, enums: enums)

    # Sets instances to begin from 1
    parsed = adjust_instance(parsed)

    {:instance, instance} = Enum.find(parsed, {:instance, @illegal_instance}, fn x -> Kernel.elem(x, 0) == :instance end)

    if instance < @snmp_max_instance and instance >= @snmp_min_instance and args_ok?(parsed, bare, errors) do
      if Enum.count(parsed) > 1 do
        """
        mutation  {
          update(input: {
            clientMutationId: "snmp",
            snmp: {
              community: {
                #{parsed2args(parsed)}
              }
            }
          })
          {
            clientMutationId
            snmp {
              community {
              #{parsed2select(parsed)}
              }
            }
          }
        }
        """
      else
        """
        query{
          snmp {
            community(instance:#{instance}){
              name
              access
              nmsIp
            }
          }
        }
        """
      end
    else
      IO.puts("E102: Parameter Error")

      @snmp_help
      |> IO.puts()

      :halt
    end
  end

  def convert(_cli_args = ["snmpv3"]) do
    """
    query{
      snmp {
        v3Enable
        userAccess {
          userAccessEnable
          userName
          nmsIp
          instance
        }
        user {
          privacyProtocol
          authenticationProtocol
          name
          instance
        }
      }
    }
    """
  end

  def convert(_cli_args = ["snmpv3", "-S"]) do
    ("\nSNMPv3 Access:\t" <> "#{ConfigManager.get(:"snmp.v3_enable")}" <> "\n")
    |> check_string_for_enable()
    |> IO.puts()

    :halt
  end

  def convert(_cli_args = ["snmpv3", "-T"]) do
    IO.puts(@success)

    snmp_map =
      """
      query{
        snmp {
          v3Enable
          userAccess {
            userAccessEnable
            userName
          }
          user {
            privacyProtocol
            authenticationProtocol
            name
          }
        }
      }
      """
      |> Absinthe.run!(CommonCore.Schema)

    all = fn :get, data, next ->
      data
      |> Enum.map(next)
    end

    user_access_enable = get_in(snmp_map, [:data, "snmp", "userAccess", all, "userAccessEnable"])
    user_name = get_in(snmp_map, [:data, "snmp", "user", all, "name"])
    privacy_protocol = get_in(snmp_map, [:data, "snmp", "user", all, "privacyProtocol"])

    authentication_protocol = get_in(snmp_map, [:data, "snmp", "user", all, "authenticationProtocol"])

    [
      ["User Name"] ++ user_name,
      ["Access"] ++ user_access_enable,
      ["Authentication"] ++ authentication_protocol,
      ["Encryption"] ++ privacy_protocol
    ]
    |> TableRex.Table.new(["Index", "0", "1", "2", "3"])
    |> TableRex.Table.put_header_meta(0..4, color: :blue)
    |> TableRex.Table.put_column_meta(0, color: :blue)
    |> TableRex.Table.put_column_meta(
      1..4,
      color: fn text, value ->
        if value == "ENABLE",
          do: [:green, text],
          else: if(value == "DISABLE", do: [:red, text], else: text)
      end
    )
    |> TableRex.Table.render!()
    |> String.replace("ENABLE ", "ENABLED")
    |> String.replace("DISABLE ", "DISABLED")
    |> IO.puts()

    :halt
  end

  def convert(_cli_args = ["snmpv3", "-S", "enable"]) do
    """
      mutation  {
        update(input: {
          clientMutationId: "snmp",
          snmp: {
              v3Enable: ENABLE
          }
        })
        {
          clientMutationId
          snmp {
            v3Enable
          }
        }
      }
    """
  end

  def convert(_cli_args = ["snmpv3", "-S", "disable"]) do
    """
      mutation  {
        update(input: {
          clientMutationId: "snmp",
          snmp: {
              v3Enable: DISABLE
          }
        })
        {
          clientMutationId
          snmp {
            v3Enable
          }
        }
      }
    """
  end

  def convert(_cli_args = ["snmpv3", arg]) when arg in ["help", "?"] do
    @snmpv3_help
    |> IO.puts()

    :halt
  end

  # SNMPv3 QUERY
  def convert(_cli_args = ["snmpv3" | snmp_args]) when length(snmp_args) == 3 do
    switches = [
      # i
      instance: :integer,
      # u
      name: :string,
      # A
      authenticationProtocol: :string,
      # a
      authenticationKey: :string,
      # p
      privacyKey: :string,
      # P
      privacyProtocol: :string,
      # e
      userAccessEnable: :string,
      # U
      userName: :string
    ]

    aliases = [
      i: :instance,
      u: :name,
      A: :authenticationProtocol,
      a: :authenticationKey,
      p: :privacyKey,
      P: :privacyProtocol,
      e: :userAccessEnable
    ]

    enums = []

    # Throw away string to parse args
    snmp_args = snmp_args ++ ["1"]
    {parsed, bare, errors} = option_parse(snmp_args, switches: switches, aliases: aliases, enums: enums)

    # Sets instances to begin from 1
    parsed = adjust_instance(parsed)

    {:instance, instance} = Enum.find(parsed, {:instance, @illegal_instance}, fn x -> Kernel.elem(x, 0) == :instance end)

    u_params = Keyword.take(parsed, [:name, :authenticationProtocol, :privacyProtocol, :privacyKey, :authenticationKey])
    ua_params = Keyword.take(parsed, [:userAccessEnable, :userName])

    # Check for which list has elements
    u_len = length(u_params)
    ua_len = length(ua_params)

    # Mitigation for a unique case where querying '-i' would get past the
    # option_parse but not be queriable resulting in an crash
    unless u_len == 0 && ua_len == 0 do
      if instance < @snmpv3_max_instance and instance >= @snmpv3_min_instance and args_ok?(parsed, bare, errors) do
        """
        query {
          snmp {
            #{case 1 do
          ^u_len -> "user (instance:#{instance}) {
                          #{parsed2select(parsed)}
                      }"
          ^ua_len -> "userAccess (instance:#{instance}) {
                          #{parsed2select(parsed)}
                      }"
        end}
          }
        }
        """
      else
        IO.puts("E102: Parameter Error")

        @snmpv3_help
        |> IO.puts()

        :halt
      end
    else
      IO.puts("E102: Parameter Error")

      @snmpv3_help
      |> IO.puts()

      :halt
    end
  end

  # SNMPv3 MUTATION
  def convert(_cli_args = ["snmpv3" | snmp_args]) do
    switches = [
      # i
      instance: :integer,
      # u
      name: :string,
      # A
      authenticationProtocol: :string,
      # a
      authenticationKey: :string,
      # p
      privacyKey: :string,
      # P
      privacyProtocol: :string,
      # e
      userAccessEnable: :string,
      # U
      userName: :string
    ]

    # These map to the full switch names (ex system -l location )
    # They must match the arg names in cli.csv for the legacy system
    aliases = [
      i: :instance,
      u: :name,
      A: :authenticationProtocol,
      a: :authenticationKey,
      p: :privacyKey,
      P: :privacyProtocol,
      e: :userAccessEnable
    ]

    enums = [
      :authenticationProtocol,
      :privacyProtocol,
      :userAccessEnable,
      :userName
    ]

    {parsed, bare, errors} = option_parse(snmp_args, switches: switches, aliases: aliases, enums: enums)

    # pulls out the profile that matches the inputted name
    referenced_profile = matched_snmp_profile_by_name(parsed[:name])

    # Adds unused keys behind the scenes when setting protocols to none
    parsed =
      if parsed[:authenticationProtocol] == :NONE do
        parsed ++ [authenticationKey: "123456789abcdef"]
      else
        parsed
      end

    parsed =
      if parsed[:privacyProtocol] == :NONE do
        parsed ++ [privacyKey: "123456789abcdef"]
      else
        parsed
      end

    # Sets instances to begin from 1
    parsed = adjust_instance(parsed)

    valid_name = referenced_profile != 0

    # case to decide whether to mutate, display error, or proceed unchanged
    c1 = parsed[:userAccessEnable] && valid_name
    c2 = parsed[:userAccessEnable] && !valid_name

    parsed =
      cond do
        c1 ->
          pointer = String.to_atom("PROFILE_#{referenced_profile[:instance]}")
          ret = List.keydelete(parsed, :name, 0)
          ret = ret ++ [userName: pointer]
          ret

        c2 ->
          """
          E102: Parameter Error

              User name must match target profile in order to change access

          """
          |> IO.puts()

          :halt

        true ->
          parsed
      end

    if args_ok?(parsed, bare, errors) do
      # As the arguments are being split, first ensure that there is an instance , then that there is at least one argument
      # (other than instance)
      # The back end does not check for the instance range, and allows any instance value, so check for the range here.
      if parsed[:instance] == nil || parsed[:instance] < @snmpv3_min_instance || parsed[:instance] >= @snmpv3_max_instance do
        IO.puts("E102: Parameter Error")

        @snmpv3_help
        |> IO.puts()

        :halt
      else
        if Enum.count(parsed) == 1 do
          """
          query{
            snmp {
              v3Enable
              userAccess {
                userAccessEnable
                userName
                nmsIp
                instance
              }
              user (instance:#{parsed[:instance]}){
                privacyProtocol
                authenticationProtocol
                name
                instance
              }
            }
          }
          """
        else
          access_args = Keyword.take(parsed, [:userAccessEnable, :userName])
          user_args = Keyword.take(parsed, [:name, :authenticationProtocol, :authenticationKey, :privacyKey, :privacyProtocol])

          case {Enum.count(access_args), Enum.count(user_args)} do
            {_, 0} ->
              if Keyword.get(access_args, :userName) && Keyword.get(access_args, :userAccessEnable) do
                # nmsIp option removed as it only accepts value "0.0.0.0", but need to include key in mutation, due to downstream validation function
                access_args =
                  Keyword.put_new(access_args, :nmsIp, "0.0.0.0")
                  |> Keyword.put_new(:instance, parsed[:instance])

                """
                mutation  {
                  update(input: {
                    clientMutationId: "snmp",
                    snmp: {
                      userAccess: {
                        #{parsed2args(access_args)}
                      }
                    }
                  })
                  {
                    clientMutationId
                    snmp {
                      userAccess {
                        #{parsed2select(access_args)}
                      }
                    }
                  }
                }
                """
              else
                """
                E102: Parameter Error

                  Both user name and access enable options must be included in the user access command

                """
                |> IO.puts()

                :halt
              end

            {0, _} ->
              user_args = Keyword.put_new(user_args, :instance, parsed[:instance])

              # CLI crashes if all some options are included without the user name,
              # so to avoid crashing the CLI, just ensure that all options are included
              if Enum.count(user_args) == 6 do
                """
                mutation  {
                  update(input: {
                    clientMutationId: "snmp",
                    snmp: {
                      user: {
                        #{parsed2args(user_args)}
                      }
                    }
                  })
                  {
                    clientMutationId
                    snmp {
                      user {
                      #{parsed2select(user_args)}
                      }
                    }
                  }
                }
                """
              else
                """
                E102: Parameter Error

                  To change user profile settings, all options must be included in the command

                """
                |> IO.puts()

                :halt
              end

            _ ->
              """
              E102: Parameter Error

                Options for both user access settings and privacy and authentication settings cannot be included in the same command

              """
              |> IO.puts()

              :halt
          end
        end
      end
    else
      IO.puts("E102: Parameter Error")

      @snmpv3_help
      |> IO.puts()

      :error
    end
  end


  def convert(_cli_args = ["user", arg]) when arg in ["help", "?"] do
    if get_current_user_type() in [:super_user, :admin] do
      user_usage()
      |> IO.puts()
    else
      user_usage_unprivileged()
      |> IO.puts()
    end

    :halt
  end

  def convert(_cli_args = ["user"]) do
    IO.puts(@success)

    user_map =
      """
      query{
        security {
          userManagement {
            users {
              userName
              userType
              accessEnable
              visible
            }
          superUser {
              userName
              userType
              userDescription
              accessEnable
            }
          }
        }
      }
      """
      |> Absinthe.run!(CommonCore.Schema)

    super_name = get_in(user_map, [:data, "security", "userManagement", "superUser", "userName"])
    super_user_type = get_in(user_map, [:data, "security", "userManagement", "superUser", "userType"])
    super_user_enable = get_in(user_map, [:data, "security", "userManagement", "superUser", "accessEnable"])

    header = ["Name", "Type", "Status"]
    first_row = ["#{super_name}", "#{String.downcase(super_user_type)}", "#{String.downcase(super_user_enable)}"]

    all = fn :get, data, next ->
      data
      |> Enum.filter(fn %{"visible" => visible} -> visible == "TRUE" end)
      |> Enum.map(next)
    end

    name = get_in(user_map, [:data, "security", "userManagement", "users", all, "userName"])
    type = get_in(user_map, [:data, "security", "userManagement", "users", all, "userType"])
    enable = get_in(user_map, [:data, "security", "userManagement", "users", all, "accessEnable"])

    row =
      if Enum.count(name) != 0 do
        for i <- 0..(Enum.count(name) - 1),
            do: [Enum.at(name, i), String.downcase(Enum.at(type, i)), String.downcase(Enum.at(enable, i))]
      else
        []
      end

    row = Enum.filter(row, fn x -> x != [nil, nil, nil] end)

    ([first_row] ++ row)
    |> filter_based_on_user_permissions()
    |> TableRex.Table.new(header)
    |> TableRex.Table.render!(
      horizontal_style: :header,
      top_frame_symbol: "",
      bottom_frame_symbol: "",
      intersection_symbol: "",
      header_separator_symbol: "-",
      horizontal_symbol: "",
      vertical_symbol: ""
    )
    |> check_string_for_enable()
    |> IO.puts()

    :error
  end

  # user - single query
  def convert(_cli_args = ["user" | user_args]) when length(user_args) == 3 and tl(tl(user_args)) !== ["-D"] do
    switches = [
      userType: :string,
      userDescription: :string,
      accessEnable: :string,
      sessionTimeout: :interger,
      eventLogColorCodingEnable: :string,
      logExportFormat: :string,
      temperatureScale: :string,
      dateFormat: :string,
      languageCode: :string
    ]

    aliases = [
      a: :userType,
      d: :userDescription,
      e: :accessEnable,
      t: :sessionTimeout,
      l: :logExportFormat,
      s: :temperatureScale
    ]

    enums = [
      :accessEnable,
      :logExportFormat,
      :eventLogColorCodingEnable,
      :temperatureScale,
      :userType
    ]

    [_head | [user_name | _tail]] = user_args

    # Throw away sring to parse args
    user_args = tl(tl(user_args)) ++ ["string"]
    {parsed, bare, errors} = option_parse(user_args, switches: switches, aliases: aliases, enums: enums)

    if args_ok?(parsed, bare, errors) do
      # user -n <name>
      if user_name == user_superusername() do
        # Do we have enough privilege ?
        if get_current_user_type() == :super_user do
          user_map =
            """
              query{
                security {
                  userManagement {
                    superUser {
                      #{parsed2select(parsed)} #{if parsed[:sessionTimeout], do: "(decimalDigits: 0)", else: ""}
                    }
                  }
                }
              }
            """
            |> Absinthe.run!(CommonCore.Schema)

          IO.puts(@success)

          if get_in(user_map, [:data, "security", "userManagement", "superUser", "accessEnable"]),
            do:
              ("\nAccess: " <> String.downcase(get_in(user_map, [:data, "security", "userManagement", "superUser", "accessEnable"])))
              |> check_string_for_enable()
              |> IO.puts()

          if get_in(user_map, [:data, "security", "userManagement", "superUser", "userType"]),
            do:
              IO.puts(
                "\nUser Permission: " <> String.downcase(get_in(user_map, [:data, "security", "userManagement", "superUser", "userType"]))
              )

          if get_in(user_map, [:data, "security", "userManagement", "superUser", "userDescription"]),
            do: IO.puts("\nUser Description: " <> get_in(user_map, [:data, "security", "userManagement", "superUser", "userDescription"]))

          if get_in(user_map, [:data, "security", "userManagement", "superUser", "sessionTimeout"]),
            do: IO.puts("\nSession Timeout: " <> get_in(user_map, [:data, "security", "userManagement", "superUser", "sessionTimeout"]))

          if get_in(user_map, [:data, "security", "userManagement", "superUser", "logExportFormat"]),
            do:
              IO.puts(
                "\nExport Log Format: " <>
                  String.downcase(get_in(user_map, [:data, "security", "userManagement", "superUser", "logExportFormat"]))
              )

          if get_in(user_map, [:data, "security", "userManagement", "superUser", "temperatureScale"]),
            do:
              IO.puts(
                "\nTemperature Scale: " <>
                  String.downcase(get_in(user_map, [:data, "security", "userManagement", "superUser", "temperatureScale"]))
              )

          IO.puts("")
          :error
        else
          IO.puts("E102: Parameter Error")
          IO.puts("Only user with admin permissions can view other users' information")
          :error
        end
      else # we're not super-user
        if user_name == get_current_user_name() or get_current_user_type() == :super_user or get_current_user_type() == :admin do
          user_index = user_name2index(user_name)

          user_map =
            """
              query {
                security {
                  userManagement{
                    users(instance:#{user_index}){
                    #{parsed2select(parsed)} #{if parsed[:sessionTimeout], do: "(decimalDigits: 0)", else: ""}
                    }
                  }
                }
              }
            """
            |> Absinthe.run!(CommonCore.Schema)

          user_map = get_in(user_map, [:data, "security", "userManagement", "users"])

          if user_map != nil do
            [user_map] = user_map
            IO.puts(@success)

            if Map.has_key?(user_map, "accessEnable"),
              do:
                ("\nAccess: " <> String.downcase(Map.fetch!(user_map, "accessEnable")))
                |> check_string_for_enable()
                |> IO.puts()

            if Map.has_key?(user_map, "userType"),
              do: IO.puts("\nUser Permission: " <> String.downcase(Map.fetch!(user_map, "userType")))

            if Map.has_key?(user_map, "userDescription"),
              do: IO.puts("\nUser Description: " <> Map.fetch!(user_map, "userDescription"))

            if Map.has_key?(user_map, "sessionTimeout"),
              do: IO.puts("\nSession Timeout: " <> Map.fetch!(user_map, "sessionTimeout"))

            if Map.has_key?(user_map, "logExportFormat"),
              do: IO.puts("\nExport Log Format: " <> String.downcase(Map.fetch!(user_map, "logExportFormat")))

            if Map.has_key?(user_map, "temperatureScale"),
              do: IO.puts("\nTemperature Scale: " <> String.downcase(Map.fetch!(user_map, "temperatureScale")))

            IO.puts("")
            :error
          else
            IO.puts("User #{user_name} could not be found!")
            IO.puts("E100: Command Failed")
            :halt
          end
        else # Either super-user or asking for information for himself
          IO.puts("E102: Parameter Error")
          IO.puts("Only user with admin permissions can view other users' information")
          :error
        end
      end
    else
      IO.puts("E102: Parameter Error")

      @user_usage
      |> IO.puts()

      :halt
    end
  end

  def convert(_cli_args = ["user" | user_args]) do
    [head | tail] = user_args

    convert_user(head, tail)
  end

  def convert(_cli_args = ["system"]) do
    """
    query {
      system {
        contact
        name
        location
        login_message
      }
    }
    """
  end

  def convert(_cli_args = ["system" | system_args]) do
    # These must match the names in the DataDictionary
    switches = [
      contact: :string,
      name: :string,
      location: :string,
      login_message: :string
    ]

    # These map to the full switch names (ex system -l location )
    # They must match the arg names in cli.csv for the legacy system
    aliases = [
      c: :contact,
      n: :name,
      l: :location,
      m: :login_message
    ]

    enums = []

    {parsed, bare, errors} = option_parse(system_args, switches: switches, aliases: aliases, enums: enums)

    if args_ok?(parsed, bare, errors) do
      """
      mutation  {
        update(input: {
          clientMutationId: "system",
          system: {
            #{parsed2args(parsed)}
          }
        })
        {
          clientMutationId
          system {
            #{parsed2select(parsed)}
          }
        }
      }
      """
    else
      if !Enum.empty?(errors) do
        case system_args do
          ["-n"] ->
            """
            query {
              system{
                name
              }
            }
            """

          ["-c"] ->
            """
            query {
              system{
                contact
              }
            }
            """

          ["-l"] ->
            """
            query {
              system{
                location
              }
            }
            """

          ["-m"] ->
            """
            query {
              system{
                login_message
              }
            }
            """

          # Handle unhandled -options
          _ ->
            IO.puts("E102: Parameter Error")

            @system_usage
            |> IO.puts()

            :halt
        end
      else
        unless help_request?(bare) do
          IO.puts("E102: Parameter Error")
        end

        @system_usage
        |> IO.puts()

        :halt
      end
    end
  end

  def convert(_cli_args = ["userdflt", arg]) when arg in ["help", "?"] do
    @userdflt_help
    |> IO.puts()

    :halt
  end

  def convert(_cli_args = ["userdflt"]) do
    IO.puts(@success)

    """
    query{
      security{
        userManagement{
          defaults{
            accessEnable
            badLoginAttempts(decimalDigits:0)
            logExportFormat
            passwordPolicy(decimalDigits:0)
            sessionTimeout(decimalDigits:0)
            strongPasswords
            temperatureScale
            userDescription
            userType
          }
        }
      }
    }
    """
  end

  # userdflt - single query
  def convert(_cli_args = ["userdflt" | arg]) when length(arg) == 1 do
    switches = [
      accessEnable: :string,
      badLoginAttempts: :string,
      logExportFormat: :string,
      passwordPolicy: :string,
      sessionTimeout: :string,
      strongPasswords: :string,
      temperatureScale: :string,
      userDescription: :string,
      userType: :string
    ]

    aliases = [
      e: :accessEnable,
      b: :badLoginAttempts,
      l: :logExportFormat,
      i: :passwordPolicy,
      t: :sessionTimeout,
      q: :strongPasswords,
      s: :temperatureScale,
      d: :userDescription,
      a: :userType
    ]

    enums = [
      :accessEnable,
      :logExportFormat,
      :passwordPolicy,
      :strongPasswords,
      :temperatureScale,
      :userType
    ]

    # Throw away string to parse args
    arg = arg ++ ["string"]
    {parsed, bare, errors} = option_parse(arg, switches: switches, aliases: aliases, enums: enums)

    if args_ok?(parsed, bare, errors) do
      num_format = parsed[:sessionTimeout] || parsed[:badLoginAttempts] || parsed[:passwordPolicy]
      IO.puts(@success)

      """
      query{
        security{
          userManagement{
            defaults{
            #{parsed2select(parsed)} #{if num_format, do: "(decimalDigits: 0)", else: ""}
            }
          }
        }
      }
      """
    else
      IO.puts("E102: Parameter Error")

      @userdflt_help
      |> IO.puts()

      :halt
    end
  end

  def convert(_cli_args = ["userdflt" | userdflt_args]) do
    # These must match the names in the DataDictionary
    switches = [
      accessEnable: :string,
      badLoginAttempts: :integer,
      logExportFormat: :string,
      passwordPolicy: :integer,
      sessionTimeout: :integer,
      strongPasswords: :string,
      temperatureScale: :string,
      userDescription: :string,
      userType: :string
    ]

    userdflt_args =
      userdflt_args
      ## -bl maps to -b
      |> replace_multi_letter_options("-bl", "-b")
      ## -lf maps to -l
      |> replace_multi_letter_options("-lf", "-l")
      ## -pp maps to -p
      |> replace_multi_letter_options("-pp", "-i")
      ## -st maps to -s
      |> replace_multi_letter_options("-st", "-t")
      ## -sp maps to -q
      |> replace_multi_letter_options("-sp", "-q")
      ## -ts maps to -t
      |> replace_multi_letter_options("-ts", "-s")
      ## -pe maps to -x
      |> replace_multi_letter_options("-pe", "-a")

    # These map to the full switch names (ex system -l location )
    # They must match the arg names in cli.csv for the legacy system
    aliases = [
      e: :accessEnable,
      b: :badLoginAttempts,
      l: :logExportFormat,
      i: :passwordPolicy,
      t: :sessionTimeout,
      q: :strongPasswords,
      s: :temperatureScale,
      d: :userDescription,
      a: :userType
    ]

    enums = [
      :accessEnable,
      :logExportFormat,
      :strongPasswords,
      :temperatureScale,
      :userType
    ]

    {parsed, bare, errors} = option_parse(userdflt_args, switches: switches, aliases: aliases, enums: enums)

    if args_ok?(parsed, bare, errors) do
      """
      mutation  {
        update(input: {
          clientMutationId: "userdflt",
          security: {
            userManagement: {
              defaults: {
              #{parsed2args(parsed)}
              }
            }
          }
        })
        {
          clientMutationId
          security {
            userManagement {
              defaults {
              #{parsed2select(parsed)}
              }
            }
          }
        }
      }
      """
    else
      unless help_request?(bare) do
        IO.puts("E102: Parameter Error")
      end

      @userdflt_help
      |> IO.puts()

      :halt
    end
  end

  def convert(_cli_args = ["web"]) do
    """
    query{
    web{
        settings{
          httpEnable
          httpPort
          httpsEnable
          httpsPort
          minimumProtocolV2
        }
      }
    }
    """
  end

  def convert(_cli_args = ["web", web_args]) when web_args in ["help", "?"] do
    @web_usage
    |> IO.puts()

    :halt
  end

  # web - single query
  def convert(_cli_args = ["web" | web_args]) when length(web_args) == 1 do
    switches = [
      httpEnable: :string,
      httpPort: :string,
      httpsEnable: :string,
      httpsPort: :string,
      minimumProtocolV2: :string
    ]

    # These map to the full switch names (ex system -l location )
    # They must match the arg names in cli.csv for the legacy system
    aliases = [
      h: :httpEnable,
      # ph
      H: :httpPort,
      s: :httpsEnable,
      # ps
      S: :httpsPort,
      # mp
      m: :minimumProtocolV2
    ]

    enums = [
      :httpEnable,
      :httpPort,
      :httpsEnable,
      :httpsPort,
      :minimumProtocolV2
    ]

    web_args =
      web_args
      |> replace_multi_letter_options("-ps", "-S")
      |> replace_multi_letter_options("-ph", "-H")
      |> replace_multi_letter_options("-mp", "-m")

    # Throw away string to parse args
    web_args = web_args ++ ["string"]
    {parsed, bare, errors} = option_parse(web_args, switches: switches, aliases: aliases, enums: enums)

    if args_ok?(parsed, bare, errors) do
      """
      query{
        web{
          settings{
            #{parsed2select(parsed)}
          }
        }
      }
      """
    else
      IO.puts("E102: Parameter Error")

      @web_usage
      |> IO.puts()

      :halt
    end
  end

  def convert(_cli_args = ["web" | web_args]) do
    # These must match the names in the DataDictionary

    # we need to replace -ph and -ps if they are present in the web_args
    # as they are causing warnings with Elixir's OptionParser Module because
    # of the multi-letter alias issue. So to counteract this without changing
    # the customer's CLI command options, we replace -ph and -ps (if they are present)
    # in the background with single letter options.
    # So here, -ph is mapped to -p and -ps is mapped to -q

    switches = [
      httpEnable: :string,
      httpPort: :integer,
      httpsEnable: :string,
      httpsPort: :integer,
      minimumProtocolV2: :string
    ]

    # These map to the full switch names (ex system -l location )
    # They must match the arg names in cli.csv for the legacy system
    aliases = [
      h: :httpEnable,
      # ph
      H: :httpPort,
      s: :httpsEnable,
      # ps
      S: :httpsPort,
      # mp
      m: :minimumProtocolV2
    ]

    enums = [
      :httpEnable,
      :httpsEnable,
      :minimumProtocolV2
    ]

    web_args =
      web_args
      |> replace_multi_letter_options("-ps", "-S")
      |> replace_multi_letter_options("-ph", "-H")
      |> replace_multi_letter_options("-mp", "-m")

    {parsed, bare, errors} = option_parse(web_args, switches: switches, aliases: aliases, enums: enums)

    if args_ok?(parsed, bare, errors) do
      """
      mutation  {
        update(input: {
          clientMutationId: "web",
          web: {
            settings: {
            #{parsed2args(parsed)}
            }
          }
        })
        {
          clientMutationId
          web {
            settings {
            #{parsed2select(parsed)}
            }
          }
        }
      }
      """
    else
      unless help_request?(bare) do
        IO.puts("E102: Parameter Error")
      end

      @web_usage
      |> IO.puts()

      :halt
    end
  end

  def convert(_cli_args = ["ssh"]) do
    """
    query{
      network{
        console{
          sshPort
          sshEnable
          telnetPort
        }
      }
    }
    """
  end

  def convert(_cli_args = ["ssh", ssh_args]) when ssh_args in ["help", "?"] do
    @ssh_usage
    |> IO.puts()

    :halt
  end

  # ssh - single query
  def convert(_cli_args = ["ssh" | ssh_args]) when length(ssh_args) == 1 do
    # These must match the names in the DataDictionary
    switches = [
      sshPort: :string,
      sshEnable: :string
    ]

    ## -ps maps to -p
    ssh_args = replace_multi_letter_options(ssh_args, "-ps", "-p")

    # These map to the full switch names (ex system -l location )
    # They must match the arg names in cli.csv for the legacy system
    aliases = [
      p: :sshPort,
      s: :sshEnable
    ]

    enums = [
      :sshEnable
    ]

    # Throw away string to parse args
    ssh_args = ssh_args ++ ["string"]
    {parsed, bare, errors} = option_parse(ssh_args, switches: switches, aliases: aliases, enums: enums)

    if args_ok?(parsed, bare, errors) do
      """
        query{
          network{
            console{
              #{parsed2select(parsed)}
            }
          }
        }
      """
    else
      IO.puts("E102: Parameter Error")

      @ssh_usage
      |> IO.puts()

      :halt
    end
  end

  def convert(_cli_args = ["ssh" | ssh_args]) do
    # These must match the names in the DataDictionary
    switches = [
      sshPort: :integer,
      sshEnable: :string
    ]

    ## -ps maps to -p
    ssh_args = replace_multi_letter_options(ssh_args, "-ps", "-p")

    # These map to the full switch names (ex system -l location )
    # They must match the arg names in cli.csv for the legacy system
    aliases = [
      p: :sshPort,
      s: :sshEnable
    ]

    enums = [
      :sshEnable
    ]

    {parsed, bare, errors} = option_parse(ssh_args, switches: switches, aliases: aliases, enums: enums)

    if args_ok?(parsed, bare, errors) do
      """
      mutation  {
        update(input: {
          clientMutationId: "ssh",
          network: {
            console: {
            #{parsed2args(parsed)}
            }
          }
        })
        {
          clientMutationId
          network {
            console {
            #{parsed2select(parsed)}
            }
          }
        }
      }
      """
    else
      unless help_request?(bare) do
        IO.puts("E102: Parameter Error")
      end

      @ssh_usage
      |> IO.puts()

      :halt
    end
  end

  def convert(_cli_args = ["dns"]) do
    """
    query{
      network{
        dns{
          activePrimaryServer
          activeSecondaryServer
          activeTertiaryServer
          activeHostName
          activeDomainNameV4v6
          activeDomainNameV6

          manualOverride
          configPrimaryServer
          configSecondaryServer
          systemNameSynch
          configHostName
          configDomainNameV4v6
          configDomainNameV6

        }
      }
    }
    """
  end

  def convert(_cli_args = ["dns", dns_arg]) when dns_arg in ["?", "help"] do
    @dns_help
    |> IO.puts()

    :halt
  end

  def convert(_cli_args = ["dns", dns_arg]) do
    switches = [
      manualOverride: :string,
      configPrimaryServer: :string,
      configSecondaryServer: :string,
      systemNameSynch: :string,
      configHostName: :string,
      configDomainNameV4v6: :string,
      configDomainNameV6: :string
    ]

    dns_arg = replace_multi_letter_options(dns_arg, "-OM", "-O")

    aliases = [
      O: :manualOverride,
      p: :configPrimaryServer,
      s: :configSecondaryServer,
      y: :systemNameSynch,
      h: :configHostName,
      d: :configDomainNameV4v6,
      n: :configDomainNameV6
    ]

    enums = []

    dns_arg = [dns_arg] ++ ["Almost Useless String"]
    {parsed, bare, errors} = option_parse(dns_arg, switches: switches, aliases: aliases, enums: enums)

    if args_ok?(parsed, bare, errors) do
      dns_params =
        Keyword.take(parsed, [
          :manualOverride,
          :configPrimaryServer,
          :configSecondaryServer,
          :systemNameSynch,
          :configHostName,
          :configDomainNameV4v6,
          :configDomainNameV6
        ])

      """
      query {
        network {
          dns {
            #{parsed2select(dns_params)}
          }
        }
      }
      """
    else
      IO.puts("E102: Parameter Error")

      @dns_help
      |> IO.puts()

      :halt
    end
  end

  def convert(_cli_args = ["dns" | dns_args]) do
    # These must match the names in the DataDictionary
    switches = [
      manualOverride: :string,
      configPrimaryServer: :string,
      configSecondaryServer: :string,
      systemNameSynch: :string,
      configHostName: :string,
      configDomainNameV4v6: :string,
      configDomainNameV6: :string
    ]

    ## -OM maps to -O
    dns_args = replace_multi_letter_options(dns_args, "-OM", "-O")

    # These map to the full switch names (ex system -l location )
    # They must match the arg names in cli.csv for the legacy system
    aliases = [
      O: :manualOverride,
      p: :configPrimaryServer,
      s: :configSecondaryServer,
      y: :systemNameSynch,
      h: :configHostName,
      d: :configDomainNameV4v6,
      n: :configDomainNameV6
    ]

    enums = [
      :manualOverride,
      :systemNameSynch
    ]

    {parsed, bare, errors} = option_parse(dns_args, switches: switches, aliases: aliases, enums: enums)

    if args_ok?(parsed, bare, errors) do
      """
      mutation  {
        update(input: {
          clientMutationId: "dns",
          network: {
            dns: {
            #{parsed2args(parsed)}
            }
          }
        })
        {
          clientMutationId
          network {
            dns{
            #{parsed2select(parsed)}
            }
          }
        }
      }
      """
    else
      IO.puts("E102: Parameter Error")

      @dns_help
      |> IO.puts()

      :halt
    end
  end

  def convert(_cli_args = ["tcpip", arg]) when arg in ["help", "?"] do
    @tcpip_usage
    |> IO.puts()

    :halt
  end

  # tcpip - single query. The queries are for Active ip settings.
  def convert(_cli_args = ["tcpip" | tcpip_args]) when length(tcpip_args) == 1 do
    # These must match the names in the DataDictionary
    switches = [
      enable: :string,
      address: :string,
      subnetMask: :string,
      defaultGateway: :string,
      addressMode: :string
    ]

    # These map to the full switch names (ex system -l location )
    # They must match the arg names in cli.csv for the legacy system
    aliases = [
      S: :enable,
      i: :address,
      s: :subnetMask,
      g: :defaultGateway,
      b: :addressMode
    ]

    enums = [
      :enable,
      :addressMode
    ]

    # Throw away string to parse args
    tcpip_args = tcpip_args ++ ["string"]

    {parsed, bare, errors} = option_parse(tcpip_args, switches: switches, aliases: aliases, enums: enums)
    # Keep macAddress jere to differenciate with a "boot" query
    if args_ok?(parsed, bare, errors) do
      """
        query{
          network{
            macAddress
            ipv4{
              #{parsed2select(parsed)}
            }
          }
        }
      """
    else
      IO.puts("E102: Parameter Error")

      @tcpip_usage
      |> IO.puts()

      :halt
    end
  end

  def convert(_cli_args = ["tcpip"]) do
    """
    query{
      network{
        macAddress
        ipv4{
          enable
          addressMode
          address
          subnetMask
          defaultGateway
          staticAddress
          staticSubnetMask
          staticDefaultGateway
        }
        dns{
          configHostName
        }
      }
    }
    """
  end

  def convert(_cli_args = ["tcpip" | tcpip_args]) do
    # These must match the names in the DataDictionary
    switches = [
      enable: :string,
      staticAddress: :string,
      staticSubnetMask: :string,
      staticDefaultGateway: :string,
      addressMode: :string
    ]

    # These map to the full switch names (ex system -l location )
    # They must match the arg names in cli.csv for the legacy system
    aliases = [
      S: :enable,
      i: :staticAddress,
      s: :staticSubnetMask,
      g: :staticDefaultGateway,
      b: :addressMode
    ]

    enums = [
      :enable,
      :addressMode
    ]

    {parsed, bare, errors} = option_parse(tcpip_args, switches: switches, aliases: aliases, enums: enums)

    if args_ok?(parsed, bare, errors) do
      """
      mutation  {
        update(input: {
          clientMutationId: "tcpip",
          network: {
            ipv4: {
            #{parsed2args(parsed)}
            }
          }
        })
        {
          clientMutationId
          network {
            ipv4 {
            #{parsed2select(parsed)}
            }
          }
        }
      }
      """
    else
      unless help_request?(bare) do
        IO.puts("E102: Parameter Error")
      end

      @tcpip_usage
      |> IO.puts()

      :halt
    end
  end

  def convert(_cli_args = ["eapol", "-S"]) do
    status =
      case EAPoL.Settings.settings().status do
        :disable -> "disabled"
        :enable -> "enabled"
      end

    IO.puts(@success)
    IO.puts("Status:		#{status}\n")

    :halt
  end

  def convert(_cli_args = ["eapol", "-p"]) do
    passphrase =
      case EAPoL.Settings.settings().passphrase do
        "" -> "<not set>"
        _ -> "<set>"
      end

    IO.puts(@success)
    IO.puts("Passphrase:		#{passphrase}\n")

    :halt
  end

  def convert(_cli_args = ["eapol", "-n"]) do
    supplicant_name =
      case EAPoL.Settings.settings().supplicant_name do
        "" -> "<not set>"
        other -> other
      end

    IO.puts(@success)
    IO.puts("Supplicant Name:	#{supplicant_name}\n")

    :halt
  end

  def convert(_cli_args = ["eapol", "-r"]) do
    case EAPoL.Settings.settings().status do
      :enable ->
        EAPoL.trigger_reconfigure(:user)
        IO.puts(@success)

      :disable ->
        """
        E102: Parameter Error
        To force EAP reauthentication EAPoL must be enabled.
        """
        |> IO.puts()
    end

    :halt
  end

  def convert(_cli_args = ["eapol"]) do
    status =
      case EAPoL.Settings.settings().status do
        :disable -> "disabled"
        :enable -> "enabled"
      end

    passphrase =
      case EAPoL.Settings.settings().passphrase do
        "" -> "<not set>"
        _ -> "<set>"
      end

    supplicant_name =
      case EAPoL.Settings.settings().supplicant_name do
        "" -> "<not set>"
        other -> other
      end

    ca_file_status = EAPoL.Settings.ca_file_status()
    private_key_status = EAPoL.Settings.pk_cert_status()
    public_key_status = EAPoL.Settings.user_cert_status()
    result_status = EAPoL.Settings.result_status()

    output = """
    Active EAPoL Settings
    --------------------

      Status:		#{status}
      Supplicant Name:	#{supplicant_name}
      Passphrase:		#{passphrase}
      CA file Status:	#{ca_file_status}
      Private Key Status:	#{private_key_status}
      Public Key Status:	#{public_key_status}
      Result:		#{result_status}
    """

    IO.puts(@success)
    IO.puts(output)

    :halt
  end

  def convert(_cli_args = ["eapol", arg]) when arg in ["help", "?"] do
    @eapol_usage
    |> IO.puts()

    :halt
  end

  def convert(_cli_args = ["eapol" | args]) do
    switches = [
      status: :string,
      passphrase: :string,
      supplicantName: :string,
      reauthenticate: :boolean
    ]

    aliases = [
      S: :status,
      p: :passphrase,
      n: :supplicantName,
      r: :reauthenticate
    ]

    enums = [
      :status,
      :passphrase,
      :supplicantName,
      :reauthenticate
    ]

    opts = [switches: switches, aliases: aliases, enums: enums]

    try do
    {parsed, bare, errors} = OptionParser.parse(args, strict: opts[:switches], aliases: opts[:aliases])

    # convert status to correct type for mutation
    {parsed, errors} =
      case Keyword.get(parsed, :status, :not_found) do
        "enable" -> {Keyword.put(parsed, :status, :ENABLE), errors}
        "disable" -> {Keyword.put(parsed, :status, :DISABLE), errors}
        :not_found -> {parsed, errors}
        invalid_value -> {parsed, [{"-S", invalid_value}] ++ errors}
      end

    errors =
      if Keyword.get(parsed, :reauthenticate) != nil do
        errors ++ ["Parameter '-r' cannot be used in conjuction with other parameters."]
      else
        errors
      end

    if errors == [] and bare == [] do
      """
      mutation  {
        update(input: {
          clientMutationId: "eapol",
          network: {
            eapol: {
              #{parsed2args(parsed)}
            }
          }
        })
        {
          clientMutationId
          network {
            eapol {
              #{parsed2select(parsed)}
            }
          }
        }
      }
      """
    else
      IO.puts("E102: Parameter Error")
      # Print errors from the list that are simply strings
      if is_list(errors),
        do:
          Enum.each(errors, fn err ->
            if is_binary(err) do
              IO.puts("#{err}")
            end
          end)

      IO.puts("")
      IO.puts(@eapol_usage)
      :halt
    end

    rescue
      error ->
        Logger.error("Error parsing #{inspect args}. Reason: #{inspect error}")
        IO.puts("E102: Parameter Error")
        IO.puts("")
        IO.puts(@eapol_usage)
        :halt
    end
  end

  def convert(_cli_args = ["tcpip6", arg]) when arg in ["help", "?"] do
    IO.puts(@success)

    @tcpip6_usage
    |> IO.puts()

    :halt
  end

  # tcpip6 - single query
  def convert(_cli_args = ["tcpip6" | tcpip6_args]) when length(tcpip6_args) == 1 do
    # These must match the names in the DataDictionary
    switches = [
      enable: :string,
      address: :string,
      manualEnable: :string,
      autoconfigEnable: :string,
      gateway: :string,
      dhcp: :string
    ]

    tcpip6_args =
      tcpip6_args
      ## -man maps to -m
      |> replace_multi_letter_options("-man", "-m")
      ## -auto maps to -a
      |> replace_multi_letter_options("-auto", "-a")
      ## -d6 maps to -d
      |> replace_multi_letter_options("-d6", "-d")

    # These map to the full switch names (ex system -l location )
    # They must match the arg names in cli.csv for the legacy system
    aliases = [
      S: :enable,
      i: :address,
      m: :manualEnable,
      a: :autoconfigEnable,
      g: :gateway,
      d: :dhcp
    ]

    enums = [
      :enable,
      :manualEnable,
      :autoconfigEnable,
      :dhcp
    ]

    # Throw away string to parse args
    tcpip6_args = tcpip6_args ++ ["string"]
    {parsed, bare, errors} = option_parse(tcpip6_args, switches: switches, aliases: aliases, enums: enums)

    if args_ok?(parsed, bare, errors) do
      """
        query{
        network{
            ipv6{
              #{parsed2select(parsed)}
            }
          }
        }
      """
    else
      IO.puts("E102: Parameter Error")

      @tcpip6_usage
      |> IO.puts()

      :halt
    end
  end

  def convert(_cli_args = ["tcpip6"]) do
    """
    query{
    network{
        macAddress
        ipv6{
          endpoints{
            address
            type
            scope
          }
          address
          autoconfigEnable
          dhcp
          enable
          gateway
          manualEnable
          pingResponse
        }
      }
    }
    """
  end

  def convert(_cli_args = ["tcpip6" | tcpip6_args]) do
    # These must match the names in the DataDictionary
    switches = [
      enable: :string,
      address: :string,
      manualEnable: :string,
      autoconfigEnable: :string,
      gateway: :string,
      dhcp: :string
    ]

    tcpip6_args =
      tcpip6_args
      ## -man maps to -m
      |> replace_multi_letter_options("-man", "-m")
      ## -auto maps to -a
      |> replace_multi_letter_options("-auto", "-a")
      ## -d6 maps to -d
      |> replace_multi_letter_options("-d6", "-d")

    # These map to the full switch names (ex system -l location )
    # They must match the arg names in cli.csv for the legacy system
    aliases = [
      S: :enable,
      i: :address,
      m: :manualEnable,
      a: :autoconfigEnable,
      g: :gateway,
      d: :dhcp
    ]

    enums = [
      :enable,
      :manualEnable,
      :autoconfigEnable,
      :dhcp
    ]

    {parsed, bare, errors} = option_parse(tcpip6_args, switches: switches, aliases: aliases, enums: enums)

    if args_ok?(parsed, bare, errors) do
      # Check to stop configuration until ipv6 has been enabled
      # while allowing multi-arg commands that include enabling ipv6
      if ConfigManager.get(:"network.ipv6.enable") == false &&
           !(parsed2args(parsed) == "enable: DISABLE" || String.contains?(parsed2args(parsed), "enable: ENABLE")) do
        IO.puts("IPv6 must be enabled in order to change IPv6 configuration")
        IO.puts("E100: Command Failed\n")
        :halt
      else
        """
        mutation  {
          update(input: {
            clientMutationId: "tcpip6",
            network: {
              ipv6: {
              #{parsed2args(parsed)}
              }
            }
          })
          {
            clientMutationId
            network {
              ipv6 {
              #{parsed2select(parsed)}
              }
            }
          }
        }
        """
      end
    else
      unless help_request?(bare) do
        IO.puts("E102: Parameter Error")
      end

      @tcpip6_usage
      |> IO.puts()

      :halt
    end
  end

  def convert(_cli_args = ["modbus", arg]) when arg in ["help", "?"] do
    @modbus_usage
    |> IO.puts()

    :halt
  end

  def convert(_cli_args = ["modbus", "-R"]) do
    """
    mutation  {
      update(input: {
        clientMutationId: "modbus",
        modbus: {
          rtuv2: {
            access: DISABLE, baudRate: BAUD_19200, slaveAddress: 1, parity: PARITY_EVEN, stopBits: STOP_BITS_ONE
          }
          tcp: {
            access: DISABLE, port: 502
          }
        }
      })
      {
        clientMutationId
        modbus {
          rtuv2 {
            access baudRate slaveAddress parity stopBits
          }
          tcp {
            access port
          }
        }
      }
    }
    """
  end

  # modbus - single query
  def convert(_cli_args = ["modbus" | modbus_args]) when length(modbus_args) == 1 do
    # These must match the names in the DataDictionary
    switches = [
      access: :string,
      baudRate: :string,
      parity: :string,
      stopBits: :string,
      slaveAddress: :string,
      # to be renamed :access later.
      tcpAccess: :string,
      port: :string
    ]

    aliases = [
      a: :access,
      b: :baudRate,
      p: :parity,
      S: :stopBits,
      s: :slaveAddress,
      e: :tcpAccess,
      n: :port
    ]

    enums = [
      :access,
      :baudRate,
      :parity,
      :stopBits,
      :tcpAccess
    ]

    # Throw away string to parse args
    modbus_args = modbus_args ++ ["string"]
    {parsed, bare, errors} = option_parse(modbus_args, switches: switches, aliases: aliases, enums: enums)

    rtu_list = [:access, :baudRate, :parity, :slaveAddress, :stopBits]
    tcp_list = [:tcpAccess, :port]

    parsed_rtu = for {key, val} <- parsed, key in rtu_list, do: {key, val}
    parsed_tcp = for {key, val} <- parsed, key in tcp_list, do: {key, val}

    if args_ok?(parsed, bare, errors) do
      if parsed_rtu != [] do
        parsed_rtu =
          if List.keymember?(parsed_rtu, :stopBits, 0) do
            {:stopBits, stop_bits} = List.keyfind(parsed_rtu, :stopBits, 0)
            List.keyreplace(parsed_rtu, :stopBits, 0, {:stopBits, convert_stop_bits_value(stop_bits)})
          else
            parsed_rtu
          end

        """
          query{
            modbus{
              rtuv2{
                #{parsed2select(parsed_rtu)}
              }
            }
          }
        """
      else
        parsed_tcp =
          if List.keymember?(parsed_tcp, :tcpAccess, 0) do
            {:tcpAccess, enable} = List.keyfind(parsed_tcp, :tcpAccess, 0)
            List.keyreplace(parsed_tcp, :tcpAccess, 0, {:access, enable})
          else
            parsed_tcp
          end

        """
          query{
            modbus{
              tcp{
                #{parsed2select(parsed_tcp)}
              }
            }
          }
        """
      end
    else
      IO.puts("E102: Parameter Error")

      @modbus_usage
      |> IO.puts()

      :halt
    end
  end

  def convert(_cli_args = ["modbus"]) do
    """
    query{
      modbus{
        rtuv2{
          access
          baudRate
          parity
          stopBits
          slaveAddress
        }
        tcp{
          access
          port
        }
      }
    }
    """
  end

  def convert(_cli_args = ["modbus" | modbus_args]) do
    # These must match the names in the DataDictionary
    switches = [
      access: :string,
      baudRate: :string,
      parity: :string,
      stopBits: :string,
      slaveAddress: :integer,
      # to be renamed :access later.
      tcpAccess: :string,
      port: :integer
    ]

    aliases = [
      a: :access,
      b: :baudRate,
      p: :parity,
      S: :stopBits,
      s: :slaveAddress,
      e: :tcpAccess,
      n: :port
    ]

    enums = [
      :access,
      :baudRate,
      :parity,
      :stopBits,
      :tcpAccess
    ]

    {parsed, bare, errors} = option_parse(modbus_args, switches: switches, aliases: aliases, enums: enums)

    rtu_list = [:access, :baudRate, :parity, :stopBits, :slaveAddress]
    tcp_list = [:tcpAccess, :port]

    parsed_rtu = for {key, val} <- parsed, key in rtu_list, do: {key, val}
    parsed_tcp = for {key, val} <- parsed, key in tcp_list, do: {key, val}

    # Extra code needed  because tcp access is called :access in the query
    # but :tcpAccess in the parser (as :access was already used)
    parsed_tcp =
      if List.keymember?(parsed_tcp, :tcpAccess, 0) do
        {:tcpAccess, enable} = List.keyfind(parsed_tcp, :tcpAccess, 0)
        List.keyreplace(parsed_tcp, :tcpAccess, 0, {:access, enable})
      else
        parsed_tcp
      end

    parsed_rtu =
      if List.keymember?(parsed_rtu, :stopBits, 0) do
        {:stopBits, stop_bits} = List.keyfind(parsed_rtu, :stopBits, 0)
        List.keyreplace(parsed_rtu, :stopBits, 0, {:stopBits, convert_stop_bits_value(stop_bits)})
      else
        parsed_rtu
      end

    if args_ok?(parsed, bare, errors) do
      """
      mutation  {
        update(input: {
          clientMutationId: "modbus",
          modbus: {
            #{parsed2args("rtuv2", parsed_rtu)}
            #{parsed2args("tcp", parsed_tcp)}
          }
        })
        {
          clientMutationId
          modbus {
            #{parsed2select("rtuv2", parsed_rtu)}
            #{parsed2select("tcp", parsed_tcp)}
          }
        }
      }
      """
    else
      IO.puts("E102: Parameter Error")

      @modbus_usage
      |> IO.puts()

      :error
    end
  end

  def convert(_cli_args = ["boot"]) do
    """
    query{
      network{
        ipv4{
          dhcp{
            requireCookie
            userClass
            vendorClass
            clientId
          }
          addressMode
        }
      }
    }
    """
  end

  # function for HELP arg
  def convert(_cli_args = ["boot", arg]) when arg in ["help", "?"] do
    @boot_help
    |> IO.puts()

    :halt
  end

  # function for QUERYING data
  def convert(_cli_args = ["boot", arg]) do
    # These must match the names in the DataDictionary
    switches = [
      requireCookie: :string,
      userClass: :string,
      vendorClass: :string,
      clientId: :string,
      addressMode: :string
    ]

    # These map to the full switch names (ex system -l location )
    # They must match the arg names in cli.csv for the legacy system
    aliases = [
      c: :requireCookie,
      u: :userClass,
      v: :vendorClass,
      i: :clientId,
      b: :addressMode
    ]

    enums = []

    # dummy_string will be ignored later - used to parse arg
    arg = [arg] ++ ["dummy_string"]
    {parsed, bare, errors} = option_parse(arg, switches: switches, aliases: aliases, enums: enums)

    ipv4_params = Keyword.take(parsed, [:addressMode])
    dhcp_params = Keyword.take(parsed, [:vendorClass, :userClass, :clientId, :requireCookie])

    ipv4_len = length(ipv4_params)
    dhcp_len = length(dhcp_params)

    if args_ok?(parsed, bare, errors) do
      """
      query {
        network {
          ipv4 {
            #{case 1 do
        ^ipv4_len -> "#{parsed2select(ipv4_params)}"
        ^dhcp_len -> "dhcp {
                    #{parsed2select(dhcp_params)}
                  }"
      end}
          }
        }
      }
      """
    else
      IO.puts("E102: Parameter Error")

      @boot_help
      |> IO.puts()

      :halt
    end
  end

  # function for MUTATING data
  def convert(_cli_args = ["boot" | boot_args]) do
    # These must match the names in the DataDictionary
    switches = [
      requireCookie: :string,
      userClass: :string,
      vendorClass: :string,
      clientId: :string,
      addressMode: :string
    ]

    # These map to the full switch names (ex system -l location )
    # They must match the arg names in cli.csv for the legacy system
    aliases = [
      c: :requireCookie,
      u: :userClass,
      v: :vendorClass,
      i: :clientId,
      b: :addressMode
    ]

    enums = [
      :requireCookie,
      :addressMode
    ]

    {parsed, bare, errors} = option_parse(boot_args, switches: switches, aliases: aliases, enums: enums)

    dhcp_list = [:requireCookie, :userClass, :vendorClass, :clientId]
    ipv4_list = [:addressMode]

    parsed_dhcp = for {key, val} <- parsed, key in dhcp_list, do: {key, val}
    parsed_ipv4 = for {key, val} <- parsed, key in ipv4_list, do: {key, val}

    if args_ok?(parsed, bare, errors) do
      mutation =
        case {parsed_dhcp, parsed_ipv4} do
          {[], _parsed} ->
            """
            mutation  {
              update(input: {
                clientMutationId: "boot",
                network: {
                  #{parsed2args("ipv4", parsed_ipv4)}
                }
              })
              {
                clientMutationId
                network {
                  #{parsed2select("ipv4", parsed_ipv4)}
                }
              }
            }
            """

          {_parsed, []} ->
            """
            mutation  {
              update(input: {
                clientMutationId: "boot",
                network: {
                  ipv4: {
                    #{parsed2args("dhcp", parsed_dhcp)}
                  }
                }
              })
              {
                clientMutationId
                network {
                  ipv4{
                    #{parsed2select("dhcp", parsed_dhcp)}
                  }
                }
              }
            }
            """

          _ ->
            """
            mutation  {
              update(input: {
                clientMutationId: "boot",
                network: {
                  ipv4: {
                    #{parsed2args(parsed_ipv4)}
                    #{parsed2args("dhcp", parsed_dhcp)}
                  }
                }
              })
              {
                clientMutationId
                network {
                  ipv4 {
                    #{parsed2select(parsed_ipv4)}
                    #{parsed2select("dhcp", parsed_dhcp)}
                  }
                }
              }
            }
            """
        end

      mutation
    else
      IO.puts("E102: Parameter Error")

      @boot_help
      |> IO.puts()

      :halt
    end
  end

    # reset to default help argument
    def convert(_cli_args = ["resetToDef", reset_args]) when reset_args in ["help", "?"] do
      @resetToDef_usage
      |> IO.puts()

      :halt
    end

  # reset to default CLI
  def convert(_cli_args = ["resetToDef" | reset_args]) do
    switches = [
      resetToDefault: :string
    ]

    aliases = [
      p: :resetToDefault
    ]

    enums = [:resetToDefault]

    {parsed, bare, errors} = option_parse(reset_args, switches: switches, aliases: aliases, enums: enums)

    # Check that the args are ok, check the value being applied is ok, and check that
    # the user has confirmed the reset
    with true <- args_ok?(parsed, bare, errors),
        [resetToDefault: arg] = parsed,
        true <- arg in [:ALL, :KEEPIP] do
      if prompt_confirm_reset() do
        """
        mutation  {
          update(input: {
            clientMutationId: "reset",
            network: {
              #{parsed2args(parsed)}
            }
          })
          {
            clientMutationId
            network {
              #{parsed2select(parsed)}
            }
          }
        }
        """
      else
        # If the user cancels the command at the prompt, do nothing
        :halt
      end
    else
      _ ->
        IO.puts("E102: Parameter Error")

        @resetToDef_usage
        |> IO.puts()

        :halt
    end
  end

  # uio status
  def format(%{"sensor" => sensor = %{"alarm_status" => _alarm}}) do
    states = UniversalIO.SensorAlarmManager.get_state()

    status_string =
      ["U1"]

      # Add temperature data or probe status data
      |> Enum.concat(
        case states[:temp_state] do
          :never_connected ->
            ["NA"]

          :disconnected ->
            ["Comm Lost"]

          _ ->
            # Strip out the ° symbol, as this is not displayed correctly on the CLI
            [String.replace(sensor["temperature"], "°", ""), states[:temp_state]]
        end
      )

      # add humidity data, if applicable
      |> Enum.concat(
        case states[:humidity_state] do
          :never_connected ->
            []

          :disconnected ->
            []

          _ ->
            [sensor["humidity"], states[:humidity_state]]
        end
      )
      |> Enum.join(":")

    """
    #{@success}
    #{status_string}

    """
  end

  # uio discovery
  def format(%{"sensor" => sensor}) do
    """
    #{@success}
    U1:#{map_sensor_variables(sensor["type"])}
    """
  end

  # session - session overview query
  def format(%{"security" => _security = %{"active_sessions" => sessions}}) do
    header = ["User ", "Interface ", "Address ", "Logged In Time "]

    {_date, time_now, _utc_offset} =
      Absinthe.run!("query{time{date_time}}", CommonCore.Schema)
      |> get_in([:data, "time", "date_time"])
      |> parse_date_time()

    if sessions != [] do
      for session <- sessions do
        {_date, time, _utc_offset} = parse_date_time(session["login_timestamp"])
        time_diff = Time.diff(Time.from_iso8601!(time_now), Time.from_iso8601!(time))
        {:ok, time_diff} = Time.new(div(time_diff, 3600), div(rem(time_diff, 3600), 60), rem(time_diff, 60))
        [session["user_name"], session["interface"], session["address"], Time.to_string(time_diff)]
      end
      |> TableRex.Table.new(header)
      |> TableRex.Table.render!(
        horizontal_style: :header,
        top_frame_symbol: "",
        bottom_frame_symbol: "",
        intersection_symbol: "",
        header_separator_symbol: "-",
        horizontal_symbol: "",
        vertical_symbol: ""
      )
    else
      """
        No active sessions
      """
      |> IO.puts()
    end
  end

  # snmptraps - single trap query
  def format(%{"snmp" => _snmp = %{"trap" => traps = [%{"visible" => _visible}]}}) do
    IO.puts("E000: Success")

    [trap] = traps

    swapped_trap =
      for {k, v} <- trap do
        case v do
          "V1_TRAPTYPE" ->
            {k, "snmpV1"}

          "V3_TRAPTYPE" ->
            {k, "snmpV3"}

          "TRAP_ON" ->
            {k, "ENABLE"}

          "TRAP_OFF" ->
            {k, "DISABLE"}

          "AUTH_ENABLED" ->
            {k, "ENABLE"}

          "AUTH_DISABLED" ->
            {k, "DISABLE"}

          "SNMP_USM_USER_1" ->
            {k, "Profile_0"}

          "SNMP_USM_USER_2" ->
            {k, "Profile_1"}

          "SNMP_USM_USER_3" ->
            {k, "Profile_2"}

          "SNMP_USM_USER_4" ->
            {k, "Profile_3"}

          _ ->
            {k, v}
        end
      end

    trap = Enum.into(swapped_trap, %{})

    # For displaying username of target snmpv3 profile
    target_profile =
      if trap["user_profile_mapping"] do
        trap["user_profile_mapping"]
        |> String.last()
        |> String.to_integer()
        |> SNMPManager.query_user_instance()
      else
        []
      end

    cond_string =
      case trap["type"] do
        "snmpV1" ->
          """

          """ <>
            "#{if trap["community"], do: "    Community:          #{trap["community"]}\n", else: ""}" <>
            "#{if trap["auth"], do: "    Authentication:     #{String.downcase(trap["auth"])}\n", else: ""}" <>
            "#{if trap["user_profile_mapping"] && Enum.count(trap) == 4, do: "    User Profile:\n", else: ""}"

        "snmpV3" ->
          "#{if trap["community"] && Enum.count(trap) == 4, do: "\n    Community:\n", else: ""}" <>
            "#{if trap["auth"] && Enum.count(trap) == 4, do: "\n    Authentication:\n", else: ""}" <>
            "#{if trap["user_profile_mapping"], do: "\n    User Profile:       #{target_profile[:name]}\n", else: ""}"
      end

    if trap["visible"] == "TRAP_VISIBLE" do
      (("""
            SNMP Trap Receiver Instance:    #{trap["instance"] + 1}
        """ <>
          "#{if trap["receiver_ip"], do: "    Trap Receiver IP:               #{trap["receiver_ip"]}\n", else: ""}" <>
          "#{if trap["receiver_port"], do: "    Trap Receiver Port:             #{trap["receiver_port"]}\n", else: ""}"<>
          "#{if trap["enable"], do: "    Generation:                     #{String.downcase(trap["enable"])}\n", else: ""}" <>
          "#{if trap["language"], do: "    Language:                       #{String.downcase(trap["language"])}\n", else: ""}" <>
          "#{if trap["type"] && Enum.count(trap) !== 4, do: "    Trap Type:                      #{trap["type"]}\n", else: ""}") <>
         cond_string)
      |> eval_string(%{})
    else
      """

          SNMP Trap Receiver:        #{trap["instance"] + 1}
          Trap Receiver Not Configured

      """
    end
  end

  # snmptraps - traps overview query
  def format(%{"snmp" => _snmp = %{"trap" => traps}}) do
    IO.puts("E000: Success")

    string =
      for trap <- traps do
        if trap["visible"] == "TRAP_VISIBLE" do
          """

              Trap Receiver Instance:  #{trap["instance"] + 1}
              Trap Receiver IP:        #{trap["receiver_ip"]}
              Trap Receiver Port:      #{trap["receiver_port"]}
              Generation:              #{if trap["enable"] == "TRAP_ON", do: "enabled", else: "disabled"}
          """
        end
      end
      |> Enum.join()

    if String.contains?(string, "Instance") do
      string
    else
      """

        No SNMP Trap Receivers Configured

      """
    end
  end

  # date - date settings query
  def format(%{"time" => data}) do
    {date, time, _utc_offset} = parse_date_time(data["date_time"])

    """
    E000: Success

      Date and Time Settings:

      Date:           #{date}
      Time:           #{time}
      UTC Offset:     #{data["config"]["utc_offset"]}

    """
  end

  # email - for single recipient settings
  def format(%{"email" => email = %{"recipients" => recipients}}) do
    [settings] =
      if length(recipients) == 1 do
        recipients
      else
        [""]
      end

    if length(recipients) == 1 do
      if settings["visible"] == "TRUE" do
        custom_settings =
          if settings["server"] != "LOCAL" && settings["custom"] do
            "#{if settings["custom"], do: "\n  Custom Route Settings:\n", else: ""}" <>
              "#{if settings["custom"]["from_address"], do: "  From Address:         #{settings["custom"]["from_address"]}\n", else: ""}" <>
              "#{if settings["custom"]["smtp_server"], do: "  SMTP Server:          #{settings["custom"]["smtp_server"]}\n", else: ""}" <>
              "#{if settings["custom"]["port"], do: "  Port:                 #{settings["custom"]["port"]}\n", else: ""}" <>
              "#{if settings["custom"]["authentication"]["enable"],
                do: "  Authentication:       #{String.downcase(settings["custom"]["authentication"]["enable"])}\n",
                else: ""}" <>
              if settings["custom"]["authentication"]["user_name"] do
                if settings["custom"]["authentication"]["user_name"] != "" do
                  "  User Name:            #{settings["custom"]["authentication"]["user_name"]}\n"
                else
                  "  User Name:            <not set>\n"
                end
              else
                ""
              end <>
              if settings["custom"]["authentication"]["password"] do
                if settings["custom"]["authentication"]["password"] != "" do
                  "  Password:             <hidden>\n"
                else
                  "  Password:             <not set>\n"
                end
              else
                ""
              end
          else
            ""
          end

        # TODO - Add in encryption settings when email encryption is implemented
        ("""
         E000: Success

           Recipient:            #{settings["instance"] + 1}

         """ <>
           "#{if settings["enable"], do: "  Generation:           #{String.downcase(settings["enable"])}\n", else: ""}" <>
           "#{if settings["address"], do: "  To Address:           #{settings["address"]}\n", else: ""}" <>
           "#{if settings["format"], do: "  Email Format:         #{String.downcase(settings["format"])}\n", else: ""}" <>
           "#{if settings["language"], do: "  Language:             #{String.downcase(settings["language"])}\n", else: ""}" <>
           "#{if settings["server"], do: "  Route:                #{String.downcase(settings["server"])}\n", else: ""}" <>
           "\n" <> custom_settings)
        |> eval_string(email)
      else
        """
        E000: Success

          Recipient #{settings["instance"] + 1} not configured

        """
      end
    else
      IO.puts("E000: Success")

      string =
        for recipient <- recipients do
          custom_settings =
            if recipient["server"] != "LOCAL" && recipient["custom"] do
              """

                Custom Route Settings:
                From Address:       #{recipient["custom"]["from_address"]}
                SMTP Server:        #{recipient["custom"]["smtp_server"]}
                Port:               #{recipient["custom"]["port"]}
                Authentication:     #{String.downcase(recipient["custom"]["authentication"]["enable"])}
              """ <>
                if recipient["custom"]["authentication"]["user_name"] != "" do
                  "  User Name:          #{recipient["custom"]["authentication"]["user_name"]}\n"
                else
                  "  User Name:          <not set>\n"
                end <>
                if recipient["custom"]["authentication"]["password"] != "" do
                  "  Password:           <hidden>\n"
                else
                  "  Password:           <not set>\n"
                end
            else
              ""
            end

          if recipient["visible"] == "TRUE" do
            ("""


               Instance:           #{recipient["instance"] + 1}
               Address:            #{recipient["address"]}
               Generation:         #{String.downcase(recipient["enable"])}
               Email Format:       #{String.downcase(recipient["format"])}
               Language:           #{String.downcase(recipient["language"])}
               Route:              #{String.downcase(recipient["server"])}
             """ <> custom_settings)
            |> eval_string(email)
          end
        end
        |> Enum.join()

      if String.contains?(string, "Instance") do
        string
      else
        """

          No email recipients configured

        """
      end
    end
  end

  # email - smtp
  def format(%{"email" => email = %{}}) do
    ("""
     E000: Success \n
     """ <>
       "#{if email["server"]["from_address"], do: "From Address:             <%= server[:from_address] %> \n", else: ""}" <>
       "#{if email["server"]["smtp_server"], do: "SMTP Server:              <%= server[:smtp_server] %> \n", else: ""}" <>
       "#{if email["server"]["port"], do: "Port:                     <%= server[:port] %> \n", else: ""}" <>
       "#{if email["authentication"]["enable"],
         do: "Authentication:           #{String.downcase(email["authentication"]["enable"])} \n",
         else: ""}" <>
       "#{if email["authentication"]["user_name"], do: "User Name:                <%= authentication[:user_name] %> \n", else: ""}" <>
       "#{if email["authentication"]["password"],
         do: if(email["authentication"]["password"] != "",
         do: "Password:                 <hidden> \n",
         else: "Password:                 <not set> \n"),
         else: ""}")

    # TODO add this back in when the functionality for encrypting emails is added
    # Ecryption:                <%= advanced[:use_ssl] %>
    # Require Certificate:      <%= advanced[:require_certificate] %>
    # Selected Certificate:     <%= advanced[:selected_certificate] %>
    # """
    |> eval_string(email)
  end

  # system
  def format(%{"system" => system = %{}}) do
    ("""
     E000: Success

     """ <>
       "#{if system["name"], do: "Name:                     <%= name %>\n", else: ""}" <>
       "#{if system["contact"], do: "Contact:                  <%= contact %>\n", else: ""}" <>
       "#{if system["location"], do: "Location:                 <%= location %>\n", else: ""}" <>
       "#{if system["login_message"], do: "Message:                  <%= login_message %>\n", else: ""}")
    |> eval_string(system)
  end

  # web
  def format(%{"web" => web = %{"settings" => settings}}) do
    base_string =
      ("""
       E000: Success\n
       """ <>
         "#{if settings["httpEnable"], do: "Http:                     #{String.downcase(settings["httpEnable"])}\n", else: ""}" <>
         "#{if settings["httpPort"], do: "Http port:                <%= settings[:httpPort] %>\n", else: ""}" <>
         "#{if settings["httpPort"] && settings["httpsEnable"], do: "\n", else: ""}" <>
         "#{if settings["httpsEnable"], do: "Https:                    #{String.downcase(settings["httpsEnable"])}\n", else: ""}" <>
         "#{if settings["httpsPort"], do: "Https port:               <%= settings[:httpsPort] %>\n", else: ""}" <>
         "#{if settings["minimumProtocolV2"], do: "Minimum Protocol:         <%= settings[:minimumProtocolV2] %>\n", else: ""}")
      |> eval_string(web)

    # Replace TLSV#_# with TLS #.#
    Regex.replace(~r/TLSV([0-9]+)_([0-9]+)/, base_string, "TLS \\1\.\\2")
  end

  # ssh
  def format(%{"network" => network = %{"console" => console}}) do
    ("""
     E000: Success\n
     """ <>
       "#{if console["sshEnable"], do: "SSH State:            #{String.downcase(console["sshEnable"])}\n", else: ""}" <>
       "#{if console["sshPort"], do: "SSH Port:             <%= console[:sshPort] %>\n", else: ""}")
    |> eval_string(network)
  end

  # tcpip
  def format(%{"network" => network = %{"ipv4" => _ipv4, "dns" => _dns}}) do
    """
    E000: Success

    Current IPv4 Settings
    ---------------------
    Address:              <%= ipv4[:address] %>
    Subnet Mask:          <%= ipv4[:subnetMask] %>
    Gateway:              <%= ipv4[:defaultGateway] %>

    Manually Configured IPv4 Settings
    ---------------------------------
    IPv4:                 #{String.downcase(network["ipv4"]["enable"])}
    Address Mode:         #{String.downcase(network["ipv4"]["addressMode"])}
    Static Address:       <%= ipv4[:staticAddress] %>
    Static Subnet Mask:   <%= ipv4[:staticSubnetMask] %>
    Static Gateway:       <%= ipv4[:staticDefaultGateway] %>

    MAC Address:          #{String.upcase(network["macAddress"])}
    Host Name:            <%= dns[:configHostName] %>
    """
    |> eval_string(network)
  end

  # tcpip - single query
  def format(%{"network" => network = %{"ipv4" => ipv4, "macAddress" => _macAddress}}) do
    ("""
     E000: Success

     """ <>
       "#{if ipv4["enable"], do: "IPv4:                 #{String.downcase(ipv4["enable"])}\n", else: ""}" <>
       "#{if ipv4["address"], do: "Current IPv4 Address:         <%= ipv4[:address] %>\n", else: ""}" <>
       "#{if ipv4["subnetMask"], do: "Current Subnet Mask:          <%= ipv4[:subnetMask] %>\n", else: ""}" <>
       "#{if ipv4["defaultGateway"], do: "Current Gateway:              <%= ipv4[:defaultGateway] %>\n", else: ""}" <>
       "#{if ipv4["addressMode"], do: "  Boot Mode:              #{String.downcase(ipv4["addressMode"])} \n", else: ""}")
    |> eval_string(network)
  end

  # boot - the "tcpip" formatting is caught above, if we get to this far it is the "boot" query
  def format(%{"network" => network = %{"ipv4" => ipv4}}) do
    ("""
     E000: Successs\n
     """ <>
       "#{if ipv4["addressMode"], do: "  Boot Mode:              #{String.downcase(ipv4["addressMode"])} \n", else: ""}" <>
       "#{if ipv4["dhcp"]["requireCookie"], do: "  DHCP Cookie:            #{String.downcase(ipv4["dhcp"]["requireCookie"])} \n", else: ""}" <>
       "#{if ipv4["dhcp"]["vendorClass"], do: "  Vendor Class:           <%= ipv4[:dhcp][:vendorClass] %> \n", else: ""}" <>
       "#{if ipv4["dhcp"]["clientId"], do: "  Client ID:              <%= ipv4[:dhcp][:clientId] %> \n", else: ""}" <>
       "#{if ipv4["dhcp"]["userClass"], do: "  User Class:             <%= ipv4[:dhcp][:userClass] %> \n", else: ""}")
    |> eval_string(network)
  end

  # tcpip6
  def format(%{"network" => network = %{"ipv6" => ipv6}}) do
    table =
      if ipv6["endpoints"] do
        %{"ipv6" => %{"endpoints" => endpoints}} = network

        ipv6_addresses =
          endpoints
          |> Enum.map(fn x -> Map.values(x) end)

        # Converting table output to lower case
        ipv6_addresses =
          if ipv6["enable"] == "ENABLE" do
            for address_info <- ipv6_addresses do
              for address_item <- address_info do
                String.downcase(address_item)
              end
            end
          else
            ipv6_addresses
          end

        if Enum.empty?(ipv6_addresses) do
          "No IP addresses currently configured\n"
        else
          title = "Current IPv6 Settings"
          header = ["IP", "Scope", "Type"]

          ipv6_addresses
          |> TableRex.quick_render!(header, title)
        end
      else
        ""
      end

    ("E000: Success\n" <>
       table <>
       "#{if ipv6["enable"], do: "\nIPv6:                   #{String.downcase(ipv6["enable"])}\n\n", else: ""}" <>
       "#{if ipv6["manualEnable"], do: "Manual Configuration:   #{String.downcase(ipv6["manualEnable"])}\n", else: ""}" <>
       "#{if ipv6["address"], do: "IPv6 Address:           <%= ipv6[:address] %>\n", else: ""}" <>
       "#{if ipv6["gateway"], do: "Gateway:                <%= ipv6[:gateway] %>\n", else: ""}" <>
       "#{if network["macAddress"], do: "MAC Address:            #{String.upcase(network["macAddress"])}\n", else: ""}" <>
       "#{if ipv6["autoconfigEnable"], do: "\nIPv6 Autoconfiguration: #{String.downcase(ipv6["autoconfigEnable"])}\n\n", else: ""}" <>
       "#{if ipv6["dhcp"], do: "DHCPv6 Mode:            #{String.downcase(ipv6["dhcp"])}\n", else: ""}")
    |> eval_string(network)
  end

  # dns
  def format(%{"network" => network = %{"dns" => dns}}) do
    ("""
     E000: Success\n
     """ <>
       "#{if dns["activePrimaryServer"], do: "Active Primary DNS Server:      <%= dns[:activePrimaryServer] %>\n", else: ""}" <>
       "#{if dns["activeSecondaryServer"], do: "Active Secondary DNS Server:    <%= dns[:activeSecondaryServer] %>\n", else: ""}" <>
       "#{if dns["activeTertiaryServer"], do: "Active Tertiary DNS Server:     <%= dns[:activeTertiaryServer] %>\n", else: ""}" <>
       "#{if dns["activeHostName"], do: "Active Host Name:               <%= dns[:activeHostName] %>\n", else: ""}" <>
       "#{if dns["activeDomainNameV4v6"], do: "Active Domain Name IPv4/IPv6:   <%= dns[:activeDomainNameV4v6] %>\n", else: ""}" <>
       "#{if dns["activeDomainNameV6"], do: "Active Domain Name IPv6:        <%= dns[:activeDomainNameV6] %>\n", else: ""}" <>
       "#{if dns["manualOverride"] && dns["configHostName"], do: "\n", else: ""}" <>
       "#{if dns["manualOverride"], do: "Override Manual DNS Settings:   #{String.downcase(dns["manualOverride"])}\n", else: ""}" <>
       "#{if dns["configPrimaryServer"], do: "Config Primary DNS Server:      <%= dns[:configPrimaryServer] %>\n", else: ""}" <>
       "#{if dns["configSecondaryServer"], do: "Config Secondary DNS Server:    <%= dns[:configSecondaryServer] %>\n", else: ""}" <>
       "#{if dns["manualOverride"] && dns["configHostName"], do: "\n", else: ""}" <>
       "#{if dns["systemNameSynch"], do: "System Name Sync:               #{String.downcase(dns["systemNameSynch"])}\n", else: ""}" <>
       "#{if dns["configHostName"], do: "Config Host Name:               <%= dns[:configHostName] %>\n", else: ""}" <>
       "#{if dns["configDomainNameV4v6"], do: "Config Domain Name IPv4/IPv6:   <%= dns[:configDomainNameV4v6] %>\n", else: ""}" <>
       "#{if dns["configDomainNameV6"], do: "Config Domain Name IPv6:        <%= dns[:configDomainNameV6] %>\n", else: ""}")
    |> eval_string(network)
  end

  # userdflt
  def format(%{"security" => _security = %{"userManagement" => user_management = %{"defaults" => defaults}}}) do
    ("\n#{if defaults["accessEnable"], do: "User Access:              #{String.downcase(defaults["accessEnable"])}\n", else: ""}" <>
       "#{if defaults["userType"], do: "User Type:                #{String.downcase(defaults["userType"])}\n", else: ""}" <>
       "#{if defaults["userDescription"], do: "User Description:         <%= defaults[:userDescription] %>\n", else: ""}" <>
       "#{if defaults["sessionTimeout"], do: "Session Timeout:          <%= defaults[:sessionTimeout] %>\n", else: ""}" <>
       "#{if defaults["badLoginAttempts"], do: "Bad Login Attempts:       <%= defaults[:badLoginAttempts] %>\n", else: ""}" <>
       "#{if defaults["logExportFormat"], do: "Export Log Format:        #{String.downcase(defaults["logExportFormat"])}\n", else: ""}" <>
       "#{if defaults["temperatureScale"], do: "Temperature Scale:        #{String.downcase(defaults["temperatureScale"])}\n", else: ""}" <>
       "#{if defaults["strongPasswords"], do: "Strong Passwords:         #{String.downcase(defaults["strongPasswords"])}\n", else: ""}" <>
       "#{if defaults["passwordPolicy"], do: "Require Password Change:  <%= defaults[:passwordPolicy] %>\n", else: ""}")
    |> eval_string(user_management)
  end

  # modbus
  def format(%{"modbus" => modbus = %{"rtuv2" => rtuv2, "tcp" => tcp}}) do
    """
    E000: Success

    Address:        <%= rtuv2[:slaveAddress] %>
    Status:               #{String.downcase(rtuv2["access"])}
    Baud Rate:            #{String.downcase(rtuv2["baudRate"])}
    Parity:               #{String.downcase(rtuv2["parity"])}
    Stop Bits:            #{String.downcase(convert_stop_bits_value(rtuv2["stopBits"]))}
    TCP Status:           #{String.downcase(tcp["access"])}
    TCP Port Number:      <%= tcp[:port] %>
    """
    |> eval_string(modbus)
  end

  # modbus - single query rtu
  def format(%{"modbus" => modbus = %{"rtuv2" => rtuv2}}) do
    ("""
     E000: Success

     """ <>
       "#{if rtuv2["stopBits"], do: "Stop Bits:            <%= CLI.Rhodes2.convert_stop_bits_value(rtuv2[:stopBits]) %>\n", else: ""}" <>
       "#{if rtuv2["slaveAddress"], do: "Address:        <%= rtuv2[:slaveAddress] %>\n", else: ""}" <>
       "#{if rtuv2["access"], do: "Status:               #{String.downcase(rtuv2["access"])}\n", else: ""}" <>
       "#{if rtuv2["baudRate"], do: "Baud Rate:            #{String.downcase(rtuv2["baudRate"])}\n", else: ""}" <>
       "#{if rtuv2["parity"], do: "Parity:               #{String.downcase(rtuv2["parity"])}\n", else: ""}")
    |> eval_string(modbus)
  end

  # modbus - single query tcp
  def format(%{"modbus" => modbus = %{"tcp" => tcp}}) do
    ("""
     E000: Success

     """ <>
       "#{if tcp["access"], do: "TCP Status:           #{String.downcase(tcp["access"])}\n", else: ""}" <>
       "#{if tcp["port"], do: "TCP Port Number:      <%= tcp[:port] %>\n", else: ""}")
    |> eval_string(modbus)
  end

  # snmp
  def format(%{"snmp" => snmp = %{"v1Enable" => v1Enable, "community" => communitys}}) do
    string =
      for i <- 0..3 do
        community = Enum.at(communitys, i)

        """
        Access Control:   #{i + 1}
        Community:        #{community["name"]}
        Access Type:      #{String.downcase(community["access"])}
        Address:          #{community["nmsIp"]}

        """
      end
      |> Enum.join()

    ("""
     E000: Success

     Access Control Summary:

     """ <>
       string <>
       """

       SNMPv1 Access: #{String.downcase(v1Enable)}
       """)
    |> eval_string(snmp)
  end

  # snmp - single query
  def format(%{"snmp" => snmp = %{"community" => community}}) do
    [settings] = community

    ("""
     E000: Success
     """ <>
       "#{if settings["name"], do: "\tCommunity:\t\t #{settings["name"]} \n", else: ""}" <>
       "#{if settings["access"], do: "\tAccess Type:\t\t #{String.downcase(settings["access"])} \n", else: ""}" <>
       "#{if settings["nmsIp"], do: "\tAddress:\t\t #{settings["nmsIp"]} \n", else: ""}")
    |> eval_string(snmp)
  end

  def format(%{"update" => data}) do
    if data != nil do
      """
      E000: Success
      """
    else
      """
      E102: Parameter Error
      """
    end
  end

  # snmpv3
  def format(%{"snmp" => snmp_map = %{"userAccess" => user_access, "user" => user}}) do
    instance_list =
      for instance <- user do
        instance["instance"]
      end

    string1 =
      for instance <- user do
        """
        Index:              #{instance["instance"] + 1}
        User Name:          #{instance["name"]}
        Authentication:     #{String.downcase(instance["authenticationProtocol"])}
        Encryption:         #{String.downcase(instance["privacyProtocol"])}

        """
      end
      |> Enum.join()

    string2 =
      for instance <- user_access do
        name =
          if length(instance_list) == 1 do
            Enum.at(user, 0)
          else
            Enum.at(user, String.to_integer(String.last(instance["userName"])))
          end

        if Enum.member?(instance_list, String.to_integer(String.last(instance["userName"]))) do
          """
          Index:              #{instance["instance"] + 1}
          User Name:          #{name["name"]}
          Access:             #{String.downcase(instance["userAccessEnable"])}

          """
        end
      end
      |> Enum.join()

    ("""

     SNMPv3 User Profiles

     """ <>
       string1 <>
       """

       SNMPv3 Access Control

       """ <>
       "#{if string2 != "", do: string2, else: "No Access Control set for this Profile\n"}" <>
       """

       SNMPv3 Access:  #{String.downcase(snmp_map["v3Enable"])}
       """)
    |> eval_string(snmp_map)
  end

  # It is important that these be AFTER the formatter dealing
  # with the full query
  def format(%{"snmp" => _snmp = %{"user" => user}}) do
    [settings] = user

    ("""
     E000: Success

     SNMPv3 User Profiles

     """ <>
       "\tIndex:\t\t\t#{settings["instance"] + 1}\n" <>
       "#{if settings["name"], do: "\tUser Name:\t\t\t#{settings["name"]}\n", else: ""}" <>
       "#{if settings["privacyProtocol"], do: "\tEncryption:\t\t#{String.downcase(settings["privacyProtocol"])}\n", else: ""}" <>
       "#{if settings["authenticationProtocol"], do: "\tAuthentication:\t\t#{String.downcase(settings["authenticationProtocol"])}\n", else: ""}" <>
       "#{if settings["authenticationKey"], do: "\tAuthentication Key:\t<hidden>\n", else: ""}" <>
       "#{if settings["privacyKey"], do: "\tPrivacy Key:\t\t<hidden>\n", else: ""}")
    |> check_string_for_enable()
  end

  def format(%{"snmp" => _snmp = %{"userAccess" => userAccess}}) do
    [settings] = userAccess

    ("""
     E000: Success

     SNMPv3 Access Control

     """ <>
       "\tIndex:\t\t\t#{settings["instance"] + 1}\n" <>
       "#{if settings["userAccessEnable"], do: "\tAccess:\t\t\t#{String.downcase(settings["userAccessEnable"])}\n", else: ""}")
    |> eval_string(%{})
  end

  @email_regex ~r/^[\w.!#$%&’*+\-\/=?\^`{|}~]+@[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)*$/i
  @email_symbols ["#", "!", "%", "$", "\'", "&", "+", "*", "-", "/", "=", "?", "^", "_", "`", ".", "{", "|", "}", "~"]

  defp check_email?(true, email) do
    # Checking if email address fits the correect format
    valid =
      case Regex.run(@email_regex, email) do
        nil -> false
        _ -> true
      end

    # Checking if the prefix pattern begins or ends with any of the above symbols
    # or contains a '..'
    valid =
      if valid do
        email_split = String.split(email, "@")

        prefix =
          email_split
          |> Enum.at(0)

        postfix =
          email_split
          |> Enum.at(1)

        good_email_segments?(prefix, postfix)
      else
        false
      end

    valid
  end

  defp check_email?(false, _email) do
    true
  end

  # Returns true if email address is OK
  defp good_email_segments?(prefix, postfix) do
    prefix_end = Enum.any?(@email_symbols, fn x -> String.ends_with?(prefix, x) end)
    prefix_start = Enum.any?(@email_symbols, fn x -> String.starts_with?(prefix, x) end)
    prefix_double_dot = String.contains?(prefix, "..")

    !(prefix_end || prefix_start || prefix_double_dot || !String.contains?(postfix, "."))
  end

  defp check_ip?(true, ip) do
    # To allow ipv6 addresses again remove 'ipv4' from the below function and it will allow both types
    result =
      case :inet.parse_ipv4strict_address(to_charlist(ip)) do
        {:ok, _} -> true
        {:error, _} -> false
      end

    result
  end

  defp check_ip?(false, _ip) do
    true
  end

  @smtp_symbols ["#", "!", "%", "$", "\'", "&", "+", "*", "/", "=", "?", "^", "_", "`", ".", "{", "|", "}", "~"]

  defp check_smtp?(true, address) do
    result =
      if check_ip?(true, address) do
        true
      else
        Enum.any?(@smtp_symbols, fn x -> String.contains?(address, x) end) &&
          String.contains?(address, ".")
      end

    result
  end

  defp check_smtp?(false, _address) do
    true
  end

  defp snmptrap_mutate(false, _parsed) do
    """
    E100: Command Failed

         When creating or setting SNMPv1 trap receiver, community must also be set

    """
    |> IO.puts()

    :halt
  end

  defp snmptrap_mutate(true, parsed) do
    """
      mutation  {
        update(input: {
          clientMutationId: "snmptrap",
          snmp: {
            trap: {
              #{parsed2args(parsed)}#{if Keyword.has_key?(parsed, :receiver_ip) do
      ",visible: TRAP_VISIBLE"
    end}
            }
          }
        })
        {
          clientMutationId
          snmp {
            trap {
              #{parsed2select(parsed)}#{if Keyword.has_key?(parsed, :receiver_ip) do
      ",visible"
    end}
            }
          }
        }
      }
    """
  end

  defp snmptrap_mutate?(parsed, check_map) do
    # Checks community is input when changing type to snmpv1 and
    # Checks that a trap is visible or that the community is not left out
    (check_map[:visible] == :trap_visible ||
       Keyword.has_key?(parsed, :community) ||
       (Keyword.has_key?(parsed, :type) && parsed[:type] == :V3_TRAPTYPE)) &&
      !(parsed[:type] == :V1_TRAPTYPE && !Keyword.has_key?(parsed, :community))
  end

  def args_ok?(parsed, bare, errors) do
    parsed != [] and bare == [] and errors == []
  end

  def help_request?(bare) do
    bare == ["help"] or bare == ["?"]
  end

  def option_parse(args, opts) do
    {parsed, bare, errors} = OptionParser.parse(args, strict: opts[:switches], aliases: opts[:aliases])

    parsed =
      for {arg, value} <- parsed do
        if arg in opts[:enums] do
          value =
            value
            |> String.upcase()
            |> String.to_atom()
            |> handle_edge_case()

          {arg, value}
        else
          {arg, value}
        end
      end

    {parsed, bare, errors}

    rescue
      error ->
        Logger.error("Error parsing #{inspect args}. Reason: #{inspect error}")
        {[], [], [error]}
  end

  @doc """
  convert a string template and graphql output
  to the screen format
  """
  def eval_string(template, gql_map) do
    template
    |> EEx.eval_string(encode_gql(gql_map))
    |> check_string_for_enable()
  end

  @doc """
  tests string input for occurences of enable/disable
  and changes them to enabled/disabled
  """
  def check_string_for_enable(string) when is_binary(string) do
    string
    |> String.replace("ENABLE", "ENABLED")
    |> String.replace("DISABLE", "DISABLED")
    |> String.replace("enable", "enabled")
    |> String.replace("disable", "disabled")
  end

  def check_string_for_enable(string), do: string

  @doc """
  Encode the GraphQL output into a form that EEx understands
  """
  def encode_gql(map) when is_map(map) do
    for {key, val} <- map, into: [] do
      {String.to_atom(key), encode_gql(val)}
    end
  end

  def encode_gql(list) when is_list(list) do
    for val <- list do
      encode_gql(val)
    end
  end

  def encode_gql(any) do
    any
  end

  # we need to replace multi-letter options, such as -ph and -ps, if they are present in the CLI args
  # as they are causing warnings with Elixir's OptionParser Module because
  # of the multi-letter alias issue. So to counteract this without changing
  # the customer's CLI command options, we replace them (if they are present)
  # in the background with single letter options.
  defp replace_multi_letter_options(args, multi_letter_opt, single_letter_opt) when is_list(args) do
    case Enum.find_index(args, fn x -> x == multi_letter_opt end) do
      nil -> args
      index -> List.replace_at(args, index, single_letter_opt)
    end
  end

  defp replace_multi_letter_options(args, multi_letter_opt, single_letter_opt) do
    arg =
      case args == multi_letter_opt do
        false -> args
        true -> single_letter_opt
      end

    arg
  end

  defp adjust_instance(parsed) do
    if parsed[:instance] do
      end_instance = parsed[:instance] - 1
      List.keyreplace(parsed, :instance, 0, {:instance, end_instance})
    else
      parsed
    end
  end

  ## These functions are used by the option_parse function. That function has a standard procedure
  ## for parsing the options. For most scenarios it works fine, but occassionly, there are edge-cases
  ## that must be handled separately.
  defp handle_edge_case(:DHCP), do: :DHCP_ONLY
  defp handle_edge_case(:BOOTP), do: :BOOTP_ONLY
  defp handle_edge_case(:"TLS1.1"), do: :TLSV1_1
  defp handle_edge_case(:"TLS1.2"), do: :TLSV1_2
  defp handle_edge_case(:"TLS1.3"), do: :TLSV1_3
  defp handle_edge_case(value), do: value

  # Gets list of snmp profiles
  defp get_snmp_instances() do
    for x <- 0..3 do
      SNMPManager.query_user_instance(x)
    end
  end

  # Returns profile that contains matched name or else 0 if none match
  defp matched_snmp_profile_by_name(name) do
    name_list = get_snmp_instances()

    for x <- 0..3 do
      if Enum.at(name_list, x)[:name] == name do
        Enum.at(name_list, x)
      else
        0
      end
    end
    |> Enum.sort()
    |> Enum.at(3)
  end

  def parse snmp_args do
    switches = [
      # -S
      v1Enable: :string,
      # -c[n]
      name: :string,
      # -a[n]
      access: :string,
      # -n[n]
      nmsIp: :string
    ]

    # These map to the full switch names (ex system -l location )
    # They must match the arg names in cli.csv for the legacy system
    aliases = [
      S: :v1Enable,
      c: :name,
      a: :access,
      n: :nmsIp
    ]

    enums = [
      :v1Enable,
      :name,
      :access,
      :nmsIP
    ]

    # {_parsed, _bare, errors} =
    option_parse(snmp_args, switches: switches, aliases: aliases, enums: enums)

    # parsed |> IO.puts
    # bare |> IO.puts
    # errors |> IO.puts
  end

  def map_sensor_variables(value) do
    case value do
      "TEMP_ONLY" ->
        "t"

      "TEMP_HUM" ->
        "th"

      "NONE" ->
        "Not Connected"
    end
  end

  def map_snmptrap_arguments(parsed) do
    # The data dictionary items are not very intuitive or user friendly, so need to swap out the arguments
    # used on the command line for the arguments required for the GraphQL query
    # This also ensures that they are consistent with the other commands
    for {keyword, value} <- parsed do
      case keyword do
        :auth ->
          case value do
            :ENABLE ->
              {keyword, :AUTH_ENABLED}

            :DISABLE ->
              {keyword, :AUTH_DISABLED}

            _ ->
              {:error, :error}
          end

        :type ->
          case value do
            :SNMPV1 ->
              {keyword, :V1_TRAPTYPE}

            :SNMPV3 ->
              {keyword, :V3_TRAPTYPE}

            _ ->
              {:error, :error}
          end

        :enable ->
          case value do
            :ENABLE ->
              {keyword, :TRAP_ON}

            :DISABLE ->
              {keyword, :TRAP_OFF}

            _ ->
              {:error, :error}
          end

        :user_profile_mapping ->
          case value do
            :PROFILE_0 ->
              {keyword, :SNMP_USM_USER_1}

            :PROFILE_1 ->
              {keyword, :SNMP_USM_USER_2}

            :PROFILE_2 ->
              {keyword, :SNMP_USM_USER_3}

            :PROFILE_3 ->
              {keyword, :SNMP_USM_USER_4}

            _ ->
              {:error, :error}
          end

        _ ->
          {keyword, value}
      end
    end
  end

  defp offset_valid?(offset_string) do
    case offset_string do
      nil ->
        true

      _ ->
        if Regex.match?(~r/(?=.{0}[+-])(?=.{1}[0-9])(?=.{2}[0-9])(?=.{3}[:])(?=.{4}[0-9])(?=.{5}[0-9])/, offset_string) do
          true
        else
          false
        end
    end
  end

  @resetToDef_logout_warning """
  Warning: resetting NMC settings to default will automatically log all users out.
  Do you wish to continue? [y/n]:
  """
  # prompt at command_line to confirm if user wishes to continue in
  # resetting the nmc's settings
  defp prompt_confirm_reset() do
    IO.puts(@resetToDef_logout_warning)

    input =
      IO.read(:line)
      # The SSH console returns a charlist, and the serial console returns a string.
      # IO.reads can also return an error tuple for which to_string() returns an empty string
      |> to_string()
      |> String.trim("\n")
      |> String.downcase()


    cond do
      input in ["y", "yes"] ->
        IO.puts("Resetting...")
        true

      input in ["n", "no"] ->
        false

      true ->
        IO.puts("Please try again, enter either y or n.")
        false
    end
  end

  defp convert_user(_first_arg = "-n", []) do
    IO.puts("E102: Parameter Error")

    @user_usage
    |> IO.puts()

    :halt
  end

  defp convert_user(_first_arg = "-n", [user_name]) do
    if user_name == user_superusername() and get_current_user_type() == :super_user do
      user_map =
        """
        query{
          security {
            userManagement {
              superUser {
                accessEnable
                userName
                userType
                userDescription
                sessionTimeout(decimalDigits:0)
                logExportFormat
                temperatureScale
              }
            }
          }
        }
      """
      |> Absinthe.run!(CommonCore.Schema)

      IO.puts(@success <> "\n")

      ("Access: " <> String.downcase(get_in(user_map, [:data, "security", "userManagement", "superUser", "accessEnable"])))
      |> check_string_for_enable()
      |> IO.puts()

      IO.puts(
        "User Permission: " <> String.downcase(get_in(user_map, [:data, "security", "userManagement", "superUser", "userType"]))
      )

      IO.puts("User Description: " <> get_in(user_map, [:data, "security", "userManagement", "superUser", "userDescription"]))
      IO.puts("Session Timeout: " <> get_in(user_map, [:data, "security", "userManagement", "superUser", "sessionTimeout"]))

      IO.puts(
        "Export Log Format: " <>
          String.downcase(get_in(user_map, [:data, "security", "userManagement", "superUser", "logExportFormat"]))
      )

      IO.puts(
        "Temperature Scale: " <>
          String.downcase(get_in(user_map, [:data, "security", "userManagement", "superUser", "temperatureScale"]))
      )

      IO.puts("\n")
      :error
    else # if super-user
      # Only administrative users can view other users' information
      if user_name == get_current_user_name() or get_current_user_type() == :super_user or get_current_user_type() == :admin do
        user_index = user_name2index(user_name)

        user_map =
          """
            query {
              security {
                userManagement{
                  users(instance:#{user_index}){
                  accessEnable
                  userName
                  userType
                  userDescription
                  sessionTimeout(decimalDigits:0)
                  logExportFormat
                  temperatureScale
                  }
                }
              }
            }
          """
          |> Absinthe.run!(CommonCore.Schema)

        user_map = get_in(user_map, [:data, "security", "userManagement", "users"])

        if user_map != nil do
          [user_map] = user_map
          IO.puts(@success <> "\n")

          ("Access: " <> String.downcase(Map.fetch!(user_map, "accessEnable")))
          |> check_string_for_enable()
          |> IO.puts()

          IO.puts("User Permission: " <> String.downcase(Map.fetch!(user_map, "userType")))
          IO.puts("User Description: " <> Map.fetch!(user_map, "userDescription"))
          IO.puts("Session Timeout: " <> Map.fetch!(user_map, "sessionTimeout"))
          IO.puts("Export Log Format: " <> String.downcase(Map.fetch!(user_map, "logExportFormat")))
          IO.puts("Temperature Scale: " <> String.downcase(Map.fetch!(user_map, "temperatureScale")))
          IO.puts("\n")
          :error
        else
          IO.puts("User #{user_name} could not be found!")
          IO.puts("E100: Command Failed\n")
          :halt
        end
      else
        IO.puts("E102: Parameter Error")
        IO.puts("Only user with admin permissions can view other users' information")
        :error
      end
    end
  end

  defp convert_user(_first_arg = "-n", [user_name | tail]) do
    # These must match the names in the DataDictionary
    switches = [
      currentPassword: :string,
      newPassword: :string,
      confirmPassword: :string,
      userType: :string,
      userDescription: :string,
      accessEnable: :string,
      sessionTimeout: :interger,
      eventLogColorCodingEnable: :string,
      logExportFormat: :string,
      temperatureScale: :string,
      dateFormat: :string,
      languageCode: :string,
      delete: :boolean
    ]

    aliases = [
      P: :currentPassword,
      p: :newPassword,
      c: :confirmPassword,
      a: :userType,
      d: :userDescription,
      e: :accessEnable,
      t: :sessionTimeout,
      l: :logExportFormat,
      s: :temperatureScale,
      D: :delete
    ]

    enums = [
      :accessEnable,
      :logExportFormat,
      :eventLogColorCodingEnable,
      :temperatureScale,
      :userType
    ]

    {parsed, bare, errors} = option_parse(tail, switches: switches, aliases: aliases, enums: enums)

    if args_ok?(parsed, bare, errors) do
      if user_name == user_superusername() do
        if Enum.any?(parsed, fn x -> Kernel.elem(x, 0) == :delete end) do
          IO.puts("E102: Parameter Error")
          IO.puts("Superuser (#{user_name}) cannot be deleted")
          :error
        else
          # Enforce that: [-P  <current password>] (Req. For Super User Account)
          if Enum.any?(parsed, fn x -> Kernel.elem(x, 0) == :currentPassword end) do
            """
            mutation  {
              update(input: {
                clientMutationId: "user",
                security: {
                  userManagement: {
                    superUser: {
                    #{parsed2args(parsed)}
                    }
                  }
                }
              })
              {
                clientMutationId
                security {
                  userManagement {
                    superUser {
                    #{parsed2select(parsed)}
                    }
                  }
                }
              }
            }
            """
          else # No current password provided
            IO.puts("E102: Parameter Error")
            IO.puts("[-P  <current password>] is required to change Super User Account\n")
            :error
          end
        end
      else # not a super-user
        if user_name == get_current_user_name() or get_current_user_type() == :super_user or get_current_user_type() == :admin do
          user_index = user_name2index(user_name)

          if user_index == nil do
            IO.puts("Creating a new user: #{user_name}...")

            if String.length(user_name) < 3 or String.length(user_name) > 20 do
              IO.puts("\nE102: Parameter Error")
              IO.puts("Username must be between 3-20 characters\n")
              :halt
            else
              parsed =
                parsed
                |> add_defaults()
                |> Keyword.put_new(:userName, user_name)
                |> Keyword.put_new(:instance, available_user_index())
                |> Keyword.put_new(:visible, :TRUE)

              userDefault =
                """
                  query {
                    security {
                      userManagement{
                        defaults{
                          strong_passwords
                        }
                      }
                    }
                  }
                """
                |> Absinthe.run!(CommonCore.Schema)

              strongPassword = get_in(userDefault, [:data, "security", "userManagement", "defaults", "strong_passwords"])

              if strongPassword == "ENABLE" do
                case Password.validate(Keyword.fetch!(parsed, :newPassword), :enable) do
                  {:error, errorMessage} ->
                    IO.puts("\nE102: Parameter Error")
                    IO.puts(errorMessage)
                    IO.puts("")
                    :halt

                  {:ok, _password} ->
                    """
                      mutation  {
                        update(input: {
                          clientMutationId: "user",
                          security: {
                            userManagement: {
                              users: {
                              #{parsed2args(parsed)}
                              }
                            }
                          }
                        })
                        {
                          clientMutationId
                          security {
                            userManagement {
                              users{
                              #{parsed2select(parsed)}
                              }
                            }
                          }
                        }
                      }
                    """
                end
              else # if strong passwords enabled
                case Password.validate(Keyword.fetch!(parsed, :newPassword), :disable) do
                  {:error, _errorMessage} ->
                    IO.puts("\nE102: Parameter Error")
                    IO.puts("New password must be between 3-64 characters")
                    IO.puts("")
                    :halt

                  {:ok, _password} ->
                    """
                      mutation  {
                        update(input: {
                          clientMutationId: "user",
                          security: {
                            userManagement: {
                              users: {
                                #{parsed2args(parsed)}
                              }
                            }
                          }
                        })
                        {
                          clientMutationId
                          security {
                            userManagement {
                              users{
                              #{parsed2select(parsed)}
                              }
                            }
                          }
                        }
                      }
                    """
                end
              end # strong passwords enabled
            end # else if String.length(user_name) < 3 or String.length(user_name) > 20
          else # if user doesn't exist
            # Adding the instance and an empty password string, if needed.
            parsed =
              if Keyword.has_key?(parsed, :newPassword) do
                Enum.concat([instance: user_index], parsed)
              else
                Enum.concat([instance: user_index, newPassword: ""], parsed)
              end

            if Enum.any?(parsed, fn x -> Kernel.elem(x, 0) == :delete end) do
              parsed =
                parsed
                |> Keyword.delete(:delete)
                |> Keyword.put(:visible, :FALSE)
                |> Keyword.put(:confirmPassword, "")
                |> add_defaults()

              """
                mutation  {
                  update(input: {
                    clientMutationId: "user",
                    security: {
                      userManagement: {
                        users: {
                        #{parsed2args(parsed)}
                        }
                      }
                    }
                  })
                  {
                    clientMutationId
                    security {
                      userManagement {
                        users{
                          #{parsed2select(parsed)}
                        }
                      }
                    }
                  }
                }
              """
            else # none of the keywords is ::delete
              """
              mutation  {
                update(input: {
                  clientMutationId: "user",
                  security: {
                    userManagement: {
                      users: {
                      #{parsed2args(parsed)}
                      }
                    }
                  }
                })
                {
                  clientMutationId
                  security {
                    userManagement {
                      users{
                      #{parsed2select(parsed)}
                      }
                    }
                  }
                }
              }
              """
            end
          end # else if non existent user
        else # if a non :super_user and non :admin modifies other user (not himself)
          IO.puts("E102: Parameter Error")
          IO.puts("Only user with admin permissions can modify other users")
          :error
        end
      end # non super-user block
    else
      IO.puts("E102: Parameter Error")

      @user_usage
      |> IO.puts()

      :halt
    end
  end

  defp convert_user(first_arg, _tail) when first_arg in ["?", "help", "-h"] do
    @user_usage
    |> IO.puts()

    :halt
  end

  defp convert_user(_first_arg, _tail) do
    IO.puts("E102: Parameter Error")

    @user_usage
    |> IO.puts()

    :halt
  end

  def user_usage() do
    @user_usage
  end

  def user_usage_unprivileged() do
    @user_usage_unprivileged
  end
end
