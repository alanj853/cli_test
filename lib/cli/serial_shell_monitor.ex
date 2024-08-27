defmodule CLI.SerialShellMonitor do
    @moduledoc """
    Getter/setter module for the PID of the serial CLI process. There can (should) only ever
    be one serial CLI process running at once, hence the single-item state.
    """
    use GenServer
    require Logger

    def start_link(_) do
        GenServer.start_link(__MODULE__, [], name: __MODULE__)
    end

    def set_serial_shell_pid(serial_shell_pid) do
        GenServer.cast(__MODULE__, {:set_serial_shell_pid, serial_shell_pid})
    end

    def get_serial_shell_pid() do
        GenServer.call(__MODULE__, :get_serial_shell_pid)
    end

    @doc """
    Function to terminate the Serial Shell process gracefully. Returns `true` if the PID exists
    and the terminate message was sent. Returns `false` otherwise.
    """
    def terminate_serial_shell() do
        GenServer.call(__MODULE__, :terminate_serial_shell)
    end

    def init(_) do
        {:ok, nil}
    end

    def handle_call(:get_serial_shell_pid, _from, serial_shell_pid) do
        {:reply, serial_shell_pid, serial_shell_pid}
    end

    def handle_call(:terminate_serial_shell, _from, serial_shell_pid) do
        if serial_shell_pid != nil and Process.alive?(serial_shell_pid) do
            send(serial_shell_pid, :terminate)
            {:reply, true, nil}
        else
            {:reply, false, nil}
        end
    end

    def handle_cast({:set_serial_shell_pid, new_serial_shell_pid}, old_serial_shell_pid) do
        if old_serial_shell_pid != nil and Process.alive?(old_serial_shell_pid) do
            Logger.warning("There is currently a serial_shell process active #{inspect old_serial_shell_pid}")
        end
        {:noreply, new_serial_shell_pid}
    end
end
