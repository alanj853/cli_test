defmodule CLI.Eventlog do
  @moduledoc """
  Documentation for CLI.Eventlog
  """
  use CLI.PromptCommand, timeout: :infinity, input_type: :hidden
  alias CLI.Confirmation
  alias CLI.Eventlog.{Handle, Formatter}
  alias UserManager.User

  @exit {"E", "Exit"}
  @refresh {"R", "Refresh"}
  @back {"B", "Back"}
  @next {"N", "Next"}
  @delete {"D", "Delete"}
  @prompt_parts [@exit, @refresh, @back, @next, @delete]
  @prompt_parts_read_only [@exit, @refresh, @back, @next]

  defp isAdmin?() do
    user_type =
      Process.get(:user)
      |> User.usertype()

    user_type == :super_user or user_type == :admin
  end

  def init([]) do
    {:ok, Handle.start()}
  end

  def handle_prompt(handle) do
    page = Enum.count(Handle.continue_at(handle))

    Handle.events(handle)
    |> print(page)

    if isAdmin?() do
      @prompt_parts
    else
      @prompt_parts_read_only
    end
    |> Enum.map(&prompt_part(&1, handle))
    |> Enum.filter(&(not is_nil(&1)))
    |> Enum.intersperse(" ")
  end

  defp prompt_part(@back, handle) do
    if Handle.has_prev?(handle) do
      to_prompt(@back)
    end
  end

  defp prompt_part(@next, handle) do
    if Handle.has_next?(handle) do
      to_prompt(@next)
    end
  end

  defp prompt_part(prompt, _) do
    to_prompt(prompt)
  end

  def to_prompt({key, word}) do
    "<#{key}>- #{word}"
  end

  def handle_command(command, handle) when is_binary(command) do
    has_prev? = Handle.has_prev?(handle)
    has_next? = Handle.has_next?(handle)

    case command do
      x when x in ["n", "N"] and has_next? ->
        {:ok, Handle.next(handle)}

      x when x in ["n", "N"] and not has_next? ->
        {:exit, :ok, handle}

      x when x in ["b", "B"] and has_prev? ->
        {:ok, Handle.prev(handle)}

      x when x in ["b", "B"] and not has_prev? ->
        {:ok, Handle.start()}

      x when x in ["r", "R"] ->
        {:ok, Handle.start()}

      x when x in ["e", "E"] ->
        {:exit, :ok, handle}

      x when x in ["d", "D"] ->
        if isAdmin?() do
          {:ok, confirm_delete(handle)}
        else
          {:ok, Handle.next(handle)}
        end

      _ ->
        if has_next? do
          {:ok, Handle.next(handle)}
        else
          {:exit, :ok, handle}
        end
    end
  end

  defp print(events, page) do
    events
    |> Formatter.format(:calendar.local_time(), page)
    |> IO.write()
  end

  defp confirm_delete(handle) do
    Confirmation.run(fn
      :confirmed ->
        Handle.clear(handle)

      :unconfirmed ->
        handle
    end)
  end
end
