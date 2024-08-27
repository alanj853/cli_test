defmodule CLI.Eventlog.Handle do
  @moduledoc """
  CLI.Eventlog.Handle handles data interactions for eventlog

  A new handle starts out with the first page of the event log. The
  next page can then be found with subsequent calls.

  Example:

    iex> handle = CLI.Eventlog.Handle.start()
    iex> CLI.Eventlog.Handle.events(handle)
      [
        %{
          description: "Something happened",
          instance: 10,
          timestamp: "",
          user: "Name"
        },
        %{
          description: "Something else happened",
          instance: 9,
          timestamp: "",
          user: "Name"
        }
      ]
    iex> CLI.Eventlog.Handle.next(handle)
         |> CLI.Eventlog.events()
         [
          %{
            description: "Now for something different",
            instance: 9,
            timestamp: "",
            user: "Name"
          },
          %{
            description: "Something different happened",
            instance: 8,
            timestamp: "",
            user: "Name"
          }
         ]
  """
  require Logger

  @max_page_length 15
  defstruct events: [], continue_at: [], page_length: @max_page_length

  @type event :: %{
          description: String.t(),
          instance: integer(),
          timestamp: String.t(),
          user: String.t()
        }

  @type t :: %__MODULE__{
          events: [event] | any(),
          continue_at: nonempty_maybe_improper_list(String.t(), String.t()) | [any()],
          page_length: pos_integer()
        }

  @doc """
  Creates a handle with the first page of events loaded
  """
  def start() do
    %__MODULE__{}
    |> execute()
  end

  @doc """
  Takes a handle and moves it to the next page
  """
  def next(handle) do
    handle
    |> execute()
  end

  def prev(handle) do
    handle
    |> pop_continue_at()
    |> execute()
  end

  @doc """
  Can we go further back in the log ?
  """
  def has_prev?(%{continue_at: continue_at}) do
    length(continue_at) > 1
  end

  @doc """
  Can we go further forward in the log ?
  """
  def has_next?(handle) do
    cond do
      # In the last page it is likely we have less entries than the max page
      count(handle) < @max_page_length ->
        false

      # In the last page 'continue_at' the first and second indexes are the same
      # eg ["MQ==", "MQ==", "Mg==", "Nk==", ...]
      Enum.at(continue_at(handle), 0) == Enum.at(continue_at(handle), 1) ->
        false

      true ->
        true
    end
  end

  @doc """
  Deletes all of the events in the log and queries for the next set
  """
  def clear(handle) do
    handle
    |> Map.put(:query, :clear)
    |> execute()

    start()
  end

  @doc """
  Grabs the events out of the handle
  """
  @spec events(t | %{:events => any(), any() => any()}) :: [event] | any()
  def events(%{events: events}), do: events

  def continue_at(%{continue_at: continue_at}), do: continue_at

  defp count(handle) do
    handle
    |> events()
    |> Enum.count()
  end

  def map(fun) do
    fn %{events: events} ->
      fun.(events)
    end
  end

  defp execute(handle) do
    query(handle)
    |> Absinthe.run!(CommonCore.Schema)
    |> from_query_result(handle)
  rescue
    error ->
      Logger.error("Couldn't execute Absinthe query: #{inspect(error)}")
      handle
  end

  defp from_query_result(results, handle) do
    events =
      results
      |> get_in([:data, "event_log", "events"])

    next =
      results
      |> get_in([:data, "event_log", "continueAt"])

    %{handle | events: events}
    |> continue_at(next)
  end

  defp continue_at(%{continue_at: continue_at} = handle, next) do
    %{handle | continue_at: [next | continue_at]}
  end

  defp pop_continue_at(%{continue_at: [_next, _current | rest]} = handle) do
    %{handle | continue_at: rest}
  end

  defp pop_continue_at(handle) do
    %{handle | continue_at: []}
  end

  defp query(%{query: :clear}) do
    """
    mutation {
      update(input: {
        clientMutationId: "1",
        event_log: {
          clear: CLEAR_LOG
        }
      }) {
      clientMutationId
    }
    }
    """
  end

  defp query(%{page_length: limit, continue_at: []}) do
    """
    query {
      event_log {
        events(limit: #{limit}) {
          instance
          user
          description
          time_stamp
        }
        continueAt
      }
    }
    """
  end

  defp query(%{page_length: limit, continue_at: [continue_at | _]}) do
    """
    query {
      event_log {
        events(limit: #{limit}, continue_at: "#{continue_at}") {
          instance
          user
          description
          time_stamp
        }
        continueAt
      }
    }
    """
  end
end
