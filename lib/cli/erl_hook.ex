defmodule CLI.ErlHook do
  @moduledoc """
  This module is designed to intercept the built in Erlang Shell
  and redirect it to IEx
  """
  # stdlib, shell_prompt_func
  def prompt(_kv_list) do
    IEx.start()
  end

  #
  # Restricted Callback hooks
  #

  def local_allowed(_, _, state) do
    # Don't allow any local function to execute
    {false, state}
  end

  def non_local_allowed(_, _, state) do
    # Redirect any function to start IEx
    {{:redirect, {IEx, :start}, []}, state}
  end
end
