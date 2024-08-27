defmodule CliTestTest do
  use ExUnit.Case
  doctest CliTest

  test "greets the world" do
    assert CliTest.hello() == :world
  end
end
