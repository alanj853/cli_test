# CliTest

Repo for reproducing "issue" with CLI OTP 26

Steps.
1. Clone this repo and run install the following elixir and erlang versions using asdf
```
asdf install erlang 25.3.2
asdf install erlang 26.2.5
asdf install elixir 1.16.3-otp-25
asdf install elixir 1.16.3-otp-26
```
2. Run "iex -S mix"
This should launch you into the custom CLI
3. Type the command "hello"
You should get response "world"
4. Now press the up arrow on the keyboard to get the "hello" command again

Expected result:
"hello" command should come up on the prompt

Actual result:
On OTP 25, the up arrow does as expected

On OTP 26, the up arrow seemingly does nothing
