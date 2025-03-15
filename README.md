# (my personal) yubikey-agent

This is a fork of [filippo.io/yubikey-agent](https://filippo.io/yubikey-agent), a seamless ssh-agent for YubiKeys.

## Key differences in this fork

* **multi-slot support**: Configures all four PIV slots with different PIN and touch policies:
  - 9a (PIV Authentication): PIN required once, touch always required
  - 9c (Digital Signature): PIN always required, touch always required
  - 9d (Key Management): PIN required once, touch never required
  - 9e (Card Authentication): PIN never required, touch never required
* **Command-lines**: Uses cobra for a more structured CLI with subcommands

## Core features from the original project

* **Easy to use.** A one-command setup, one environment variable, and it just runs in the background.
* **Indestructible.** Tolerates unplugging, sleep, and suspend. Never needs restarting.
* **Compatible.** Provides a public key that works with all services and servers.
* **Secure.** The key is generated on the YubiKey and can't be extracted. Every session requires the PIN, every login requires a touch. Setup takes care of PUK and management key.

Written in pure Go, it's based on [github.com/go-piv/piv-go/v2](https://github.com/go-piv/piv-go/v2) and [golang.org/x/crypto/ssh](https://golang.org/x/crypto/ssh).

## Installation

```
go install github.com/ncode/yubikey-agent@latest
yubikey-agent setup # generate new keys on the YubiKey
```

Then add the following line to your `~/.zshrc` and restart the shell.

```
export SSH_AUTH_SOCK="${HOME}/.ssh/yubikey-agent.sock"
```

### Windows

Windows support is currently WIP.

## Commands

```
yubikey-agent list     # List available YubiKey devices
yubikey-agent setup    # Set up a YubiKey with SSH keys\
yubikey-agent unblock  # Unblock pin
```

### Unblocking the PIN with the PUK

If the wrong PIN is entered incorrectly three times in a row, YubiKey Manager can be used to unlock it.

`yubikey-agent setup` sets the PUK to the same value as the PIN.

```
yubikey-agent unblock -s <serial>
```

If the PUK is also entered incorrectly three times, the key is permanently irrecoverable. The YubiKey PIV applet can be reset with `yubikey-agent setup --really-delete-all-piv-keys`.
