# (my personal version of) yubikey-agent

This is a fork of [filippo.io/yubikey-agent](https://filippo.io/yubikey-agent), a seamless `ssh-agent` for YubiKeys.

## Key differences in this fork

- **Multi-slot support**: configures all four main PIV slots with distinct PIN and touch policies.
  - `9a` (PIV Authentication): PIN once, touch always
  - `9c` (Digital Signature): PIN always, touch always
  - `9d` (Key Management): PIN once, touch never
  - `9e` (Card Authentication): PIN never, touch never
- **Structured CLI**: uses Cobra subcommands (`setup`, `list`, `unblock`).

## Core features inherited from the original project

- **Easy to use**: one-command setup and one `SSH_AUTH_SOCK` export.
- **Resilient**: tolerates unplugging, sleep, and suspend without restart.
- **Compatible**: exposes standard SSH public keys usable across providers.
- **Secure**: key material is generated on-device and remains non-exportable.

Written in pure Go, based on [github.com/go-piv/piv-go/v2](https://github.com/go-piv/piv-go/v2) and [golang.org/x/crypto/ssh](https://golang.org/x/crypto/ssh).

## Installation

```bash
go install github.com/ncode/yubikey-agent@latest
yubikey-agent setup
```

Then add this to your shell profile (`~/.zshrc`, `~/.bashrc`, etc.):

```bash
export SSH_AUTH_SOCK="${HOME}/.ssh/yubikey-agent.sock"
```

## Service setup guides

- Linux (`systemd`): `systemd.md`
- macOS (`launchd`): `launchd.md`

## Commands

```bash
yubikey-agent list     # List connected YubiKeys
yubikey-agent setup    # Configure a YubiKey PIV applet for SSH
yubikey-agent unblock  # Unblock/reset a locked PIN using the PUK
```

## Unblocking the PIN with the PUK

If the PIN is entered incorrectly three times, it becomes blocked.

`yubikey-agent setup` sets the PUK to the same value as the PIN.

```bash
yubikey-agent unblock -s <serial>
```

If the PUK is also entered incorrectly three times, recovery is not possible without resetting the PIV applet. To reset the applet and regenerate keys:

`yubikey-agent setup --really-delete-all-piv-keys`

## Platform notes

- Linux and macOS are supported.
- Windows support is currently work in progress.
