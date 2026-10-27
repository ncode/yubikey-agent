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

Setup checks all four target slots before changing credentials or generating
keys, including private keys that have no stored certificate. If any target
slot is occupied, setup stops. Firmware older than 5.3 cannot reliably report
certificate-less keys, so setup on those devices requires the explicit
`--really-delete-all-piv-keys` flag. That flag wipes the entire PIV applet,
including keys outside the four SSH slots.

An explicit `--config` file must exist and parse successfully. A malformed
configuration stops the command before it accesses devices. The default
configuration file is optional.

## Signing and device recovery

Signing requests have a two-minute deadline, including discovery, signer
preparation, and waiting for another request. Software PIN dialogs can be
canceled when their request ends. External pinentry password caches are
disabled so a stale cached PIN cannot silently exhaust hardware retries.
The YubiKey's PIN-once session behavior is preserved. Once PIN verification
has been submitted to the YubiKey, that hardware operation cannot be canceled
through the PIV API; the agent must wait for the hardware to return. Incorrect
PINs can be retried
while the device reports decreasing remaining attempts.

The two-minute deadline bounds the caller's wait; it does not interrupt
hardware PIN verification or an in-flight PC/SC signing/touch operation. If a
card call outlives the deadline, the caller receives a timeout, but the agent
retains exclusive use of the device until that call returns. It then releases
the cached handles before the next request reconnects. SIGHUP also releases
cached handles once outstanding device work finishes. If the OS smart-card
stack never releases a blocked call, recovery may require restarting the agent, reconnecting the
YubiKey, or restarting the OS smart-card service.

Public keys and slot metadata are cached for each connected device session.
Signing prepares only the requested slot, and validates reader connections
before using the device. Healthy connections stay open, preserving PIN-once
sessions. Reconnecting a device or sending SIGHUP refreshes its slot metadata.

Key listings check for reader changes at most once per second while idle.
While hardware is busy, listings return the last cached public keys without
waiting for PIN verification or touch. That snapshot may temporarily include
a disconnected device or omit a newly attached one; the next idle refresh or
signing request reconciles the readers. An initial listing without a cached
snapshot has a two-minute caller deadline and follows the same hardware
ownership rules as signing.

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
