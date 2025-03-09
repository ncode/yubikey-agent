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

### Linux

#### Arch

On Arch, use [the `yubikey-agent` package](https://aur.archlinux.org/packages/yubikey-agent/) from the AUR.

```
git clone https://aur.archlinux.org/yubikey-agent.git
cd yubikey-agent && makepkg -si

systemctl daemon-reload --user
sudo systemctl enable --now pcscd.socket
systemctl --user enable --now yubikey-agent

export SSH_AUTH_SOCK="${XDG_RUNTIME_DIR}/yubikey-agent/yubikey-agent.sock"
```

#### NixOS / nixpkgs

On NixOS unstable and 20.09, you can add this to your `/etc/nixos/configuration.nix`:

```
services.yubikey-agent.enable = true;
```

This installs `yubikey-agent` and sets up a systemd unit to start yubikey-agent for you.

On other systems using nix, you can also install from nixpkgs:

```
nix-env -iA nixpkgs.yubikey-agent
```

This installs the software but does *not* install a systemd unit. You will have to set up service management manually (see below).

#### Other systemd-based Linux systems

On other systemd-based Linux systems, follow [the manual installation instructions](systemd.md).

Packaging contributions are very welcome.

### FreeBSD

Install the [`yubikey-agent` port](https://svnweb.freebsd.org/ports/head/security/yubikey-agent/).

### Windows

Windows support is currently WIP.

## Commands

```
yubikey-agent list    # List available YubiKey devices
yubikey-agent setup   # Set up a YubiKey with SSH keys
```

## Advanced topics

### Coexisting with other `ssh-agent`s

It's possible to configure `ssh-agent`s on a per-host basis.

For example to only use `yubikey-agent` when connecting to `example.com`, you'd add the following lines to `~/.ssh/config` instead of setting `SSH_AUTH_SOCK`.

```
Host example.com
    IdentityAgent /usr/local/var/run/yubikey-agent.sock
```

To use `yubikey-agent` for all hosts but one, you'd add the following lines instead. In both cases, you can keep using `ssh-add` to interact with the main `ssh-agent`.

```
Host example.com
    IdentityAgent $SSH_AUTH_SOCK

Host *
    IdentityAgent /usr/local/var/run/yubikey-agent.sock
```

### Conflicts with `gpg-agent` and Yubikey Manager

`yubikey-agent` takes a persistent transaction so the YubiKey will cache the PIN after first use. Unfortunately, this makes the YubiKey PIV and PGP applets unavailable to any other applications, like `gpg-agent` and Yubikey Manager.

If you need `yubikey-agent` to release its lock on the YubiKey, send it a hangup signal. Likewise, you might have to kill `gpg-agent` after use for it to release its own lock.

```
killall -HUP yubikey-agent
```

This does not affect the FIDO2 functionality.

### Unblocking the PIN with the PUK

If the wrong PIN is entered incorrectly three times in a row, YubiKey Manager can be used to unlock it.

`yubikey-agent setup` sets the PUK to the same value as the PIN.

```
ykman piv unblock-pin
```

If the PUK is also entered incorrectly three times, the key is permanently irrecoverable. The YubiKey PIV applet can be reset with `yubikey-agent setup --really-delete-all-piv-keys`.
