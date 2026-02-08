# Manual Linux setup with systemd

This repository no longer ships a built-in systemd unit file. If you want to run `yubikey-agent` with a user service, create your own user unit.

First, install Go and the [`piv-go` dependencies](https://github.com/go-piv/piv-go#installation), build `yubikey-agent`, and place it in `$PATH`.

```text
$ git clone https://github.com/ncode/yubikey-agent && cd yubikey-agent
$ go build && sudo cp yubikey-agent /usr/local/bin/
```

Make sure you have a `pinentry` program (terminal or graphical) in `$PATH`.

Set up your key first:

```text
$ yubikey-agent setup
```

Then create `~/.config/systemd/user/yubikey-agent.service` with contents similar to:

```ini
[Unit]
Description=YubiKey SSH agent
After=default.target

[Service]
Type=simple
ExecStart=%h/go/bin/yubikey-agent
Restart=on-failure

[Install]
WantedBy=default.target
```

Adjust `ExecStart=` for your install path as needed.

Refresh systemd, make sure PC/SC is available, and start the service:

```text
$ systemctl daemon-reload --user
$ sudo systemctl enable --now pcscd.socket
$ systemctl --user enable --now yubikey-agent
```

Finally, add the socket path to your shell profile and restart it:

```bash
export SSH_AUTH_SOCK="${HOME}/.ssh/yubikey-agent.sock"
```
