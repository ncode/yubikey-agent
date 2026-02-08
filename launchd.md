# Manual macOS setup with launchd

This repository does not ship a built-in launchd plist. If you want to run `yubikey-agent` as a background user service on macOS, create your own LaunchAgent.

First, install Go and build `yubikey-agent`, then place it in your `$PATH`.

```text
$ git clone https://github.com/ncode/yubikey-agent && cd yubikey-agent
$ go build && cp yubikey-agent /usr/local/bin/
```

Set up your key first:

```text
$ yubikey-agent setup
```

Create `~/Library/LaunchAgents/io.github.ncode.yubikey-agent.plist` with contents similar to:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>io.github.ncode.yubikey-agent</string>

  <key>ProgramArguments</key>
  <array>
    <string>/usr/local/bin/yubikey-agent</string>
  </array>

  <key>RunAtLoad</key>
  <true/>

  <key>KeepAlive</key>
  <true/>

  <key>StandardOutPath</key>
  <string>/tmp/yubikey-agent.log</string>

  <key>StandardErrorPath</key>
  <string>/tmp/yubikey-agent.err</string>
</dict>
</plist>
```

Adjust the binary path in `ProgramArguments` if your install path differs.

Load and start the agent:

```text
$ launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/io.github.ncode.yubikey-agent.plist
$ launchctl enable gui/$(id -u)/io.github.ncode.yubikey-agent
$ launchctl kickstart -k gui/$(id -u)/io.github.ncode.yubikey-agent
```

If you change the plist later, reload it:

```text
$ launchctl bootout gui/$(id -u) ~/Library/LaunchAgents/io.github.ncode.yubikey-agent.plist
$ launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/io.github.ncode.yubikey-agent.plist
```

Finally, add the socket path to your shell profile and restart it:

```bash
export SSH_AUTH_SOCK="${HOME}/.ssh/yubikey-agent.sock"
```
