.PHONY: build install test

LAUNCH_PLIST = ~/Library/LaunchAgents/com.yubikey.agent.plist
ERROR_LOG    = /tmp/com.yubikey.agent.err.log

all: build install test

build:
	go build -o yubikey-agent ../../


install:
	launchctl unload -w $(LAUNCH_PLIST)
	go install ../../
	launchctl load -w $(LAUNCH_PLIST)


test:
	ssh-add -L
	tail $(ERROR_LOG)
