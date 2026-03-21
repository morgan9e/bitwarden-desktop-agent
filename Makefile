PREFIX ?= $(HOME)/.local/bin
IDENTITY ?= -

all:
	cargo build --release

install: all
	mkdir -p $(PREFIX)
	install -m 755 target/release/bw-agent $(PREFIX)/bw-agent
	install -m 755 target/release/bw-proxy $(PREFIX)/bw-proxy

sep:
	swiftc -O -o target/release/sep-helper src/sep/sep-helper.swift
	codesign --force --sign "$(IDENTITY)" --entitlements src/sep/sep-helper.entitlements target/release/sep-helper

install-sep: sep
	install -m 755 target/release/sep-helper $(PREFIX)/sep-helper

uninstall:
	rm -f $(PREFIX)/bw-agent $(PREFIX)/bw-proxy $(PREFIX)/sep-helper

launchd:
	mkdir -p $(HOME)/Library/LaunchAgents
	sed 's|/Users/USER/.local/bin|$(PREFIX)|' docs/com.bitwarden.agent.plist \
		> $(HOME)/Library/LaunchAgents/com.bitwarden.agent.plist
	launchctl bootout gui/$$(id -u) $(HOME)/Library/LaunchAgents/com.bitwarden.agent.plist 2>/dev/null || true
	launchctl bootstrap gui/$$(id -u) $(HOME)/Library/LaunchAgents/com.bitwarden.agent.plist

launchd-unload:
	launchctl bootout gui/$$(id -u) $(HOME)/Library/LaunchAgents/com.bitwarden.agent.plist 2>/dev/null || true
	rm -f $(HOME)/Library/LaunchAgents/com.bitwarden.agent.plist

systemd:
	mkdir -p $(HOME)/.config/systemd/user
	sed 's|%h/.local/bin|$(PREFIX)|' docs/bw-agent.service \
		> $(HOME)/.config/systemd/user/bw-agent.service
	systemctl --user daemon-reload
	systemctl --user enable --now bw-agent

systemd-unload:
	systemctl --user disable --now bw-agent 2>/dev/null || true
	rm -f $(HOME)/.config/systemd/user/bw-agent.service
	systemctl --user daemon-reload

clean:
	cargo clean
	rm -f target/release/sep-helper

.PHONY: all install sep install-sep uninstall launchd launchd-unload systemd systemd-unload clean
