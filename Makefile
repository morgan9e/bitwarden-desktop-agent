PREFIX ?= $(HOME)/.local/bin

all:
	cargo build --release

install: all
	mkdir -p $(PREFIX)
	install -m 755 target/release/bw-agent $(PREFIX)/bw-agent
	install -m 755 target/release/bw-proxy $(PREFIX)/bw-proxy

uninstall:
	rm -f $(PREFIX)/bw-agent $(PREFIX)/bw-proxy

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
	sed 's|%h/.local/bin|$(PREFIX)|' docs/com.bitwarden.agent.service \
		> $(HOME)/.config/systemd/user/com.bitwarden.agent.service
	systemctl --user daemon-reload
	systemctl --user enable --now com.bitwarden.agent

systemd-unload:
	systemctl --user disable --now com.bitwarden.agent 2>/dev/null || true
	rm -f $(HOME)/.config/systemd/user/com.bitwarden.agent.service
	systemctl --user daemon-reload

clean:
	cargo clean

.PHONY: all install uninstall launchd launchd-unload systemd systemd-unload clean
