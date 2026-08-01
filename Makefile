PREFIX ?= $(HOME)/.local/bin
SERVER_PREFIX ?= /usr/local/bin

STATIC_TARGET ?= x86_64-unknown-linux-musl
STATIC_DIR     = target/$(STATIC_TARGET)/release
CARGO_STATIC  := $(shell command -v cargo-zigbuild >/dev/null 2>&1 \
	&& echo "cargo zigbuild" || echo "cargo build")

all: submodules
	cargo build --workspace --release

submodules:
	@test -e .git || { echo "not a git checkout — skipping submodules"; exit 0; }; \
	git submodule sync --recursive && \
	git submodule update --init --recursive

static: submodules
	@command -v rustup >/dev/null 2>&1 && { \
		rustup target list --installed | grep -qx '$(STATIC_TARGET)' \
			|| rustup target add $(STATIC_TARGET); \
	} || true
	@test "$(CARGO_STATIC)" = "cargo zigbuild" || echo \
		"note: cargo-zigbuild not found, using plain cargo build — this needs a \
musl C toolchain for rusqlite (brew install cargo-zigbuild)"
	$(CARGO_STATIC) -p bw-key --bins --release --target $(STATIC_TARGET)
	@echo
	@ls -l $(STATIC_DIR)/bw-keyd $(STATIC_DIR)/bw-keyctl
	@command -v file >/dev/null 2>&1 && file $(STATIC_DIR)/bw-keyd || true

install: all
	mkdir -p $(PREFIX)
	install -m 755 target/release/bw-agent $(PREFIX)/bw-agent
	install -m 755 target/release/bw-proxy $(PREFIX)/bw-proxy
	test -f target/release/adw-askpass && install -m 755 target/release/adw-askpass $(PREFIX)/adw-askpass || true

install-server: static
	install -m 755 $(STATIC_DIR)/bw-keyd $(SERVER_PREFIX)/bw-keyd
	install -m 755 $(STATIC_DIR)/bw-keyctl $(SERVER_PREFIX)/bw-keyctl

install-nm: install
	PREFIX=$(PREFIX) sh docs/install-nm.sh

uninstall:
	rm -f $(PREFIX)/bw-agent $(PREFIX)/bw-proxy $(PREFIX)/adw-askpass
	rm -f $(SERVER_PREFIX)/bw-keyd $(SERVER_PREFIX)/bw-keyctl

uninstall-nm:
	find $(HOME)/Library/Application\ Support $(HOME)/.config $(HOME)/.mozilla \
		-name com.8bit.bitwarden.json -path '*ative*essaging*' -delete 2>/dev/null || true

test: submodules
	cargo test --workspace

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

.PHONY: all submodules static \
	install install-server install-nm uninstall uninstall-nm test \
	launchd launchd-unload systemd systemd-unload clean
