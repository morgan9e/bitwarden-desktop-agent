PREFIX ?= $(HOME)/.local/bin

STATIC_TARGET     ?= x86_64-unknown-linux-musl
STATIC_ARCH       := $(firstword $(subst -, ,$(STATIC_TARGET)))
STATIC_TARGET_ENV := $(shell echo $(STATIC_TARGET) | tr 'a-z-' 'A-Z_')
STATIC_TARGET_US  := $(subst -,_,$(STATIC_TARGET))

CARGO_STATIC := $(shell command -v cross >/dev/null 2>&1 && echo cross || echo cargo)
MUSL_CC      := $(shell command -v $(STATIC_ARCH)-linux-musl-gcc 2>/dev/null)
STATIC_ENV   := $(if $(MUSL_CC),CC_$(STATIC_TARGET_US)="$(MUSL_CC)" \
                  CARGO_TARGET_$(STATIC_TARGET_ENV)_LINKER="$(MUSL_CC)")

all: submodules
	cargo build --workspace --release

static: submodules 
	$(STATIC_ENV) $(CARGO_STATIC) build --release -p bw-key --target $(STATIC_TARGET)

install-server-static: static
	mkdir -p $(PREFIX)
	install -m 755 target/$(STATIC_TARGET)/release/bw-keyd $(PREFIX)/bw-keyd
	install -m 755 target/$(STATIC_TARGET)/release/bw-keyctl $(PREFIX)/bw-keyctl

submodules:
	@test -e .git || { echo "not a git checkout — skipping submodules"; exit 0; }; \
	git submodule sync --recursive && \
	git submodule update --init --recursive

install: all
	mkdir -p $(PREFIX)
	install -m 755 target/release/bw-agent $(PREFIX)/bw-agent
	install -m 755 target/release/bw-proxy $(PREFIX)/bw-proxy
	test -f target/release/adw-askpass && install -m 755 target/release/adw-askpass $(PREFIX)/adw-askpass || true

install-server: all
	install -m 755 target/release/bw-keyd $(PREFIX)/bw-keyd
	install -m 755 target/release/bw-keyctl $(PREFIX)/bw-keyctl

install-nm: install
	PREFIX=$(PREFIX) sh docs/install-nm.sh

uninstall:
	rm -f $(PREFIX)/bw-agent $(PREFIX)/bw-proxy $(PREFIX)/adw-askpass
	rm -f $(PREFIX)/bw-keyd $(PREFIX)/bw-keyctl

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

.PHONY: all submodules static  \
	install install-server install-nm uninstall uninstall-nm test \
	launchd launchd-unload systemd systemd-unload clean
