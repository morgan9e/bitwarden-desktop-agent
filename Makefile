PREFIX ?= $(HOME)/.local/bin

all:
	cargo build --release

install: all
	mkdir -p $(PREFIX)
	install -m 755 target/release/bw-agent $(PREFIX)/bw-agent
	install -m 755 target/release/bw-proxy $(PREFIX)/bw-proxy

uninstall:
	rm -f $(PREFIX)/bw-agent $(PREFIX)/bw-proxy

clean:
	cargo clean

.PHONY: all install uninstall clean
