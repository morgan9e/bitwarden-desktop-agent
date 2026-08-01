#!/bin/sh
set -eu

PREFIX="${PREFIX:-$HOME/.local/bin}"
PROXY="$PREFIX/bw-proxy"
NAME="com.8bit.bitwarden"
DESCRIPTION="Bitwarden browser <-> bw-agent bridge"

CHROME_ID="${CHROME_ID:-nngceckbapebfimnlniiiahkandclblb}"
EDGE_ID="${EDGE_ID:-jbkfoedolllekgbhcbcoahefnbanhhlh}"

FIREFOX_ID_DEFAULT='{446900e4-71c2-419f-a6a7-df9c091e268b}'
FIREFOX_ID="${FIREFOX_ID:-$FIREFOX_ID_DEFAULT}"

if [ ! -x "$PROXY" ]; then
    echo "install-nm: $PROXY not found or not executable; run 'make install' first" >&2
    exit 1
fi

installed=0

write_manifest() {
    dir="$1"
    family="$2"
    label="$3"
    [ -d "$(dirname "$dir")" ] || return 0

    mkdir -p "$dir"
    if [ "$family" = firefox ]; then
        allow="\"allowed_extensions\": [\"$FIREFOX_ID\"]"
    elif [ "$label" = "Edge" ]; then
        allow="\"allowed_origins\": [\"chrome-extension://$EDGE_ID/\"]"
    else
        allow="\"allowed_origins\": [\"chrome-extension://$CHROME_ID/\"]"
    fi

    cat > "$dir/$NAME.json" <<EOF
{
  "name": "$NAME",
  "description": "$DESCRIPTION",
  "path": "$PROXY",
  "type": "stdio",
  $allow
}
EOF
    echo "  $label -> $dir/$NAME.json"
    installed=$((installed + 1))
}

case "$(uname -s)" in
Darwin)
    S="$HOME/Library/Application Support"
    write_manifest "$S/Google/Chrome/NativeMessagingHosts"                  chromium "Chrome"
    write_manifest "$S/Chromium/NativeMessagingHosts"                       chromium "Chromium"
    write_manifest "$S/BraveSoftware/Brave-Browser/NativeMessagingHosts"    chromium "Brave"
    write_manifest "$S/Microsoft Edge/NativeMessagingHosts"                 chromium "Edge"
    write_manifest "$S/Vivaldi/NativeMessagingHosts"                        chromium "Vivaldi"
    write_manifest "$S/Mozilla/NativeMessagingHosts"                        firefox  "Firefox"
    ;;
Linux)
    C="${XDG_CONFIG_HOME:-$HOME/.config}"
    write_manifest "$C/google-chrome/NativeMessagingHosts"                  chromium "Chrome"
    write_manifest "$C/chromium/NativeMessagingHosts"                       chromium "Chromium"
    write_manifest "$C/BraveSoftware/Brave-Browser/NativeMessagingHosts"    chromium "Brave"
    write_manifest "$C/microsoft-edge/NativeMessagingHosts"                 chromium "Edge"
    write_manifest "$C/vivaldi/NativeMessagingHosts"                        chromium "Vivaldi"
    write_manifest "$HOME/.mozilla/native-messaging-hosts"                  firefox  "Firefox"
    ;;
*)
    echo "install-nm: unsupported platform $(uname -s)" >&2
    exit 1
    ;;
esac

if [ "$installed" -eq 0 ]; then
    echo "install-nm: no supported browser found" >&2
    exit 1
fi
echo "installed $installed manifest(s); restart the browser to pick them up"
