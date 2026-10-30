#!/bin/bash
# install-permission-bot-relay.sh
#
# Installs the permission-bot relay launchd unit (macOS): the standalone process
# that is the ONLY poller of the permission bot and forwards its apv: button
# presses to the dashboard (card d7f586bf). See docs/permission-bot-relay.md.
#
# Safe by default: this script writes the plist and NOTHING else. It does not
# call launchctl, does not read or write any token, and does not touch .env, the
# Vault or the dashboard. The unit stays dormant until you ask for --load, and
# even loaded it polls only when PERMISSION_BOT_RELAY_ENABLED=1 is in .env.
#
# Steps performed:
#   1. Verify the build artifact (dist/permission-bot-relay.js) exists.
#   2. Write ~/Library/LaunchAgents/com.<SERVICE_ID>.permission-bot-relay.plist
#      (no token: not in ProgramArguments, not in the environment).
#   3. With --load: launchctl load the unit.
#
# Usage:
#   scripts/install-permission-bot-relay.sh              # write the plist, do not start
#   scripts/install-permission-bot-relay.sh --load       # write the plist and load it
#   scripts/install-permission-bot-relay.sh --uninstall  # unload and remove the plist
#   scripts/install-permission-bot-relay.sh --print-label

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
# com.<SERVICE_ID>.permission-bot-relay: two installs under one user must not share one job (#1873).
. "$SCRIPT_DIR/launchd-label.sh"
LABEL="$(helper_launchd_label "$PROJECT_DIR" permission-bot-relay)"
if [ "${1:-}" = "--print-label" ]; then printf '%s\n' "$LABEL"; exit 0; fi
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
DIST_ENTRY="$PROJECT_DIR/dist/permission-bot-relay.js"

MODE="install"
case "${1:-}" in
  "") ;;
  --load) MODE="load" ;;
  --uninstall) MODE="uninstall" ;;
  *) echo "usage: $0 [--load|--uninstall|--print-label]" >&2; exit 64 ;;
esac

# --uninstall: stop the job and remove the unit. store/permission-bot-relay.* stay.
if [ "$MODE" = "uninstall" ]; then
  if [ -f "$PLIST" ]; then
    launchctl bootout "gui/$(id -u)/$LABEL" >/dev/null 2>&1 \
      || launchctl unload "$PLIST" >/dev/null 2>&1 \
      || true
    rm -f "$PLIST"
    echo "Removed launchd unit: $PLIST (store/permission-bot-relay.* files are kept)"
  else
    echo "No launchd unit at $PLIST, nothing to remove"
  fi
  exit 0
fi

# 1. build artifact
if [ ! -f "$DIST_ENTRY" ]; then
  echo "ERROR: $DIST_ENTRY not found. Run 'npm run build' first." >&2
  exit 1
fi

NODE_BIN="$(command -v node || true)"
if [ -z "$NODE_BIN" ]; then
  echo "ERROR: node not found on PATH" >&2
  exit 1
fi

# The main channel's state dir is passed through (a path, not a secret) so the
# relay can exclude the main bot's id the same way the channel plugin finds it.
# It is only written when it is known: the installer's own TELEGRAM_STATE_DIR,
# else the install-scoped dir if it already holds a .env.
STATE_DIR_ENTRY=""
if [ -n "${TELEGRAM_STATE_DIR:-}" ]; then
  STATE_DIR_ENTRY="$TELEGRAM_STATE_DIR"
elif [ -f "$PROJECT_DIR/.claude/channels/telegram/.env" ]; then
  STATE_DIR_ENTRY="$PROJECT_DIR/.claude/channels/telegram"
fi
STATE_DIR_BLOCK=""
if [ -n "$STATE_DIR_ENTRY" ]; then
  STATE_DIR_BLOCK="    <key>TELEGRAM_STATE_DIR</key>
    <string>$STATE_DIR_ENTRY</string>"
fi

# 2. launchd plist. KeepAlive restarts a crash; ThrottleInterval keeps a refused
# start (exit 2) from respawning every few seconds. Disabled mode idles, it does not exit.
mkdir -p "$HOME/Library/LaunchAgents"
mkdir -p "$PROJECT_DIR/store"
cat > "$PLIST" <<PLIST_EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>$LABEL</string>
  <key>ProgramArguments</key>
  <array>
    <string>$NODE_BIN</string>
    <string>$DIST_ENTRY</string>
  </array>
  <key>WorkingDirectory</key>
  <string>$PROJECT_DIR</string>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>ThrottleInterval</key>
  <integer>60</integer>
  <key>StandardOutPath</key>
  <string>$PROJECT_DIR/store/permission-bot-relay.log</string>
  <key>StandardErrorPath</key>
  <string>$PROJECT_DIR/store/permission-bot-relay.error.log</string>
  <key>EnvironmentVariables</key>
  <dict>
    <key>PATH</key>
    <string>/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin</string>
    <key>HOME</key>
    <string>$HOME</string>
    <key>USER</key>
    <string>$(id -un)</string>
    <key>LANG</key>
    <string>hu_HU.UTF-8</string>
$STATE_DIR_BLOCK
  </dict>
</dict>
</plist>
PLIST_EOF
chmod 644 "$PLIST"
echo "Wrote launchd unit: $PLIST"

# 3. optional load
if [ "$MODE" = "load" ]; then
  launchctl unload "$PLIST" 2>/dev/null || true
  launchctl load "$PLIST"
  echo "Loaded $LABEL. It polls only with PERMISSION_BOT_RELAY_ENABLED=1 in .env; check with: node $DIST_ENTRY --status"
else
  echo "Installed but NOT loaded. To start: $0 --load"
fi
