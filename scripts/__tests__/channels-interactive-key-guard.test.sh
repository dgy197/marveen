#!/bin/bash
# fec6335f N3b: INTERACTIVE_ANTHROPIC_KEY_POLICY on the MAIN agent's shell
# launch paths (spec I-01 for the main agent; blueprint 3.1, N3b).
#
# Under `forbid` the main agent is a first-party interactive session like any
# other and must not run on an API key:
#   - channels.sh does not read/export the .env ANTHROPIC_API_KEY, unsets an
#     inherited ANTHROPIC_API_KEY / ANTHROPIC_AUTH_TOKEN, -u's both in the tmux
#     SERVER's global env instead of -g setting the key, never writes the key
#     into the pane-auth file, and the pane command strips both names right
#     after the auth file is sourced;
#   - a customProvider that is NOT Anthropic keeps its command exactly;
#   - main-agent-custom-provider.mjs refuses an Anthropic provider (exit 3,
#     no stdout, the vault key never read) and channels.sh aborts on it;
#   - a key route in the main agent's settings does not stop the launch but
#     leaves a guard event and a failures-log line (blueprint 12.8);
#   - channel-watchdog.sh and stuck-modal-guard.sh strip the names in their
#     respawn command (fail-closed when the policy cannot be resolved).
# Under `allow` (absent, empty, `allow`) every launch stays what it was.
#
# HERMETIC: nothing here runs channels.sh as a whole (its orphan reap kills
# processes by environment). The blocks under test are cut VERBATIM out of the
# scripts and run in a throwaway root with a FAKE tmux that only records its
# argv, a fake claude that records env NAMES (never values), HOME pointing into
# the throwaway root, and a per-run dummy key that is asserted absent from every
# log, event and argv it must not reach. The helper runs on a copy of dist/
# whose keychain module is a stub, so the vault uses a file key in the
# throwaway store and the host's Keychain is never touched.
#
# Run: bash scripts/__tests__/channels-interactive-key-guard.test.sh
#   (IKG_DIST=<dir> uses a prebuilt dist instead of building $INSTALL_DIR/dist)

set -u

PASS=0; FAIL=0
pass() { PASS=$((PASS + 1)); echo "  PASS: $1"; }
fail() { FAIL=$((FAIL + 1)); echo "  FAIL: $1 -- expected: $2, got: $3"; }
check() { if [ "$2" = "$3" ]; then pass "$1"; else fail "$1" "$2" "$3"; fi; }
has() { case "$1" in *"$2"*) return 0 ;; esac; return 1; }

INSTALL_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
CH="${CHANNELS_BIN:-$INSTALL_DIR/scripts/channels.sh}"
WD="$INSTALL_DIR/scripts/channel-watchdog.sh"
SG="$INSTALL_DIR/scripts/stuck-modal-guard.sh"
HELPER="$INSTALL_DIR/scripts/main-agent-custom-provider.mjs"

TMP="$(mktemp -d)"
trap 'chmod -R u+rwx "$TMP" 2>/dev/null; rm -rf "$TMP"' EXIT
DUMMY="sk-ant-TEST-DUMMY-$$-$RANDOM$RANDOM"
DUMMY2="sk-ant-TEST-DUMMY2-$$-$RANDOM$RANDOM"
OAT="oat-test-$$"
UNSET='unset ANTHROPIC_API_KEY ANTHROPIC_AUTH_TOKEN && '

# --- the fakes ---------------------------------------------------------------
mkdir -p "$TMP/bin"
cat > "$TMP/bin/tmux" <<'FAKE'
#!/bin/sh
# Records one line per call: CALL [arg] [arg] ...  (never runs anything)
{ printf 'CALL'; for a in "$@"; do printf ' [%s]' "$a"; done; printf '\n'; } >> "$FAKE_TMUX_LOG"
exit 0
FAKE
cat > "$TMP/bin/claude" <<'FAKE'
#!/bin/sh
# Records which auth NAMES reached the launched claude, never their values.
printf 'API=%s AUTH=%s OAUTH=%s BASE=%s\n' "${ANTHROPIC_API_KEY:+set}" "${ANTHROPIC_AUTH_TOKEN:+set}" "${CLAUDE_CODE_OAUTH_TOKEN:+set}" "${ANTHROPIC_BASE_URL:+set}" > "$FAKE_CLAUDE_OUT"
FAKE
chmod +x "$TMP/bin/tmux" "$TMP/bin/claude"
SAFE_PATH="/usr/bin:/bin:/usr/sbin:/sbin"

# --- cut a block out of a script: the first line starting with $2 through the
# next line starting with $3 (leading whitespace ignored on both) ---------------
cut_block() {
  awk -v s="$2" -v e="$3" '
    function lt(x) { sub(/^[ \t]+/, "", x); return x }
    on { print; if (index(lt($0), e) == 1) exit; next }
    index(lt($0), s) == 1 { on = 1; print }
  ' "$1"
}

ENV_BLOCK="$(cut_block "$CH" '# WHO THE GUARD ALERTS IN THIS SCRIPT ARE SENT AS.' 'CHANNEL_PROVIDER="${CHANNEL_PROVIDER:-telegram}"')"
AUTH_BLOCK="$(cut_block "$CH" '_tmux_set_auth_globals() {' 'unset _auth_file')"
KEY_BLOCK="$(cut_block "$CH" 'KEY_UNSET_ENV=""' 'unset _ikg_cfg_dir')"
LAUNCH_BLOCK="$(cut_block "$CH" 'env -u "$STATE_ENV_VAR" $TMUX new-session -d -s "$SESSION" -c "$INSTALL_DIR"' '_tmux_set_auth_globals')"
EPERM_BLOCK="$(cut_block "$CH" 'env -u "$STATE_ENV_VAR" $TMUX new-session -d -s "$SESSION" -c "$_CHANNELS_STARTDIR"' '"${AUTH_PANE_ENV}')"
CP_BLOCK="$(cut_block "$CH" 'if [ -f "$INSTALL_DIR/dist/web/custom-providers.js" ]; then' 'unset _cp_env _cp_rc _cp_cfg_dir')"
SQ_LINE="$(grep '^sh_single_quote() {' "$CH")"

echo "channels.sh interactive-key guard (fec6335f N3b)"
for b in ENV_BLOCK AUTH_BLOCK KEY_BLOCK LAUNCH_BLOCK EPERM_BLOCK CP_BLOCK SQ_LINE; do
  if [ -n "${!b}" ]; then pass "$b cut out of channels.sh"; else fail "$b cut out of channels.sh" "non-empty" "(marker not found)"; fi
done
check "the env block reaches the policy function" "1" "$(printf '%s\n' "$ENV_BLOCK" | grep -c '^interactive_key_policy() {')"

# --- the harness: env block -> auth block -> key block -> launch (+ EPERM) ----
# $1 root  $2 .env body  $3 inherit keys (yes|no)  $4 CUSTOM_PROVIDER_ENV
# $5 extra harness lines (before the auth block)  $6 a setup function, called
# with the root before the run (fixtures)  $7 PATH for the run
run_launch() {
  local root="$1" envbody="$2" inherit="$3" cpenv="$4" extra="${5:-}" setup="${6:-}" runpath="${7:-$SAFE_PATH}"
  rm -rf "$root"; mkdir -p "$root/store" "$root/.claude" "$root/home/.claude"
  printf '%s\n' "$envbody" > "$root/.env"
  [ -n "$setup" ] && "$setup" "$root"
  {
    echo 'set -u'
    printf 'INSTALL_DIR=%q\n' "$root"
    echo 'TMUX="$FAKE_TMUX"'
    echo "$SQ_LINE"
    echo "$ENV_BLOCK"
    printf 'CUSTOM_PROVIDER_ENV=%q\n' "$cpenv"
    echo "$extra"
    echo 'SESSION=t-channels STATE_ENV_VAR=TELEGRAM_STATE_DIR STATE_DIR_ENV= MCP_BATCH_ENV= CFG_ENV= MODEL_FLAG= PLUGIN_ID=telegram@x EXTRA_CHANNELS= EXTRA_SETTINGS_FLAG='
    echo 'CLAUDE="$FAKE_CLAUDE"'
    echo "$AUTH_BLOCK"
    echo "$KEY_BLOCK"
    echo "$LAUNCH_BLOCK"
    echo '_CHANNELS_STARTDIR=/tmp/eperm-fallback'
    echo "$EPERM_BLOCK"
    echo 'echo "POLICY=$INTERACTIVE_KEY_POLICY"'
  } > "$root/harness.sh"
  : > "$root/tmux.log"
  local inh=()
  [ "$inherit" = yes ] && inh=(ANTHROPIC_API_KEY="$DUMMY" ANTHROPIC_AUTH_TOKEN="$DUMMY2")
  env -i PATH="$runpath" HOME="$root/home" FAKE_TMUX="$TMP/bin/tmux" FAKE_TMUX_LOG="$root/tmux.log" \
    FAKE_CLAUDE="$TMP/bin/claude" ${inh[@]+"${inh[@]}"} /bin/bash "$root/harness.sh" > "$root/harness.out" 2>&1
  echo $? > "$root/harness.rc"
}
# The pane command of the Nth new-session call (1 = primary, 2 = EPERM fallback).
pane_cmd() { grep '^CALL \[new-session\]' "$1/tmux.log" | sed -n "${2}p" | sed -E 's/^.* \[(.*)\]$/\1/'; }
# Run a pane command the way tmux does (default-shell -c), with the tmux SERVER's
# global env simulated as carrying both keys.
run_pane() {
  local shell="$1" cmd="$2" out="$TMP/claude.out"
  rm -f "$out"
  env -i PATH="$TMP/bin:$SAFE_PATH" HOME="$TMP" FAKE_CLAUDE_OUT="$out" \
    ANTHROPIC_API_KEY="$DUMMY" ANTHROPIC_AUTH_TOKEN="$DUMMY2" "$shell" -c "$cmd" >/dev/null 2>&1
  cat "$out" 2>/dev/null || echo "claude-not-reached"
}
no_dummy() { # $1 label, $2.. files
  local label="$1"; shift
  if cat "$@" 2>/dev/null | grep -qF -e "$DUMMY" -e "$DUMMY2"; then fail "$label" "no dummy value" "dummy value present"; else pass "$label"; fi
}

BASE_ENV="MAIN_AGENT_ID=tmain
CLAUDE_CODE_OAUTH_TOKEN=$OAT
ANTHROPIC_API_KEY=$DUMMY"

# ---- allow: the launch is what it was --------------------------------------
for variant in "absent|" "empty|INTERACTIVE_ANTHROPIC_KEY_POLICY=" "allow|INTERACTIVE_ANTHROPIC_KEY_POLICY=allow" "quoted|INTERACTIVE_ANTHROPIC_KEY_POLICY=\"allow\""; do
  name="${variant%%|*}"; line="${variant#*|}"
  R="$TMP/allow-$name"
  run_launch "$R" "$BASE_ENV
$line" yes ""
  check "allow ($name): harness ran clean under set -u" "0" "$(cat "$R/harness.rc")"
  check "allow ($name): policy" "POLICY=allow" "$(grep '^POLICY=' "$R/harness.out")"
  # the .env key still goes to the tmux globals, twice (before + after new-session)
  check "allow ($name): -g ANTHROPIC_API KEY set as before (2x)" "2" "$(grep -c '^CALL \[set-environment\] \[-g\] \[ANTHROPIC_API_KEY\] \[' "$R/tmux.log")"
  check "allow ($name): no -u of the key names" "0" "$(grep -c '\[-u\] \[ANTHROPIC_' "$R/tmux.log")"
  check "allow ($name): the auth file still carries the key line" "1" "$(grep -c '^export ANTHROPIC_API_KEY=' "$R/store/.channels-pane-auth")"
  P1="$(pane_cmd "$R" 1)"; P2="$(pane_cmd "$R" 2)"
  if has "$P1" 'unset ANTHROPIC_API_KEY' || has "$P2" 'unset ANTHROPIC_API_KEY'; then fail "allow ($name): no unset in the pane commands" "none" "$P1 | $P2"; else pass "allow ($name): no unset in the pane commands"; fi
  check "allow ($name): primary pane command, exact" ". '$R/store/.channels-pane-auth' && $TMP/bin/claude --dangerously-skip-permissions --channels plugin:telegram@x" "$P1"
  check "allow ($name): EPERM pane command, exact" "$P1" "$P2"
done
R="$TMP/allow-absent"
check "allow: the claude in the pane gets the key, as today (bash)" "API=set AUTH=set OAUTH=set BASE=" "$(run_pane /bin/bash "$(pane_cmd "$R" 1)")"

# ---- forbid: no key on any route --------------------------------------------
for variant in "forbid|INTERACTIVE_ANTHROPIC_KEY_POLICY=forbid" "typo|INTERACTIVE_ANTHROPIC_KEY_POLICY=alow" "last-wins|INTERACTIVE_ANTHROPIC_KEY_POLICY=allow
INTERACTIVE_ANTHROPIC_KEY_POLICY= 'forbid' "; do
  name="${variant%%|*}"; line="${variant#*|}"
  R="$TMP/forbid-$name"
  run_launch "$R" "$BASE_ENV
$line" yes ""
  check "forbid ($name): harness ran clean under set -u" "0" "$(cat "$R/harness.rc")"
  check "forbid ($name): policy (fail-closed)" "POLICY=forbid" "$(grep '^POLICY=' "$R/harness.out")"
  check "forbid ($name): no -g set of ANTHROPIC_API_KEY" "0" "$(grep -c '^CALL \[set-environment\] \[-g\] \[ANTHROPIC_API_KEY\] \[' "$R/tmux.log")"
  check "forbid ($name): -g -u ANTHROPIC_API_KEY (2x)" "2" "$(grep -c '^CALL \[set-environment\] \[-g\] \[-u\] \[ANTHROPIC_API_KEY\]$' "$R/tmux.log")"
  check "forbid ($name): -g -u ANTHROPIC_AUTH_TOKEN (2x)" "2" "$(grep -c '^CALL \[set-environment\] \[-g\] \[-u\] \[ANTHROPIC_AUTH_TOKEN\]$' "$R/tmux.log")"
  check "forbid ($name): the OAuth token still goes to the globals" "2" "$(grep -c '^CALL \[set-environment\] \[-g\] \[CLAUDE_CODE_OAUTH_TOKEN\] \[' "$R/tmux.log")"
  check "forbid ($name): no ANTHROPIC_ line in the pane-auth file" "0" "$(grep -c 'ANTHROPIC_' "$R/store/.channels-pane-auth")"
  check "forbid ($name): the pane-auth file still carries the OAuth token" "1" "$(grep -c '^export CLAUDE_CODE_OAUTH_TOKEN=' "$R/store/.channels-pane-auth")"
  P1="$(pane_cmd "$R" 1)"; P2="$(pane_cmd "$R" 2)"
  check "forbid ($name): primary pane command = auth file, then the unset, then the rest" ". '$R/store/.channels-pane-auth' && ${UNSET}$TMP/bin/claude --dangerously-skip-permissions --channels plugin:telegram@x" "$P1"
  check "forbid ($name): EPERM pane command, same" "$P1" "$P2"
  for sh in /bin/bash /bin/zsh; do
    check "forbid ($name): the claude in the pane gets neither key, OAuth kept ($sh)" "API= AUTH= OAUTH=set BASE=" "$(run_pane "$sh" "$P1")"
  done
  no_dummy "forbid ($name): the dummy key is in no tmux argv, output or file" "$R/tmux.log" "$R/harness.out" "$R/store/.channels-pane-auth"
done

# forbid with NO auth at all (no OAuth, no key): no auth file, the unset still leads.
R="$TMP/forbid-noauth"
run_launch "$R" "MAIN_AGENT_ID=tmain
INTERACTIVE_ANTHROPIC_KEY_POLICY=forbid" yes ""
check "forbid, no auth configured: harness clean" "0" "$(cat "$R/harness.rc")"
check "forbid, no auth configured: no auth file" "no" "$([ -e "$R/store/.channels-pane-auth" ] && echo yes || echo no)"
check "forbid, no auth configured: the pane starts with the unset" "${UNSET}$TMP/bin/claude --dangerously-skip-permissions --channels plugin:telegram@x" "$(pane_cmd "$R" 1)"
check "forbid, no auth configured: the claude gets no key (zsh)" "API= AUTH= OAUTH= BASE=" "$(run_pane /bin/zsh "$(pane_cmd "$R" 1)")"

# ---- a customProvider that is NOT Anthropic: unchanged under forbid ----------
CPENV="unset CLAUDE_CODE_OAUTH_TOKEN && export ANTHROPIC_BASE_URL='http://127.0.0.1:4010' && export ANTHROPIC_AUTH_TOKEN=ollama && unset ANTHROPIC_API_KEY && export ANTHROPIC_MODEL='oc/x' && "
RA="$TMP/cp-allow"; run_launch "$RA" "$BASE_ENV" yes "$CPENV"
RF="$TMP/cp-forbid"; run_launch "$RF" "$BASE_ENV
INTERACTIVE_ANTHROPIC_KEY_POLICY=forbid" yes "$CPENV"
PA="$(pane_cmd "$RA" 1)"; PF="$(pane_cmd "$RF" 1)"
check "custom provider (not Anthropic): the forbid pane command is byte-identical to allow, modulo the root path" "$PA" "${PF//$RF/$RA}"
if has "$PF" 'unset ANTHROPIC_API_KEY ANTHROPIC_AUTH_TOKEN &&'; then fail "custom provider: no extra unset" "none" "$PF"; else pass "custom provider: no extra unset"; fi
check "custom provider: what the claude gets is the same under forbid and allow (zsh)" "$(run_pane /bin/zsh "$PA")" "$(run_pane /bin/zsh "$PF")"
check "custom provider: ...and that is the provider's own auth only" "API= AUTH=set OAUTH= BASE=set" "$(run_pane /bin/zsh "$PF")"

# ---- the main agent's settings carry a key route: start anyway, loudly -------
settings_fixture() { # user settings: env key + apiKeyHelper; project local: broken JSON naming the other key
  printf '{"env":{"ANTHROPIC_API_KEY":"%s","OTHER":"x"},"apiKeyHelper":"echo %s"}\n' "$DUMMY" "$DUMMY" > "$1/home/.claude/settings.json"
  printf '{"env":{"ANTHROPIC_AUTH_TOKEN":"%s"}\n' "$DUMMY" > "$1/.claude/settings.local.json"
}
R="$TMP/settings-key"
run_launch "$R" "MAIN_AGENT_ID=tmain
CLAUDE_CODE_OAUTH_TOKEN=$OAT
INTERACTIVE_ANTHROPIC_KEY_POLICY=forbid" no "" "" settings_fixture
check "settings key route: harness clean" "0" "$(cat "$R/harness.rc")"
check "settings key route: the main agent STILL starts (2 new-session: boot + EPERM)" "2" "$(grep -c '^CALL \[new-session\]' "$R/tmux.log")"
EV="$R/store/interactive-key-guard-events.jsonl"
check "settings key route: one guard event per file with a finding" "2" "$(wc -l < "$EV" 2>/dev/null | tr -d ' ')"
check "settings key route: the event names (user settings)" '["ANTHROPIC_API_KEY", "apiKeyHelper"]' "$(python3 -c 'import json,sys; print(json.dumps([json.loads(l)["names"] for l in open(sys.argv[1]) if "/home/.claude/" in json.loads(l)["where"]][0]))' "$EV" 2>/dev/null)"
check "settings key route: the broken-JSON file is still searched by name" '["ANTHROPIC_AUTH_TOKEN"]' "$(python3 -c 'import json,sys; print(json.dumps([json.loads(l)["names"] for l in open(sys.argv[1]) if "settings.local.json" in json.loads(l)["where"]][0]))' "$EV" 2>/dev/null)"
check "settings key route: event source and agent" "main-launch-guard tmain" "$(python3 -c 'import json,sys; l=json.loads(open(sys.argv[1]).readline()); print(l["source"], l["agent"])' "$EV" 2>/dev/null)"
check "settings key route: the event file is 0600" "600" "$(stat -f %Lp "$EV" 2>/dev/null || stat -c %a "$EV" 2>/dev/null)"
check "settings key route: a failures-log line per finding" "2" "$(grep -c 'interactive-key-guard: INTERACTIVE_ANTHROPIC_KEY_POLICY=forbid, but the main agent' "$R/store/channels-failures.log" 2>/dev/null)"
no_dummy "settings key route: the settings VALUE is in no event, log or output" "$EV" "$R/store/channels-failures.log" "$R/harness.out" "$R/tmux.log"

# the event file is a symlink a same-uid process planted: the Python writer opens
# it O_NOFOLLOW and chmods by fd, so it neither appends through the link nor
# chmods its target (the TS writer's appendNoFollow rule, BE-1 point 6)
symlink_events_fixture() {
  settings_fixture "$1"
  printf 'victim\n' > "$1/victim"; chmod 644 "$1/victim"
  ln -s "$1/victim" "$1/store/interactive-key-guard-events.jsonl"
}
R="$TMP/settings-key-symlink"
run_launch "$R" "MAIN_AGENT_ID=tmain
CLAUDE_CODE_OAUTH_TOKEN=$OAT
INTERACTIVE_ANTHROPIC_KEY_POLICY=forbid" no "" "" symlink_events_fixture
check "events symlink: harness clean, the main agent still starts" "0|2" "$(cat "$R/harness.rc")|$(grep -c '^CALL \[new-session\]' "$R/tmux.log")"
check "events symlink: nothing appended through the link" "victim" "$(cat "$R/victim")"
check "events symlink: the link target's mode is untouched" "644" "$(stat -f %Lp "$R/victim" 2>/dev/null || stat -c %a "$R/victim" 2>/dev/null)"
check "events symlink: the log says the event was NOT written" "2" "$(grep -c 'guard event NOT written' "$R/store/channels-failures.log" 2>/dev/null)"

# isolated config dir: the scan follows CFG_ENV's dir, not ~/.claude
iso_fixture() { mkdir -p "$1/iso"; echo '{"apiKeyHelper":"x"}' > "$1/iso/settings.json"; echo '{"apiKeyHelper":"x"}' > "$1/home/.claude/settings.json"; }
R="$TMP/settings-isolated"
run_launch "$R" "MAIN_AGENT_ID=tmain
INTERACTIVE_ANTHROPIC_KEY_POLICY=forbid" no "" '_ikg_cfg_dir="$INSTALL_DIR/iso"' iso_fixture
check "isolated dir: the finding is in the isolated settings, the shared one is not scanned" "$R/iso/settings.json" "$(python3 -c 'import json,sys; print(" ".join(json.loads(l)["where"] for l in open(sys.argv[1])))' "$R/store/interactive-key-guard-events.jsonl" 2>/dev/null)"

# allow: no scan at all, even with a key route in the settings
home_helper_fixture() { echo '{"apiKeyHelper":"x"}' > "$1/home/.claude/settings.json"; }
R="$TMP/settings-allow"
run_launch "$R" "MAIN_AGENT_ID=tmain" no "" "" home_helper_fixture
check "allow: no settings scan, no event file" "no" "$([ -e "$R/store/interactive-key-guard-events.jsonl" ] && echo yes || echo no)"

# no python3: the scan says it did not measure, the launch goes ahead
R="$TMP/settings-nopy"
mkdir -p "$TMP/nopy"
for t in sh bash cat rm mkdir mv printf head tail grep sed cut tr date env mktemp id awk wc; do
  for d in /bin /usr/bin; do [ -x "$d/$t" ] && { ln -sf "$d/$t" "$TMP/nopy/$t"; break; }; done
done
run_launch "$R" "MAIN_AGENT_ID=tmain
INTERACTIVE_ANTHROPIC_KEY_POLICY=forbid" no "" "" "" "$TMP/nopy"
check "no python3: the launch still happens" "2" "$(grep -c '^CALL \[new-session\]' "$R/tmux.log")"
check "no python3: the log says NOT measured" "1" "$(grep -c 'could not be scanned for an API-key route' "$R/store/channels-failures.log" 2>/dev/null)"

# ---- channels.sh --interactive-key-policy: the seam the respawners ask --------
seam() { # $1 .env body (or __none__) -> printed policy
  local r="$TMP/seam"; rm -rf "$r"; mkdir -p "$r/scripts"; cp "$CH" "$r/scripts/channels.sh"
  [ "$1" != __none__ ] && printf '%s\n' "$1" > "$r/.env"
  env -i PATH="$SAFE_PATH" HOME="$r" /bin/bash "$r/scripts/channels.sh" --interactive-key-policy 2>/dev/null
}
check "seam: no .env -> allow" "allow" "$(seam __none__)"
check "seam: allow -> allow" "allow" "$(seam 'INTERACTIVE_ANTHROPIC_KEY_POLICY=allow')"
check "seam: forbid -> forbid" "forbid" "$(seam 'INTERACTIVE_ANTHROPIC_KEY_POLICY=forbid')"
check "seam: CRLF + spaces around allow -> allow" "allow" "$(seam "  INTERACTIVE_ANTHROPIC_KEY_POLICY = allow $(printf '\r')")"
check "seam: a commented forbid is ignored" "allow" "$(seam '# INTERACTIVE_ANTHROPIC_KEY_POLICY=forbid')"
check "seam: unknown value -> forbid" "forbid" "$(seam 'INTERACTIVE_ANTHROPIC_KEY_POLICY=no')"
check "seam: the function is byte-identical to watchdog.sh's" \
  "$(cut_block "$INSTALL_DIR/scripts/watchdog.sh" 'interactive_key_policy() {' '}')" \
  "$(cut_block "$CH" 'interactive_key_policy() {' '}')"

# ---- the custom-provider rc handling in channels.sh ---------------------------
# A stub `sleep` (records its argument, never waits) and a stub clock (`date +%s`
# reads $FAKE_NOW; every other format goes to the real date) come first in PATH.
HOLD_BIN="$TMP/holdbin"; mkdir -p "$HOLD_BIN"
cat > "$HOLD_BIN/sleep" <<'FAKE'
#!/bin/sh
echo "SLEEP $1" >> "$FAKE_SLEEP_LOG"
FAKE
cat > "$HOLD_BIN/date" <<'FAKE'
#!/bin/sh
if [ "$1" = "+%s" ]; then echo "$FAKE_NOW"; else exec /bin/date "$@"; fi
FAKE
chmod +x "$HOLD_BIN/sleep" "$HOLD_BIN/date"
cp_rc() { # $1 = exit code of a fake helper -> "<rc>|<log>"
  local r="$TMP/cprc"; rm -rf "$r"; mkdir -p "$r/store" "$r/dist/web"; : > "$r/dist/web/custom-providers.js"
  printf '#!/bin/sh\nexit %s\n' "$1" > "$r/fake-node"; chmod +x "$r/fake-node"
  { printf 'INSTALL_DIR=%q\n_node_bin=%q\nCUSTOM_PROVIDER_ENV=""\n' "$r" "$r/fake-node"; echo "$CP_BLOCK"; echo 'fi'; echo 'echo continued'; } > "$r/h.sh"
  local out; out="$(env -i PATH="$HOLD_BIN:$SAFE_PATH" FAKE_NOW=1000 FAKE_SLEEP_LOG="$r/sleep.log" /bin/bash "$r/h.sh" 2>&1)"; local rc=$?
  printf '%s|%s|%s' "$rc" "$out" "$(cat "$r/store/channels-failures.log" 2>/dev/null)"
}
G="$(cp_rc 3)"
check "helper exit 3: channels.sh stops with 3" "3" "${G%%|*}"
if has "$G" 'refused (exit 3): INTERACTIVE_ANTHROPIC_KEY_POLICY=forbid' && ! has "$G" 'continued'; then pass "helper exit 3: named as the guard refusal, nothing launched"; else fail "helper exit 3: named as the guard refusal" "refused (exit 3) log" "$G"; fi
G="$(cp_rc 1)"
if [ "${G%%|*}" = 1 ] && has "$G" 'customProvider configured but broken'; then pass "helper exit 1: the old abort, unchanged"; else fail "helper exit 1: the old abort" "1 + broken" "$G"; fi
G="$(cp_rc 0)"
if has "$G" 'continued'; then pass "helper exit 0: carries on"; else fail "helper exit 0: carries on" "continued" "$G"; fi

# ---- the refusal is HELD, not retried at launchd's 30s pace (review finding) ----
# One install dir across the runs, as launchd (or the dashboard) would start
# channels.sh again and again. The fake helper does what the real one does on a
# refusal: one guard event unless IKG_GUARD_EVENT_QUIET=1, exit 3 (or exit 0
# once the config is fixed). It also records that it RAN: the decision is never
# skipped (BE-1). The clock is the real one plus an offset, so the marker's real
# mtime is never "in the future" of the fake now.
HR="$TMP/hold"; rm -rf "$HR"; mkdir -p "$HR/store" "$HR/dist/web" "$HR/agents/tmain"
: > "$HR/dist/web/custom-providers.js"; : > "$HR/dist/web/interactive-key-guard.js"
printf 'MAIN_AGENT_ID=tmain\nINTERACTIVE_ANTHROPIC_KEY_POLICY=forbid\n' > "$HR/.env"
echo '{"customProvider":"p"}' > "$HR/agents/tmain/agent-config.json"
echo '{"providers":[]}' > "$HR/store/custom-providers.json"
cat > "$HR/fake-node" <<'FAKE'
#!/bin/sh
echo "ran quiet=${IKG_GUARD_EVENT_QUIET:-}" >> "$IKG_RAN"
[ "${IKG_GUARD_EVENT_QUIET:-}" = 1 ] || echo '{"source":"main-launch-guard","names":["ANTHROPIC_API_KEY","ANTHROPIC_AUTH_TOKEN"]}' >> "$IKG_EVENTS"
exit "$FAKE_HELPER_RC"
FAKE
chmod +x "$HR/fake-node"
hold_harness() { # $1 policy
  { printf 'INSTALL_DIR=%q\n_node_bin=%q\nMAIN_AGENT_ID=tmain\nINTERACTIVE_KEY_POLICY=%s\nCUSTOM_PROVIDER_ENV=""\n' "$HR" "$HR/fake-node" "$1"; echo "$CP_BLOCK"; echo 'fi'; echo 'echo continued'; } > "$HR/h.sh"
}
hold_harness forbid
N0="$(/bin/date +%s)"
hold_run() { # $1 seconds after N0  $2 helper rc -> "<rc>"; sleep calls in $HR/sleep.log
  : > "$HR/sleep.log"
  env -i PATH="$HOLD_BIN:$SAFE_PATH" FAKE_NOW="$((N0 + $1))" FAKE_HELPER_RC="${2:-3}" FAKE_SLEEP_LOG="$HR/sleep.log" \
    IKG_EVENTS="$HR/store/interactive-key-guard-events.jsonl" IKG_RAN="$HR/ran.log" /bin/bash "$HR/h.sh" > "$HR/out" 2>&1
  echo $?
}
events() { wc -l < "$HR/store/interactive-key-guard-events.jsonl" 2>/dev/null | tr -d ' ' || echo 0; }
ran() { wc -l < "$HR/ran.log" 2>/dev/null | tr -d ' ' || echo 0; }
MK="$HR/store/.channels-key-guard-refused"
check "hold: 1st start refused -> exit 3" "3" "$(hold_run 0)"
check "hold: 1st start: one guard event" "1" "$(events)"
check "hold: 1st start waits the full hold BEFORE it exits (launchd cannot restart it sooner)" "SLEEP 300" "$(cat "$HR/sleep.log")"
check "hold: the marker = the time and the sha256 of the inputs" "1" "$(grep -cE "^$N0 [0-9a-f]{64}\$" "$MK" 2>/dev/null)"
check "hold: the marker is written atomically (no tmp left)" "0" "$(ls -A "$HR/store" | grep -c 'refused\.')"
check "hold: 2nd start 30s later -> exit 3" "3" "$(hold_run 30)"
check "hold: 2nd start RAN the helper (the decision is never skipped), quietly" "2|ran quiet=1" "$(ran)|$(tail -1 "$HR/ran.log")"
check "hold: 2nd start inside the hold writes NO second guard event" "1" "$(events)"
check "hold: 2nd start waits out the rest of the hold" "SLEEP 270" "$(cat "$HR/sleep.log")"
check "hold: 2nd start: nothing launched, no second log line" "0|1" "$(grep -c continued "$HR/out")|$(grep -c 'refused (exit 3)' "$HR/store/channels-failures.log")"
check "hold: 3rd start at 299s -> still quiet" "1|SLEEP 1" "$(hold_run 299 >/dev/null; events)|$(cat "$HR/sleep.log")"
check "hold: a start after the hold writes the event again (at most one per 300s)" "3|2" "$(hold_run 300)|$(events)"
check "hold: ...and the marker moves on" "1" "$(grep -c "^$((N0 + 300)) " "$MK")"
check "hold: a clock that went backwards is not a hold" "3|3" "$(hold_run 100)|$(events)"
# BE-1: what a forger (or a stale marker) cannot do
cp "$MK" "$HR/good-marker"
touch -t 203001010000 "$MK"
check "hold: a marker mtime in the future is ignored (a new event)" "3|4" "$(hold_run 101)|$(events)"
cp "$HR/good-marker" "$MK"; printf '%s %s\n' "$((N0 + 102))" "$(cut -d' ' -f2 "$HR/good-marker")" > "$MK"
echo '{"customProvider":"other"}' > "$HR/agents/tmain/agent-config.json"
touch -t 202001010000 "$HR/agents/tmain/agent-config.json"
check "hold: a changed input releases it BY CONTENT, even with an old mtime (a new event)" "3|5" "$(hold_run 103)|$(events)"
rm -f "$MK"; ln -s "$HR/good-marker" "$MK"
printf '%s %s\n' "$((N0 + 104))" "$(cut -d' ' -f2 "$HR/good-marker")" > "$HR/good-marker"
check "hold: a marker that is a symlink is ignored (a new event)" "3|6" "$(hold_run 105)|$(events)"
check "hold: ...and the symlink was replaced by our own file, not written through" "no|1" "$([ -L "$MK" ] && echo yes || echo no)|$(grep -c "^$((N0 + 104)) " "$HR/good-marker")"
printf '%s %s\n' "$((N0 + 106))" "$(cut -d' ' -f2 "$MK")" > "$MK"
hold_harness allow
check "hold: under allow a valid marker has no effect (not quiet)" "ran quiet=" "$(hold_run 107 >/dev/null; tail -1 "$HR/ran.log")"
hold_harness forbid
check "hold: the config fixed (helper exit 0) -> carries on and drops the marker" "0|1|no" "$(hold_run 400 0)|$(grep -c continued "$HR/out")|$([ -e "$MK" ] && echo yes || echo no)"
check "hold: the event file and the log never carry the marker hash or a key" "0" "$(cat "$HR/store/interactive-key-guard-events.jsonl" "$HR/store/channels-failures.log" 2>/dev/null | grep -cE '[0-9a-f]{64}|sk-ant-')"
# A marker owned by another uid cannot be planted without root here; the [ -O ]
# check is pinned by the TS side's uid test and by this grep.
check "hold: the shell honours the marker only as our own regular file ([ -f ] [ ! -L ] [ -O ])" "1" "$(printf '%s\n' "$CP_BLOCK" | grep -c '\[ -f "$_kg_marker" \] && \[ ! -L "$_kg_marker" \] && \[ -O "$_kg_marker" \]')"

# ---- the two shell respawners ----------------------------------------------------
respawn_cmd() { # $1 script  $2 end marker  $3 .env body or __nochannels__ -> RESPAWN_CMD
  local src="$1" endm="$2" r="$TMP/resp"; rm -rf "$r"; mkdir -p "$r/scripts"
  if [ "$3" != __nochannels__ ]; then cp "$CH" "$r/scripts/channels.sh"; printf '%s\n' "$3" > "$r/.env"; fi
  local blk; blk="$(cut_block "$src" '# fec6335f: INTERACTIVE_ANTHROPIC_KEY_POLICY' "$endm")"
  {
    echo 'set -u'
    printf 'INSTALL_DIR=%q\n' "$r"
    echo 'FLEET_VENV_PREFIX= STATE_DIR_ENV= CFG_ENV= CLAUDE=claude CLAUDE_Q=claude EXTRA_SETTINGS_FLAG= MODEL_FLAG= CHANNEL_PROVIDER=telegram EXTRA_CHANNELS= PLUGIN_Q=plugin:telegram@x'
    echo 'f() {'; echo "$blk"; echo 'printf "%s" "$RESPAWN_CMD"'; echo '}'; echo f
  } > "$r/h.sh"
  env -i PATH="$SAFE_PATH" HOME="$r" /bin/bash "$r/h.sh" 2>&1
}
for trio in "channel-watchdog.sh|$WD|RESPAWN_CMD=" "stuck-modal-guard.sh|$SG|local RESPAWN_CMD="; do
  IFS='|' read -r n s endm <<EOF
$trio
EOF
  check "$n: the key block was cut (ends at its RESPAWN_CMD line)" "1" "$(cut_block "$s" '# fec6335f: INTERACTIVE_ANTHROPIC_KEY_POLICY' "$endm" | grep -c 'RESPAWN_CMD="')"
  A="$(respawn_cmd "$s" "$endm" 'INTERACTIVE_ANTHROPIC_KEY_POLICY=allow')"
  F="$(respawn_cmd "$s" "$endm" 'INTERACTIVE_ANTHROPIC_KEY_POLICY=forbid')"
  N="$(respawn_cmd "$s" "$endm" __nochannels__)"
  if has "$A" 'export PATH=' && [ "${A#export PATH=}" != "$A" ]; then pass "$n allow: RESPAWN_CMD starts as before (export PATH=)"; else fail "$n allow: RESPAWN_CMD starts as before" "export PATH=..." "$A"; fi
  check "$n forbid: RESPAWN_CMD = the unset + the allow command, byte for byte" "${UNSET}${A}" "$F"
  check "$n channels.sh not answering: fail-closed, the unset is there" "${UNSET}${A}" "$N"
  for sh in /bin/bash /bin/zsh; do
    check "$n forbid: the respawned claude gets no key ($sh)" "API= AUTH= OAUTH= BASE=" "$(run_pane "$sh" "${F//claude --/$TMP/bin/claude --}")"
  done
done

# ---- main-agent-custom-provider.mjs ---------------------------------------------
DIST="${IKG_DIST:-$INSTALL_DIR/dist}"
# Built when missing, and -- for the install's own dist -- when any source file
# is newer than it: a dist that merely EXISTS may predate the change under test
# (tsc rewrites every output, so the guard module's mtime is the build time).
# An explicit IKG_DIST is taken as given.
_ikg_stale=""
if [ ! -f "$DIST/web/interactive-key-guard.js" ]; then
  _ikg_stale="not built (or predates the guard)"
elif [ -z "${IKG_DIST:-}" ] && [ -n "$(find "$INSTALL_DIR/src" -name '*.ts' -newer "$DIST/web/interactive-key-guard.js" -print 2>/dev/null | head -1)" ]; then
  _ikg_stale="older than src/"
fi
if [ -n "$_ikg_stale" ]; then
  echo "dist/ $_ikg_stale -- building now (npm run build)..." >&2
  ( cd "$INSTALL_DIR" && npm run build ) >&2 || { echo "FAIL: npm run build failed" >&2; exit 1; }
  DIST="$INSTALL_DIR/dist"
fi
check "dist: no source file is newer than the dist the helper runs on" "" \
  "$([ -n "${IKG_DIST:-}" ] || find "$INSTALL_DIR/src" -name '*.ts' -newer "$DIST/web/interactive-key-guard.js" -print 2>/dev/null | head -1)"
M="$TMP/mjs"
mkdir -p "$M/scripts" "$M/store" "$M/agents/tmain" "$M/home"
cp -R "$DIST" "$M/dist"
ln -s "$INSTALL_DIR/node_modules" "$M/node_modules"
cp "$HELPER" "$M/scripts/main-agent-custom-provider.mjs"
# Keychain stub: the vault falls back to a file key in $M/store -- the host's
# Keychain (and the live vault master key in it) is never asked.
cat > "$M/dist/web/keychain.js" <<'STUB'
export function isKeychainAvailable() { return false }
export function keychainRetrieveStatus() { return { status: 'unavailable', value: null } }
export function keychainRetrieve() { return null }
export function keychainStore() { throw new Error('test: keychain stubbed') }
export function keychainDelete() { return false }
STUB
mjs() { # $1 policy line, $2 agent-config, $3 providers -> sets OUT RC ERR
  printf 'MAIN_AGENT_ID=tmain\n%s\n' "$1" > "$M/.env"
  printf '%s\n' "$2" > "$M/agents/tmain/agent-config.json"
  printf '%s\n' "$3" > "$M/store/custom-providers.json"
  rm -f "$M/store/interactive-key-guard-events.jsonl"
  OUT="$(env -i PATH="$PATH" HOME="$M/home" node "$M/scripts/main-agent-custom-provider.mjs" "$M/home" 2>"$M/err")"; RC=$?
  ERR="$(cat "$M/err")"
}
prov() { printf '{"providers":[{"id":"p","label":"P","baseUrl":"%s","authHeader":"%s","vaultKey":%s}]}' "$1" "$2" "$3"; }
AGENT='{"customProvider":"p","model":"oc/x"}'
EV="$M/store/interactive-key-guard-events.jsonl"

mjs 'INTERACTIVE_ANTHROPIC_KEY_POLICY=forbid' '{"model":"claude-opus-5-5"}' '{"providers":[]}'
check "helper, forbid, no customProvider: exit 0, no output, no event" "0||no" "$RC|$OUT|$([ -e "$EV" ] && echo yes || echo no)"

mjs 'INTERACTIVE_ANTHROPIC_KEY_POLICY=allow' "$AGENT" "$(prov http://127.0.0.1:4010 none null)"
ALLOW_NONE="$OUT"
check "helper, allow, none-auth local provider: the known prefix" "unset CLAUDE_CODE_OAUTH_TOKEN && export ANTHROPIC_BASE_URL='http://127.0.0.1:4010' && export ANTHROPIC_AUTH_TOKEN=ollama && unset ANTHROPIC_API_KEY && export ANTHROPIC_MODEL='oc/x' && " "$OUT"
mjs 'INTERACTIVE_ANTHROPIC_KEY_POLICY=forbid' "$AGENT" "$(prov http://127.0.0.1:4010 none null)"
check "helper, forbid, NOT Anthropic: byte-identical to allow, exit 0" "0|$ALLOW_NONE" "$RC|$OUT"

for case in "https://api.anthropic.com|Bearer|\"MY_KEY\"|anthropic.com URL" "https://eu.api.anthropic.com/v1|x-api-key|\"MY_KEY\"|anthropic subdomain" "http://127.0.0.1:4010|Bearer|\"ANTHROPIC_API_KEY_BATCH\"|the shared Team key at a local URL" "not a url|none|null|an unreadable baseUrl"; do
  IFS='|' read -r url hdr vk label <<EOF
$case
EOF
  mjs 'INTERACTIVE_ANTHROPIC_KEY_POLICY=forbid' "$AGENT" "$(prov "$url" "$hdr" "$vk")"
  check "helper, forbid, $label: exit 3, empty stdout" "3|" "$RC|$OUT"
  if has "$ERR" 'vault key'; then fail "helper, forbid, $label: refused BEFORE the vault lookup" "no vault message" "$ERR"; else pass "helper, forbid, $label: refused before the vault lookup"; fi
  check "helper, forbid, $label: one guard event, names only" 'main-launch-guard|["ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN"]|tmain' \
    "$(python3 -c 'import json,sys; l=[json.loads(x) for x in open(sys.argv[1])]; print("%s|%s|%s" % (l[0]["source"], json.dumps(l[0]["names"]), l[0]["agent"]) if len(l)==1 else len(l))' "$EV" 2>/dev/null)"
done
mjs 'INTERACTIVE_ANTHROPIC_KEY_POLICY=allow' "$AGENT" "$(prov https://api.anthropic.com none null)"
check "helper, allow, Anthropic URL: unchanged (exit 0, the prefix)" "0|unset CLAUDE_CODE_OAUTH_TOKEN && export ANTHROPIC_BASE_URL='https://api.anthropic.com' && export ANTHROPIC_AUTH_TOKEN=ollama && unset ANTHROPIC_API_KEY && export ANTHROPIC_MODEL='oc/x' && " "$RC|$OUT"

# Bearer to a non-Anthropic endpoint, with a key in the (file-keyed) test vault.
if (cd "$M" && env -i PATH="$PATH" HOME="$M/home" K="$DUMMY" node --input-type=module -e "const { setSecret } = await import('$M/dist/web/vault.js'); setSecret('MY_KEY', 'test', process.env.K)") >/dev/null 2>&1; then
  mjs 'INTERACTIVE_ANTHROPIC_KEY_POLICY=allow' "$AGENT" "$(prov http://127.0.0.1:4010 Bearer '"MY_KEY"')"; A_OUT="$OUT"; A_RC="$RC"
  mjs 'INTERACTIVE_ANTHROPIC_KEY_POLICY=forbid' "$AGENT" "$(prov http://127.0.0.1:4010 Bearer '"MY_KEY"')"
  check "helper, Bearer NOT Anthropic: forbid output = allow output" "0|$A_OUT" "$RC|$OUT"
  check "helper, Bearer NOT Anthropic: allow ran as before (exit 0, \$(cat) reference)" "0|yes" "$A_RC|$(has "$A_OUT" "export ANTHROPIC_AUTH_TOKEN=\"\$(cat '" && echo yes || echo no)"
  if has "$OUT$A_OUT" "$DUMMY"; then fail "helper, Bearer: the key value is not in the output" "absent" "present"; else pass "helper, Bearer: the key value is not in the output"; fi
else
  fail "helper, Bearer: test vault setup" "setSecret ok" "failed"
fi

# A dist that predates the guard module (a `git pull` before `npm run build`): the
# REAL dist cannot stand in for it -- its agent-process.js imports the guard -- so
# the helper runs on a minimal dist of that age: stub launcher modules plus the
# real env.js chain (node builtins only; on an install with the 053f4e66
# patch env.js also imports env-entry.js), and no interactive-key-guard.js.
S="$TMP/stale"
mkdir -p "$S/scripts" "$S/dist/web"
cp "$HELPER" "$S/scripts/main-agent-custom-provider.mjs"
cp "$DIST/env.js" "$DIST/env-parse.js" "$S/dist/"; cp "$DIST/web/atomic-write.js" "$S/dist/web/"
[ ! -f "$DIST/env-entry.js" ] || cp "$DIST/env-entry.js" "$S/dist/"
echo "export const MAIN_AGENT_ID = 'tmain'" > "$S/dist/config.js"
echo "export const readAgentCustomProvider = () => 'p'; export const readAgentModel = () => 'oc/x'" > "$S/dist/web/agent-config.js"
echo "export const loadCustomProvider = () => ({ id: 'p', label: 'P', baseUrl: 'http://127.0.0.1:4010', authHeader: 'none', vaultKey: null })" > "$S/dist/web/custom-providers.js"
echo "export const getSecret = () => { throw new Error('the vault must not be read') }" > "$S/dist/web/vault.js"
echo "export const launchSecretRef = () => { throw new Error('no key expected') }" > "$S/dist/web/agent-process.js"
stale() { # $1 .env body -> sets OUT RC ERR
  printf '%s\n' "$1" > "$S/.env"
  OUT="$(env -i PATH="$PATH" HOME="$S" node "$S/scripts/main-agent-custom-provider.mjs" 2>"$S/err")"; RC=$?
  ERR="$(cat "$S/err")"
}
stale 'INTERACTIVE_ANTHROPIC_KEY_POLICY=allow'
check "helper, stale dist, allow: unchanged output" "0|$ALLOW_NONE" "$RC|$OUT"
stale ''
check "helper, stale dist, no policy: unchanged output" "0|$ALLOW_NONE" "$RC|$OUT"
stale 'INTERACTIVE_ANTHROPIC_KEY_POLICY=forbid'
if [ "$RC" = 1 ] && [ -z "$OUT" ] && has "$ERR" 'npm run build'; then pass "helper, stale dist, forbid: loud abort (exit 1, npm run build)"; else fail "helper, stale dist, forbid: loud abort" "1, empty, npm run build" "$RC|$OUT|$ERR"; fi
stale 'INTERACTIVE_ANTHROPIC_KEY_POLICY=typo'
check "helper, stale dist, unknown value: fail-closed abort" "1|" "$RC|$OUT"

echo
echo "  $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
