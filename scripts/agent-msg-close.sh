#!/usr/bin/env bash
# agent-msg-close.sh -- reliable, SIGNED close of an inter-agent message (card f137f980, Brainy 6367).
#
# WHY: the raw `curl -X PUT /api/messages/<id>` close has the same two flaws agent-msg.sh fixed for the send:
# curl exits 0 when the server REFUSED the request, so a failed close looks like a done one; and it carries no
# per-agent send key, so the dashboard cannot tell who closed the row (closer_auth, shadow phase). This helper
# signs the close with the agent's send key, checks the answer, and retries a dead or failing server. The MAIN
# agent uses it too (notify false, result from a file or stdin).
#
# Usage:  bash scripts/agent-msg-close.sh <id> <done|failed> [--notify true|false] [--result-file <file>|-]
#   <id>            the message id (digits only).
#   <done|failed>   the terminal status to set.
#   --notify        a real JSON boolean. Absent = the server default (the original sender gets the receipt).
#                   For an INCOMING report or notification pass `--notify false`.
#   --result-file   the result text, from a FILE (write it with your file tool first), or `-` for STDIN. The
#                   bytes are sent as they are (quotes, backticks, $(...) and newlines are plain text); they are
#                   never put on the command line or interpolated by the shell. A bare third argument `-` means
#                   the same as `--result-file -`.
# Output (stdout):
#   success                   -> "OK id=<n> status=<s>"                      exit 0
#   already closed (HTTP 409) -> "ALREADY-CLOSED id=<n> ..." a no-op, the first close already took effect, exit 0
#   anything else             -> "FAIL close id=<n> ... http=<code>" (+ a line in store/agent-msg-failures.log), exit 1
#   usage error / no token    -> "FAIL: ..." on stderr, nothing sent, exit 2
# Success means HTTP 200 AND {"ok":true}. A 5xx or no answer (000) is retried, 3 tries in all; the retry is safe:
# if the first try did land, the next one gets the 409 above. Other 4xx answers (400, 401, 403, 404) are final.
# Env (the same as agent-msg.sh):
#   MARVEEN_API_BASE   full base URL (overrides host+port); only loopback or this install's own configured origin
#   MARVEEN_WEB_PORT   port for the default localhost base (default 3420; then WEB_PORT, then .env)
#   MARVEEN_TOKEN_FILE bearer token file (default <repo>/store/.dashboard-token)
#   MARVEEN_AGENT_KEY_FILE this agent's send key file, set by the dashboard at launch ("X-Agent-Key: <key>", one
#     line). The path comes ONLY from this variable. Missing or refused (scripts/lib/marveen_api.py vets it) means
#     the close goes out UNSIGNED and a note says so on stderr: shadow mode accepts it, it is never a FAIL.
# The token and the key travel to curl on STDIN (`-H @-`), so neither is in any argv; both are redacted from the
# failure log and from anything the server said back.
set -uo pipefail

BASE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
KEYLIB="$BASE/scripts/lib/marveen_api.py"
LOG="$BASE/store/agent-msg-failures.log"
USAGE="usage: bash scripts/agent-msg-close.sh <id> <done|failed> [--notify true|false] [--result-file <file>|-]"
die() { echo "FAIL: $1; nothing was sent." >&2; exit 2; }

# --- arguments --------------------------------------------------------------
ID=""; STATUS=""; NOTIFY=""; NOTIFY_GIVEN=0; RESULT_FILE=""; POS=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --notify) [ "$#" -ge 2 ] || die "--notify needs true or false"; NOTIFY="$2"; NOTIFY_GIVEN=1; shift 2 ;;
    --notify=*) NOTIFY="${1#--notify=}"; NOTIFY_GIVEN=1; shift ;;
    --result-file) [ "$#" -ge 2 ] || die "--result-file needs a path or -"; RESULT_FILE="$2"; shift 2 ;;
    --result-file=*) RESULT_FILE="${1#--result-file=}"; shift ;;
    -) RESULT_FILE="-"; shift ;;
    -h|--help) echo "$USAGE"; exit 0 ;;
    -*) die "unknown option $1 ($USAGE)" ;;
    *)
      POS=$((POS+1))
      case "$POS" in 1) ID="$1" ;; 2) STATUS="$1" ;; *) die "unexpected argument ($USAGE)" ;; esac
      shift ;;
  esac
done
[ -n "$ID" ] && [ -n "$STATUS" ] || die "$USAGE"
case "$ID" in ''|*[!0-9]*) die "the message id must be digits only" ;; esac
[ "${#ID}" -le 18 ] || die "the message id is too long"
case "$STATUS" in done|failed) : ;; *) die "status must be done or failed" ;; esac
if [ "$NOTIFY_GIVEN" = 1 ]; then
  case "$NOTIFY" in true|false) : ;; *) die "--notify must be true or false (a JSON boolean)" ;; esac
fi
if [ -n "$RESULT_FILE" ] && [ "$RESULT_FILE" != "-" ] && [ ! -r "$RESULT_FILE" ]; then
  die "cannot read the result file"
fi
command -v python3 >/dev/null 2>&1 || die "python3 is required"

# --- endpoint, token --------------------------------------------------------
# The same guard marveen-api.sh applies before it hands anything to the helpers: the token goes only to
# loopback or this install's own configured origin. Without the vetting library a custom base is refused.
if [ -r "$KEYLIB" ]; then
  python3 "$KEYLIB" --check-env || exit 2
elif [ -n "${MARVEEN_API_BASE:-}" ] || [ -n "${MARVEEN_TOKEN_FILE:-}" ]; then
  die "scripts/lib/marveen_api.py is missing, so MARVEEN_API_BASE / MARVEEN_TOKEN_FILE cannot be vetted"
fi
PORT="${MARVEEN_WEB_PORT:-${WEB_PORT:-$(sed -n 's/^WEB_PORT=//p' "$BASE/.env" 2>/dev/null | head -1 | tr -d ' "'"'"''; true)}}"
PORT="${PORT:-3420}"
API_BASE="${MARVEEN_API_BASE:-http://localhost:${PORT}}"
API_BASE="${API_BASE%/}"
TOKEN_FILE="${MARVEEN_TOKEN_FILE:-$BASE/store/.dashboard-token}"
URL="${API_BASE}/api/messages/${ID}"
[ -r "$TOKEN_FILE" ] || die "no token file at $TOKEN_FILE"
TOKEN="$(tr -d '\r\n' < "$TOKEN_FILE")"
[ -n "$TOKEN" ] || die "the token file at $TOKEN_FILE is empty"

# --- per-agent send key (the same vetting and format as agent-msg.sh) --------
KEY_LINE=""; KEY_VAL=""
if [ -n "${MARVEEN_AGENT_KEY_FILE:-}" ] && [ -r "$KEYLIB" ]; then
  KEY_RAW="$(python3 "$KEYLIB" --read-key-line || true)"
  KEY_RE='^X-Agent-Key: ([A-Za-z0-9_.~-]{1,128})$'
  case "$KEY_RAW" in
    *$'\n'*|*$'\r'*) : ;;
    *) if [[ "$KEY_RAW" =~ $KEY_RE ]]; then KEY_LINE="$KEY_RAW"; KEY_VAL="${BASH_REMATCH[1]}"; fi ;;
  esac
  unset KEY_RAW
fi
if [ -z "$KEY_LINE" ]; then
  echo "NOTE: no usable send key (MARVEEN_AGENT_KEY_FILE unset, missing or refused); closing msg $ID UNSIGNED. Shadow mode accepts it and records it as unsigned." >&2
fi

# --- body: built by python from the FILE, never through a shell variable ----------
WORK="$(mktemp -d "${TMPDIR:-/tmp}/agent-msg-close.XXXXXX")" || die "cannot create a work directory"
trap 'rm -rf "$WORK"' EXIT
BODYFILE="$WORK/body.json"
if [ -n "$RESULT_FILE" ]; then
  SRC="$RESULT_FILE"
else
  SRC=""
fi
python3 -c '
import json, sys
status, notify, src, out = sys.argv[1:5]
d = {"status": status}
if notify:
    d["notify"] = (notify == "true")
if src:
    raw = sys.stdin.buffer.read() if src == "-" else open(src, "rb").read()
    d["result"] = raw.decode("utf-8")
with open(out, "w") as f:
    f.write(json.dumps(d))
' "$STATUS" "$NOTIFY" "$SRC" "$BODYFILE" || die "could not build the request (the result must be UTF-8 text)"
[ -s "$BODYFILE" ] || die "the request body is empty"

# --- send, verify, retry ---------------------------------------------------
HEADERS="Authorization: Bearer $TOKEN"
[ -n "$KEY_LINE" ] && HEADERS="$HEADERS"$'\n'"$KEY_LINE"

redact() {
  local t="$1"
  t="${t//"$TOKEN"/[redacted]}"
  [ -n "$KEY_VAL" ] && t="${t//"$KEY_VAL"/[redacted]}"
  printf '%s' "$t"
}

attempt=0; max=3; CODE=""; JSON=""
while [ "$attempt" -lt "$max" ]; do
  attempt=$((attempt+1))
  RESP="$(printf '%s\n' "$HEADERS" | curl -s --max-time 30 -X PUT "$URL" -H "Content-Type: application/json" -H @- --data-binary "@$BODYFILE" -w $'\n%{http_code}' 2>/dev/null || true)"
  CODE="$(printf '%s' "$RESP" | tail -n1)"
  JSON="$(printf '%s' "$RESP" | sed '$d')"
  VERDICT="$(printf '%s' "$JSON" | python3 -c 'import sys,json
try:
  d=json.load(sys.stdin)
  if not isinstance(d,dict): d={}
except Exception:
  d={}
if d.get("ok") is True: print("ok")
elif d.get("error")=="Message already closed": print("closed")
else: print("other")' 2>/dev/null || echo other)"
  if [ "$CODE" = "200" ] && [ "$VERDICT" = "ok" ]; then
    echo "OK id=$ID status=$STATUS"
    exit 0
  fi
  if [ "$CODE" = "409" ] && [ "$VERDICT" = "closed" ]; then
    echo "ALREADY-CLOSED id=$ID (HTTP 409): the first close already took effect, nothing was changed and no receipt went out. Not an error; do not retry."
    exit 0
  fi
  # Final answers: retrying a 4xx (or an odd 200) cannot change it. Only 5xx and no answer (000) are retried.
  case "$CODE" in
    5[0-9][0-9]|000|"") [ "$attempt" -lt "$max" ] && sleep 1 ;;
    *) break ;;
  esac
done

echo "FAIL close id=$ID url=$URL http=${CODE:-?} (after $attempt tr$([ "$attempt" = 1 ] && echo y || echo ies))"
# The response text is the server's: if it ever echoed the key or the token, it must reach neither the log nor the screen.
LOG_RESP="$(redact "$(printf '%s' "${JSON:-}" | head -c 200)")"
[ -n "$LOG_RESP" ] && echo "  server said: $LOG_RESP" >&2
printf '%s\tFAIL\tclose id=%s\turl=%s\thttp=%s\tresp=%s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$ID" "$URL" "${CODE:-?}" "$LOG_RESP" >> "$LOG" 2>/dev/null || true
exit 1
