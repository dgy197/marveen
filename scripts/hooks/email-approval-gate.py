#!/usr/bin/env python3
"""Level-aware email approval gate for the MAIN agent (EMAILKAPU901 PR2).

Wired in the repo's .claude/settings.json (PreToolUse: Bash + *send_email* +
*manage_email*), i.e. for sessions rooted at PROJECT_ROOT -- the main agent.
Sub-agents keep their unconditional hard-deny (scripts/email-send-gate.mjs in
their own settings); a sub-agent session that also loads this hook is still
blocked by that one, so this gate can never widen sub-agent rights.

The `email_send.level` in store/autonomy-config.json becomes a real switch:
  level 1  -> hard deny (signal-only autonomy).
  level 2  -> CHECK-BEFORE-SEND: the send is allowed only against an APPROVED,
              UNCONSUMED, IN-WINDOW approval whose content_hash equals the
              sha256 anchor of THIS letter's envelope (to + cc + bcc + subject +
              body). A body+subject hash alone would let an approved letter be
              re-sent to a different recipient -- hence every recipient field, bcc included (msg 17936, EMAILBCCHORGONY903).
  level 3  -> allow (autonomous; the outgoing-copy-gate still audits copy).

At level 2 there is ONE narrow bypass, the standing recipient list
(store/email-standing-recipients.json, EMAILALLANDOCIMZETT926): a letter whose
sole recipient is on that list, with no cc and no bcc, is allowed without an
approval. It exists because the owner wants notifications to his own address
without clicking, and the alternative he was about to reach for -- raising the
level to 3 -- is far wider: the level knows nothing about WHO the letter goes
to, so it would also release every supplier letter. The list is checked only at
level 2; level 1 stays a hard deny, so "signal only" keeps meaning that.
Because that path authorises with no human deciding on THAT letter, it carries
two obligations the rest of the gate does not (review of #1608): it LEAVES A
TRACE the owner can read -- an append-only local log plus an entry in the
dashboard's daily log, and an unrecordable send is denied -- and the level-2
DENY MESSAGE does not name the list file or the way onto it. The old wording
did, and since the agent can write store/ itself, the gate's own refusal was
the manual for getting around it. The right to send still comes from the
owner; the route to it is no longer handed out by the thing doing the
refusing.
The list alone no longer grants anything (the review's third ask): an entry makes
an address a CANDIDATE, and a one-time, owner-resolved approval
(category email_standing_recipient, content_hash = sha256 of the normalised
address) makes it live. That approval is neither consumed nor time-windowed --
a standing right that expires or dies on first use is just a per-letter approval
under another name -- and the owner's LAST resolved decision wins, so a later
rejection revokes the right without anyone editing the file. Whoever can write
the list still cannot grant themselves the right; that separation is the whole
point, and it only holds where the approvals path is out of the agent's reach.

Anchor semantics (Marveen msg 17900, 5+1 conditions):
  1. the hash is computed from the SAME extraction the copy gate audits
     (email_extract.collect_email_envelope -- single implementation);
  2. an approval is ONE-SHOT: consumed atomically on allow;
  3. a TIME WINDOW (~30 min from approval) bounds the hash match;
  4. FAIL-CLOSED: unreadable letter, unrecoverable recipient, missing config,
     or unreachable approvals DB all DENY -- "cannot decide" never means
     "allowed";
  5. the deny message hands the agent the exact hash + a readable summary, so
     the approval's action_description is human-readable and the resend can
     only succeed with byte-identical content.

graph-forward (Brainy 2958): the Graph CLI's `forward` has its own rules, which
hold at EVERY level, before the level is read: one simple command, one plain
@fireeng.hu recipient, no cc/bcc/attachment/HTML, exactly one comment source
(inline, or a file pinned by its sha256), and the regex and shlex readings of
every value must agree (email_extract.parse_forward_command). After that the
usual level / standing / anchor flow decides; the anchor also covers the
forwarded message's id and subject.

graph-forward r3 (Brainy 3092, 3094): the rules above are one verb of a WHITELIST that
covers every Bash command mentioning graph-mail (email_extract.classify_graph_mail).
It runs FIRST, before is_send_invocation and before any level, standing-list or
approval branch: a command it cannot prove simple (operator, substitution, newline,
wrapper, any head but the strict CLI form or one of cat grep head tail wc ls) is a deny
at every level; a read (list, show, verify, cat/grep/...) exits 0; a send or a forward
goes on to the level, standing and anchor flow below. If the extractor does not load and
the command mentions graph-mail, the answer is a deny.

cli-send-enforce (card efa58ad2): the decision lives in authorize(env, mode, ...), which
the Graph CLI's authorizer (email_send_authorize.py) calls too. For a command that
mentions graph-mail (any case) this hook only PEEKS (mode "peek": nothing consumed, no
standing trace): the CLI is the one consumer, at the moment of sending. Every other send
path (MCP send_email, connectors, other Bash senders) still consumes here, as before.
find_and_consume() consumes under BEGIN IMMEDIATE and fills consumed_by/consumed_ref and
approval_events where the schema has them.

Exit codes (PreToolUse contract): 0 = allow, 2 = block. A crash must never
exit 1 (non-blocking) -- the __main__ net converts it to 2 on send paths.
The net only covers main(), so only the standard library loads at module
level (HOOKDEPLOAD1008): the two repo dependencies, email_extract.py and
outgoing-copy-gate.py, are loaded where they are first needed, and a load
failure is a deny that names the file. A syntax error in THIS file, or a
broken interpreter, still exits 1 before any of it runs; only the hook
command that starts the file can catch that.
EVERY malformed input (unparseable stdin included) blocks: unlike the copy
gate, which audits and stays alive on harness faults, this gate authorizes,
so "cannot decide" is always a deny.
"""
import email.utils
import hashlib
import importlib.util
import json
import os
import re
import sqlite3
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(os.path.dirname(_HERE))
STORE_DIR = os.environ.get("EMAIL_APPROVAL_GATE_STORE",
                           os.path.join(_ROOT, "store"))
DB_PATH = os.path.join(STORE_DIR, "claudeclaw.db")
CONFIG_PATH = os.path.join(STORE_DIR, "autonomy-config.json")
# EMAILALLANDOCIMZETT926: a standing recipient list, consulted at level 2 ONLY.
# The owner asked for one address (his own) to receive notifications without a
# per-letter approval, WITHOUT widening the gate to every recipient -- which is
# what raising the level to 3 would do, because the level knows nothing about
# who the letter goes to.
STANDING_PATH = os.path.join(STORE_DIR, "email-standing-recipients.json")


def _window_from_env():
    """(seconds, error). HOOKDEPLOAD1008: a non-integer override used to
    raise at module load, before the __main__ net: exit 1, which PreToolUse
    treats as NON-blocking. The error is kept here, and the send path denies
    with it."""
    raw = os.environ.get("EMAIL_APPROVAL_WINDOW_S", "1800")
    try:
        return int(raw), None
    except ValueError:
        return None, f"EMAIL_APPROVAL_WINDOW_S={raw!r} nem egesz szam"


# ~30 minutes from approval (resolved_at) to send; env override is for tests.
WINDOW_S, _WINDOW_ERR = _window_from_env()

# GMAILCONNECTOR914: the claude.ai Gmail connector's send-shaped tools carry
# neither word (mcp__claude_ai_Gmail__send_message / reply / forward), so the
# gate exited 0 on them and an unapproved connector send was never denied.
_LEGACY_SEND_TOOL = re.compile(r"send_email|manage_email|gmail__(reply|reply_all|send_message|forward)$", re.I)


class _SendToolMatcher:
    """The send-tool test: the name pattern above, then the action classifier.

    graph-forward N1b (spec G1-G6): a send under a name the pattern does not
    list (mcp__gmail-v2__v2_send_draft, __v2_reply_all, __replyAll) reached
    this hook through the "[Gg]mail" matcher and left with exit 0, unapproved.
    email_extract.mail_tool_action reads the OPERATION instead of the name.
    The pattern is asked FIRST and is unchanged, so every name it matched keeps
    its verdict byte for byte (golden). Kept as an object with .search(tool):
    scripts/approval-envelope.py (pinned, 345f34e2) calls gate._SEND_TOOL.search.

    Only an MCP tool name loads the extractor, from main() where the deny net
    covers it (HOOKDEPLOAD1008); Bash and the built-in tools never do. A module
    that does not load (or predates the classifier) makes an unlisted MCP tool
    a send: fail-closed, and at level 2 the extractor load then denies naming
    the broken file."""

    def search(self, tool):
        hit = _LEGACY_SEND_TOOL.search(tool)
        if hit:
            return hit
        if str(tool)[:5].lower() != "mcp__":
            return None
        try:
            sys.path.insert(0, _HERE)
            from email_extract import mail_tool_action
        except Exception:  # noqa: BLE001 -- SyntaxError, ImportError, anything: fail-closed
            return True
        return True if mail_tool_action(tool) == "send" else None


_SEND_TOOL = _SendToolMatcher()

# manage_email is a MULTIPLEXER, not a send tool: the same MCP tool searches the
# mailbox, reads a thread, writes a draft AND sends. Scoping this gate on the
# tool NAME alone therefore denies reading the inbox whenever email_send sits at
# level 1 -- measured on a live install 2026-09-04, where `operation=search` and
# `operation=draft` were both refused with "a kuldes tiltott". That is not the
# gate this is meant to be: a draft-only workflow REQUIRES reading and drafting,
# and the level exists to stop the SEND.
#
# So manage_email is in scope only for the calls that actually put a letter on
# the wire: a send operation WITHOUT an explicit draft:true. Anything else
# passes, drafts included (MANAGEDRAFT905). Fail-closed on doubt: a missing or
# unreadable operation counts as a send, because that is the case where we
# cannot prove it is not one. `send_email` needs no such test -- it only sends.
_MULTIPLEX_TOOL = re.compile(r"manage_email", re.I)
_MANAGE_EMAIL_SEND_OPS = {"send", "reply", "reply_all", "replyall", "forward"}


def _is_explicit_draft(tool_input: dict) -> bool:
    """Did the call EXPLICITLY ask for a draft? Only a literal true (bool) or the
    exact string "true" counts; everything else is treated as a send.

    Deliberately the SAME strict test as the sibling gate
    (scripts/email-send-gate.mjs: `draft === true || draft === 'true'`), so a
    call cannot be a draft for one gate and a send for the other. Anything
    fuzzier ("True", "yes", 1) stays a send: fail-closed."""
    draft = tool_input.get("draft")
    return draft is True or draft == "true"


def manage_email_is_send(tool_input: dict) -> bool:
    """Is this manage_email call a send? Unreadable operation -> True (closed).

    MANAGEDRAFT905: the send OPERATIONS are also the only way to write a
    THREADED draft with this MCP tool -- `{"operation":"reply","draft":true}`
    is the exact call the sibling gate (scripts/email-send-gate.mjs) sends the
    agent back to write, and which it lets through on `draft === true`. Keying
    on the operation alone therefore denied the draft-only workflow itself at
    level 1: measured on the live install 2026-09-04, a reply draft to a
    customer thread was refused with "a kuldes tiltott", and the only way
    around it would have been an untreaded new letter -- the very thing the
    reply-as-new gate stops. A draft puts nothing on the wire; the level exists
    to stop the SEND. Fail-closed stays: only an explicit draft:true passes,
    a missing/ambiguous flag is a send.
    """
    op = tool_input.get("operation")
    if not isinstance(op, str) or not op.strip():
        return True
    if op.strip().lower().replace("-", "_") not in _MANAGE_EMAIL_SEND_OPS:
        return False
    return not _is_explicit_draft(tool_input)


def _load_is_send_invocation():
    """Import is_send_invocation from outgoing-copy-gate.py (dashed filename,
    so importlib by path). Single implementation: the same classifier that
    decides what the copy gate audits decides what this gate levels.

    HOOKDEPLOAD1008: a load failure here was already a deny (the __main__ net), but
    its message told the agent to make the CALL checkable, and no rewrite of a
    command helps when the classifier itself does not load. Without it no Bash
    call can be told apart from a send, so every one is refused until the
    module loads again; the deny names the file to repair."""
    try:
        spec = importlib.util.spec_from_file_location(
            "outgoing_copy_gate", os.path.join(_HERE, "outgoing-copy-gate.py"))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod.is_send_invocation
    except Exception as exc:  # noqa: BLE001 -- SyntaxError, missing file, anything: fail-closed
        deny("A kapu fuggosege (scripts/hooks/outgoing-copy-gate.py) nem toltheto be "
             f"({exc!r}) -- fail-closed: nem dontheto el, hogy egy Bash-hivas levelet "
             "kuld-e, ezert minden Bash-hivas tiltva, amig a modul nem javul. A javitas "
             "fajl-szerkeszto eszkozzel mehet: ez a kapu csak a Bash- es a levelezo "
             "eszkozokon fut.")


def default_paths():
    """The gate's own file locations (store dir from the env override or the
    repo root). The CLI authorizer (email_send_authorize.py) never uses this:
    it passes explicit paths derived from its own location, so no env variable
    can point the decision at a different DB."""
    return {"db": DB_PATH, "config": CONFIG_PATH, "standing": STANDING_PATH,
            "log": STANDING_LOG, "store": STORE_DIR}


def read_email_level(config_path=None, unreadable_level=2):
    """Return (level, note). Missing category / unreadable config -> level 2:
    fail-closed but recoverable through an approval, instead of a hard lockout
    on an install whose config never listed the category.

    unreadable_level: the CLI authorizer passes 1 -- a config it cannot read
    must never let a letter out (a missing CATEGORY in a readable config is
    still 2, as for the hook)."""
    try:
        with open(config_path or CONFIG_PATH, encoding="utf-8") as fh:
            cfg = json.load(fh)
        for cat in cfg.get("categories") or []:
            if cat.get("key") == "email_send":
                level = int(cat.get("level"))
                mx = cat.get("maxLevel")
                if isinstance(mx, int):
                    level = min(level, mx)
                return max(1, min(3, level)), None
        return 2, "az email_send kategoria hianyzik az autonomy-configbol -> level 2 (fail-closed)"
    except Exception as exc:  # noqa: BLE001 -- unreadable config is a fail-closed input
        return (unreadable_level,
                f"az autonomy-config nem olvashato ({exc!r}) -> level {unreadable_level} (fail-closed)")


def read_standing(path=None):
    """Return (addresses, note). A MISSING file means no standing rights, which
    is the normal state and not a fault. A CORRUPT or wrongly shaped file also
    yields no rights -- fail-closed -- but returns a note, because an empty set
    from a broken file looks exactly like an empty set from no file, and that is
    the silent failure this gate cannot afford.

    Accepted shapes: {"recipients": [...]} or a bare list. Each entry is either
    an address string or {"address": ..., "note": ...}; the note is for the
    human reading the file, the gate ignores it."""
    path = path or STANDING_PATH
    if not os.path.exists(path):
        return set(), None
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except Exception as exc:  # noqa: BLE001 -- unreadable list grants nothing
        return set(), (f"az allando cimzett-lista nem olvashato ({exc!r}) -> "
                       "nincs allando jog (fail-closed)")
    raw = data.get("recipients") if isinstance(data, dict) else data
    if not isinstance(raw, list):
        return set(), ("az allando cimzett-lista alakja nem lista -> nincs "
                       "allando jog (fail-closed)")
    out = set()
    for item in raw:
        addr = item.get("address") if isinstance(item, dict) else item
        if not isinstance(addr, str):
            continue
        _, parsed = email.utils.parseaddr(addr.strip())
        parsed = parsed.strip().lower()
        if "@" in parsed:
            out.add(parsed)
    return out, None


def standing_match(env: dict, standing):
    """The address this letter may be sent to WITHOUT an approval, or None.

    Deliberately narrow, because this is the one path that authorises without a
    human in the loop for THIS letter:
      - exactly ONE recipient resolves out of `to`, and it is on the list;
      - cc and bcc are empty.
    The extractor keeps recipients RAW and does NOT split them, so a single
    `to` entry can carry several comma-joined addresses; getaddresses expands
    that, and the count is taken AFTER expansion. Anything that does not parse
    to exactly one known address falls through to the approval path -- never to
    an allow."""
    if not standing:
        return None
    for field in ("cc", "bcc"):
        if any(str(v).strip() for v in (env.get(field) or [])):
            return None
    addrs = [a.strip().lower()
             for _, a in email.utils.getaddresses([str(v) for v in (env.get("to") or [])])
             if a and a.strip()]
    if len(addrs) != 1:
        return None
    return addrs[0] if addrs[0] in standing else None


# --- EMAILALLANDOCIMZETT926 / SZAMONKERHETOSEG ----------------------------
# The standing list is the ONLY path on this gate that puts a letter on the
# wire without a human deciding on THAT letter. Its entire accountability is
# therefore the trace it leaves, and the trace has to reach the OWNER -- a
# systemMessage is read by the very process this gate exists to constrain, so
# on its own it is not a record, it is a receipt handed to the sender.
# Every approval-free send is recorded twice:
#   - locally, in an append-only log next to the list (last-resort record);
#   - in the dashboard's daily log, which is where the owner actually reads.
# The two failure modes are handled DIFFERENTLY, on purpose:
#   - a failed LOCAL append DENIES the send. It is a file append into the same
#     directory the gate just read the list from; if that cannot be done, the
#     send cannot be recorded at all, and an unrecordable approval-free send is
#     precisely the invisible hole this list would otherwise open.
#   - a failed DASHBOARD post does NOT deny. The owner's own notifications must
#     not hinge on the dashboard being up. Instead the local line says in words
#     that the owner was not reached, and so does the systemMessage, so the gap
#     is itself on the record rather than being the absence of one.
STANDING_LOG = os.path.join(STORE_DIR, "email-standing-sends.log")


def _install_setting(key: str, default: str) -> str:
    """Env first, then the install .env, then the default. Never an
    install-specific hardcode (distribution rule)."""
    v = os.environ.get(key)
    if v and v.strip():
        return v.strip()
    try:
        with open(os.path.join(_ROOT, ".env"), encoding="utf-8") as fh:
            for line in fh:
                if line.startswith(key + "="):
                    val = line.split("=", 1)[1].strip()
                    if val:
                        return val
    except Exception:  # noqa: BLE001 -- a missing .env just means the default
        pass
    return default


def _standing_log_append(line: str, log_path=None) -> None:
    """Append ONE timestamped line. Deliberately lets OSError out: the caller
    turns it into a deny. Local time with offset, never UTC -- same reason as
    the copy gate's log (an entry that cannot be placed in time checks
    nothing)."""
    from datetime import datetime
    stamp = datetime.now().astimezone().strftime("%Y-%m-%dT%H:%M:%S%z")
    with open(log_path or STANDING_LOG, "a", encoding="utf-8") as fh:
        fh.write(f"{stamp} {line}\n")


def _post_daily_log(text: str, store_dir=None):
    """Best-effort daily-log entry on the dashboard. Returns (ok, detail).
    Never raises: its failure is data for the local log, not an exception."""
    import urllib.request
    try:
        with open(os.path.join(store_dir or STORE_DIR, ".dashboard-token"), encoding="utf-8") as fh:
            token = fh.read().strip()
        if not token:
            return False, "ures dashboard-token"
        url = "http://127.0.0.1:%s/api/daily-log" % _install_setting("WEB_PORT", "3420")
        body = json.dumps({"agent_id": _install_setting("MAIN_AGENT_ID", "marveen"),
                           "content": text}, ensure_ascii=False).encode("utf-8")
        req = urllib.request.Request(url, data=body, method="POST", headers={
            "Authorization": "Bearer " + token,
            "Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=4) as resp:
            code = getattr(resp, "status", None) or resp.getcode()
            if 200 <= int(code) < 300:
                return True, "ok"
            return False, f"HTTP {code}"
    except Exception as exc:  # noqa: BLE001 -- the local log carries the failure
        return False, repr(exc)


def standing_trace(addr: str, env: dict, paths=None):
    """Record an approval-free send. Returns None when the owner was reached,
    otherwise the reason he was not -- which the caller puts into the
    systemMessage, so the sending agent cannot believe the owner saw it.

    Raises OSError when the LOCAL append fails; the caller denies on that."""
    paths = paths or default_paths()
    if env.get("forward"):
        return _forward_standing_trace(addr, env, paths)
    from datetime import datetime
    head = env.get("text", "").replace("\n", " ").strip()[:120] or "(nincs szoveg)"
    owner_entry = (
        f"## {datetime.now().astimezone().strftime('%H:%M')} -- Level ment ki "
        "JOVAHAGYAS NELKUL (allando cimzett)\n"
        f"Cimzett: {addr}\n"
        f"Level eleje: {head}\n"
        "Ez a level az allando cimzett-lista alapjan ment ki, per-level jovahagyas "
        "nelkul. Ha erre a cimre nem akarod ezt, vedd ki a cimet a listabol.")
    ok, detail = _post_daily_log(owner_entry, paths["store"])
    _standing_log_append(
        f"allando cimzett, jovahagyas nelkuli kuldes | cimzett={addr} | "
        f"level-eleje={head!r} | gazda-ertesites="
        + ("ok" if ok else f"NEM MENT KI ({detail})"), paths["log"])
    return None if ok else detail


def _comment_facts(env: dict):
    """(source, full sha256, characters, lines) of a forward's comment. The sha256
    is the one the command pinned (file) or of the comment's UTF-8 bytes (inline)."""
    text = env.get("text", "")
    sha = env.get("comment_sha256") or hashlib.sha256(text.encode("utf-8")).hexdigest()
    lines = text.count("\n") + (0 if not text or text.endswith("\n") else 1)
    return env.get("comment_source") or "inline", sha, len(text), lines


def _forward_standing_trace(addr: str, env: dict, paths=None):
    """standing_trace for a forward (spec C7, spec-delta KC5). The gate runs
    BEFORE the CLI, and the CLI can still refuse (subject or hash mismatch), so
    the trace says the forward was ALLOWED, never that a letter went out; the
    CLI's own output is the proof of sending. Same two records and the same
    failure handling as a send."""
    paths = paths or default_paths()
    from datetime import datetime
    fwd = env["forward"]
    src, sha, chars, _lines = _comment_facts(env)
    head = env.get("text", "").replace("\n", " ").strip()[:120] or "(nincs szoveg)"
    owner_entry = (
        f"## {datetime.now().astimezone().strftime('%H:%M')} -- Tovabbitas engedelyezve jovahagyas "
        "nelkul (allando cimzett); a tenyleges kuldest a CLI kimenete igazolja\n"
        f"Cimzett: {addr}\n"
        f"Tovabbitott level: {fwd['subject']} | id: {fwd['message_id'][:16]}...\n"
        f"Komment: komment-forras={src} | komment-sha256={sha} | komment-hossz={chars}\n"
        f"Komment eleje: {head}\n"
        "A kapu a CLI futasa ELOTT ir: ha a CLI utana elutasitotta a hivast (targy- vagy "
        "hash-elteres), level nem ment ki. Ha erre a cimre nem akarod ezt, vedd ki a cimet a listabol.")
    ok, detail = _post_daily_log(owner_entry, paths["store"])
    _standing_log_append(
        "allando cimzett, tovabbitas engedelyezve jovahagyas nelkul; a tenyleges kuldest a CLI "
        f"kimenete igazolja | cimzett={addr} | tovabbitott-targy={fwd['subject']!r} | "
        f"id={fwd['message_id'][:16]}... | komment-forras={src} | komment-sha256={sha} | "
        f"komment-hossz={chars} | komment-eleje={head!r} | gazda-ertesites="
        + ("ok" if ok else f"NEM MENT KI ({detail})"), paths["log"])
    return None if ok else detail

# --- BIRALOI KERES 3: a lista felvetel, nem elesites -----------------------
# The review's strongest ask: an address must not become live merely by being
# written into the list file. The list says WHICH addresses are candidates; a
# one-time, owner-resolved approval says which of them may actually be written
# to without a per-letter decision. Two separate acts, on purpose -- whoever can
# edit the file still cannot grant themselves the right.
#
# This approval is deliberately UNLIKE the per-letter one, and both differences
# are load-bearing:
#   - it is NOT consumed. A standing right that dies on first use is just a
#     per-letter approval wearing a different name.
#   - it is NOT time-windowed. The 30-minute window exists so an approved letter
#     cannot be re-sent days later; a standing recipient is a standing decision,
#     and an expiring one would silently turn every notification into a deny.
# What it IS: the owner's LAST resolved decision about this address. A later
# `rejected` row therefore revokes the right without anyone touching the file,
# which is the only revocation path that works when the file is not writable by
# the person who wants the right gone.
STANDING_CATEGORY = "email_standing_recipient"


def standing_anchor(addr: str) -> str:
    """sha256 over the NORMALISED address, matching read_standing's
    normalisation (parseaddr + lowercase), so the owner's approval and the
    list entry can never disagree about what was approved."""
    return hashlib.sha256(addr.strip().lower().encode("utf-8")).hexdigest()


def standing_authorized(addr: str, db_path=None):
    """Return (ok, detail) for THIS address. Raises on any DB problem -- the
    caller turns that into a fail-closed deny, exactly as the per-letter path
    does: "cannot decide" never means "allowed"."""
    db_path = db_path or DB_PATH
    if not os.path.exists(db_path):
        raise OSError(f"approvals DB hianyzik ({db_path})")
    anchor = standing_anchor(addr)
    con = sqlite3.connect(db_path, timeout=5)
    try:
        con.execute("PRAGMA query_only=ON")
        con.execute("PRAGMA busy_timeout=5000")
        # The LAST resolved decision wins, so a later rejection revokes an
        # earlier approval. rowid breaks same-second ties deterministically.
        row = con.execute(
            f"SELECT id, status FROM approvals WHERE category='{STANDING_CATEGORY}'"
            " AND content_hash=? AND resolved_at IS NOT NULL"
            " ORDER BY resolved_at DESC, rowid DESC LIMIT 1", (anchor,)).fetchone()
        if row and row[1] == "approved":
            return True, row[0]
        if row:
            return False, f"a gazda utolso dontese erre a cimre: {row[1]} ({row[0]})"
        pending = con.execute(
            f"SELECT id FROM approvals WHERE category='{STANDING_CATEGORY}'"
            " AND content_hash=? AND status='pending' LIMIT 1", (anchor,)).fetchone()
        if pending:
            return False, f"a cim elesitese FUGGOBEN van a gazdanal ({pending[0]})"
        return False, "ehhez a cimhez nincs gazdai elesites"
    finally:
        con.close()

def content_anchor(env: dict) -> str:
    """sha256 over the envelope: to + cc + bcc + text (subject+body exactly as
    the copy gate audits it, from the shared extractor). Canonical JSON so the
    same letter always yields the same anchor.

    EMAILBCCHORGONY903: bcc joins the canon, but ONLY when non-empty. Two
    reasons, both load-bearing:
      - the gap this closes: without bcc in the hash, to=[owner], cc=[],
        bcc=[stranger] anchored identically to the approved bcc-less letter,
        so one approval could deliver to a recipient nobody approved;
      - the conditional inclusion keeps every bcc-less anchor BYTE-IDENTICAL
        to the pre-fix value, so open approvals (recorded before this change)
        stay valid for the letters they approved. There is no ambiguity to
        exploit: the extractor decides bcc deterministically, and any
        non-empty bcc changes the hash -- fail-closed in the only direction
        that matters.

    EMAILHTMLHORGONY929: the HTML body's and the attachments' sha256 join the
    canon the same way, ONLY when present: an approved letter re-sent with a
    different HTML or an added/changed attachment has another anchor, and a
    plain letter's anchor is unchanged.

    graph-forward (spec C1): a forward adds {"message_id", "subject"} under
    "forward", ONLY on a forward -- the extractor builds that key for nothing
    else -- so every send anchor stays byte-identical (C2), an approval for one
    message cannot forward another (C3), and a send approval with the same to and
    text cannot authorise a forward or the other way round (C4). The envelope's
    comment_* keys are deliberately NOT in this list (spec-delta KC2)."""
    fields = {"to": env["to"], "cc": env["cc"], "text": env["text"]}
    if env.get("bcc"):
        fields["bcc"] = env["bcc"]
    if env.get("html_sha256"):
        fields["html_sha256"] = env["html_sha256"]
    if env.get("attachments"):
        fields["attachments"] = env["attachments"]
    if env.get("forward"):
        fields["forward"] = {"message_id": env["forward"]["message_id"], "subject": env["forward"]["subject"]}
    canon = json.dumps(fields, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canon.encode("utf-8")).hexdigest()


# SQLite's unixepoch() only exists from 3.38 (2022-02). The hook runs under
# the HOST's python3, whose bundled sqlite3 can be older than the one node's
# better-sqlite3 carries -- measured 2026-09-02 on the live install: python
# sqlite3 3.37.2, so every such call raised OperationalError. That is
# not a crash the operator ever sees as a version problem: find_and_consume
# raises, the caller turns any DB fault into a fail-closed deny, and the
# message reads "approvals not available" -- i.e. at level 2 a genuinely
# APPROVED letter is refused and the reason looks like a missing approval.
# CI stayed green throughout because its SQLite is newer, so the suite tested
# every host except the one the gate actually runs on.
# strftime('%s') is present in every SQLite that ships a date function; the
# CAST keeps the comparison integer-to-integer against resolved_at.
NOW_S = "CAST(strftime('%s','now') AS INTEGER)"


def _consume_row(con, row_id, anchor, window, consumer, ref):
    """The one conditional UPDATE that decides a consumption (same conditions
    as src/db.ts consumeApproval). consumed_by / consumed_ref and the
    approval_events row are written when the schema has them: the installs the
    hook tests build carry only consumed_at, a real DB carries all of it."""
    cols = {r[1] for r in con.execute("PRAGMA table_info(approvals)")}
    sets, args = [f"consumed_at={NOW_S}"], []
    if "consumed_by" in cols:
        sets.append("consumed_by=?")
        args.append(consumer)
    if "consumed_ref" in cols:
        sets.append("consumed_ref=?")
        args.append(ref)
    cur = con.execute(
        f"UPDATE approvals SET {', '.join(sets)} WHERE id=? AND category='email_send'"
        " AND status='approved' AND consumed_at IS NULL AND content_hash=?"
        f" AND resolved_at IS NOT NULL AND resolved_at >= {NOW_S}-?",
        args + [row_id, anchor, window])
    if cur.rowcount > 0 and con.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='approval_events'").fetchone():
        con.execute("INSERT INTO approval_events (approval_id, event, reason, actor, ref)"
                    " VALUES (?, 'consumed', NULL, ?, ?)", (row_id, consumer, ref))
    return cur.rowcount > 0


def find_and_consume(anchor: str, db_path=None, window_s=None, consume=True,
                     consumer="email-approval-gate", ref=None):
    """Return (verdict, detail). verdict: 'allowed' (the approval id; consumed
    when consume=True, only looked at when False), 'pending', 'consumed',
    'expired', 'none', 'race'. Raises on any DB problem -- the caller turns
    that into a fail-closed deny.

    consume=True runs SELECT + conditional UPDATE inside BEGIN IMMEDIATE, so
    two processes on one row serialise on the write lock and exactly one gets
    'allowed'. consume=False ("peek") is read-only (query_only): it writes
    nothing, not a consumed_at, not an event."""
    db_path = db_path or DB_PATH
    window = WINDOW_S if window_s is None else window_s
    if not os.path.exists(db_path):
        raise OSError(f"approvals DB hianyzik ({db_path})")
    con = sqlite3.connect(db_path, timeout=5, isolation_level=None)
    try:
        con.execute("PRAGMA busy_timeout=5000")
        if consume:
            con.execute("BEGIN IMMEDIATE")
        else:
            con.execute("PRAGMA query_only=ON")
        try:
            row = con.execute(
                "SELECT id FROM approvals WHERE category='email_send' AND status='approved'"
                f" AND content_hash=? AND consumed_at IS NULL AND resolved_at >= {NOW_S}-?"
                " ORDER BY resolved_at DESC LIMIT 1", (anchor, window)).fetchone()
            result = None
            if row and not consume:
                result = ("allowed", row[0])
            elif row:
                # Atomic one-shot: only the UPDATE that flips NULL->now wins.
                won = _consume_row(con, row[0], anchor, window, consumer, ref)
                result = ("allowed", row[0]) if won else ("race", row[0])
            else:
                for verdict, cond in (
                    ("pending", "status='pending'"),
                    ("consumed", "status='approved' AND consumed_at IS NOT NULL"),
                    ("expired", f"status='approved' AND consumed_at IS NULL AND resolved_at < {NOW_S}-{int(window)}"),
                ):
                    hit = con.execute(
                        f"SELECT id FROM approvals WHERE category='email_send' AND content_hash=? AND {cond} LIMIT 1",
                        (anchor,)).fetchone()
                    if hit:
                        result = (verdict, hit[0])
                        break
                else:
                    result = ("none", None)
            if consume:
                con.execute("COMMIT")
            return result
        except BaseException:
            if consume:
                try:
                    con.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
            raise
    finally:
        con.close()


def _qa_problems(text: str):
    """Hungarian copy QA before any consumption: the same audit() the
    outgoing-copy-gate hook runs, loaded from its file. Returns a list of
    problems; a gate that does not load, or a rules file that exists but is
    unusable, is itself a problem (fail-closed)."""
    try:
        spec = importlib.util.spec_from_file_location(
            "outgoing_copy_gate", os.path.join(_HERE, "outgoing-copy-gate.py"))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        if mod.RULES_STATE == mod.RULES_INVALID:
            return ["a nev-szabaly fajl letezik, de ervenytelen -- fail-closed"]
        return list(mod.audit(text))
    except Exception as exc:  # noqa: BLE001 -- QA that cannot run is a refusal
        return [f"a masolat-ellenorzes (outgoing-copy-gate.py) nem futtathato ({exc!r}) -- fail-closed"]


def authorize(env: dict, mode: str, paths=None, consumer="email-approval-gate", ref=None,
              level_info=None, run_qa=False, unreadable_level=2, window=None,
              bare_recipients=False):
    """The whole decision for one outgoing letter, as data (no exit, no print).
    mode "consume": an approval is spent / a standing send is traced.
    mode "peek": nothing is written -- no consumption, no standing trace.

    Result keys: decision ("allow"|"refuse"), reason, approval_id, anchor,
    standing (the standing recipient or None), detail, note (config notes to
    put in front of a message), owner_gap (None = owner reached), level, exc.
    Reasons: allow -> level3, standing, approval; refuse -> level1, qa_failed,
    config_invalid, unreadable, no_text, no_recipient, standing_not_live,
    trace_unwritable, db_unavailable, none, pending, consumed, expired, race."""
    paths = paths or default_paths()
    window_s, window_err = window if window is not None else (WINDOW_S, _WINDOW_ERR)
    out = {"decision": "refuse", "reason": None, "approval_id": None, "anchor": None,
           "standing": None, "detail": None, "note": "", "owner_gap": None,
           "level": None, "exc": None, "mode": mode}

    def done(decision, reason, **kw):
        out.update(decision=decision, reason=reason, **kw)
        return out

    if bare_recipients:
        # Card efa58ad2 (S2), graph-mail only: the CLI splits --to/--cc on ',' while this
        # gate reads them with getaddresses. Only a bare address list reads the same in
        # both, so anything else is refused here at EVERY level, before any approval or
        # standing recipient is looked at (peek and consume alike).
        try:
            sys.path.insert(0, _HERE)
            from email_extract import bare_address_list_ok
        except Exception as exc:  # noqa: BLE001 -- cannot decide = refuse
            return done("refuse", "bad_request", detail=f"email_extract nem toltheto be ({exc!r})")
        for field in ("to", "cc", "bcc"):
            entries = env.get(field) or []
            if not all(isinstance(v, str) and bare_address_list_ok(v) for v in entries):
                return done("refuse", "bad_request",
                            detail=f"a {field} nem sima cimek vesszovel elvalasztott listaja (S2)")

    level, note = level_info or read_email_level(paths["config"], unreadable_level)
    out["level"] = level
    prefix = f"({note})\n" if note else ""
    if level <= 1:
        return done("refuse", "level1", note=prefix)
    if run_qa:
        problems = _qa_problems(str(env.get("text") or ""))
        if problems:
            return done("refuse", "qa_failed", note=prefix, detail="; ".join(problems))
    if level >= 3:
        return done("allow", "level3", note=prefix)

    if window_err:
        return done("refuse", "config_invalid", note=prefix, detail=window_err)
    if env.get("unreadable_reason"):
        return done("refuse", "unreadable", note=prefix, detail=env["unreadable_reason"])
    if not str(env.get("text") or "").strip():
        return done("refuse", "no_text", note=prefix)
    if not env.get("to"):
        return done("refuse", "no_recipient", note=prefix)

    standing, standing_note = read_standing(paths["standing"])
    if standing_note:
        prefix = prefix + f"({standing_note})\n"
    out["note"] = prefix
    hit = standing_match(env, standing)
    if hit:
        out["standing"] = hit
        try:
            live, live_detail = standing_authorized(hit, paths["db"])
        except Exception as exc:  # noqa: BLE001 -- unreachable DB is fail-closed
            return done("refuse", "db_unavailable", exc=repr(exc))
        if not live:
            return done("refuse", "standing_not_live", detail=live_detail)
        if mode != "consume":
            return done("allow", "standing")
        # The trace is part of the AUTHORISATION: this is the one allow-path with
        # no human deciding on THIS letter, so a send that cannot be recorded
        # does not go out at all.
        try:
            owner_gap = standing_trace(hit, env, paths)
        except OSError as exc:
            return done("refuse", "trace_unwritable", exc=repr(exc))
        return done("allow", "standing", owner_gap=owner_gap)

    anchor = content_anchor(env)
    out["anchor"] = anchor
    try:
        verdict, detail = find_and_consume(anchor, paths["db"], window_s,
                                           consume=(mode == "consume"), consumer=consumer, ref=ref)
    except Exception as exc:  # noqa: BLE001 -- DB unreachable is fail-closed, not no-right
        return done("refuse", "db_unavailable", exc=repr(exc))
    if verdict == "allowed":
        return done("allow", "approval", approval_id=detail)
    return done("refuse", verdict, approval_id=detail)


def deny(msg: str):
    sys.stderr.write(f"EMAIL JOVAHAGYASI KAPU: TILTVA.\n{msg}\n")
    sys.exit(2)


def _load_collect_email_envelope():
    """The extractor, loaded where the gate first needs it (HOOKDEPLOAD1008).
    A module-level import of a broken email_extract.py (a syntax error, a
    conflicted merge) raised before the __main__ net: exit 1, which PreToolUse
    treats as NON-blocking, so the letter went out UNCHECKED. Here any load
    failure is a deny with the reason, and a call that is not a send never
    needs the module."""
    try:
        sys.path.insert(0, _HERE)
        from email_extract import collect_email_envelope
    except Exception as exc:  # noqa: BLE001 -- SyntaxError, ImportError, anything: fail-closed
        deny(f"A kapu fuggosege (scripts/hooks/email_extract.py) nem toltheto be ({exc!r}) "
             "-- fail-closed: a level nem mehet ki, amig a modul nem javul.")
    return collect_email_envelope


# graph-forward (spec B, r3): the graph-mail whitelist holds at EVERY level, so it runs
# FIRST, before is_send_invocation and before the level, the standing list and any
# approval are read. A cheap text test decides whether the extractor is needed at all;
# a command that does not mention graph-mail never loads it here, so every other Bash
# send keeps its old path byte for byte. A mention whose extractor does not load is a
# deny (fail-closed): without it nothing can tell a read from a send.
_GRAPH_MAIL_MENTION = re.compile(r"graph-mail", re.I)


# B4 (Brainy): a script-runner command (tsx node npx bun deno) with a glob, quote or
# expansion character in a script-looking word is refused at every level, whatever the
# script is called (email_extract.script_path_meta_reason, ONE function shared with the
# copy gate). Asked before the grammar and before any level. Fail-closed: when the
# extractor does not load, a script-runner command naming a script file is a deny.
_B4_SCRIPT_EXT = re.compile(r"\.(?:ts|js|mjs|mts|cts|cjs)", re.I)
_B4_RUNNERS = ("tsx", "node", "npx", "bun", "deno")


def _script_path_meta_or_deny(cmd: str) -> None:
    if not _B4_SCRIPT_EXT.search(cmd):
        return
    try:
        sys.path.insert(0, _HERE)
        from email_extract import script_path_meta_reason
    except Exception as exc:  # noqa: BLE001 -- fail-closed, as for the graph-mail mention
        words = [w for w in cmd.split() if not re.match(r"[A-Za-z_][A-Za-z0-9_]*=", w)]
        if words and words[0].rsplit("/", 1)[-1] in _B4_RUNNERS:
            deny(f"A kapu fuggosege (scripts/hooks/email_extract.py) nem toltheto be ({exc!r}) -- fail-closed: "
                 "a parancs scriptet futtat, ezert a modul javitasaig tiltva.")
        return
    reason = script_path_meta_reason(cmd)
    if reason:
        deny("Graph-mail kapu (script-ut): " + reason + ".\n"
             "A szabaly minden szinten all, a szint, az allando cimzett-lista es a jovahagyas elott.")


def _classify_graph_mail_or_deny(cmd: str):
    """(kind, fields): "none", "read", "send" or "forward". A refused command is a deny
    (exit 2) right here, whatever the level, the standing list or an approval would say."""
    if not _GRAPH_MAIL_MENTION.search(cmd):
        return "none", None
    try:
        sys.path.insert(0, _HERE)
        from email_extract import classify_graph_mail, GM_HELP
    except Exception as exc:  # noqa: BLE001 -- SyntaxError, an extractor without the grammar, anything
        deny(f"A kapu fuggosege (scripts/hooks/email_extract.py) nem toltheto be, vagy nem ismeri a "
             f"graph-mail szabalyokat ({exc!r}) -- fail-closed: a parancs a graph-mail-t nevezi meg, ezert "
             "a modul javitasaig tiltva.")
    kind, fields, reason = classify_graph_mail(cmd)
    if kind == "deny":
        deny("Graph-mail kapu (graph-mail parancs): " + str(reason or "a parancs nem egyszeru") + ".\n"
             "A graph-mail szabalyai minden szinten allnak, a szint, az allando cimzett-lista es a "
             "jovahagyas elott: a parancs egyetlen, szigoru alaku parancs lehet.\n" + GM_HELP)
    return kind, fields


def summarize(env: dict) -> str:
    to = ", ".join(env["to"]) or "(nincs)"
    cc = ", ".join(env["cc"]) or "-"
    head = env["text"].replace("\n", " ")[:120]
    if env.get("forward"):
        # spec C6 + spec-delta KC4: the forwarded letter, then the comment's
        # facts and its first 120 characters -- never the whole comment, which
        # can be 3-5 thousand characters and would land in the approval's
        # action_description (dashboard tooltip, Telegram text).
        fwd = env["forward"]
        src, sha, chars, lines = _comment_facts(env)
        shown = "fajl " + str(env.get("comment_file") or "?") if src == "file" else "inline"
        return (f"Cimzett: {to} | CC: {cc} | Tovabbitott level: {fwd['subject']} | "
                f"id: {fwd['message_id'][:16]}... | Komment: {shown} | sha256: {sha[:16]} | "
                f"{chars} karakter, {lines} sor | Szoveg eleje: {head}")
    extra = ""
    if env.get("html_sha256"):
        extra += f" | HTML sha256: {env['html_sha256'][:16]}"
    if env.get("attachments"):
        extra += " | Csatolmany: " + ", ".join(f"{a['name']} ({a['sha256'][:16]})" for a in env["attachments"])
    return f"Cimzett: {to} | CC: {cc} | Szoveg eleje: {head}{extra}"


def main():
    try:
        payload = json.load(sys.stdin)
    except Exception:
        # FAIL-CLOSED, deliberately DIVERGING from the copy gate (Marveen's
        # #1149 review): the copy gate AUDITS and chooses session-liveness on
        # a broken harness payload; this gate AUTHORIZES, and an unreadable
        # payload on a send-matched call must not authorize anything. Loud
        # deny beats a silent fail-open on the one hook whose whole job is
        # the deny. (Costs: a systematically broken harness blocks Bash on
        # the main agent -- visible immediately, which is the point.)
        deny("A hook-payload nem ertelmezheto (nem-JSON stdin) -- fail-closed, "
             "mert ez a kapu ENGEDELYEZ: ertelmezhetetlen hivas nem kaphat engedelyt.")
    tool = str(payload.get("tool_name") or "")
    tool_input = payload.get("tool_input")
    tool_input = tool_input if isinstance(tool_input, dict) else {}

    forward_env = None
    graph_mail = False
    if _SEND_TOOL.search(tool):
        # A multiplexer tool is in scope only when the call is a send; a search,
        # a read or a draft is not what email_send levels.
        if _MULTIPLEX_TOOL.search(tool) and not manage_email_is_send(tool_input):
            sys.exit(0)
    elif tool == "Bash":
        cmd = str(tool_input.get("command") or "")
        # r3: the whitelist FIRST. It denies what it cannot prove simple, lets a read
        # through, and hands a forward over with its envelope already built (its comment
        # file read once). Only a command that does not mention graph-mail reaches the
        # old send classifier, unchanged.
        _script_path_meta_or_deny(cmd)
        gm_kind, gm_fields = _classify_graph_mail_or_deny(cmd)
        # cli-send-enforce: ANY command that mentions graph-mail (any case) is only
        # peeked at below. The Graph CLI authorizes and consumes by itself.
        graph_mail = bool(_GRAPH_MAIL_MENTION.search(cmd))
        if gm_kind == "read":
            sys.exit(0)
        if gm_kind == "forward":
            from email_extract import forward_envelope_from_fields
            forward_env = forward_envelope_from_fields(gm_fields)
        elif gm_kind == "none" and not _load_is_send_invocation()(cmd):
            sys.exit(0)
    else:
        sys.exit(0)

    level, note = read_email_level()
    prefix = f"({note})\n" if note else ""
    if level >= 3:
        sys.exit(0)
    if level <= 1:
        deny(prefix +
             "Az email_send autonomia-szint 1 (csak jelez): a kuldes tiltott.\n"
             "Jelezd a gazdanak inter-agent uzenettel vagy a dashboardon; a szint "
             "emelese a store/autonomy-config.json-ban a gazda dontese.")

    # level 2: CHECK-BEFORE-SEND
    if _WINDOW_ERR:
        deny(prefix + f"A kapu beallitasa hibas ({_WINDOW_ERR}) -- fail-closed, "
             "a level nem mehet ki.")
    # A forward's envelope was already built (and its comment file read) above;
    # reading it again here would only open a second window on the file.
    env = forward_env if forward_env is not None else _load_collect_email_envelope()(tool, tool_input)

    # The decision itself (standing list, anchor, consumption) is authorize(): the
    # same function the Graph CLI's authorizer runs. A graph-mail command is only
    # PEEKED at here (cli-send-enforce): the CLI is the one consumer, at the moment
    # of sending, so this hook neither spends the approval nor writes the standing
    # trace -- either would burn the right before the letter can leave.
    mode = "peek" if graph_mail else "consume"
    res = authorize(env, mode, level_info=(level, note), bare_recipients=graph_mail)
    reason, hit, anchor = res["reason"], res["standing"], res["anchor"]
    prefix = res["note"] or prefix
    detail = res["approval_id"] or res["detail"]

    if reason == "unreadable":
        deny(prefix +
             f"A level nem horgonyozhato: {res['detail']}.\n"
             "Fail-closed: tedd a hivast determinisztikusan olvashatova (inline "
             "--to/--cc/--subject/--body vagy MCP-mezok, shell-valtozo NELKUL), "
             "aztan kuldd ujra.")
    if reason == "no_text":
        deny(prefix + "A hivasbol nem nyerheto ki level-szoveg -- fail-closed.")
    if reason == "no_recipient":
        deny(prefix +
             "A hivasbol nem nyerheto ki cimzett (a horgony a cimzettet is fedi).\n"
             "Hasznalj explicit --to flaget vagy MCP to-mezot, aztan kuldd ujra.")

    if hit:
        # The list makes the address a CANDIDATE; only the owner's one-time
        # approval makes it live (checked inside authorize, before the trace).
        if reason == "db_unavailable":
            deny(prefix +
                 f"email_send level 2: {hit} rajta van az allando cimzett-listan, de az "
                 f"elesitese nem ellenorizheto ({res['exc']}) -- nem-eldontheto, ezert "
                 "fail-closed TILTVA. Ha a dashboard/DB helyreallt, kuldd ujra.")
        if reason == "standing_not_live":
            deny(prefix +
                 f"email_send level 2: {hit} szerepel az allando cimzett-listan, DE NINCS "
                 f"ELESITVE -- {res['detail']}.\n"
                 "Egy cim attol valik elese, hogy a gazda EGYSZER jovahagyta, NEM attol, "
                 "hogy felkerult a listara. A felvetel javaslat, az elesites dontes.\n"
                 f"Cim-horgony (sha256): {standing_anchor(hit)}\n"
                 "Elesites KERESE: POST /api/approvals a sajat agent_id-ddal, "
                 f'category="{STANDING_CATEGORY}", content_hash=a fenti cim-horgony, '
                 "action_description=melyik cimet es miert. A dontes a gazdae: a sajat "
                 "keresedet NE hagyd jova.\n"
                 "Addig ez a level a szokasos, level-enkenti jovahagyasi uton mehet.")
        if reason == "trace_unwritable":
            deny(prefix +
                 f"email_send level 2: {hit} rajta van az allando cimzett-listan, DE a "
                 f"kuldes nem rogzitheto ({res['exc']}) -- fail-closed TILTVA.\n"
                 "A lista az egyetlen ut, amin emberi dontes nelkul megy ki level, ezert "
                 f"a NYOMA a feltetele: ha a {os.path.basename(STANDING_LOG)} nem irhato, "
                 "a jog sem all. Tedd irhatova, aztan kuldd ujra.")
        if graph_mail:
            # Peek: no trace was written. The CLI records the standing send, once,
            # at the moment it sends.
            what = "a tovabbitas" if env.get("forward") else "a kuldes"
            print(json.dumps({"systemMessage":
                f"email-approval-gate: {hit} allando cimzett, {what} jovahagyas nelkul "
                "mehet; a nyomot (napi naplo + helyi log) a CLI irja, a tenyleges kuldeskor. "
                "Minden mas cimzett tovabbra is jovahagyas-koteles."}))
            sys.exit(0)
        owner_gap = res["owner_gap"]
        note = ("A kuldes a gazda napi naplojaba is bekerult."
                if owner_gap is None else
                f"FIGYELEM: a gazdat NEM sikerult ertesiteni ({owner_gap}). A helyi "
                f"{os.path.basename(STANDING_LOG)} rogzitette a kuldest ES az ertesites "
                "hianyat is, de a gazda ettol meg nem tud rola -- ha a level fontos, "
                "szolj neki a csatornan.")
        if env.get("forward"):
            print(json.dumps({"systemMessage":
                f"email-approval-gate: {hit} allando cimzett, a tovabbitas jovahagyas nelkul "
                "mehet; hogy tenyleg kiment-e, azt a CLI kimenete mondja meg (exit 0 es a "
                f"forwarded sor). Minden mas cimzett tovabbra is jovahagyas-koteles. {note}"}))
            sys.exit(0)
        print(json.dumps({"systemMessage":
            f"email-approval-gate: {hit} allando cimzett, a kuldes jovahagyas nelkul "
            f"mehet. Minden mas cimzett tovabbra is jovahagyas-koteles. {note}"}))
        sys.exit(0)

    if reason == "db_unavailable":
        deny(prefix +
             f"A jovahagyasok nem elerheto(k) ({res['exc']}) -- nem-eldontheto, ezert "
             "fail-closed TILTVA. Ha a dashboard/DB helyreallt, kuldd ujra.")

    if reason == "approval":
        if graph_mail:
            print(json.dumps({"systemMessage":
                f"email-approval-gate: jovahagyas {detail} megvan; a CLI egyszer-hasznalatosan "
                "fogyasztja el a kuldes pillanataban, a kuldes mehet."}))
        else:
            print(json.dumps({"systemMessage":
                f"email-approval-gate: jovahagyas {detail} felhasznalva (egyszer-hasznalatos), a kuldes mehet."}))
        sys.exit(0)

    reasons = {
        "pending": f"A(z) {detail} jovahagyas meg FUGGOBEN van -- varj a gazda donteseig, aztan kuldd ujra.",
        "consumed": f"A(z) {detail} jovahagyas MAR FEL LETT HASZNALVA (egyszer-hasznalatos) -- uj jovahagyas kell.",
        "expired": f"A(z) {detail} jovahagyas IDOABLAKA lejart ({WINDOW_S // 60} perc) -- uj jovahagyas kell.",
        "race": "A jovahagyast egy parhuzamos kuldes hasznalta fel -- uj jovahagyas kell.",
        "none": "Ehhez a levelhez NINCS jovahagyas.",
        "config_invalid": f"A kapu beallitasa hibas ({res['detail']}) -- fail-closed, a level nem mehet ki.",
    }
    # cli-send-enforce: a graph-mail letter's approval is spent by the CLI, at the
    # moment of sending, not here. Say so, and say what a Graph failure costs.
    if graph_mail:
        spent = ("A jovahagyast a CLI fogyasztja el, a kuldes pillanataban (egyszer-hasznalatos): "
                 "ha a Graph-hivas utana hibazik, uj jovahagyas kell.\n")
    else:
        spent = ""
    # graph-forward (C6, KC4): a forward's anchor also covers the forwarded
    # message's id and subject. A send's wording stays byte for byte.
    if env.get("forward"):
        covers = "to+cc+komment+a tovabbitott level azonositoja es targya"
    else:
        covers = "to+cc+bcc+targy+torzs"
    deny(prefix +
         f"email_send level 2 (CHECK-BEFORE-SEND). {reasons.get(reason, 'Belso hiba: ' + str(reason))}\n"
         f"Tartalom-horgony (sha256; {covers}): {anchor}\n"
         f"{summarize(env)}\n"
         "Jovahagyas kerese: POST /api/approvals a sajat agent_id-ddal, "
         'category="email_send", content_hash=a fenti horgony, action_description='
         "az olvashato osszefoglalo (cimzett + targy + torzs eleje).\n"
         "Jovahagyas UTAN PONTOSAN ugyanezt a hivast kuldd ujra -- a horgony csak "
         "byte-azonos levelre egyezik, es a jovahagyas egyszer hasznalhato, "
         f"{WINDOW_S // 60} percig ervenyes.\n"
         f"{spent}"
         "Ha ez visszatero, EGY cimzettnek szolo level (tipikusan a gazda sajat "
         "ertesitese), a gazda beallithatja a cimet allando cimzettnek. KERD TOLE "
         "a csatornan es vard meg a valaszat. A beallitast MAGAD NE vegezd el: ez "
         "a kapu sajat korlatja, es egy korlatot nem a korlatozott old fel.")


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as exc:  # noqa: BLE001 -- deliberate fail-closed net
        # Same contract as the copy gate: an unhandled crash would exit 1,
        # which PreToolUse treats as NON-blocking -- the send would run
        # unchecked. On this gate every matched path is a send path, so
        # blocking is always the safe failure mode.
        sys.stderr.write(
            f"EMAIL JOVAHAGYASI KAPU: TILTVA, belso hiba a vizsgalat kozben ({exc!r}).\n"
            "Fail-closed: tedd vizsgalhatova a hivast, aztan kuldd ujra.\n")
        sys.exit(2)
