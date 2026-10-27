#!/usr/bin/env python3
"""Shared email-payload extraction (EMAILKAPU901 PR1).

Single source of truth for recovering the OUTGOING LETTER (recipients, subject,
body) from a send invocation, used by BOTH gates:
  - scripts/hooks/outgoing-copy-gate.py (copy audit: accents, names, em dash)
  - the level-2 email approval gate (PR2): content-hash anchor over
    to + cc + subject + body -- the approval record pins the EXACT letter, and
    a send is allowed only on an exact match.

The extraction boundary (Marveen, msg 17900) is deterministic-or-deny:
  - readable literal (--body "...", < /abs/path, heredoc, MCP fields) -> text
  - anything shell-expanded at run time ($(cat), `...`, $VAR, unresolvable
    path, pipe) -> unreadable_reason, and the CALLER must fail closed.
The SAME boundary applies to recipients (msg 17936): a --to that comes from a
variable is not "approximately right", it is unreadable -> deny. A body+subject
hash alone would let an approved letter be re-sent to a DIFFERENT recipient.

collect_bash_body / collect_mcp_body moved here VERBATIM from
outgoing-copy-gate.py (behavior-neutral; parity proven byte-for-byte against a
golden captured from the pre-move code -- scripts/__tests__/email-extract-parity.test.py).

graph-forward (Brainy 2958, N2): the Graph CLI's `forward` is read here too, by
its own strict reader (parse_forward_command, below), and never by the general
branches. Both gates reach it through the two entry points they already call:
collect_bash_body (copy gate: the comment is the text it audits) and
collect_email_envelope (approval gate: the envelope gains a `forward` field).

graph-forward r3 (Brainy 3092, 3094): every Bash command that mentions graph-mail is
classified FIRST by classify_graph_mail, a whitelist grammar (see the section below).
Both gates call it before any send classifier, level, standing-list or approval branch;
a command it cannot prove simple is denied at every level. The old heuristics that
guessed what a shell would make of such a command are gone.
"""
import hashlib
import json
import os
import re

def collect_bash_body(cmd: str):
    """Return (text, unreadable_reason). text is '' when nothing was recovered."""
    # graph-forward (spec-delta KD2, r3): a command that mentions graph-mail is read by
    # the whitelist grammar and by NO general branch below -- they would take other
    # parts of the command (a `<` path, an @file, the lax --body-file of the wget form)
    # for the letter. A forward's text is the comment only: the forwarded subject is
    # third-party (B6). A send's text is its subject and body, in command order, the
    # body from the strict outbox reader when it comes from a file.
    kind, fields, why = classify_graph_mail(cmd)
    if kind == "forward":
        return (fields["comment"], None)
    if kind == "send":
        return _graph_send_text(fields)
    if kind == "deny":
        return ("", why)
    parts = []
    for m in re.finditer(r"--(?:body|subject)[= ]+(\"([^\"]*)\"|'([^']*)'|(\S+))", cmd):
        val = m.group(2) or m.group(3) or m.group(4) or ""
        # A shell-expanded --body ($(cat f), `cat f`, $VAR) reaches this hook
        # UNEXPANDED: what we would audit is the literal command text, not the
        # letter. That is worse than useless -- it fires on words that happen to
        # sit in the PATH while the real copy goes uninspected. Measured
        # 2026-08-11 on a live customer letter: `--body "$(cat .../hidli_zaro_
        # level.txt)"` blocked on "level" from the FILENAME, and the letter
        # itself was never read. Same fail-closed rule as the `<` branch below.
        if re.search(r"\$\(|`|\$\{?\w", val):
            return ("\n".join(parts),
                    "a --body shell-behelyettesitest tartalmaz, amit a hook nem old fel "
                    f"({val[:60]}...) -- igy a parancs szoveget vizsgalnam, nem a levelet")
        parts.append(val)
    # heredoc payloads sit inline in the command string
    for m in re.finditer(r"<<-?\s*'?(\w+)'?\n(.*?)\n\1", cmd, re.S):
        parts.append(m.group(2))
    # A single `<` only. Without the lookarounds a heredoc (`<<'EOF'`) matches
    # here and the quoted delimiter is taken for a filename -- caught by the
    # first live probe of this gate, which blocked with "'EOF': No such file".
    # `(?<![<=])`: a `=<` is curl's `-F "name=<file"` (read by the file-body
    # forms below), not a shell redirect; the quoted form would otherwise be
    # taken as a redirect to a path ending in the closing quote.
    redirect = re.search(r"(?<![<=])<(?!<)\s*([^\s|;&<>]+)", cmd)
    if redirect:
        raw = redirect.group(1)
        path = os.path.expandvars(os.path.expanduser(raw))
        if "$" in path:
            return ("\n".join(parts), f"a torzs egy fel nem oldhato utvonalrol jon ({raw})")
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                parts.append(fh.read())
        except OSError as exc:
            return ("\n".join(parts), f"a torzs-fajl nem olvashato ({path}: {exc})")
    # GATEBINVAK916: curl's `@file` payload (-d/--data/--data-binary/--json/
    # --data-urlencode @path). Before this branch the body of such a call was
    # never read: on the Resend path that made every @file letter -- clean ones
    # too -- fail closed with the generic "no inspectable text" reason, and the
    # real content was never audited. --data-raw is deliberately NOT here: it
    # sends a literal "@path", it reads no file.
    # Every curl/wget shape that sends a FILE as the body, each with its own
    # label: an unreadable one then says WHICH shape failed, instead of the
    # generic "no inspectable text" that this change exists to retire
    # (Marveen's #1507 review: `--data-urlencode name@file` LOOKED handled --
    # the flag was in the @ regex -- but the name@ form never matched).
    for label, rx in _FILE_BODY_FORMS:
        for m in rx.finditer(cmd):
            ref = m.group(1)
            if ref in ("-", "."):
                # stdin: a heredoc is already in `parts`; a pipe is not readable.
                if not parts:
                    return ("", f"a torzs stdin-rol jon ({label} {ref}), heredoc nelkul -- a hook nem latja")
                continue
            text, reason = _read_body_file(ref, label)
            if reason:
                return ("\n".join(parts), reason)
            parts.append(text)
    if not parts and re.search(r"\|\s*(python3?|node|tsx)?[^|]*send", cmd):
        return ("", "a torzs egy pipe-bol jon, a hook nem latja")
    return ("\n".join(parts), None)


# GATEBINVAK916: the file-body shapes. Each flag must stand alone (leading
# space or start), so an address like x@y.hu or an @ inside a quoted payload is
# never taken for a file. Measured list (Marveen's #1507 review, against the
# gate's own _CURL_BODY_OPTS): the six @-flags, plus the five shapes that also
# send a FILE but were not read: --data-urlencode name@file, -F/--form
# name=@file or name=<file, wget --post-file / --body-file, curl -T.
# NOT here, deliberately: --data-raw (sends a literal "@path", reads nothing)
# and --form-string (literal). The inline literal flags (-d '...',
# --post-data '...') stay outside this branch as before.
_REF = r"['\"]?([^\s'\"|;&<>]+)"
_FILE_BODY_FORMS = (
    ("@", re.compile(
        r"(?:^|\s)(?:-d|--data|--data-binary|--data-ascii|--json|--data-urlencode)"
        r"(?:=|\s+|(?<=-d))['\"]?@([^\s'\"|;&<>]+)")),
    ("--data-urlencode name@", re.compile(
        r"(?:^|\s)--data-urlencode(?:=|\s+)['\"]?[A-Za-z0-9_.-]+@([^\s'\"|;&<>]+)")),
    ("-F/--form name=@|<", re.compile(
        r"(?:^|\s)(?:-F|--form)(?:=|\s+)['\"]?[^\s'\"=]+=[@<]([^\s'\";|&<>]+)")),
    ("wget --post-file/--body-file", re.compile(
        r"(?:^|\s)--(?:post|body)-file(?:=|\s+)" + _REF)),
    ("curl -T/--upload-file", re.compile(
        r"(?:^|\s)(?:-T|--upload-file)(?:=|\s+)" + _REF)),
)


def _read_body_file(ref: str, label: str):
    """(text, unreadable_reason) for a file named as a request body."""
    shown = f"@{ref}" if label == "@" else f"{label} {ref}"  # as the user typed it
    path = os.path.expandvars(os.path.expanduser(ref))
    if "$" in path:
        return ("", f"a torzs egy fel nem oldhato utvonalrol jon ({shown})")
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            data = fh.read()
    except OSError as exc:
        return ("", f"a torzs-fajl ({shown}) nem olvashato ({path}: {exc})")
    return _payload_text(data, ref)


# The prose fields of a JSON payload. A JSON body is audited through these,
# DECODED: the raw file would show "\u00e1" for "a" with an accent, and the
# accent audit would read escape sequences instead of the letter.
_PAYLOAD_TEXT_FIELDS = ("subject", "text", "html", "body", "content", "message")


def _payload_text(data: str, raw: str):
    """(text, unreadable_reason) for a payload read from an @file."""
    try:
        obj = json.loads(data)
    except ValueError:
        return (data, None)  # not JSON: the file IS the text
    if not isinstance(obj, dict):
        return ("", f"a torzs-fajl (@{raw}) JSON, de nem objektum -- a hook nem tudja, mi benne a szoveg")
    got = [str(obj[f]) for f in _PAYLOAD_TEXT_FIELDS if obj.get(f)]
    if not got:
        return ("", f"a torzs-fajl (@{raw}) JSON-jaban nincs ismert szoveg-mezo "
                    f"({', '.join(_PAYLOAD_TEXT_FIELDS)})")
    return ("\n".join(got), None)


def collect_mcp_body(tool_input: dict):
    fields = ("body", "text", "html", "htmlBody", "message", "subject", "content", "forwardText")
    got = [str(tool_input[f]) for f in fields if tool_input.get(f)]
    return "\n".join(got)

# --- recipients (new in PR1; consumed by the PR2 approval gate) --------------
# Same unreadable boundary as the body branches above: shell substitution in a
# recipient value means the hook would hash the COMMAND TEXT while the real
# recipient is decided at run time -- deny, never approximate.
_SHELL_SUBST = re.compile(r"\$\(|`|\$\{?\w")


def collect_bash_recipients(cmd: str):
    """Return (to, cc, bcc, unreadable_reason); recipient lists hold literal
    values. bcc is part of the envelope since EMAILBCCHORGONY903: an anchor
    that ignores it lets an approved letter be re-sent WITH an added --bcc,
    delivering to a recipient nobody approved."""
    to, cc, bcc = [], [], []
    buckets = {"to": to, "cc": cc, "bcc": bcc}
    for m in re.finditer(r"--(to|cc|bcc)[= ]+(\"([^\"]*)\"|'([^']*)'|(\S+))", cmd):
        val = m.group(3) or m.group(4) or m.group(5) or ""
        if _SHELL_SUBST.search(val):
            return (to, cc, bcc,
                    f"a --{m.group(1)} shell-behelyettesitest tartalmaz, amit a hook "
                    f"nem old fel ({val[:60]}...) -- a cimzett futasidoben dol el")
        buckets[m.group(1)].append(val)
    return (to, cc, bcc, None)


def collect_mcp_recipients(tool_input: dict):
    """Return (to, cc, bcc, unreadable_reason). Values are kept RAW (no
    splitting, no lowercasing): the hash anchor needs exact bytes, not address
    semantics. bcc: see collect_bash_recipients (EMAILBCCHORGONY903)."""
    def norm(v):
        if v is None or v == "":
            return []
        if isinstance(v, (list, tuple)):
            return [str(x) for x in v]
        return [str(v)]
    return (norm(tool_input.get("to")), norm(tool_input.get("cc")),
            norm(tool_input.get("bcc")), None)


# --- HTML body and attachments (EMAILHTMLHORGONY929) -------------------------
# A send.py-style command can carry the letter's HTML alternative (--html <file>)
# and attachments (--attach <file>, repeatable). Neither is in `text` (the copy
# gate audits the plain letter), so an anchor over to/cc/bcc/text alone let an
# APPROVED letter go out with a different HTML body or with an added or changed
# attachment: the owner received something other than what was approved. The
# envelope carries their sha256 digests; the approval gate's anchor takes them
# only when present, so every existing anchor stays byte-identical. Same
# unreadable boundary as the body and the recipients: a shell-expanded, empty
# or unreadable path is not approximated -- the caller denies.
#
# The flag is read the way argparse reads it (a tester's finding): it may be quoted
# ("--attach") or an unambiguous prefix (--att, --ht); after "=" the value is
# literal; after whitespace the next token is the value ONLY if it does not start
# with "-", because argparse takes such a token as the next option. So a
# store_true switch of the same name is not a file flag: scripts/support-mail/
# send.py's --html ("... --html --cc x") stays a switch, and the anchor of that
# letter is unchanged. The value is captured in a lookahead, so a token after a
# switch (another --attach) is still seen by the next match. --html-wrap is not
# --html (the flag must end in "=" or whitespace).
_FILE_FLAG_RE = re.compile(
    r"(?:^|\s)([\"']?)--(html|htm|ht|attach|attac|atta|att)\1"
    r"(?=(=|\s+)(?:\"([^\"]*)\"|'([^']*)'|([^\s|;&<>]+)))")


def collect_bash_attachments(cmd: str):
    """Return (html_sha256 or None, attachments, unreadable_reason); attachments
    is a list of {"name", "sha256", "size"} sorted by name then digest, so the
    order of the flags on the command line does not change the anchor."""
    html, atts = None, []
    for m in _FILE_FLAG_RE.finditer(cmd):
        flag = "html" if m.group(2).startswith("ht") else "attach"
        ref = next(g for g in (m.group(4), m.group(5), m.group(6)) if g is not None)
        if m.group(3) != "=" and ref.startswith("-"):
            continue  # the next token is an option: a switch of this name, not a file
        if not ref or _SHELL_SUBST.search(ref):
            return (None, [], f"a --{flag} ures vagy shell-behelyettesitest tartalmaz ({ref[:60]}) "
                              "-- a fajl futasidoben dol el")
        path = os.path.expanduser(ref)
        try:
            with open(path, "rb") as fh:
                data = fh.read()
        except OSError as exc:
            return (None, [], f"a --{flag} fajl nem olvashato ({path}: {exc})")
        digest = hashlib.sha256(data).hexdigest()
        if flag == "html":
            if html is not None:
                return (None, [], "tobb --html egy hivasban -- nem donthato el, melyik a level HTML-je")
            html = digest
        else:
            atts.append({"name": os.path.basename(path), "sha256": digest, "size": len(data)})
    atts.sort(key=lambda a: (a["name"], a["sha256"]))
    return (html, atts, None)


# The claude.ai Gmail connector's send-shaped tools (mcp__claude_ai_Gmail__*):
# no "send_email" in the name, so the name-based test above never saw them.
CONNECTOR_SEND_RE = re.compile(r"gmail__(reply|reply_all|send_message|forward)$", re.I)


# --- The ACTION of a mail tool (graph-forward N1b, spec G1-G5) ----------------
# Every gate recognised mail tools by a fixed list of NAMES (send_email,
# gmail__reply ...), so a send under a name nobody listed walked through:
# mcp__gmail-v2__v2_send_draft and __v2_reply_all reach the hooks (the
# "[Gg]mail" matcher fires on them) and left with exit 0 -- a send with no
# approval, no copy audit and, for a sub-agent, no hard deny. This classifier
# reads the OPERATION instead, whatever the server name or version prefix:
#   - only MCP tools (mcp__<server>__<tool>) are classified; the action is the
#     part after the server, each "__"-separated segment on its own, and the
#     most severe segment wins (the last segment is the spec's reading; a tool
#     named send_message__v2 must not hide behind its suffix);
#   - a segment is split into words: camelCase and acronyms apart, every
#     non-alphanumeric character a separator, lowercase, leading v<n> version
#     words dropped;
#   - a word is a VERB when it is one of the verbs below, alone or glued to a
#     mail noun ("sendmessage", "replyall", "createdraft");
#   - send: a send/resend verb anywhere (get_send_as is an accepted false
#     positive), or the FIRST verb is reply/forward/fwd ("message_reply": the
#     noun before it is not a verb);
#   - draft: the first verb drafts or writes (draft/create/update/save/compose/
#     edit) and there is no send verb;
#   - anything else, and every channel-plugin tool (Telegram/Discord/Slack
#     reply is the owner's channel, never a letter), is None.
# It ADDS to the name patterns, it never replaces them: every gate asks its own
# legacy pattern first and unchanged, so a name it matched keeps its verdict,
# envelope and anchor byte for byte (spec G6, pinned by the golden). The same
# rules live in scripts/email-send-gate.mjs (mailToolAction); the shared
# vectors (scripts/hooks/mail-tool-action-cases.json) bind the two.
_MAIL_SEND_VERBS = frozenset({"send", "resend", "reply", "replyall", "forward", "fwd"})
_MAIL_SEND_ANYWHERE = frozenset({"send", "resend"})
_MAIL_DRAFT_VERBS = frozenset({"draft", "create", "update", "save", "compose", "edit"})
# Verbs that are neither: they only matter as the FIRST verb, so that a later
# reply/forward/draft word does not decide (get_reply_settings, delete_draft).
# A verb missing here is skipped like a noun, which can only move a name
# towards send or draft (the fail-closed side), never away from it.
_MAIL_OTHER_VERBS = frozenset({
    "search", "find", "query", "lookup", "read", "get", "fetch", "list", "show", "view",
    "open", "download", "export", "count", "check", "describe", "inspect", "summarize",
    "delete", "remove", "trash", "untrash", "archive", "unarchive", "move", "copy",
    "mark", "label", "unlabel", "tag", "untag", "star", "unstar", "flag", "unflag",
    "modify", "set", "unset", "add", "watch", "unwatch", "stop", "subscribe",
    "unsubscribe", "block", "unblock", "mute", "unmute", "snooze", "sync", "refresh",
    "import", "upload", "attach", "detach", "parse", "extract", "verify", "validate",
    "ping", "auth", "authenticate", "login", "logout", "revoke", "whoami", "poll",
    "clear", "purge", "restore", "preview", "print", "filter", "sort", "scan",
    "report", "track", "translate", "convert", "render",
})
_MAIL_VERBS = _MAIL_SEND_VERBS | _MAIL_DRAFT_VERBS | _MAIL_OTHER_VERBS
_MAIL_GLUE_NOUNS = ("mail", "email", "emails", "message", "messages", "msg",
                    "draft", "drafts", "all", "now", "reply")
_CHANNEL_PLUGIN_RE = re.compile(r"mcp__plugin_(?:telegram|discord|slack)[-_]")
_VERSION_WORD = re.compile(r"v[0-9]+")


def _mail_verb(word: str):
    """The verb a word stands for ("sendmessage" -> "send"), or None."""
    if word in _MAIL_VERBS:
        return word
    for noun in _MAIL_GLUE_NOUNS:
        if word.endswith(noun) and word[:-len(noun)] in _MAIL_VERBS:
            return word[:-len(noun)]
    return None


def _action_words(segment: str):
    """The words of one action segment, leading version words dropped."""
    s = re.sub(r"[^\x00-\x7f]", "_", segment)  # ASCII only: same lowercasing in python and JS
    s = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", s)
    s = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", s)
    words = [w for w in re.split(r"[^a-z0-9]+", s.lower()) if w]
    while words and _VERSION_WORD.fullmatch(words[0]):
        words.pop(0)
    return words


def _segment_action(segment: str):
    verbs = [v for v in (_mail_verb(w) for w in _action_words(segment)) if v]
    if any(v in _MAIL_SEND_ANYWHERE for v in verbs):
        return "send"
    if verbs and verbs[0] in _MAIL_SEND_VERBS:
        return "send"
    if verbs and verbs[0] in _MAIL_DRAFT_VERBS:
        return "draft"
    return None


def mail_tool_action(tool_name):
    """Return "send", "draft" or None for a tool name (spec G1-G4). Pure, never raises."""
    name = tool_name if isinstance(tool_name, str) else ""
    parts = name.split("__")
    if len(parts) < 3 or parts[0].lower() != "mcp" or _CHANNEL_PLUGIN_RE.match(name):
        return None
    found = {_segment_action(p) for p in parts[2:]}
    if "send" in found:
        return "send"
    if "draft" in found:
        return "draft"
    return None


def _stored_content_reason(tool_name: str, tool_input: dict):
    """Why a send by the action classifier cannot be anchored, or None (G5).
    A send of a stored draft (a draft word in the action, or a draft id in the
    input) puts the DRAFT's content on the wire, which this hook never sees:
    a body in the same call is not what goes out, so it must not be what is
    approved. A call with no text at all has nothing to anchor either."""
    words = [w for seg in tool_name.split("__")[2:] for w in _action_words(seg)]
    names_draft = any(w in ("draft", "drafts") or (w.endswith(("draft", "drafts")) and _mail_verb(w))
                      for w in words)
    keys = {re.sub(r"[^a-z0-9]", "", str(k).lower()) for k in tool_input}
    if names_draft or keys & {"draftid", "draftids"}:
        return ("a kuldendo level egy mentett piszkozat (draftId), a tartalma nincs a hivasban "
                "-- a hook nem latja, mi menne ki")
    if not collect_mcp_body(tool_input).strip():
        return "a level tartalma nincs a hivasban -- a hook nem latja, mi menne ki"
    return None


# --- graph-mail forward (graph-forward N2: spec B, C, D; spec-delta KA-KF) ----
# `npx tsx scripts/graph-mail.ts forward --id I --to T --orig-subject S` plus ONE
# comment source: (a) `--comment C`, or (b) `--comment-file <ROOT>/<NAME>
# --comment-sha256 <hex>`. The general extractor above never read --comment, so
# a forward had no text and no recipient anchor; and a forward is not a send:
# the recipient gets SOMEONE ELSE's letter, with our comment on top. So it gets
# its own reader, and it is deliberately narrow, because the approval gate
# applies its rules at EVERY level, before the level is even read:
#   - one simple command, run exactly as `npx tsx <path>/graph-mail.ts forward`
#     or `tsx <path>/graph-mail.ts forward` (B2). No `$`, backtick or backslash
#     anywhere (B3): with those gone, and with no operator, glob, `#` or
#     newline outside quotes, the only quoting left is plain '...' and "...",
#     where shlex and bash split a command into the same words;
#   - every flag once, as its own token, never --flag=value, nothing unknown and
#     nothing positional; --cc, --bcc, --attach and --html are refused by name
#     (B1, B3); the recipient is one plain @fireeng.hu address (D1);
#   - each flag's value as the extractor's regex reads it must equal the shlex
#     token (B4): where the two parsers disagree, so may bash, and a letter must
#     not go to an address the gate did not look at.
# The reader REFUSES (reason) rather than approximates: the caller denies.
# Since r3 (Brainy 3092) this reader is the `forward` verb of the whitelist grammar
# further down (classify_graph_mail), which both gates ask FIRST; a comment may no
# longer hold a newline, inline or in a file-form command.
FORWARD_COMMENT_FILE = 1  # the CLI's gate probe (E6, KE2) asks for this capability
SEND_BODY_FILE = 1  # the same for `send --body-file` + `--body-sha256` (r3): read by the strict outbox reader
FORWARD_COMMENT_MAX_BYTES = 16384

try:
    _REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
except NameError:  # source exec'd without a file (the parity test's mutation harness)
    _REPO_ROOT = None
_FWD_MENTION_CLI = re.compile(r"graph-mail", re.I)
# Outside quotes, the rest of a forward command may hold only these (plus space,
# TAB and the two quote characters): no operator, redirect, glob, `#`, `~`, `!`,
# brace or newline, and nothing non-ASCII.
_FWD_BARE_OK = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._/@+=,:%-")
_FWD_FLAGS = ("--id", "--to", "--comment", "--comment-file", "--comment-sha256", "--orig-subject")
_FWD_REFUSED_FLAGS = ("--cc", "--bcc", "--attach", "--html")
# B4: the extractor's own regex shape (collect_bash_recipients / collect_bash_body),
# over every flag a forward has or must not have, each flag scanned ON ITS OWN, as
# the extractor scans --to/--cc/--bcc apart from --body/--subject. So a flag
# written inside another value (`--comment 'x --to evil@evil.com'`) is seen
# too, and it is a disagreement with the shlex words, not a hidden extra.
_FWD_REGEX_FLAGS = ("comment-sha256", "comment-file", "orig-subject", "comment", "subject", "body",
                    "attach", "html", "bcc", "cc", "to", "id")
_FWD_REGEX = tuple((f, re.compile(r"--" + re.escape(f) + r"[= ]+(\"([^\"]*)\"|'([^']*)'|(\S+))"))
                   for f in _FWD_REGEX_FLAGS)
_GRAPH_MESSAGE_ID = re.compile(r"[A-Za-z0-9_=+/-]{16,512}\Z")
_SHA256_HEX = re.compile(r"[0-9a-f]{64}\Z")
_OUTBOX_ROOT_RE = re.compile(r"/[A-Za-z0-9._/-]+\Z")
_OUTBOX_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_LOCAL_PART_RE = re.compile(r"[A-Za-z0-9._+-]{1,64}\Z")
_ASCII_DOMAIN_RE = re.compile(r"[A-Za-z.]+\Z")
# KB7: a CLOSED list of code points, the same list in the CLI
# (src/graph-forward-comment-file.ts), written as numbers and not as Unicode
# categories, so the two runtimes' Unicode versions cannot disagree. TAB and LF
# are allowed; CR, the other C0/C1 controls, DEL, zero-width and bidi controls,
# the line/paragraph separators and U+FEFF (a BOM too) are not.
_FWD_FORBIDDEN_RANGES = ((0x00, 0x08), (0x0B, 0x1F), (0x7F, 0x9F), (0x200B, 0x200F),
                         (0x2028, 0x202E), (0x2060, 0x2064), (0x2066, 0x2069), (0xFEFF, 0xFEFF))
_FWD_FORBIDDEN = frozenset(cp for lo, hi in _FWD_FORBIDDEN_RANGES for cp in range(lo, hi + 1))


def forward_recipient_ok(addr) -> bool:
    """Spec D1, the Python twin of isForwardRecipient (src/graph-forward-validate.ts):
    one plain `local@fireeng.hu`, ASCII only; the local part 1-64 of
    [A-Za-z0-9._+-], no leading or trailing dot, no `..`; the domain exactly
    fireeng.hu up to ASCII case. The ASCII test comes BEFORE the case fold, so a
    non-ASCII lookalike cannot fold into the real domain."""
    if not isinstance(addr, str) or addr.count("@") != 1:
        return False
    local, domain = addr.split("@")
    if not _LOCAL_PART_RE.match(local) or local.startswith(".") or local.endswith(".") or ".." in local:
        return False
    return bool(_ASCII_DOMAIN_RE.match(domain)) and domain.lower() == "fireeng.hu"


_BARE_LOCAL_RE = re.compile(r"[A-Za-z0-9._+-]{1,64}\Z")
_BARE_DOMAIN_RE = re.compile(
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\Z")


def bare_address_ok(addr) -> bool:
    """Card efa58ad2 (S2), the twin of isBareAddress (src/graph-forward-validate.ts):
    one `local@domain`, ASCII only; the local part 1-64 of [A-Za-z0-9._+-] without a
    leading or trailing dot or `..`; the domain at least two dot-separated ASCII
    labels, none starting or ending with a hyphen."""
    if not isinstance(addr, str) or len(addr) > 254 or addr.count("@") != 1:
        return False
    local, domain = addr.split("@")
    if not _BARE_LOCAL_RE.match(local) or local.startswith(".") or local.endswith(".") or ".." in local:
        return False
    return bool(_BARE_DOMAIN_RE.match(domain))


def bare_address_list_ok(value) -> bool:
    """The twin of isBareAddressList: a comma-separated list of bare addresses and
    nothing else (no display name, quote, angle bracket, comment, semicolon,
    whitespace or empty element). Shared vectors: graph-bare-recipient-cases.json.
    The CLI splits on ',' and the gate reads the same string with getaddresses; on
    a list that passes this test the two readings are the same set of mailboxes."""
    return isinstance(value, str) and value != "" and all(bare_address_ok(a) for a in value.split(","))


def graph_message_id_ok(mid) -> bool:
    """Spec E2, the twin of isGraphMessageId: 16-512 of [A-Za-z0-9_=+/-]."""
    return isinstance(mid, str) and bool(_GRAPH_MESSAGE_ID.match(mid))


def _forbidden_codepoint(text: str):
    """(1-based position, code point) of the first KB7 character, or None."""
    for i, ch in enumerate(text):
        if ord(ch) in _FWD_FORBIDDEN:
            return i + 1, ord(ch)
    return None


# --- graph-mail whitelist grammar (graph-forward r3, Brainy 3092 and 3094) ---------
# ONE function, classify_graph_mail, which BOTH gates call before any send classifier
# and before any level, standing-list or approval branch. It replaces the heuristics
# of review rounds 1 and 2 (raw-word scans, wrapper recursion, reader lists), which
# tried to guess what a shell would do with a command and were beaten twice (B1, X1).
# A whitelist does not guess: a command that mentions graph-mail passes only when its
# TEXT is provably simple, and everything else is denied at every level.
#
# The decision, in order:
#   1. no "graph-mail" in the text (any case, any path): "none", and the old
#      classifiers decide exactly as before;
#   2. NUL, CR, LF, `$`, backtick or backslash anywhere: deny. With these gone, the
#      two quote kinds have no escape in them, so the quote state is unambiguous and
#      shlex and bash cut a command into the same words;
#   3. outside quotes only plain safe characters (_FWD_BARE_OK, blank, TAB, the
#      quotes): no `# ; & | < > ( ) { } * ? [ ] ~ !`, nothing non-ASCII; an
#      unterminated quote: deny;
#   4. the head word is one of a CLOSED read-only list (cat grep head tail wc ls,
#      Brainy 3094), bare or exactly /bin/<name> or /usr/bin/<name> (B3, any other
#      path is no reader; no alias is resolved): "read". Only the program is trusted here, steps 2 and 3 already
#      removed everything that could chain, redirect or substitute;
#   5. any other head must be exactly `[npx] tsx <path>/graph-mail.ts <verb>` with a
#      bare literal verb (verify, list, show, send, forward), and the rest must fit
#      that verb's closed flag table, each flag once, as its own token, never
#      --flag=value, nothing unknown, nothing positional; for send and forward the
#      regex reading and the shlex reading of every value must be the same;
#   6. anything else: deny.
# Kinds: "none", "read", "send", "forward", "deny". fields: the parsed forward (the
# comment already read, once) or the parsed send (no file is read here: the body file
# is read by collect_bash_body, by the ONE strict reader). reason: why a deny is one,
# never quoting a comment or a body.
_GM_BANNED = (("\x00", "NUL"), ("\r", "CR"), ("\n", "ujsor"),
              ("$", "dollarjel ($: valtozo vagy parancs-behelyettesites)"),
              ("`", "backtick (parancs-behelyettesites)"), ("\\", "backslash"))
_GM_READ_HEADS = frozenset(("cat", "grep", "head", "tail", "wc", "ls"))
_GM_FIRST_WORD = re.compile(r"[ \t]*([A-Za-z0-9._/-]+)(?=[ \t]|\Z)")
# B3 (Brainy): a reader head counts ONLY as the bare name or exactly /bin/<name> or
# /usr/bin/<name>; every other path (./x/grep, x/cat, /opt/bin/grep) is no reader.
_GM_READ_PATHS = frozenset(p + n for n in _GM_READ_HEADS for p in ("/bin/", "/usr/bin/"))
# Q2: the CLI path is exactly scripts/graph-mail.ts or <repo>/scripts/graph-mail.ts, the
# repo derived from this file's own place (never hardcoded).
_GM_CLI_PATHS = frozenset(("scripts/graph-mail.ts",) + (
    (_REPO_ROOT + "/scripts/graph-mail.ts",) if _REPO_ROOT else ()))
_GM_HEAD_RE = re.compile(
    r"^[ \t]*(?:npx[ \t]+)?tsx[ \t]+((?:[A-Za-z0-9._/-]*/)?graph-mail\.ts)[ \t]+"
    r"(verify|list|show|send|forward)(?=[ \t]|\Z)")


def _gm_head(cmd):
    """The strict CLI head match with the Q2 path pin; None for any other path."""
    m = _GM_HEAD_RE.search(cmd)
    return m if m and m.group(1) in _GM_CLI_PATHS else None


_GM_FLAGS = {
    "list": {"--unread": 0, "--top": 1, "--folder": 1},
    "show": {"--id": 1},
    "send": {"--to": 1, "--cc": 1, "--subject": 1, "--body": 1, "--body-file": 1,
             "--body-sha256": 1, "--html": 0, "--attach": 1},
}
_GM_REFUSED = {"send": ("--bcc",)}
# The extractor's own regex shape over the value flags of a send (collect_bash_recipients,
# collect_bash_body, collect_bash_attachments), each flag scanned ON ITS OWN.
_GM_SEND_REGEX_FLAGS = ("body-sha256", "body-file", "body", "subject", "attach", "bcc", "cc", "to")
_GM_SEND_REGEX = tuple((f, re.compile(r"--" + re.escape(f) + r"[= ]+(\"([^\"]*)\"|'([^']*)'|(\S+))"))
                       for f in _GM_SEND_REGEX_FLAGS)
_GM_HTML_SWITCH = re.compile(r"(?:^|[ \t'\"])--html(?=$|[ \t'\"=])")
_GM_TOP_RE = re.compile(r"[0-9]{1,3}\Z")
GM_HELP = ("Helyes alakok (egy sorban, `npx tsx scripts/graph-mail.ts` utan, operator, valtozo es "
           "ujsor nelkul): verify | list [--unread] [--top N] [--folder inbox|sentitems] | show --id <id> | "
           "send --to <cim> --subject '<targy>' --body '<egysoros szoveg>' [--cc <cim>] [--html] "
           "[--attach '<abszolut ut>'] (vagy --body-file <kimeno-mappa>/<nev> --body-sha256 <hex> a --body "
           "helyett) | forward --id <id> --to <cim>@fireeng.hu --comment-file <kimeno-mappa>/<nev> "
           "--comment-sha256 <hex> --orig-subject '<targy>' (vagy --comment '<egysoros szoveg>'). "
           "A graph-mail fajlt csak cat, grep, head, tail, wc es ls olvashatja, operator nelkul.")


def _gm_walk(toks, verb):
    """(vals, order, None) or (None, None, reason): the shlex words of the part after the
    verb, read against the closed flag table of that verb. A switch maps to True."""
    spec = _GM_FLAGS.get(verb, {})
    refused = _GM_REFUSED.get(verb, ())
    vals, order, i = {}, [], 0
    while i < len(toks):
        tok = toks[i]
        if tok in refused:
            return None, None, f"{tok} nem adhato a {verb} parancsnak: a boritek elterne attol, ami kimegy"
        if tok.startswith("--") and "=" in tok:
            return None, None, f"a {tok.split('=', 1)[0]}=ertek alak nem megengedett: a zaszlo es az erteke kulon szo"
        if tok not in spec:
            if tok.startswith("-"):
                return None, None, f"ismeretlen zaszlo a {verb} parancsnal: {tok[:60]!r}"
            return None, None, f"felesleges pozicionalis argumentum a {verb} parancsnal ({len(tok)} karakter)"
        if tok in vals:
            return None, None, f"a {tok} tobbszor szerepel"
        order.append(tok)
        if spec[tok] == 0:
            vals[tok] = True
            i += 1
            continue
        if i + 1 >= len(toks):
            return None, None, f"a {tok} utan nincs ertek"
        if toks[i + 1].startswith("--"):
            return None, None, f"a {tok} erteke helyen egy zaszlo all"
        vals[tok] = toks[i + 1]
        i += 2
    return vals, order, None


def _gm_send_fields(rest, vals, order):
    """(fields, None) or (None, reason) for a send whose flags walked clean."""
    for flag in ("--to", "--subject"):
        if not vals.get(flag):
            return None, f"hianyzik vagy ures a {flag}"
    if "--cc" in vals and not vals["--cc"]:
        return None, "ures a --cc"
    # Card efa58ad2 (S2): the CLI splits on ',', the gate reads with getaddresses; only a
    # bare list reads the same in both, so anything else is a deny, at every level.
    for flag in ("--to", "--cc"):
        if flag in vals and not bare_address_list_ok(vals[flag]):
            return None, (f"a {flag} csak sima cimek vesszovel elvalasztott listaja lehet (a@b.hu,c@d.hu): "
                          "megjelenitett nev, idezojel, <>, zarojel, pontosvesszo, szokoz vagy ures elem nelkul")
    has_body, has_file, has_sha = "--body" in vals, "--body-file" in vals, "--body-sha256" in vals
    if has_body and (has_file or has_sha):
        return None, "egyszerre csak egy torzs-forras lehet: --body VAGY --body-file + --body-sha256"
    if not has_body and not (has_file and has_sha):
        if has_file or has_sha:
            return None, "a --body-file es a --body-sha256 csak egyutt adhato meg"
        return None, "hianyzik a torzs: --body, vagy --body-file + --body-sha256"
    if "--attach" in vals and not vals["--attach"].startswith("/"):
        return None, ("az --attach csak abszolut utat kaphat (a kapu a fajlt a sajat munkakonyvtarabol "
                      "olvasna, a CLI a csatolmany-mappabol: a ketto nem lehet ugyanaz a fajl)")
    # B4 for a send: the extractor's regexes, value for value, against the shlex words.
    by_regex = {}
    for flag, rx in _GM_SEND_REGEX:
        for m in rx.finditer(rest):
            val = m.group(2) if m.group(2) is not None else m.group(3) if m.group(3) is not None else m.group(4)
            by_regex.setdefault("--" + flag, []).append(val)
    by_shlex = {k: [v] for k, v in vals.items() if k in {"--" + f for f in _GM_SEND_REGEX_FLAGS}}
    if by_regex != by_shlex:
        diff = sorted(k for k in set(by_regex) | set(by_shlex) if by_regex.get(k) != by_shlex.get(k))
        return None, ("a parancs ketfele olvasata elter (regex es shlex) itt: " + ", ".join(diff)
                      + " -- egy zaszlo idezojelben, osszefuzott idezet, vagy zaszlo-szoveg egy masik ertekben")
    if len(_GM_HTML_SWITCH.findall(rest)) != (1 if "--html" in vals else 0):
        return None, "a --html kapcsolo szovegben vagy idezetben is szerepel -- a ketfele olvasat elter"
    fields = {"to": vals["--to"], "cc": vals.get("--cc"), "subject": vals["--subject"],
              "html": "--html" in vals, "attach": vals.get("--attach"), "order": order}
    if has_body:
        fields.update(source="inline", body=vals["--body"])
        return fields, None
    sha = vals["--body-sha256"]
    if not _SHA256_HEX.match(sha):
        return None, "a --body-sha256 nem 64 kisbetus hex jel (a shasum -a 256 kimenetenek elso mezoje)"
    root = forward_outbox_root()
    name = forward_comment_name(vals["--body-file"], root)
    if name is None:
        return None, (f"a --body-file nem pontosan <kimeno-mappa>/<nev> alaku (kimeno-mappa: {root}; "
                      "nev: betu vagy szam az elejen, utana betu, szam, . _ -, legfeljebb 128 jel, .. nelkul)")
    fields.update(source="file", body_file=vals["--body-file"], body_sha256=sha, body_file_name=name)
    return fields, None


def classify_graph_mail(cmd):
    """(kind, fields, reason): see the grammar above. Pure apart from the strict forward
    reader's one read of a comment file; never raises on a string."""
    cmd = cmd if isinstance(cmd, str) else ""
    if not _FWD_MENTION_CLI.search(cmd):
        return ("none", None, None)
    for ch, what in _GM_BANNED:
        if ch in cmd:
            return ("deny", None, f"a parancsban {what} all -- a kapu igy nem tudja, mit kap a CLI")
    reason = _unquoted_reason(cmd, "a parancsban")
    if reason:
        return ("deny", None, reason)
    first = _GM_FIRST_WORD.match(cmd)
    if first and (first.group(1) in _GM_READ_HEADS or first.group(1) in _GM_READ_PATHS):
        return ("read", None, None)
    head = _gm_head(cmd)
    if not head:
        return ("deny", None, "a graph-mail-t nevezo parancs csak egyetlen egyszeru, pontosan "
                              "`npx tsx <ut>/graph-mail.ts <ige> ...` vagy `tsx <ut>/graph-mail.ts <ige> ...` "
                              "alaku parancs lehet (az ige csupasz szo), vagy cat, grep, head, tail, wc, ls "
                              "olvasas: elotte nem allhat valtozo-ertekadas, burkolo (env, sudo, bash -c), cd "
                              "vagy masik parancs, es a tsx-nek nem lehet sajat kapcsoloja")
    verb = head.group(2)
    if verb == "forward":
        fwd, reason = parse_forward_command(cmd)
        return ("forward", fwd, None) if fwd is not None else ("deny", None, reason)
    rest = cmd[head.end():]
    toks, reason = _forward_tokens(rest)
    if reason:
        return ("deny", None, reason)
    if verb == "verify":
        return ("read", None, None) if not toks else ("deny", None, "a verify nem fogad argumentumot")
    vals, order, reason = _gm_walk(toks, verb)
    if reason:
        return ("deny", None, reason)
    if verb == "list":
        if "--top" in vals and not _GM_TOP_RE.match(vals["--top"]):
            return ("deny", None, "a --top 1-3 szamjegy lehet")
        if "--folder" in vals and vals["--folder"] not in ("inbox", "sentitems"):
            return ("deny", None, "a --folder inbox vagy sentitems lehet")
        return ("read", None, None)
    if verb == "show":
        if "--id" not in vals:
            return ("deny", None, "hianyzik a --id")
        if not graph_message_id_ok(vals["--id"]):
            return ("deny", None, f"a --id nem Graph-uzenetazonosito alaku ({vals['--id'][:60]!r})")
        return ("read", None, None)
    fields, reason = _gm_send_fields(rest, vals, order)
    return ("send", fields, None) if fields is not None else ("deny", None, reason)


def _graph_send_text(fields):
    """(text, reason) of a classified send: subject and body in the order the flags stand
    in the command, joined by LF -- the same text the general branches built for an inline
    send, so every inline anchor stays what it was. A body file is read by the ONE strict
    outbox reader (never by _read_body_file) and only once."""
    parts = []
    for flag in fields["order"]:
        if flag == "--subject":
            parts.append(fields["subject"])
        elif flag == "--body":
            parts.append(fields["body"])
        elif flag == "--body-file":
            text, reason = read_graph_body_file(fields["body_file"], fields["body_sha256"])
            if reason:
                return ("\n".join(parts), reason)
            parts.append(text)
    return ("\n".join(parts), None)


# --- B4 (Brainy): glob or quote in a script path, whatever the script is called ---------
# The whitelist above keys on the text "graph-mail"; a shell glob or a quoted/assembled
# script path (scripts/graph-mai?.ts, 'scripts/graph-mail.ts', graph-mai{l,}.ts) hides
# the name from it while the shell still runs the CLI. So BOTH gates ask this ONE
# function first, and it keys neither on the verb nor on the name: a command whose head
# is a script runner and that has a script-looking RAW word (split on blanks, no quote
# removal) with a metacharacter below is refused at every level. Fail-closed on purpose;
# beyond Brainy's list: { } $ backtick backslash (a shell-assembled path).
_B4_RUNNERS = frozenset(("tsx", "node", "npx", "bun", "deno"))
_B4_SCRIPT_WORD = re.compile(r"\.(?:ts|js|mjs|mts|cts|cjs)", re.I)
_B4_META = frozenset("*?[]'\"{}$`\\")
_B4_ASSIGN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=")


def script_path_meta_reason(cmd):
    """None, or the reason a script-runner command is refused: a raw argument word that
    looks like a script path holds a glob, quote or expansion character. Pure."""
    if not isinstance(cmd, str):
        return None
    words = cmd.split()
    i = 0
    while i < len(words) and _B4_ASSIGN.match(words[i]):  # VAR=value in front of the head
        i += 1
    if i >= len(words) or words[i].rsplit("/", 1)[-1] not in _B4_RUNNERS:
        return None
    for w in words[i + 1:]:
        if _B4_SCRIPT_WORD.search(w) and any(ch in _B4_META for ch in w):
            return ("a scriptet futtato parancs egyik szavaban (" + w[:60] + ") fajlnev-minta, idezojel vagy "
                    "kiterjesztes-karakter (* ? [ ] ' \" { } $ backtick backslash) van: a kapu igy nem tudja, "
                    "melyik scriptet futtatja a shell")
    return None


def is_forward_invocation(cmd) -> bool:
    """Is this Bash command a forward, or a graph-mail command the whitelist refuses?
    Kept under its old name and call shape (the approval gate and the CLI's E6 probe
    call it); the meaning is now `kind in (forward, deny)`, so a caller that asks "must
    the strict rules judge this?" gets yes for the forward AND for everything the
    grammar cannot prove simple: the refusal reason then comes from the same place."""
    return classify_graph_mail(cmd)[0] in ("forward", "deny")


def forward_outbox_root() -> str:
    """KF1: <repo>/store/mail-outbox, from this file's own place; GRAPH_MAIL_OUTBOX_DIR
    overrides it (tests; the CLI reads the same variable). The content is bound by
    the sha256 in the command, so a moved root cannot change what goes out."""
    root = os.environ.get("GRAPH_MAIL_OUTBOX_DIR")
    if root is None:
        # no known place: "" matches no root pattern, so every file forward is refused
        return os.path.join(_REPO_ROOT, "store", "mail-outbox") if _REPO_ROOT else ""
    return root


def forward_comment_name(path, root: str):
    """KA4: the NAME when `path` is exactly <root>/<NAME>, else None."""
    if not isinstance(path, str) or not _OUTBOX_ROOT_RE.match(root or "") or not path.startswith(root + "/"):
        return None
    name = path[len(root) + 1:]
    if not _OUTBOX_NAME_RE.match(name) or ".." in name:
        return None
    return name


def _read_outbox_file(path, sha256_hex, what, file_flag, hash_flag):
    """KB1-KB10: (text, None) or (None, reason). The ONE reader both gates use, for a forward's
    comment file and (r3) a send's body file alike: `what` names the file in a reason, the two
    flags name the command words. The rules are the same for both, by construction.

    Never blocks and never follows a link: the root is checked with lstat and
    realpath, opened O_DIRECTORY|O_NOFOLLOW and pinned by (dev, ino); the file is
    opened relative to that descriptor with O_NOFOLLOW|O_NONBLOCK, and its fstat
    decides (regular, ours, one link, <= 16 KiB) BEFORE a byte is read, so a FIFO,
    a directory or a link is refused without reading. One read of at most
    16385 bytes; everything after works on those bytes only. The reason never
    carries the content: only hash prefixes, a code point and its position."""
    import stat as _stat
    root = forward_outbox_root()
    if not _OUTBOX_ROOT_RE.match(root):
        return None, f"a kimeno-mappa utja nem megengedett alaku ({root[:120]!r})"
    if not isinstance(sha256_hex, str) or not _SHA256_HEX.match(sha256_hex):
        return None, f"a {hash_flag} nem 64 kisbetus hex jel"
    name = forward_comment_name(path, root)
    if name is None:
        return None, f"a {file_flag} nem pontosan <kimeno-mappa>/<nev> alaku (kimeno-mappa: {root})"
    try:
        st_root = os.lstat(root)
    except FileNotFoundError:
        return None, f"a kimeno-mappa hianyzik ({root}); egyszer letre kell hozni 0700-as joggal"
    except OSError as exc:
        return None, f"a kimeno-mappa nem vizsgalhato ({root}: {exc.strerror or exc})"
    if _stat.S_ISLNK(st_root.st_mode):
        return None, f"a kimeno-mappa symlink ({root})"
    if not _stat.S_ISDIR(st_root.st_mode):
        return None, f"a kimeno-mappa nem konyvtar ({root})"
    if st_root.st_uid != os.geteuid():
        return None, f"a kimeno-mappa nem a futo felhasznaloe ({root})"
    if st_root.st_mode & 0o022:
        return None, f"a kimeno-mappa csoport- vagy mindenki-irhato ({root}, {oct(st_root.st_mode & 0o777)})"
    if os.path.realpath(root) != root:
        return None, f"a kimeno-mappa utjaban symlink van (realpath: {os.path.realpath(root)})"
    if os.open not in os.supports_dir_fd:
        return None, "a Python itt nem tud konyvtar-leirohoz kepest megnyitni (dir_fd) -- fail-closed"
    rootfd = fd = None
    try:
        try:
            rootfd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        except OSError as exc:
            return None, f"a kimeno-mappa nem nyithato meg ({exc.strerror or exc})"
        st_fd = os.fstat(rootfd)
        if (st_fd.st_dev, st_fd.st_ino) != (st_root.st_dev, st_root.st_ino):
            return None, "a kimeno-mappa megvaltozott a vizsgalat kozben"
        try:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=rootfd)
        except FileNotFoundError:
            return None, f"a {what} nem letezik ({name})"
        except OSError as exc:
            return None, f"a {what} nem nyithato meg symlink-kovetes nelkul ({name}: {exc.strerror or exc})"
        st = os.fstat(fd)
        if not _stat.S_ISREG(st.st_mode):
            return None, f"a {what} nem rendes fajl ({name})"
        if st.st_uid != os.geteuid():
            return None, f"a {what} nem a futo felhasznaloe ({name})"
        if st.st_nlink != 1:
            return None, f"a {what}nak tobb hard linkje van ({name}, nlink={st.st_nlink})"
        if st.st_size > FORWARD_COMMENT_MAX_BYTES:
            return None, f"a {what} nagyobb, mint {FORWARD_COMMENT_MAX_BYTES} bajt ({st.st_size})"
        chunks, total = [], 0
        while total <= FORWARD_COMMENT_MAX_BYTES:
            chunk = os.read(fd, FORWARD_COMMENT_MAX_BYTES + 1 - total)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        data = b"".join(chunks)
    finally:
        for d in (fd, rootfd):
            if d is not None:
                os.close(d)
    if len(data) > FORWARD_COMMENT_MAX_BYTES:
        return None, f"a {what} nagyobb, mint {FORWARD_COMMENT_MAX_BYTES} bajt"
    got = hashlib.sha256(data).hexdigest()
    if got != sha256_hex:
        return None, (f"a {what} sha256-ja nem egyezik a {hash_flag} ertekevel "
                      f"(vart {sha256_hex[:16]}..., kapott {got[:16]}...)")
    try:
        text = data.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        return None, f"a {what} nem ervenyes UTF-8 (a(z) {exc.start + 1}. bajtnal)"
    bad = _forbidden_codepoint(text)
    if bad:
        return None, f"tiltott karakter a {what}ban: U+{bad[1]:04X} a(z) {bad[0]}. karakternel"
    if not text.strip():
        return None, f"a {what} ures vagy csak whitespace"
    return text, None


def read_forward_comment_file(path: str, sha256_hex: str):
    """The comment file of a forward (--comment-file + --comment-sha256)."""
    return _read_outbox_file(path, sha256_hex, "komment-fajl", "--comment-file", "--comment-sha256")


def read_graph_body_file(path: str, sha256_hex: str):
    """The body file of a graph-mail send (--body-file + --body-sha256), r3: the SAME reader."""
    return _read_outbox_file(path, sha256_hex, "torzs-fajl", "--body-file", "--body-sha256")


def _unquoted_reason(text: str, where: str):
    """Why `text` is not simple enough, or None. Outside quotes only _FWD_BARE_OK, space
    and TAB may stand, and a quote must be closed. Run AFTER `$`, backtick and backslash
    are refused: the two quote kinds then have no escape in them, so the state machine
    below is exactly the shell's (single quotes literal, double quotes literal too)."""
    q = None
    for i, ch in enumerate(text):
        if q:
            if ch == q:
                q = None
            continue
        if ch in "'\"":
            q = ch
        elif ch not in " \t" and ch not in _FWD_BARE_OK:
            shown = "ujsor" if ch == "\n" else f"U+{ord(ch):04X}" if not ch.isprintable() or ord(ch) > 0x7e else repr(ch)
            return (f"idezojelen kivul nem megengedett karakter ({shown}, a(z) {i + 1}. helyen {where}): "
                    "egyetlen egyszeru parancs lehet, operator, atiranyitas, glob, megjegyzes (#) es ujsor nelkul")
    if q:
        return "lezaratlan idezojel"
    return None


def _forward_tokens(rest: str):
    """(tokens, None) or (None, reason) for the part after the verb. Outside quotes
    only _FWD_BARE_OK, space and TAB may stand; with `$`, backtick and backslash
    already refused, shlex then splits it into the words bash would pass."""
    reason = _unquoted_reason(rest, "a parancs-ige utan")
    if reason:
        return None, reason
    import shlex
    try:
        lex = shlex.shlex(rest, posix=True)
        lex.whitespace_split = True
        lex.commenters = ""
        return list(lex), None
    except ValueError as exc:
        return None, f"a parancs nem bonthato szavakra ({exc})"


def parse_forward_command(cmd: str):
    """(fields, None) or (None, reason) for a forward command (spec B1-B5, KA1-KA5,
    KB via read_forward_comment_file). fields: id, to, subject, comment, source
    ("inline" | "file"), comment_sha256 (of the comment's UTF-8 bytes), comment_file
    (the NAME, file source only). The reason never quotes the comment."""
    for ch, what in _GM_BANNED:  # r3: LF is banned too, a comment is ONE line
        if ch in cmd:
            return None, f"a tovabbito parancsban {what} all -- a kapu igy nem tudja, mit kap a CLI"
    head = _gm_head(cmd)
    if not head or head.group(2) != "forward":
        return None, ("a tovabbitas csak egyetlen egyszeru parancs lehet, pontosan "
                      "`npx tsx <ut>/graph-mail.ts forward ...` vagy `tsx <ut>/graph-mail.ts forward ...` "
                      "alakban: elotte nem allhat valtozo-ertekadas, burkolo (env, sudo, bash -c), cd vagy "
                      "masik parancs, es a tsx-nek nem lehet sajat kapcsoloja")
    toks, reason = _forward_tokens(cmd[head.end():])
    if reason:
        return None, reason
    vals = {}
    i = 0
    while i < len(toks):
        tok = toks[i]
        if tok in _FWD_REFUSED_FLAGS:
            return None, f"{tok} nem adhato tovabbitasnal: egy level egy cimzettnek megy, cc, bcc, csatolmany es HTML nelkul"
        if "=" in tok and tok.startswith("--"):
            return None, f"a {tok.split('=', 1)[0]}=ertek alak nem megengedett: a zaszlo es az erteke kulon szo"
        if tok not in _FWD_FLAGS:
            if tok.startswith("-"):
                return None, f"ismeretlen zaszlo: {tok[:60]!r}"
            return None, f"felesleges pozicionalis argumentum ({len(tok)} karakter)"
        if tok in vals:
            return None, f"a {tok} tobbszor szerepel"
        if i + 1 >= len(toks):
            return None, f"a {tok} utan nincs ertek"
        val = toks[i + 1]
        if val.startswith("--"):
            return None, f"a {tok} erteke helyen egy zaszlo all"
        vals[tok] = val
        i += 2
    # B4: the extractor's regex, value for value, against the shlex words.
    by_regex = {}
    for flag, rx in _FWD_REGEX:
        for m in rx.finditer(cmd[head.end():]):
            val = m.group(2) if m.group(2) is not None else m.group(3) if m.group(3) is not None else m.group(4)
            by_regex.setdefault("--" + flag, []).append(val)
    by_shlex = {k: [v] for k, v in vals.items()}
    if by_regex != by_shlex:
        diff = sorted(k for k in set(by_regex) | set(by_shlex) if by_regex.get(k) != by_shlex.get(k))
        return None, ("a parancs ketfele olvasata elter (regex es shlex) itt: " + ", ".join(diff)
                      + " -- egy zaszlo idezojelben, osszefuzott idezet, vagy zaszlo-szoveg egy masik ertekben")
    for flag in ("--id", "--to", "--orig-subject"):
        if flag not in vals:
            return None, f"hianyzik a {flag}"
    has_inline = "--comment" in vals
    has_file = "--comment-file" in vals
    has_hash = "--comment-sha256" in vals
    if has_inline and (has_file or has_hash):
        return None, "egyszerre csak egy komment-forras lehet: --comment VAGY --comment-file + --comment-sha256"
    if not has_inline and not (has_file and has_hash):
        if has_file or has_hash:
            return None, "a --comment-file es a --comment-sha256 csak egyutt adhato meg"
        return None, "hianyzik a komment: --comment, vagy --comment-file + --comment-sha256"
    if not graph_message_id_ok(vals["--id"]):
        return None, f"a --id nem Graph-uzenetazonosito alaku ({vals['--id'][:60]!r})"
    if not forward_recipient_ok(vals["--to"]):
        return None, (f"a --to nem egyetlen, sima @fireeng.hu cim ({vals['--to'][:80]!r}): "
                      "tovabbitas csak egy @fireeng.hu cimzettnek mehet")
    fields = {"id": vals["--id"], "to": vals["--to"], "subject": vals["--orig-subject"]}
    if has_inline:
        comment = vals["--comment"]
        bad = _forbidden_codepoint(comment)
        if bad:
            return None, f"tiltott karakter a --comment ertekeben: U+{bad[1]:04X} a(z) {bad[0]}. karakternel"
        if not comment.strip():
            return None, "a --comment ures vagy csak whitespace"
        fields.update(comment=comment, source="inline",
                      comment_sha256=hashlib.sha256(comment.encode("utf-8")).hexdigest())
        return fields, None
    sha = vals["--comment-sha256"]
    if not _SHA256_HEX.match(sha):
        return None, "a --comment-sha256 nem 64 kisbetus hex jel (a shasum -a 256 kimenetenek elso mezoje)"
    root = forward_outbox_root()
    name = forward_comment_name(vals["--comment-file"], root)
    if name is None:
        return None, (f"a --comment-file nem pontosan <kimeno-mappa>/<nev> alaku (kimeno-mappa: {root}; "
                      "nev: betu vagy szam az elejen, utana betu, szam, . _ -, legfeljebb 128 jel, .. nelkul)")
    comment, reason = read_forward_comment_file(vals["--comment-file"], sha)
    if reason:
        return None, reason
    fields.update(comment=comment, source="file", comment_sha256=sha, comment_file=name)
    return fields, None


def forward_envelope(cmd: str):
    """The approval gate's envelope for a forward (spec C1, KC1-KC2). The anchor
    covers to, cc, text (the comment) and forward {message_id, subject}; the other
    comment_* keys are for the summary and the trace only -- content_anchor takes
    an explicit field list, so they never reach the hash. A refused forward has
    no `forward` key and carries the reason; the caller denies at every level."""
    fwd, reason = parse_forward_command(cmd)
    if reason:
        return {"to": [], "cc": [], "bcc": [], "text": "", "unreadable_reason": reason}
    return forward_envelope_from_fields(fwd)


def forward_envelope_from_fields(fwd: dict):
    """The envelope of a forward the grammar already parsed (the comment file is read ONCE,
    by classify_graph_mail; a gate that has the fields must not open the file again)."""
    env = {"to": [fwd["to"]], "cc": [], "bcc": [], "text": fwd["comment"], "unreadable_reason": None,
           "forward": {"message_id": fwd["id"], "subject": fwd["subject"]},
           "comment_source": fwd["source"], "comment_sha256": fwd["comment_sha256"]}
    if fwd["source"] == "file":
        env["comment_file"] = fwd["comment_file"]
    return env


def collect_email_envelope(tool_name: str, tool_input: dict):
    """PR2 entry point: one dict for the recipient+content hash anchor (to/cc/bcc/text), built from the
    SAME collectors the copy gate runs (no second extraction implementation).
    Returns {"to", "cc", "bcc", "text", "unreadable_reason"}; text is the combined
    subject+body exactly as the copy gate audits it. On the Bash path the dict
    also carries "html_sha256" and "attachments" when the command names them
    (EMAILHTMLHORGONY929). The CALLER decides policy
    (e.g. an empty recipient list on a send is itself grounds to deny)."""
    html_sha256, attachments = None, []
    if re.search(r"send_email", tool_name or "", re.I) or CONNECTOR_SEND_RE.search(tool_name or ""):
        ti = tool_input if isinstance(tool_input, dict) else {}
        text = collect_mcp_body(ti)
        to, cc, bcc, reason = collect_mcp_recipients(ti)
        # A connector reply/forward addresses the ORIGINAL message: its
        # recipient is fixed by messageId, not by a `to` field, so the id is
        # the recipient anchor (GMAILCONNECTOR914). Same bytes-exact rule as
        # the addresses: an approval for one message cannot answer another.
        if not to and ti.get("messageId"):
            to = [f"messageId:{ti['messageId']}"]
    elif mail_tool_action(tool_name) == "send":
        # graph-forward N1b (G5): a send the NAME patterns above do not know,
        # recognised by its action. Same collectors and the same messageId
        # anchor as the connector branch; the legacy names never reach here,
        # so their envelopes stay byte-identical.
        ti = tool_input if isinstance(tool_input, dict) else {}
        text = collect_mcp_body(ti)
        to, cc, bcc, reason = collect_mcp_recipients(ti)
        if not to and ti.get("messageId"):
            to = [f"messageId:{ti['messageId']}"]
        reason = reason or _stored_content_reason(tool_name, ti)
    elif tool_name == "Bash":
        cmd = str((tool_input or {}).get("command") or "") if isinstance(tool_input, dict) else ""
        kind, fields, why = classify_graph_mail(cmd)
        if kind == "forward":
            return forward_envelope_from_fields(fields)
        if kind == "deny":
            # r3: a command the whitelist refuses has no envelope. (A "read" is no letter, and
            # both gates have exited before they ask for its envelope; it keeps the old
            # extraction below, byte for byte, so the N0 golden of the reads does not move.)
            return {"to": [], "cc": [], "bcc": [], "text": "", "unreadable_reason": why}
        text, reason = collect_bash_body(cmd)
        if not reason:
            to, cc, bcc, reason = collect_bash_recipients(cmd)
        else:
            to, cc, bcc = [], [], []
        if not reason:
            html_sha256, attachments, reason = collect_bash_attachments(cmd)
    else:
        return {"to": [], "cc": [], "bcc": [], "text": "",
                "unreadable_reason": f"nem email-kuldo tool ({tool_name!r})"}
    env = {"to": to, "cc": cc, "bcc": bcc, "text": text, "unreadable_reason": reason}
    if html_sha256:
        env["html_sha256"] = html_sha256
    if attachments:
        env["attachments"] = attachments
    return env
