// Card 0bb35172, node N0: the corpus for the shell-context work of the self-pace gate and the kanban write gate
// (findings 3660cf43 B3 and B4). Strings only: nothing in this file is executed, and nothing that imports it
// spawns a process. The gates are only ever handed these strings (gateDecision / the exported strippers).
//
// Notation: BS = one backslash, NL = LF, Q = one single quote. The three are built with fromCharCode so that no
// escape sequence has to survive a file write.
//
// Row shape:
//   id       stable id (the ids of the reviewer probes are kept: H1-H4, D1, D2, t1-t3, K1, K6, k1-k4)
//   command  the text handed to the gate
//   expect   the verdict the card requires ('DENY' | 'ALLOW')
//   source   where the shape comes from (reviewer probe file of card 3e13973c / 3660cf43, or the measurement)
//   note     (optional) why the row is special
//
// The dangerous words are written in pieces (C, A, T, S) so that a text search of the test sources does not
// confuse a corpus row with a command.
// Rows H1-H4, D1, D2, t1-t3, K1, K6, k1-k4 are taken verbatim from the reviewer probes
// /Volumes/8T/10_LOCAL/Brainy/_ezermester/3e13973c/tmp/be-r1/p1.mjs (H), p3.mjs (D, K), p7.mjs (k), p8.mjs (t).
// The FLEET rows and the kanban ALLOW rows are taken verbatim from tmp/m1.mjs of this card.

export const BS = String.fromCharCode(92)
export const NL = String.fromCharCode(10)
export const Q = String.fromCharCode(39)

const C = 'cron' + 'tab'
const A = 'a' + 't now'
const T = 'tm' + 'ux'
const S = 'send' + '-keys'
const K = '/api/kan' + 'ban/abc/move'
const TOK = '$(cat /Users/gyorgydecsi/marveen/store/.dashboard-token)'

// 1. ATTACK: the shell runs the dangerous line, the gate must DENY. 9 of the 11 are gaps on 78b178b2
// (H1 H2 H3 H4 D1 D2 t1 t2 t3); K1 and K6 are already DENY there and stay as regression guards.
export const ATTACK_CASES = [
  // fake heredoc openers: a comment / a double quote / a single quote holds the `<<TAG`, the shell does not open a
  // heredoc, so the line after it runs
  { id: 'H1', command: `# note <<${Q}E${Q}${NL}${C} -r${NL}E`, expect: 'DENY', source: 'p1' },
  { id: 'H2', command: `echo "<<${Q}E${Q}"${NL}${C} -r${NL}E`, expect: 'DENY', source: 'p1' },
  { id: 'H3', command: `# <<E${NL}${C} -r${NL}E`, expect: 'DENY', source: 'p1' },
  { id: 'H4', command: `echo ${Q}<<E${Q}${NL}${A}${NL}E`, expect: 'DENY', source: 'p1' },
  // fake payload / message flags: the flag sits in a comment, the quote after it is a comment text
  { id: 'D1', command: `# -d ${Q}${NL}${C} -r${NL}# ${Q}`, expect: 'DENY', source: 'p3' },
  { id: 'D2', command: `echo x # git -m ${Q}${NL}${C} -r${NL}# ${Q}`, expect: 'DENY', source: 'p3' },
  // a quoted newline (with or without a continuation) must not cut the dangerous pair into two segments
  { id: 't1', command: `${T} ${Q}a${BS}${NL}${Q} ${S} -t x Enter`, expect: 'DENY', source: 'p8', note: 'regression against the base gate (base: DENY)' },
  { id: 't2', command: `${T} ${Q}a${NL}${Q} ${S} -t x Enter`, expect: 'DENY', source: 'p8' },
  { id: 't3', command: `${T} -L ${Q}a${BS}${NL}${Q} ${S} x`, expect: 'DENY', source: 'p8', note: 'regression against the base gate (base: DENY)' },
  // `case` split by a continuation inside $( ): already DENY on 78b178b2 (exact=false), kept as guards
  { id: 'K1', command: `echo "$(ca${BS}${NL}se a in a) # c ${BS}${NL}${C} -r ;; esac)"`, expect: 'DENY', source: 'p3' },
  { id: 'K6', command: `echo $(ca${BS}${NL}se a in a) # c ${BS}${NL}${C} -r ;; esac)`, expect: 'DENY', source: 'p3' },
]

// The rows whose text has NO backslash-newline (the joined text equals the input): the four strippers must hand
// the text back byte for byte, because the `<<TAG` / `-d '` / `-m '` in them is in a comment or in a quote (E2).
export const STRIPPER_UNCHANGED_IDS = ['H1', 'H2', 'H3', 'H4', 'D1', 'D2']

// Kanban-gate ATTACK rows (the kanban write gate must DENY): k1 and k4 are the gaps on 78b178b2.
export const KANBAN_ATTACK_CASES = [
  { id: 'k1', command: `curl -X POST -H ${Q}X: a${BS}${NL}${Q} http://localhost:3420${K}`, expect: 'DENY', source: 'p7' },
  { id: 'k2', command: `curl -X POST http://localhost:3420/api/kan${BS}${NL}ban/abc/move`, expect: 'DENY', source: 'p7/m1' },
  { id: 'k3', command: `curl -X${BS}${NL}POST http://localhost:3420${K}`, expect: 'DENY', source: 'p7/m1' },
  { id: 'k4', command: `curl -X POST -H ${Q}X: a${NL}${Q} http://localhost:3420${K}`, expect: 'DENY', source: 'p7' },
]

// Kanban-gate ALLOW rows: the six worker duties of the heartbeat runner (kanban-write-gate.test.ts shapes + the
// continuation curl read of the fleet).
export const KANBAN_ALLOW_CASES = [
  { id: 'ka0', command: `sqlite3 store/claudeclaw.db "SELECT id, status, substr(title,1,50) FROM kanban_cards WHERE archived_at IS NULL AND status IN ('in_progress','waiting')"`, expect: 'ALLOW', source: 'kanban-write-gate.test.ts' },
  { id: 'ka1', command: `python3 -c "import json,urllib.request; tok=open('store/.dashboard-token').read().strip(); d=json.load(urllib.request.urlopen(urllib.request.Request('http://localhost:3420/api/kanban/heartbeat-summary', headers={'Authorization':'Bearer '+tok})))"`, expect: 'ALLOW', source: 'kanban-write-gate.test.ts' },
  { id: 'ka2', command: `sqlite3 store/claudeclaw.db "INSERT INTO memories (agent_id, content) VALUES ('heartbeat', 'x')"`, expect: 'ALLOW', source: 'kanban-write-gate.test.ts' },
  { id: 'ka3', command: `curl -s -X POST http://localhost:3420/api/messages -H "Content-Type: application/json" -d '{"from":"heartbeat","to":"marveen","content":"NYERSANYAG: X kartya | waiting | javasolt: UPDATE kanban_cards SET status=done | evidencia msg 123"}'`, expect: 'ALLOW', source: 'kanban-write-gate.test.ts' },
  { id: 'ka4', command: 'date && git status', expect: 'ALLOW', source: 'kanban-write-gate.test.ts' },
  { id: 'ka5', command: `curl -s ${BS}${NL}  -H "Authorization: Bearer ${TOK}" ${BS}${NL}  http://localhost:3420/api/kanban`, expect: 'ALLOW', source: 'm1' },
]

// 2. INTERP: a heredoc whose owner runs the body (bash, python3 -, ssh): the body is code, the anchored scheduler
// check must see it (spec E4, coordinator decision Q1: part of this card). Own describe in the test, so it can be
// lifted out. The same shapes are ALLOW on 78b178b2 and on the base gate (measured).
export const INTERP_CASES = [
  { id: 'gd47', command: `bash <<${Q}EOF${Q}${NL}${C} -r; ${A}${NL}EOF`, expect: 'DENY', source: 'governance-gates.test.ts stripHeredocBodies shapes' },
  { id: 'gd48', command: `python3 - <<${Q}EOF${Q}${NL}${C} -r; ${A}${NL}EOF`, expect: 'DENY', source: 'governance-gates.test.ts stripHeredocBodies shapes' },
  { id: 'gd49', command: `ssh box <<${Q}EOF${Q}${NL}${C} -r; ${A}${NL}EOF`, expect: 'DENY', source: 'governance-gates.test.ts stripHeredocBodies shapes' },
]

// 2b. OPLINE: the rest of the operator line of a heredoc is ordinary shell text (`cat <<'EOF' > f; <cmd>` runs
// <cmd>). The blueprint named this shape as an unmeasured tip; measured on 78b178b2 (stand-in, 2026-11-01): the
// stripper cuts the body group from right after the tag, so it erases the rest of the operator line together with
// the body, and the gate verdict is ALLOW (a gap). Required: DENY, and the stripper keeps the remainder. Own
// export so it can be lifted out like INTERP.
export const OPLINE_CASES = [
  { id: 'OP1', command: `cat <<${Q}EOF${Q} > /dev/null; ${C} -r${NL}body${NL}EOF`, keep: `${C} -r`, expect: 'DENY', source: 'blueprint N0 (spec section 2 tip), measured' },
  { id: 'OP2', command: `git commit -F - <<${Q}EOF${Q} && ${C} -r${NL}a message${NL}EOF`, keep: `${C} -r`, expect: 'DENY', source: 'blueprint N0 (spec section 2 tip), measured' },
]

// 3. FLEET: real multi-line fleet shapes (p6 rows and Q1-Q20 of the measurement). Every row must keep its
// verdict: ALLOW, except Q17 (prose with both trigger words, no separator): DENY on the base gate and on
// 78b178b2, a pre-existing over-block that this card does not touch (spec section 6).
export const FLEET_CASES = [
  { id: 'gh', command: `gh pr create --title "fix: x" ${BS}${NL}  --base develop ${BS}${NL}  --body "$(cat <<${Q}EOF${Q}${NL}## Summary${NL}- a ${BS}${NL}- b${NL}${NL}EOF${NL})"`, expect: 'ALLOW', source: 'p6' },
  { id: 'py', command: `python3 - <<${Q}PY${Q}${NL}x = (1 + ${BS}${NL} 2)${NL}print(x)${NL}PY`, expect: 'ALLOW', source: 'p6' },
  { id: 'curl', command: `curl -s -X POST http://localhost:3420/api/messages ${BS}${NL}  -H "Content-Type: application/json" ${BS}${NL}  -H "Authorization: Bearer ${TOK}" ${BS}${NL}  --data-binary @/tmp/x.json`, expect: 'ALLOW', source: 'p6' },
  { id: 'find', command: `find . -name ${Q}*.log${Q} -exec wc -l {} ${BS}; ${BS}${NL}  -print`, expect: 'ALLOW', source: 'p6' },
  { id: 'awk', command: `awk ${Q}{print $1}${Q} ${BS}${NL}  file.txt`, expect: 'ALLOW', source: 'p6' },
  { id: 'dqsub', command: `echo "$(git rev-parse HEAD)" ${BS}${NL}  "$(date +%s)"`, expect: 'ALLOW', source: 'p6' },
  { id: 'docker', command: `docker run --rm ${BS}${NL}  -v "$PWD:/w" ${BS}${NL}  node:20 node -v`, expect: 'ALLOW', source: 'p6' },
  { id: 'Q1-commit-ml', command: `git commit -m "fix(gate): one lexer${NL}${NL}at the same time the kanban gate follows${NL}Co-Authored-By: x"`, expect: 'ALLOW', source: 'm1' },
  { id: 'Q2-py-c-ml', command: `python3 -c "${NL}import json${NL}print(json.dumps({'a': 1}))${NL}"`, expect: 'ALLOW', source: 'm1' },
  { id: 'Q3-agentmsg-ml', command: `bash /Users/gyorgydecsi/marveen/scripts/agent-msg.sh ezermester brainy "report:${NL}- tests green${NL}- at least 3 rows; see log"`, expect: 'ALLOW', source: 'm1' },
  { id: 'Q4-gh-body-ml', command: `gh pr create --title "x" --body "Summary${NL}- runs at the same time${NL}- batch size"`, expect: 'ALLOW', source: 'm1' },
  { id: 'Q5-curl-d-ml', command: `curl -s -X POST http://localhost:3420/api/messages -H "Content-Type: application/json" -d '{"from":"a","to":"b",${NL}"content":"see /api/schedules; tmux docs"}'`, expect: 'ALLOW', source: 'm1' },
  { id: 'Q6-awk-ml', command: `awk '${NL}/foo/ { n++ }${NL}END { print n }${NL}' file.txt`, expect: 'ALLOW', source: 'm1' },
  { id: 'Q7-comment-apos', command: `# don't touch the live tree${NL}ls -la`, expect: 'ALLOW', source: 'm1' },
  { id: 'Q8-body-hash-quote', command: `cat > /tmp/n.md <<'EOF'${NL}# it's a heading${NL}"quoted" line${NL}EOF${NL}echo ok`, expect: 'ALLOW', source: 'm1' },
  { id: 'Q9-printf-ml', command: `printf '%s${NL}' one two`, expect: 'ALLOW', source: 'm1' },
  { id: 'Q10-jq-ml', command: `python3 -c 'import sys${NL}print(sys.argv)' a b`, expect: 'ALLOW', source: 'm1' },
  { id: 'Q11-sed-ml', command: `sed -n '1,5p${NL}10p' file.txt`, expect: 'ALLOW', source: 'm1' },
  { id: 'Q12-echo-lt', command: `echo "use <<EOF for heredocs"${NL}ls`, expect: 'ALLOW', source: 'm1' },
  { id: 'Q13-gitlog-fmt', command: `git log --format='%h${NL}%s' -3`, expect: 'ALLOW', source: 'm1' },
  { id: 'Q14-tmux-ls-ml', command: `tmux list-sessions -F '#{session_name}${NL}'`, expect: 'ALLOW', source: 'm1' },
  { id: 'Q15-msg-tmux-ml', command: `bash /Users/gyorgydecsi/marveen/scripts/agent-msg.sh ezermester brainy "the tmux pane${NL}was idle; send-keys is blocked by the gate"`, expect: 'ALLOW', source: 'm1', note: 'the naive split cuts it today; the masked pass must not make it a DENY' },
  { id: 'Q17-msg-1line-comma', command: `bash /Users/gyorgydecsi/marveen/scripts/agent-msg.sh ezermester brainy "the ${T} pane was idle, ${S} is blocked by the gate"`, expect: 'DENY', source: 'm1', note: 'pre-existing over-block (spec section 6): DENY on the base gate and on 78b178b2' },
  { id: 'Q18-msg-1line-semi', command: `bash /Users/gyorgydecsi/marveen/scripts/agent-msg.sh ezermester brainy "the ${T} pane was idle; ${S} is blocked by the gate"`, expect: 'ALLOW', source: 'm1', note: 'the naive split cuts it today; the masked pass must not make it a DENY' },
  { id: 'Q19-py-heredoc-at', command: `python3 - <<'PY'${NL}at = 1${NL}batch = [at]${NL}print(batch)${NL}PY`, expect: 'ALLOW', source: 'm1', note: 'an interpreter heredoc body that merely holds the word at: keepRunBodies must not turn it into a DENY' },
  { id: 'Q20-bash-heredoc-ls', command: `bash <<'EOF'${NL}ls -la${NL}git status${NL}EOF`, expect: 'ALLOW', source: 'm1' },
  { id: 'Q16-kanban-get-ml', command: `curl -s -H 'Accept:${NL} application/json' http://localhost:3420/api/kanban`, expect: 'ALLOW', source: 'm1' },
]

// 4. STILL-STRIPS: what the strippers do today and must keep doing on real code-position input (E8 guard
// against over-fixing: a fix that stops stripping would pass every ATTACK row and break the false-positive
// protection). `fn` names the exported stripper; `out` is its exact output (measured on 78b178b2).
export const STRIP_CONTRACT_CASES = [
  { id: 'S1-heredoc', fn: 'stripHeredocBodies', command: `git commit -F - <<${Q}EOF${Q}${NL}at the same time we fixed the parser${NL}EOF`, out: `git commit -F - <<${Q}EOF${Q}${NL}EOF` },
  { id: 'S2-data', fn: 'stripDataPayloads', command: `curl -X POST http://localhost:3420/api/messages -d ${Q}{"to":"dev4","content":"x; tmux y"}${Q}`, out: `curl -X POST http://localhost:3420/api/messages -d ${Q}${Q}` },
  { id: 'S3-commit', fn: 'stripGitCommitMessages', command: `git commit -m "add batch endpoint + ${C} docs"`, out: 'git commit -m ""' },
  { id: 'S4-prose', fn: 'stripProseArguments', command: `gh pr create --body ${Q}runs at midnight, cron style${Q}`, out: `gh pr create --body ${Q}${Q}` },
  // the flag on a LATER code line, after a comment line, is still a flag
  { id: 'S5-after-comment', fn: 'stripGitCommitMessages', command: `# note${NL}git commit -m "x; ${C} y"`, out: `# note${NL}git commit -m ""` },
]

// 5. SHELL-CONTEXT rows for shellContext(src): how many heredocs / quoted tokens the lexer opens. A `<<TAG` in a
// comment or in a quote opens none (the core of B3); a real one opens exactly one.
// `quotes: null` = the row makes no claim about the quote count (a double-quoted token: the blueprint leaves open
// whether `quotes` lists double quotes).
const attack = (id) => ATTACK_CASES.find((r) => r.id === id).command
export const CONTEXT_CASES = [
  { id: 'H1', command: attack('H1'), heredocs: 0, quotes: 0 },
  { id: 'H2', command: attack('H2'), heredocs: 0, quotes: null },
  { id: 'H3', command: attack('H3'), heredocs: 0, quotes: 0 },
  { id: 'H4', command: attack('H4'), heredocs: 0, quotes: 1 },
  { id: 'D1', command: attack('D1'), heredocs: 0, quotes: 0 },
  { id: 'D2', command: attack('D2'), heredocs: 0, quotes: 0 },
  { id: 't2', command: attack('t2'), heredocs: 0, quotes: 1 },
  { id: 'real-heredoc', command: `cat <<${Q}EOF${Q}${NL}x${NL}EOF`, heredocs: 1, quotes: 0 },
  { id: 'real-heredoc-then-code', command: `cat <<${Q}EOF${Q}${NL}x; ${Q}y${NL}EOF${NL}echo ${Q}z${Q}`, heredocs: 1, quotes: 1 },
]
