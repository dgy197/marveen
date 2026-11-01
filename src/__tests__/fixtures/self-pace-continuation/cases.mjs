// Card 3660cf43 (planned under the duplicate id 3e13973c), node N0: the corpus for the self-pace gate's
// backslash-newline handling. Strings only: nothing in this file is executed. The differential shell oracle
// (oracle.mjs) is the only thing that spawns a shell, and only on marker-rewritten text behind a guard.
//
// Notation: BS = one backslash, NL = LF, CRLF = CR LF.
// Row shape:
//   id       stable id (R = reviewer shape, V = variant, B = benign control, X = extra, G = real fleet shape)
//   command  the text handed to the gate
//   oracle   (optional) the same text with its dangerous words already replaced by marker functions, for the
//            rows where the word is split by the continuation itself (cron\<NL>tab): the generic rewrite in
//            oracle.mjs cannot see a word that is not in one piece
//   runs     what a real shell does with the dangerous binary: true / false, or null = the shells disagree or
//            reject the text (then the corpus makes no claim and the differential test skips the claim)
//   expect   the gate verdict the card requires ('DENY' | 'ALLOW')
//   readOnly true: a shell run is expected and still ALLOW (crontab -l is a listing)
//   noOracle a reason string: the row is not run through the oracle at all
// Measured 2026-11-01 on /bin/bash 3.2.57 and /bin/zsh 5.9 (spec.md section 2, tmp/probe.mjs).

export const BS = '\\'
export const NL = '\n'
export const CRLF = '\r\n'

// The 35 shapes of the card's measurement. 13 of the DENY rows are GAPs on the unfixed gate:
// R1, R2, R3, V1, V3, V4, V5, V13, V17, V18, V19, V20, V21 (verified on the 44167c0b branch too).
export const SPEC_CASES = [
  { id: 'R1', command: `echo a${BS}${BS}${NL}crontab -r`, runs: true, expect: 'DENY' },
  { id: 'R2', command: `echo a${BS.repeat(4)}${NL}at now`, runs: true, expect: 'DENY' },
  { id: 'R3', command: `# note ${BS}${NL}crontab -r`, runs: true, expect: 'DENY' },
  { id: 'V1', command: `echo a${BS.repeat(6)}${NL}crontab -r`, runs: true, expect: 'DENY' },
  { id: 'V2', command: `echo a${BS.repeat(3)}${NL}crontab -r`, runs: false, expect: 'ALLOW' },
  { id: 'V3', command: `echo a${BS}${BS}${CRLF}crontab -r`, runs: true, expect: 'DENY' },
  { id: 'V4', command: `echo a${BS}${CRLF}crontab -r`, runs: true, expect: 'DENY' },
  { id: 'V5', command: `ls -la # tail ${BS}${NL}crontab -r`, runs: true, expect: 'DENY' },
  { id: 'V6', command: `echo a#b${BS}${NL}crontab -r`, runs: false, expect: 'ALLOW' },
  { id: 'V7', command: `echo "# x" ${BS}${NL}crontab -r`, runs: false, expect: 'ALLOW' },
  { id: 'V8', command: `echo 'a${BS}${NL}'; crontab -r`, runs: true, expect: 'DENY' },
  { id: 'V9', command: `echo 'a${BS}${NL}crontab -r'`, runs: false, expect: 'ALLOW' },
  { id: 'V10', command: `echo "a${BS}${BS}${NL}"; crontab -r`, runs: true, expect: 'DENY' },
  { id: 'V11', command: `cat <<'EOF'${NL}x${BS}${NL}EOF${NL}crontab -r`, runs: true, expect: 'DENY' },
  // V12: the shell does NOT run crontab (the unquoted body joins to `xEOF`, which does not close the heredoc),
  // the gate denies anyway: an accepted over-deny, and it stays a DENY.
  { id: 'V12', command: `cat <<EOF${NL}x${BS}${NL}EOF${NL}crontab -r`, runs: false, expect: 'DENY' },
  { id: 'V13', command: `cat <<< a${BS}${BS}${NL}crontab -r`, runs: true, expect: 'DENY' },
  { id: 'V14', command: `cat <<< 'a${BS}'${NL}crontab -r`, runs: true, expect: 'DENY' },
  { id: 'V15', command: `echo a${BS}${BS}${NL}tmux send-keys -t x Enter`, runs: true, expect: 'DENY' },
  { id: 'V16', command: `echo a${BS} ${NL}crontab -r`, runs: true, expect: 'DENY' },
  { id: 'V17', command: `printf x # c ${BS}${BS}${BS}${NL}at now`, runs: true, expect: 'DENY' },
  { id: 'V18', command: `cron${BS}${NL}tab -r`, oracle: `__m${BS}${NL}1 -r`, runs: true, expect: 'DENY' },
  { id: 'V19', command: `echo ok; c${BS}${NL}rontab -r`, oracle: `echo ok; _${BS}${NL}_m1 -r`, runs: true, expect: 'DENY' },
  { id: 'V20', command: `tm${BS}${NL}ux send-keys -t x Enter`, oracle: `__m${BS}${NL}3 send-keys -t x Enter`, runs: true, expect: 'DENY' },
  { id: 'V21', command: `echo $(echo a${BS}${BS}${NL}crontab -r)`, runs: true, expect: 'DENY' },
  // V22: bash/zsh do not run it (the backtick halves the backslash run, so the line joins), but the card
  // accepts the fail-closed path: a continuation inside backticks is not read exactly, so the gate denies
  // (reason 'ambiguous-continuation', spec E7).
  { id: 'V22', command: `echo \`echo a${BS}${BS}${NL}crontab -r\``, runs: false, expect: 'DENY', reason: 'ambiguous-continuation' },
  { id: 'B1', command: `curl -s ${BS}${NL}  -H "Accept: application/json" ${BS}${NL}  http://localhost:3420/api/kanban`, runs: false, expect: 'ALLOW' },
  { id: 'B2', command: `git log ${BS}${NL}  --oneline -5`, runs: false, expect: 'ALLOW' },
  { id: 'B3', command: `crontab ${BS}${NL}  -l`, runs: true, expect: 'ALLOW', readOnly: true },
  { id: 'B4', command: `echo "line one ${BS}${NL}line two"`, runs: false, expect: 'ALLOW' },
  // B5: `\<CR>` is NOT a continuation, so `c` is a separate (harmless) command and the gate keeps ALLOW.
  { id: 'B5', command: `printf '%s\\n' a ${BS}${NL}  b ${BS}${CRLF}  c`, runs: false, expect: 'ALLOW', noOracle: 'allowlist: the lone word c is a command word the guard does not allow' },
  { id: 'B6', command: `# just a note${NL}ls -la`, runs: false, expect: 'ALLOW' },
  { id: 'B7', command: `python3 - <<'PY'${NL}print("a ${BS}${NL}b")${NL}PY${NL}echo done`, runs: false, expect: 'ALLOW' },
  { id: 'B8', command: `echo a ${BS}${BS}${NL}echo b`, runs: false, expect: 'ALLOW' },
  { id: 'B9', command: `cat > /tmp/x.md <<'EOF'${NL}see the scheduler notes ${BS}${NL}EOF${NL}echo ok`, runs: false, expect: 'ALLOW' },
  { id: 'B10', command: `grep -n foo ${BS}${NL}  file.txt # search ${BS}${NL}ls`, runs: false, expect: 'ALLOW' },
]

// Extra shapes around the 35: edges of the same rule (leading / trailing / doubled continuation, `;` and `&&`
// glued across a line, ANSI-C quote, comment inside $(...), CRLF in the middle of a word, E7 fail-closed rows).
export const EXTRA_CASES = [
  { id: 'X1', command: `echo $'a${BS}${NL}'; crontab -r`, runs: true, expect: 'DENY' },
  { id: 'X2', command: `${BS}${NL}crontab -r`, runs: true, expect: 'DENY' },
  { id: 'X3', command: `crontab -r ${BS}${NL}`, runs: true, expect: 'DENY' },
  // two continuations in a row join to ONE line: `echo a crontab -r` is a harmless echo
  { id: 'X4', command: `echo a ${BS}${NL}${BS}${NL}crontab -r`, runs: false, expect: 'ALLOW' },
  // a comment inside $(...) ends at the newline in zsh (the second line runs there); bash 3.2 rejects the text
  // with a syntax error and runs nothing. The conservative reading is the card's rule: DENY.
  { id: 'X5', command: `echo $(echo a # c ${BS}${NL}crontab -r)`, runs: null, expect: 'DENY' },
  // `\<CR>` escapes the CR, the LF then ends the line: `cron\r` and `tab -r` are two harmless words
  { id: 'X6', command: `cron${BS}${CRLF}tab -r`, oracle: `__m${BS}${CRLF}1 -r`, runs: false, expect: 'ALLOW', noOracle: 'allowlist: the CR-glued word __m<CR> is not a marker function' },
  // the second backslash-newline is a lone continuation on its own line: it vanishes and crontab starts a line
  { id: 'X7', command: `echo a${BS}${BS}${NL}${BS}${NL}crontab -r`, runs: true, expect: 'DENY' },
  { id: 'X8', command: `echo "$(echo a${BS}${BS}${NL}crontab -r)"`, runs: true, expect: 'DENY' },
  { id: 'X9', command: `cat <<< a${BS}${NL}crontab -r`, runs: false, expect: 'ALLOW' },
  { id: 'X10', command: `echo a;${BS}${NL}crontab -r`, runs: true, expect: 'DENY' },
  { id: 'X11', command: `true &&${BS}${NL}crontab -r`, runs: true, expect: 'DENY' },
  // E7: an unterminated quote / heredoc with a continuation is read inexactly -> DENY (reason ambiguous-continuation)
  { id: 'X12', command: `echo 'abc${BS}${NL}crontab -r`, runs: null, expect: 'DENY', reason: 'ambiguous-continuation' },
  { id: 'X13', command: `cat <<EOF${NL}x${BS}${NL}crontab -r`, runs: null, expect: 'DENY', reason: 'ambiguous-continuation' },
  { id: 'X14', command: `echo \`echo a${BS}${NL}b\``, runs: false, expect: 'DENY', reason: 'ambiguous-continuation', noOracle: 'backtick: not rewritten' },
  // Fix round 1 (B1, the reviewer's K shapes): a `case` keyword split by a continuation inside $(...) used to be
  // missed (the keyword was read on the raw stream), the pattern `)` closed the substitution early and the next
  // command hid in a "comment" of the dq context. The joiner now reads the keyword on the joined stream and the
  // shape is inexact -> DENY. The dq-wrapped rows are not run through the oracle (the guard cannot prove that the
  // # after the pattern is a comment inside the quotes); `runs` is null for all: the corpus makes no claim.
  { id: 'X15', command: `echo "$(ca${BS}${NL}se a in a) # c ${BS}${NL}crontab -r ;; esac)"`, runs: null, expect: 'DENY', reason: 'ambiguous-continuation', noOracle: 'guard: # inside $( ) inside "..." cannot be proven a comment' },
  { id: 'X16', command: `echo "$(case${BS}${NL} a in a) # c ${BS}${NL}crontab -r ;; esac)"`, runs: null, expect: 'DENY', reason: 'ambiguous-continuation', noOracle: 'guard: # inside $( ) inside "..." cannot be proven a comment' },
  { id: 'X17', command: `echo "$(case a in a) # c ${BS}${NL}crontab -r ;; esac)"`, runs: null, expect: 'DENY', reason: 'ambiguous-continuation', noOracle: 'guard: # inside $( ) inside "..." cannot be proven a comment' },
  { id: 'X18', command: `echo "$(ca${BS}${NL}se a in a) # c ${BS}${NL}at now ;; esac)"`, runs: null, expect: 'DENY', reason: 'ambiguous-continuation', noOracle: 'guard: # inside $( ) inside "..." cannot be proven a comment' },
  { id: 'X19', command: `echo "\${x:-$(ca${BS}${NL}se a in a) # c ${BS}${NL}crontab -r ;; esac)}"`, runs: null, expect: 'DENY', reason: 'ambiguous-continuation', noOracle: 'guard: # inside $( ) inside "..." cannot be proven a comment' },
  { id: 'X20', command: `echo $(ca${BS}${NL}se a in a) # c ${BS}${NL}crontab -r ;; esac)`, runs: null, expect: 'DENY', reason: 'ambiguous-continuation' },
  { id: 'X21', command: `echo $(case${BS}${NL} a in a) # c ${BS}${NL}tmux send-keys -t x Enter ;; esac)`, runs: null, expect: 'DENY', reason: 'ambiguous-continuation' },
]

// Real multi-line shapes of the fleet (curl with several headers, gh / git with files, python and node heredocs,
// find, printf, vitest, agent-msg ...). Every row is a harmless command and must stay ALLOW. No row contains a
// dangerous word, so none of them goes through the oracle.
const TOKEN = '$(cat /Users/gyorgydecsi/marveen/store/.dashboard-token)'
export const BENIGN_CASES = [
  { id: 'G01', command: `curl -s ${BS}${NL}  -H "Authorization: Bearer ${TOKEN}" ${BS}${NL}  -H "Accept: application/json" ${BS}${NL}  http://localhost:3420/api/kanban` },
  { id: 'G02', command: `curl -s -X POST http://localhost:3420/api/kanban/abc12345/comments ${BS}${NL}  -H "Content-Type: application/json" ${BS}${NL}  -H "Authorization: Bearer ${TOKEN}" ${BS}${NL}  --data-binary @- <<'JSON'${NL}{"author":"ezermester","content":"done, see the report ${BS}${NL}second line"}${NL}JSON` },
  { id: 'G03', command: `gh pr create --title "fix: join lines" ${BS}${NL}  --body-file /Volumes/8T/10_LOCAL/Brainy/_ezermester/3660cf43/pr-body.md ${BS}${NL}  --base develop` },
  { id: 'G04', command: `git commit ${BS}${NL}  -F /Volumes/8T/10_LOCAL/Brainy/_ezermester/3660cf43/msg.txt` },
  { id: 'G05', command: `git commit -m "$(cat <<'EOF'${NL}fix(gate): join lines like the shell ${BS}${NL}and keep the comment tail${NL}${NL}Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>${NL}EOF${NL})"` },
  { id: 'G06', command: `python3 - <<'PY'${NL}total = 1 + ${BS}${NL}  2${NL}print(total)${NL}PY` },
  { id: 'G07', command: `node --input-type=module - <<'JS'${NL}console.log("a ${BS}${NL}b")${NL}JS` },
  { id: 'G08', command: `find /Users/gyorgydecsi/marveen-wt/3660cf43/src -name '*.ts' ${BS}${NL}  -not -path '*/node_modules/*' ${BS}${NL}  -newer /Users/gyorgydecsi/marveen-wt/3660cf43/package.json` },
  { id: 'G09', command: `printf '%s${BS}n' ${BS}${NL}  one ${BS}${NL}  two ${BS}${NL}  three` },
  { id: 'G10', command: `npx vitest run src/__tests__/a.test.ts ${BS}${NL}  src/__tests__/b.test.ts ${BS}${NL}  src/__tests__/c.test.ts` },
  { id: 'G11', command: `npx tsc ${BS}${NL}  --noEmit` },
  { id: 'G12', command: `ls -la ${BS}${NL}  /Users/gyorgydecsi/marveen-wt/3660cf43/src` },
  { id: 'G13', command: `grep -rn "foo" ${BS}${NL}  src scripts ${BS}${NL}  --include='*.mjs'` },
  { id: 'G14', command: `sed -n '1,20p' ${BS}${NL}  /Users/gyorgydecsi/marveen-wt/3660cf43/package.json` },
  { id: 'G15', command: `bash /Users/gyorgydecsi/marveen/scripts/agent-msg.sh ezermester brainy ${BS}${NL}  "short report, nothing blocked"` },
  { id: 'G16', command: `cd /Users/gyorgydecsi/marveen-wt/3660cf43 && ${BS}${NL}  git status --short` },
  { id: 'G17', command: `FOO=bar ${BS}${NL}  BAR=baz ${BS}${NL}  node -e "console.log(process.env.FOO)"` },
  { id: 'G18', command: `git diff --stat ${BS}${NL}  91b6a2c1..HEAD -- scripts/self-pace-gate.mjs` },
  { id: 'G19', command: `crontab -l ${BS}${NL}  | wc -l` },
  { id: 'G20', command: `echo "done" # trailing comment ${BS}${NL}ls` },
  { id: 'G21', command: `if [ -f package.json ]; then ${BS}${NL}  echo yes; ${BS}${NL}fi` },
  { id: 'G22', command: `for f in a b; do ${BS}${NL}  echo "$f"; ${BS}${NL}done` },
  { id: 'G23', command: `cat <<EOF${NL}line a ${BS}${NL}line b${NL}EOF` },
  { id: 'G24', command: `cat > notes.md <<'EOF'${NL}# Heading${NL}path /Users/x ${BS}${NL}EOF${NL}echo written` },
  { id: 'G25', command: `curl -s ${BS}${NL}  http://localhost:3420/api/memories ${BS}${NL}  -G ${BS}${NL}  --data-urlencode "q=hot notes"` },
]

// Matrix: context x backslash-run length x line ending x second line. 8 x 6 x 2 x 4 = 384 rows. The expected
// verdict is NOT written here: the differential test asks the real shells (oracle.mjs) and requires DENY
// whenever a shell reaches the dangerous second line; the harmless `ls` rows are required to stay ALLOW except
// where the card's own E7 rule (unterminated heredoc with a continuation) legitimately denies.
export const MATRIX_CONTEXTS = ['normal', 'dq', 'sq', 'subst', 'comment', 'herestring', 'qheredoc', 'heredoc']
export const MATRIX_RUNS = [0, 1, 2, 3, 4, 5]
export const MATRIX_EOLS = { LF: NL, CRLF }
export const MATRIX_SECONDS = {
  crontab: { text: 'crontab -r', dangerous: true },
  at: { text: 'at now', dangerous: true },
  tmux: { text: 'tmux send-keys -t x Enter', dangerous: true },
  ls: { text: 'ls', dangerous: false },
}

function matrixCommand(ctx, x, e, d) {
  switch (ctx) {
    case 'normal': return `echo a${x}${e}${d}`
    case 'dq': return `echo "a${x}${e}"; ${d}`
    case 'sq': return `echo 'a${x}${e}'; ${d}`
    case 'subst': return `echo $(echo a${x}${e}${d})`
    case 'comment': return `echo ok # c${x}${e}${d}`
    case 'herestring': return `cat <<< a${x}${e}${d}`
    case 'qheredoc': return `cat <<'EOF'${e}x${x}${e}EOF${e}${d}`
    case 'heredoc': return `cat <<EOF${e}x${x}${e}EOF${e}${d}`
    default: throw new Error(`unknown matrix context ${ctx}`)
  }
}

export function buildMatrix() {
  const rows = []
  for (const ctx of MATRIX_CONTEXTS) {
    for (const n of MATRIX_RUNS) {
      for (const [eolName, e] of Object.entries(MATRIX_EOLS)) {
        for (const [secondName, second] of Object.entries(MATRIX_SECONDS)) {
          // a harmless row may legitimately DENY when the heredoc is not closed on the joined text (CRLF tag
          // line `EOF\r`, or an odd run that joins `xEOF`): the card's E7 rule makes that a fail-closed DENY
          const maybeUnclosed = (ctx === 'qheredoc' || ctx === 'heredoc') && eolName === 'CRLF'
            || ctx === 'heredoc' && n % 2 === 1
          rows.push({
            id: `M-${ctx}-${n}-${eolName}-${secondName}`,
            ctx, n, eol: eolName, second: secondName,
            command: matrixCommand(ctx, BS.repeat(n), e, second.text),
            dangerous: second.dangerous,
            // for a harmless row: true = the gate must ALLOW
            mustAllow: !second.dangerous && !maybeUnclosed,
          })
        }
      }
    }
  }
  return rows
}

// The four large shapes of the card's timing probe (tmp/perf.mjs). 100 ms ceiling per gateDecision (spec E9).
export function bigShapes() {
  return {
    'continuations x2000': 'curl -s ' + Array.from({ length: 2000 }, (_, i) => `-H "X-${i}: v" ${BS}${NL}`).join('') + 'http://localhost:3420/api/kanban',
    'even runs x2000': Array.from({ length: 2000 }, (_, i) => `echo ${i}${BS}${BS}${NL}`).join(''),
    'comments x2000': Array.from({ length: 2000 }, (_, i) => `ls # c${i} ${BS}${NL}`).join(''),
    'heredoc 2000 lines': `cat <<'EOF'${NL}` + Array.from({ length: 2000 }, (_, i) => `line ${i} ${BS}${NL}`).join('') + `EOF${NL}echo ok`,
  }
}

// Every command text of the corpus, for the idempotence checks.
export function allCommands() {
  return [
    ...SPEC_CASES, ...EXTRA_CASES, ...BENIGN_CASES, ...buildMatrix(),
  ].map((c) => c.command)
}
