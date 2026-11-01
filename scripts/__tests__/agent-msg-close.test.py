#!/usr/bin/env python3
"""scripts/agent-msg-close.sh (card f137f980, Brainy 6367): the signed, verified close of a message.

Contract under test:
  - PUT /api/messages/<id> with the bearer token and, when MARVEEN_AGENT_KEY_FILE names a valid key file,
    the X-Agent-Key header; neither the token nor the key is ever in an argv (the curl PATH shim records it);
  - success only on HTTP 200 and {"ok":true}; 409 "Message already closed" is a clear no-op with exit 0; 4xx is
    final (one request, exit 1); 5xx and no answer are retried (3 tries) and then FAIL;
  - notify is a real JSON boolean and absent unless asked; the result comes from a file or stdin and survives
    byte-exact (quotes, backticks, $(), newlines, non-ASCII, a trailing newline), also when it is large;
  - no key file: the close still goes out, unsigned, with a note on stderr; a key the server echoes never reaches
    stdout, stderr or the failure log;
  - usage errors send nothing (exit 2).

Everything talks to a fake server on 127.0.0.1 (MARVEEN_API_BASE) with a dummy token file; nothing reaches a real
dashboard. This process also refuses any non-loopback connect and the live CDP ports 18800/18899 before the connect
(Brainy 1769), and the stub never uses 3420.

Run:  python3 scripts/__tests__/agent-msg-close.test.py
"""
import http.server
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))

# --- loopback-only socket guard (in this process), checked before any connect -------------------
SELFTEST_PORT = 18994  # our own test port, on the deny list: the self-test never touches a live port
_BANNED_PORTS = (18800, 18899, 3420, SELFTEST_PORT)
_real_connect = socket.socket.connect


def _guarded_connect(self, address):
    host, port = address[0], address[1]
    if host not in ('127.0.0.1', '::1', 'localhost') or port in _BANNED_PORTS:
        raise PermissionError(f'test guard: connect to {host}:{port} refused')
    return _real_connect(self, address)


socket.socket.connect = _guarded_connect

# self-test of the guard on a port of our own that is on the ban list: it must be refused before any connect
# (never 18800/18899/3420 here: if the guard were broken, the test would hit the live browser or dashboard)
try:
    socket.socket().connect(('127.0.0.1', SELFTEST_PORT))
    raise SystemExit(f'guard self-test FAILED: a connect to {SELFTEST_PORT} was not refused')
except PermissionError:
    pass
try:
    socket.socket().connect(('192.0.2.1', 80))
    raise SystemExit('guard self-test FAILED: a non-loopback connect was not refused')
except PermissionError:
    pass

KEY = 'mvak_IRODAkey0123456789abcdefghijklmnopqrstuvwx'
TOKEN = 'test-token-0123456789'
FAILS = []
N = [0]
SEEN = []
QUEUE = []  # responses for the next requests: (code, dict | raw str); empty = 200 {"ok":true}


def check(name, cond, detail=''):
    N[0] += 1
    if cond:
        print('PASS  ' + name)
    else:
        print('FAIL  ' + name + (('  -- ' + detail) if detail else ''))
        FAILS.append(name)


class Stub(http.server.BaseHTTPRequestHandler):
    def _answer(self):
        n = int(self.headers.get('Content-Length', '0'))
        raw = self.rfile.read(n)
        try:
            parsed = json.loads(raw.decode('utf-8')) if raw else None
        except ValueError:
            parsed = 'NOT-JSON'
        SEEN.append({'method': self.command, 'path': self.path, 'key': self.headers.get_all('X-Agent-Key'),
                     'auth': self.headers.get('Authorization'), 'ctype': self.headers.get('Content-Type'),
                     'body': parsed, 'raw': raw})
        code, body = QUEUE.pop(0) if QUEUE else (200, {'ok': True})
        if callable(body):
            body = body(self)
        out = (body if isinstance(body, str) else json.dumps(body)).encode()
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    do_POST = do_GET = do_PUT = _answer

    def log_message(self, *a):
        pass


srv = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Stub)
PORT = srv.server_address[1]
assert PORT not in _BANNED_PORTS, 'ephemeral port collided with a banned port; rerun'
threading.Thread(target=srv.serve_forever, daemon=True).start()

# a port with nothing behind it, for the "no answer" (curl 000) case
_probe = socket.socket()
_probe.bind(('127.0.0.1', 0))
DEAD_PORT = _probe.getsockname()[1]
_probe.close()
assert DEAD_PORT not in _BANNED_PORTS, 'dead port collided with a banned port; rerun'

SANDBOX = tempfile.mkdtemp(prefix='msgclose.')
INST = os.path.join(SANDBOX, 'install')
BIN = os.path.join(SANDBOX, 'bin')
KEYS = os.path.join(SANDBOX, 'keys')
WORKTMP = os.path.join(SANDBOX, 'tmp')  # the helper's TMPDIR: must be empty again after every run
for d in ('scripts/lib', 'store'):
    os.makedirs(os.path.join(INST, d))
for d in (BIN, KEYS, WORKTMP):
    os.makedirs(d)
for f in ('scripts/agent-msg-close.sh', 'scripts/lib/marveen_api.py'):
    shutil.copy(os.path.join(ROOT, f), os.path.join(INST, f))
SCRIPT = os.path.join(INST, 'scripts', 'agent-msg-close.sh')
TOKEN_FILE = os.path.join(SANDBOX, '.dashboard-token')
with open(TOKEN_FILE, 'w') as f:
    f.write(TOKEN + '\n')
LOG = os.path.join(INST, 'store', 'agent-msg-failures.log')
ARGV_LOG = os.path.join(SANDBOX, 'curl-argv.log')

REAL_CURL = shutil.which('curl') or '/usr/bin/curl'
with open(os.path.join(BIN, 'curl'), 'w') as f:
    # records every argument, then runs the real curl with the same stdin
    f.write('#!/usr/bin/env bash\nfor a in "$@"; do printf "%s\\n" "$a" >> "$ARGV_LOG"; done\nexec "$REAL_CURL" "$@"\n')
os.chmod(os.path.join(BIN, 'curl'), 0o755)
with open(os.path.join(BIN, 'sleep'), 'w') as f:
    f.write('#!/usr/bin/env bash\nexit 0\n')
os.chmod(os.path.join(BIN, 'sleep'), 0o755)


def keyfile(name, content, mode=0o600):
    p = os.path.join(KEYS, name)
    with open(p, 'w') as f:
        f.write(content)
    os.chmod(p, mode)
    return p


KEY_FILE = keyfile('iroda', f'X-Agent-Key: {KEY}\n')


def env(key_file=None, base=None, extra=None):
    e = {'PATH': BIN + ':' + os.environ.get('PATH', '/usr/bin:/bin'), 'HOME': SANDBOX, 'TMPDIR': WORKTMP,
         'MARVEEN_API_BASE': base or f'http://127.0.0.1:{PORT}', 'MARVEEN_TOKEN_FILE': TOKEN_FILE,
         'ARGV_LOG': ARGV_LOG, 'REAL_CURL': REAL_CURL}
    if key_file is not None:
        e['MARVEEN_AGENT_KEY_FILE'] = key_file
    e.update(extra or {})
    return e


def close(args, key_file=KEY_FILE, queue=None, stdin=None, base=None, extra=None, binary_stdin=None, cwd=None):
    SEEN.clear()
    QUEUE[:] = queue or []
    for p in (ARGV_LOG, LOG):
        if os.path.exists(p):
            os.unlink(p)
    kw = {'input': binary_stdin} if binary_stdin is not None else {'input': stdin}
    text = binary_stdin is None
    return subprocess.run(['bash', SCRIPT] + args, env=env(key_file, base, extra), capture_output=True, text=text,
                          cwd=cwd or SANDBOX, timeout=120, **kw)


def argv_text():
    try:
        return open(ARGV_LOG).read()
    except OSError:
        return ''


def log_text():
    try:
        return open(LOG).read()
    except OSError:
        return ''


def write(name, content, mode='w'):
    p = os.path.join(SANDBOX, name)
    with open(p, mode) as f:
        f.write(content)
    return p


# ------------------------------------------------------------------ success, signed
r = close(['7', 'done'])
check('ok: exit 0 and "OK id=7 status=done"', r.returncode == 0 and r.stdout.strip() == 'OK id=7 status=done', r.stdout + r.stderr)
check('ok: exactly one PUT on /api/messages/7', len(SEEN) == 1 and SEEN[0]['method'] == 'PUT' and SEEN[0]['path'] == '/api/messages/7', repr(SEEN))
check('ok: the bearer token arrives', SEEN[0]['auth'] == f'Bearer {TOKEN}', repr(SEEN[0]['auth']))
check('ok: the key header arrives exactly once', SEEN[0]['key'] == [KEY], repr(SEEN[0]['key']))
check('ok: JSON content type and the minimal body {"status":"done"}',
      SEEN[0]['ctype'] == 'application/json' and SEEN[0]['body'] == {'status': 'done'}, repr(SEEN[0]['body']))
argv = argv_text()
check('argv: the curl invocation was recorded', argv != '' and '-X\nPUT' in argv, argv)
check('argv: neither the key nor the token is in it', KEY not in argv and 'mvak_' not in argv and TOKEN not in argv and 'Bearer' not in argv, argv)
check('argv: no key file path and the headers are passed on stdin (-H @-)', KEY_FILE not in argv and '-H\n@-' in argv, argv)
check('stdout and stderr carry no key and no token', KEY not in r.stdout + r.stderr and TOKEN not in r.stdout + r.stderr)
check('the work directory is cleaned up', os.listdir(WORKTMP) == [], repr(os.listdir(WORKTMP)))
check('no NOTE about an unsigned close when the key is valid', 'UNSIGNED' not in r.stderr, r.stderr)

r = close(['8', 'failed'])
check('failed status: body {"status":"failed"}', r.returncode == 0 and SEEN[0]['body'] == {'status': 'failed'} and SEEN[0]['path'] == '/api/messages/8', repr(SEEN))

# ------------------------------------------------------------------ notify
r = close(['7', 'done', '--notify', 'false'])
check('notify false: a JSON boolean false, not the string',
      r.returncode == 0 and SEEN[0]['body'] == {'status': 'done', 'notify': False} and SEEN[0]['body']['notify'] is False, repr(SEEN[0]['body']))
check('notify false: the raw body has no quoted "false"', b'"notify": "false"' not in SEEN[0]['raw'] and b'"notify": false' in SEEN[0]['raw'], repr(SEEN[0]['raw']))
r = close(['7', 'done', '--notify=true'])
check('notify true: a JSON boolean true', r.returncode == 0 and SEEN[0]['body'].get('notify') is True, repr(SEEN[0]['body']))
for bad in ('False', 'no', '0', '', 'null'):
    r = close(['7', 'done', '--notify', bad])
    check(f'notify {bad!r}: refused, exit 2, nothing sent', r.returncode == 2 and SEEN == [] and 'FAIL' in r.stderr, r.stdout + r.stderr)

# ------------------------------------------------------------------ result from a file or stdin, byte-exact
NASTY = 'quotes "double" and \'single\'\nbackticks `id` and $(whoami) and ${HOME}\n\\n \\" \t tab\nunicode: árvíztűrő tükörfúrógép 日本語 🙂\n$(rm -rf /) ; echo hi | cat > /dev/null\n\n'
rf = write('result.txt', NASTY)
r = close(['7', 'done', '--result-file', rf, '--notify', 'false'])
check('result file: exit 0', r.returncode == 0 and r.stdout.startswith('OK id=7'), r.stdout + r.stderr)
check('result file: byte-exact (quotes, backticks, $(), newlines, unicode, trailing newlines)',
      SEEN[0]['body'].get('result') == NASTY, repr(SEEN[0]['body'].get('result')))
check('result file: nothing of the text is on the curl argv', 'whoami' not in argv_text() and 'backticks' not in argv_text())

r = close(['7', 'done', '--result-file', '-'], stdin=NASTY)
check('stdin via --result-file -: byte-exact', r.returncode == 0 and SEEN[0]['body'].get('result') == NASTY, repr(SEEN and SEEN[0]['body']))
r = close(['7', 'done', '-'], stdin='bare dash $(x) `y`\n')
check('stdin via a bare -: byte-exact', r.returncode == 0 and SEEN[0]['body'].get('result') == 'bare dash $(x) `y`\n', repr(SEEN and SEEN[0]['body']))
r = close(['7', 'done', '--result-file=' + rf])
check('--result-file=PATH form works', r.returncode == 0 and SEEN[0]['body'].get('result') == NASTY)

BIG = ('x' * 99 + '\n') * 3000  # 300 kB: far beyond any single-argument limit
r = close(['7', 'done', '--result-file', write('big.txt', BIG)])
check('a 300 kB result goes through (it is in no argv)', r.returncode == 0 and SEEN[0]['body'].get('result') == BIG, r.stdout + r.stderr)

r = close(['7', 'done', '--result-file', write('empty.txt', '')])
check('an empty result file is sent as an empty result', r.returncode == 0 and SEEN[0]['body'] == {'status': 'done', 'result': ''}, repr(SEEN and SEEN[0]['body']))

r = close(['7', 'done', '--result-file', write('bad.bin', b'\xff\xfe\x00bad', 'wb')])
check('invalid UTF-8: exit 2, nothing sent', r.returncode == 2 and SEEN == [] and 'UTF-8' in r.stderr, r.stdout + r.stderr)
r = close(['7', 'done', '--result-file', os.path.join(SANDBOX, 'no-such-file')])
check('missing result file: exit 2, nothing sent', r.returncode == 2 and SEEN == [], r.stdout + r.stderr)
check('the work directory is still clean', os.listdir(WORKTMP) == [], repr(os.listdir(WORKTMP)))

# ------------------------------------------------------------------ 409: already closed = success no-op
r = close(['7', 'done'], queue=[(409, {'error': 'Message already closed', 'status': 'done', 'hint': 'x'})])
check('409 already closed: exit 0, ALREADY-CLOSED line, one request, no retry',
      r.returncode == 0 and r.stdout.startswith('ALREADY-CLOSED id=7') and 'Not an error' in r.stdout and len(SEEN) == 1, r.stdout + r.stderr)
check('409 already closed: no failure log line', log_text() == '', log_text())
r = close(['7', 'done'], queue=[(409, {'error': 'something else'})])
check('409 with another error: FAIL, exit 1, no retry', r.returncode == 1 and r.stdout.startswith('FAIL close id=7') and 'http=409' in r.stdout and len(SEEN) == 1, r.stdout)
r = close(['7', 'done'], queue=[(200, {'ok': False})])
check('200 without {"ok":true}: FAIL, exit 1, one request', r.returncode == 1 and r.stdout.startswith('FAIL') and len(SEEN) == 1, r.stdout)
r = close(['7', 'done'], queue=[(200, 'not json at all')])
check('200 with a non-JSON body: FAIL', r.returncode == 1 and r.stdout.startswith('FAIL') and len(SEEN) == 1, r.stdout)

# ------------------------------------------------------------------ 4xx: final
for code, body in ((401, {'error': 'unauthorized'}), (403, {'error': 'forbidden'}), (404, {'error': 'Message not found or invalid status'}), (400, {'error': 'notify must be a boolean'})):
    r = close(['7', 'done'], queue=[(code, body)])
    check(f'{code}: FAIL, exit 1, ONE request (final), logged',
          r.returncode == 1 and r.stdout.startswith('FAIL close id=7') and f'http={code}' in r.stdout and len(SEEN) == 1
          and f'http={code}' in log_text() and 'FAIL\tclose id=7' in log_text(), r.stdout + log_text())

# ------------------------------------------------------------------ 5xx / no answer: retry
r = close(['7', 'done'], queue=[(500, {'error': 'boom'})] * 3)
check('5xx x3: FAIL after 3 tries, exit 1', r.returncode == 1 and len(SEEN) == 3 and 'http=500' in r.stdout and 'after 3 tries' in r.stdout, r.stdout + repr(len(SEEN)))
check('5xx x3: the failure log has the line', 'FAIL\tclose id=7' in log_text() and 'http=500' in log_text(), log_text())
r = close(['7', 'done'], queue=[(500, {'error': 'boom'}), (200, {'ok': True})])
check('500 then 200: OK after a retry (2 requests)', r.returncode == 0 and r.stdout.startswith('OK id=7') and len(SEEN) == 2, r.stdout)
r = close(['7', 'done'], queue=[(503, {'error': 'busy'}), (409, {'error': 'Message already closed'})])
check('503 then 409: the retry finds the close landed -> ALREADY-CLOSED, exit 0', r.returncode == 0 and r.stdout.startswith('ALREADY-CLOSED') and len(SEEN) == 2, r.stdout)
r = close(['7', 'done'], base=f'http://127.0.0.1:{DEAD_PORT}')
check('no answer (connection refused): FAIL after 3 tries, exit 1, http=000',
      r.returncode == 1 and 'http=000' in r.stdout and 'after 3 tries' in r.stdout and argv_text().count('PUT') == 3, r.stdout + argv_text())

# ------------------------------------------------------------------ the key never leaks, even when the server echoes it
r = close(['7', 'done'], queue=[(500, lambda h: {'error': 'boom ' + (h.headers.get('X-Agent-Key') or '') + ' ' + (h.headers.get('Authorization') or '')})] * 3)
out = r.stdout + r.stderr + log_text() + argv_text()
check('an echoing server: FAIL, exit 1', r.returncode == 1 and r.stdout.startswith('FAIL'))
check('an echoing server: neither key nor token in stdout, stderr, log or argv', KEY not in out and TOKEN not in out, out)
check('an echoing server: the log shows [redacted]', '[redacted]' in log_text(), log_text())

# ------------------------------------------------------------------ unsigned fall-backs: a note, never a FAIL
r = close(['7', 'done'], key_file=None)
check('no MARVEEN_AGENT_KEY_FILE: closes unsigned, exit 0, no key header', r.returncode == 0 and r.stdout.startswith('OK id=7') and SEEN[0]['key'] is None, r.stdout + r.stderr)
check('no MARVEEN_AGENT_KEY_FILE: stderr says it went UNSIGNED', 'UNSIGNED' in r.stderr and 'FAIL' not in r.stdout + r.stderr, r.stderr)
check('no MARVEEN_AGENT_KEY_FILE: the bearer token is still sent', SEEN[0]['auth'] == f'Bearer {TOKEN}')
r = close(['7', 'done'], key_file=os.path.join(KEYS, 'does-not-exist'))
check('missing key file: unsigned, exit 0, note', r.returncode == 0 and SEEN[0]['key'] is None and 'UNSIGNED' in r.stderr)
loose = keyfile('mode644', f'X-Agent-Key: {KEY}\n', 0o644)
r = close(['7', 'done'], key_file=loose)
check('a 0644 key file is refused: unsigned, the helper warning, no key anywhere',
      r.returncode == 0 and SEEN[0]['key'] is None and 'send key file refused' in r.stderr and 'UNSIGNED' in r.stderr and KEY not in r.stdout + r.stderr + argv_text(), r.stderr)
two = keyfile('two-lines', f'X-Agent-Key: {KEY}\nX-Evil: 1\n')
r = close(['7', 'done'], key_file=two)
check('a key file with a second header line: unsigned, nothing smuggled', r.returncode == 0 and SEEN[0]['key'] is None, repr(SEEN[0]))
link = os.path.join(KEYS, 'link')
os.symlink(KEY_FILE, link)
r = close(['7', 'done'], key_file=link)
check('a symlinked key file is refused: unsigned', r.returncode == 0 and SEEN[0]['key'] is None and 'UNSIGNED' in r.stderr)
r = close(['7', 'done'], key_file=KEY_FILE)
check('the valid key file still signs', r.returncode == 0 and SEEN[0]['key'] == [KEY])

# ------------------------------------------------------------------ usage errors send nothing
for label, args in (
    ('no arguments', []),
    ('only the id', ['7']),
    ('a bad status', ['7', 'closed']),
    ('an uppercase status', ['7', 'DONE']),
    ('a path-like id', ['7/../../api/x', 'done']),
    ('a non-numeric id', ['abc', 'done']),
    ('an id with a query', ['7?x=1', 'done']),
    ('a 19-digit id', ['1' * 19, 'done']),
    ('an unknown option', ['7', 'done', '--force']),
    ('an extra argument', ['7', 'done', 'extra']),
    ('--notify without a value', ['7', 'done', '--notify']),
    ('--result-file without a value', ['7', 'done', '--result-file']),
):
    r = close(args)
    check(f'usage: {label} -> exit 2, nothing sent', r.returncode == 2 and SEEN == [] and argv_text() == '', r.stdout + r.stderr)

# ------------------------------------------------------------------ environment guards
r = close(['7', 'done'], base='http://192.0.2.1:9')
check('a non-loopback MARVEEN_API_BASE is refused before anything is sent (the token would leave the machine)',
      r.returncode == 2 and SEEN == [] and argv_text() == '' and 'FAIL' in r.stderr, r.stdout + r.stderr)
r = close(['7', 'done'], extra={'MARVEEN_TOKEN_FILE': KEY_FILE})
check('a token file not named .dashboard-token is refused (the key file must not travel as a bearer)',
      r.returncode == 2 and SEEN == [] and KEY not in r.stdout + r.stderr, r.stdout + r.stderr)
r = close(['7', 'done'], extra={'MARVEEN_TOKEN_FILE': os.path.join(SANDBOX, 'nope', '.dashboard-token')})
check('a missing token file: exit 2, nothing sent', r.returncode == 2 and SEEN == [] and 'no token file' in r.stderr, r.stdout + r.stderr)
empty_tok = os.path.join(SANDBOX, 'empty', '.dashboard-token')
os.makedirs(os.path.dirname(empty_tok))
open(empty_tok, 'w').close()
r = close(['7', 'done'], extra={'MARVEEN_TOKEN_FILE': empty_tok})
check('an empty token file: exit 2, nothing sent', r.returncode == 2 and SEEN == [], r.stdout + r.stderr)

# the key file is chosen by the environment alone: a file named after anything in the arguments is never looked up
decoy = os.path.join(SANDBOX, 'decoy')
os.makedirs(os.path.join(decoy, '.agent-keys'))
for p in (os.path.join(decoy, 'iroda'), os.path.join(decoy, '.agent-keys', 'iroda'), os.path.join(decoy, '7')):
    with open(p, 'w') as f:
        f.write('X-Agent-Key: mvak_DECOYdecoy0123456789abcdefghijklmnopqrstuv\n')
    os.chmod(p, 0o600)
SEEN.clear()
r = subprocess.run(['bash', SCRIPT, '7', 'done'], env=env(None), capture_output=True, text=True, cwd=decoy, timeout=60)
check('env unset -> unsigned even with key-looking files in the cwd', r.returncode == 0 and SEEN[0]['key'] is None, repr(SEEN))

# ------------------------------------------------------------------ B1: python runs isolated (-I)
# A planted json.py / marveen_api.py in the cwd and on PYTHONPATH must not run; the close still works signed.
plant = os.path.join(SANDBOX, 'plant')
os.makedirs(plant)
MARK = os.path.join(SANDBOX, 'PLANTED-RAN')
for mod in ('json.py', 'marveen_api.py', 'sys.py', 'os.py'):
    with open(os.path.join(plant, mod), 'w') as f:
        f.write(f'open({MARK!r}, "a").write("{mod}")\nraise SystemExit(99)\n')
r = close(['7', 'done', '--notify', 'false', '--result-file', rf], cwd=plant, extra={'PYTHONPATH': plant})
check('planted json.py/marveen_api.py in cwd and PYTHONPATH: marker absent', not os.path.exists(MARK), open(MARK).read() if os.path.exists(MARK) else '')
check('planted modules: the close still works, signed, body intact',
      r.returncode == 0 and r.stdout.startswith('OK id=7') and SEEN[0]['key'] == [KEY] and SEEN[0]['body'].get('result') == NASTY
      and SEEN[0]['body'].get('notify') is False, r.stdout + r.stderr)
src = open(SCRIPT).read()
check('every python3 call in the helper is isolated (-I)',
      all(l.count('python3') == l.count('python3 -I') for l in src.splitlines() if 'python3' in l and not l.lstrip().startswith('#') and 'command -v' not in l and 'die ' not in l))

# ------------------------------------------------------------------ B3: the port is digits only, 1-65535
for label, val in (('1@attacker.local', '1@attacker.local'), ('3420/x', '3420/x'), ('empty', ''), ('99999', '99999'),
                   ('leading space', ' 3420'), ('zero', '0'), ('6 digits', '000001'), ('negative', '-1')):
    for var in ('MARVEEN_WEB_PORT', 'WEB_PORT'):
        r = close(['7', 'done'], extra={var: val})
        check(f'{var}={label!r}: refused, exit 2, no request, no curl call',
              r.returncode == 2 and SEEN == [] and argv_text() == '' and 'FAIL' in r.stderr and 'port' in r.stderr, r.stdout + r.stderr)
for var in ('MARVEEN_WEB_PORT', 'WEB_PORT'):
    r = close(['7', 'done'], extra={var: '65535'})
    check(f'{var}=65535 is accepted (stub base still wins)', r.returncode == 0 and r.stdout.startswith('OK id=7'), r.stdout + r.stderr)
# .env source: a bad WEB_PORT line is refused too; a good one is fine
with open(os.path.join(INST, '.env'), 'w') as f:
    f.write('WEB_PORT=1@attacker.local\n')
r = close(['7', 'done'])
check('.env WEB_PORT=1@attacker.local: refused, nothing sent', r.returncode == 2 and SEEN == [] and argv_text() == '', r.stdout + r.stderr)
with open(os.path.join(INST, '.env'), 'w') as f:
    f.write('WEB_PORT="3420"\n')
r = close(['7', 'done'])
check('.env WEB_PORT="3420": accepted', r.returncode == 0 and r.stdout.startswith('OK id=7'), r.stdout + r.stderr)
os.unlink(os.path.join(INST, '.env'))

srv.shutdown()
# cleanup via the tempdir module
shutil.rmtree(SANDBOX, ignore_errors=True)
print(f'---- {N[0] - len(FAILS)}/{N[0]} passed')
sys.exit(1 if FAILS else 0)
