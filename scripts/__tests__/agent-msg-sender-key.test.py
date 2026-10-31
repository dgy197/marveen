#!/usr/bin/env python3
"""Sender side of the per-agent send key (card 0d7e2c04 N4): agent-msg.sh and scripts/lib/marveen_api.py.

The dashboard hands each agent a key file (one line, "X-Agent-Key: <key>") and names it in
MARVEEN_AGENT_KEY_FILE. The senders must:
  - put the key in the X-Agent-Key header when that file is valid;
  - never put it in an argv (`ps` shows other users' argv), tested by recording curl's argv;
  - choose the file ONLY from that variable, never from <from> or any argument: FROM=iroda under a
    feszek environment still sends the feszek key;
  - fall back to the unsigned send of before (no FAIL) for an unset, missing, unreadable, directory or
    malformed file, and never forward other header lines from the file;
  - keep the key out of the failure log and the output, even if a server echoed it.

Everything talks to a fake server on 127.0.0.1 (MARVEEN_API_BASE) with a dummy token file; nothing
reaches a real dashboard. This process also refuses any non-loopback connect and the live CDP ports
18800/18899 before the connect (Brainy 1769).

Run:  python3 scripts/__tests__/agent-msg-sender-key.test.py
"""
import http.server
import json
import os
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import threading

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))

# --- loopback-only socket guard (in this process), checked before any connect -------------------
_BANNED_PORTS = (18800, 18899)
_real_connect = socket.socket.connect


def _guarded_connect(self, address):
    host, port = address[0], address[1]
    if host not in ('127.0.0.1', '::1', 'localhost') or port in _BANNED_PORTS:
        raise PermissionError(f'test guard: connect to {host}:{port} refused')
    return _real_connect(self, address)


socket.socket.connect = _guarded_connect

KEY_FESZEK = 'mvak_FESZEKkey0123456789abcdefghijklmnopqrstuv'
KEY_IRODA = 'mvak_IRODAkey0123456789abcdefghijklmnopqrstuvwx'
FAILS = []
N = [0]
SEEN = []
MODE = {'v': 'ok'}


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
        self.rfile.read(n)
        SEEN.append({'method': self.command, 'path': self.path, 'key': self.headers.get_all('X-Agent-Key'),
                     'auth': self.headers.get('Authorization'), 'evil': self.headers.get('X-Evil')})
        if MODE['v'] == 'ok':
            code, body = 200, {'id': 7, 'status': 'pending'}
        else:
            # a server that echoes the key it received: the senders must not print or log it
            code, body = 500, {'error': 'boom ' + (self.headers.get('X-Agent-Key') or '')}
        out = json.dumps(body).encode()
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

SANDBOX = tempfile.mkdtemp(prefix='sendkey.')
INST = os.path.join(SANDBOX, 'install')
BIN = os.path.join(SANDBOX, 'bin')
KEYS = os.path.join(SANDBOX, 'keys')
for d in ('scripts/lib', 'store'):
    os.makedirs(os.path.join(INST, d))
os.makedirs(BIN)
os.makedirs(KEYS)
for f in ('scripts/agent-msg.sh', 'scripts/lib/homoglyph.py', 'scripts/lib/mixed_script.py', 'scripts/lib/marveen_api.py'):
    shutil.copy(os.path.join(ROOT, f), os.path.join(INST, f))
TOKEN_FILE = os.path.join(SANDBOX, '.dashboard-token')
with open(TOKEN_FILE, 'w') as f:
    f.write('test-token-0123456789\n')
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


def keyfile(name, content):
    p = os.path.join(KEYS, name)
    with open(p, 'w') as f:
        f.write(content)
    os.chmod(p, 0o600)
    return p


FESZEK_FILE = keyfile('feszek', f'X-Agent-Key: {KEY_FESZEK}\n')
IRODA_FILE = keyfile('iroda', f'X-Agent-Key: {KEY_IRODA}\n')  # exists on disk, must never be picked up


def env(extra=None, key_file=None):
    e = {'PATH': BIN + ':' + os.environ.get('PATH', '/usr/bin:/bin'), 'HOME': SANDBOX,
         'MARVEEN_API_BASE': f'http://127.0.0.1:{PORT}', 'MARVEEN_TOKEN_FILE': TOKEN_FILE,
         'ARGV_LOG': ARGV_LOG, 'REAL_CURL': REAL_CURL}
    if key_file is not None:
        e['MARVEEN_AGENT_KEY_FILE'] = key_file
    e.update(extra or {})
    return e


def msg(sender, key_file, content='tiszta uzenet', extra=None, cwd=None):
    SEEN.clear()
    for p in (ARGV_LOG, LOG):
        if os.path.exists(p):
            os.unlink(p)
    r = subprocess.run(['bash', os.path.join(INST, 'scripts', 'agent-msg.sh'), sender, 'brainy', content],
                       env=env(extra, key_file), capture_output=True, text=True, cwd=cwd or SANDBOX, timeout=60)
    return r


def api(args, key_file, extra=None):
    SEEN.clear()
    return subprocess.run([sys.executable, os.path.join(INST, 'scripts', 'lib', 'marveen_api.py')] + args,
                          env=env(extra, key_file), capture_output=True, text=True, cwd=SANDBOX, timeout=60)


def argv_text():
    try:
        return open(ARGV_LOG).read()
    except OSError:
        return ''


# ---------------------------------------------------------------- agent-msg.sh
MODE['v'] = 'ok'
r = msg('feszek', FESZEK_FILE)
check('msg: signed send is OK id=7', r.returncode == 0 and r.stdout.startswith('OK id=7'), r.stdout + r.stderr)
check('msg: the key header arrives at the server, exactly once',
      len(SEEN) == 1 and SEEN[0]['key'] == [KEY_FESZEK], repr(SEEN))
check('msg: the bearer token still arrives', len(SEEN) == 1 and SEEN[0]['auth'] == 'Bearer test-token-0123456789')
argv = argv_text()
check('msg: the curl argv has no key', KEY_FESZEK not in argv and 'mvak_' not in argv and argv != '', argv)
check('msg: the curl argv names no key file either', FESZEK_FILE not in argv)
check('msg: stdout and stderr carry no key', KEY_FESZEK not in r.stdout + r.stderr)

# FROM=iroda under a feszek environment: the file is chosen by the environment only
r = msg('iroda', FESZEK_FILE)
check('msg: FROM=iroda under the feszek env sends the feszek key',
      r.returncode == 0 and len(SEEN) == 1 and SEEN[0]['key'] == [KEY_FESZEK], repr(SEEN))
check('msg: ... and never the iroda key', KEY_IRODA not in argv_text() and SEEN[0]['key'] != [KEY_IRODA])

# a file named after the sender, in the cwd, in the key dir: none of them is looked up
decoy_dir = os.path.join(SANDBOX, 'decoy')
os.makedirs(os.path.join(decoy_dir, '.agent-keys'))
for p in (os.path.join(decoy_dir, 'iroda'), os.path.join(decoy_dir, '.agent-keys', 'iroda')):
    with open(p, 'w') as f:
        f.write(f'X-Agent-Key: {KEY_IRODA}\n')
r = msg('iroda', None, cwd=decoy_dir)
check('msg: env unset -> unsigned even with iroda files lying around (the sender picks no file)',
      r.returncode == 0 and r.stdout.startswith('OK id=7') and SEEN[0]['key'] is None, repr(SEEN) + r.stdout + r.stderr)

# unsigned fall-backs: OK, no FAIL, no header
r = msg('feszek', os.path.join(KEYS, 'does-not-exist'))
check('msg: missing key file -> unsigned send, OK id=7, no FAIL',
      r.returncode == 0 and r.stdout.startswith('OK id=7') and SEEN[0]['key'] is None and 'FAIL' not in r.stdout + r.stderr)

unreadable = keyfile('unreadable', f'X-Agent-Key: {KEY_FESZEK}\n')
os.chmod(unreadable, 0)
if os.geteuid() != 0:
    r = msg('feszek', unreadable)
    check('msg: unreadable key file -> unsigned send, OK id=7, no FAIL',
          r.returncode == 0 and r.stdout.startswith('OK id=7') and SEEN[0]['key'] is None and 'FAIL' not in r.stdout + r.stderr)
else:
    print('SKIP  msg: unreadable key file (running as root)')

r = msg('feszek', KEYS)
check('msg: a directory as key file -> unsigned send', r.returncode == 0 and SEEN[0]['key'] is None)

two = keyfile('two-lines', f'X-Agent-Key: {KEY_FESZEK}\nX-Evil: 1\n')
r = msg('feszek', two)
check('msg: a file with a second header line -> unsigned, the extra header never goes out',
      r.returncode == 0 and SEEN[0]['key'] is None and SEEN[0]['evil'] is None, repr(SEEN))
bad = keyfile('other-header', 'Authorization: Bearer stolen\n')
r = msg('feszek', bad)
check('msg: a file holding another header -> unsigned', r.returncode == 0 and SEEN[0]['key'] is None and SEEN[0]['auth'] == 'Bearer test-token-0123456789')
empty = keyfile('empty', '')
r = msg('feszek', empty)
check('msg: an empty file -> unsigned', r.returncode == 0 and SEEN[0]['key'] is None)

# --priority and STDIN content keep working with a key
SEEN.clear()
r = subprocess.run(['bash', os.path.join(INST, 'scripts', 'agent-msg.sh'), '--priority', 'high', 'feszek', 'brainy', '-'],
                   input='from stdin', env=env(None, FESZEK_FILE), capture_output=True, text=True, cwd=SANDBOX, timeout=60)
check('msg: --priority + STDIN content with a key still OK', r.returncode == 0 and r.stdout.startswith('OK id=7') and SEEN[0]['key'] == [KEY_FESZEK], r.stdout + r.stderr)

# FAIL path: a server that echoes the key
MODE['v'] = 'echo'
r = msg('feszek', FESZEK_FILE)
log = open(LOG).read() if os.path.exists(LOG) else ''
check('msg: server error -> FAIL line and exit 1 (semantics unchanged)', r.returncode == 1 and r.stdout.startswith('FAIL from=feszek to=brainy'), r.stdout)
check('msg: the FAIL log has the line', 'FAIL\tfrom=feszek' in log and 'http=500' in log, log)
check('msg: no key in the FAIL log, stdout or stderr (even when the server echoed it)',
      KEY_FESZEK not in log + r.stdout + r.stderr and '[redacted]' in log, log)
check('msg: no key in the curl argv on the failure path', KEY_FESZEK not in argv_text())
# unsigned failure is the old failure
r = msg('feszek', None)
check('msg: unsigned + server error -> the same FAIL as before', r.returncode == 1 and r.stdout.startswith('FAIL from=feszek'))
MODE['v'] = 'ok'

# ---------------------------------------------------------------- marveen_api.py
r = api(['directive-verify', '5'], FESZEK_FILE)
check('api: signed GET -> key header arrives, exit 0', r.returncode == 0 and SEEN[0]['key'] == [KEY_FESZEK], repr(SEEN) + r.stderr)
check('api: token header still arrives', SEEN[0]['auth'] == 'Bearer test-token-0123456789')
check('api: output has no key', KEY_FESZEK not in r.stdout + r.stderr)

pf = os.path.join(SANDBOX, 'payload.txt')
with open(pf, 'w') as f:
    f.write('hello')
r = api(['daily-log', 'iroda', pf], FESZEK_FILE)
check('api: a verb naming agent iroda under the feszek env sends the feszek key',
      r.returncode == 0 and SEEN[0]['key'] == [KEY_FESZEK], repr(SEEN))
r = api(['memory-save', 'iroda', 'warm', 'kw', pf], FESZEK_FILE)
check('api: memory-save for iroda still sends the feszek key, never the iroda one',
      r.returncode == 0 and SEEN[0]['key'] == [KEY_FESZEK])

for label, kf in (('unset', None), ('missing', os.path.join(KEYS, 'nope')), ('directory', KEYS),
                  ('two lines', two), ('other header', bad), ('empty', empty)):
    r = api(['directive-verify', '5'], kf)
    check(f'api: {label} key file -> unsigned, exit 0, no header',
          r.returncode == 0 and SEEN[0]['key'] is None and SEEN[0]['evil'] is None, repr(SEEN) + r.stderr)
if os.geteuid() != 0:
    r = api(['directive-verify', '5'], unreadable)
    check('api: unreadable key file -> unsigned, exit 0', r.returncode == 0 and SEEN[0]['key'] is None)

MODE['v'] = 'echo'
r = api(['directive-verify', '5'], FESZEK_FILE)
check('api: server error -> exit 1 as before', r.returncode == 1 and 'HTTP 500' in r.stderr, r.stderr)
check('api: an echoing server does not make the key reach stdout or stderr',
      KEY_FESZEK not in r.stdout + r.stderr and '[redacted]' in r.stderr, r.stderr)
MODE['v'] = 'ok'

# marveen-api.sh message verb runs agent-msg.sh: the env carries the key file through
for f in ('scripts/marveen-api.sh',):
    shutil.copy(os.path.join(ROOT, f), os.path.join(INST, f))
with open(pf, 'w') as f:
    f.write('via wrapper')
SEEN.clear()
r = subprocess.run(['bash', os.path.join(INST, 'scripts', 'marveen-api.sh'), 'message', 'iroda', 'brainy', pf],
                   env=env(None, FESZEK_FILE), capture_output=True, text=True, cwd=SANDBOX, timeout=60)
check('marveen-api.sh message: FROM=iroda under the feszek env sends the feszek key',
      r.returncode == 0 and r.stdout.startswith('OK id=7') and SEEN[0]['key'] == [KEY_FESZEK], r.stdout + r.stderr)

# ------------------------------------------------ key file vetting (card ed5fc02c)
# A key file that is a symlink, not a regular file, not ours, not exactly 0600 or over 256 bytes is
# NOT read: the send goes out unsigned, with a one-line warning that carries no path and no key.
WARN = 'WARN: send key file refused'
VALID = f'X-Agent-Key: {KEY_FESZEK}\n'

link = os.path.join(KEYS, 'link-to-feszek')
os.symlink(FESZEK_FILE, link)
loose644 = keyfile('mode644', VALID)
os.chmod(loose644, 0o644)
loose640 = keyfile('mode640', VALID)
os.chmod(loose640, 0o640)
tight400 = keyfile('mode400', VALID)
os.chmod(tight400, 0o400)
oversize = keyfile('oversize', VALID + '\n' * 300)  # one valid line, then padding: only the size check refuses it
foreign_uid = {'MARVEEN_AGENT_KEY_EXPECT_UID': str(os.geteuid() + 4242)}  # test seam: "the file is owned by someone else"

CASES = (
    ('symlink to a valid key file', link, None),
    ('mode 0644', loose644, None),
    ('mode 0640', loose640, None),
    ('mode 0400', tight400, None),
    ('over 256 bytes', oversize, None),
    ('foreign uid', FESZEK_FILE, foreign_uid),
    ('directory', KEYS, None),
)
for label, kf, extra in CASES:
    r = msg('feszek', kf, extra=extra)
    out = r.stdout + r.stderr
    check(f'msg: {label} -> unsigned send, OK id=7, one warning, no FAIL',
          r.returncode == 0 and r.stdout.startswith('OK id=7') and SEEN[0]['key'] is None and r.stderr.count(WARN) == 1
          and 'FAIL' not in out, repr(SEEN) + out)
    check(f'msg: {label} -> no key, no key-file path in the output or the curl argv',
          KEY_FESZEK not in out + argv_text() and kf not in out and 'mvak_' not in argv_text(), out)
    r = api(['directive-verify', '5'], kf, extra=extra)
    out = r.stdout + r.stderr
    check(f'api: {label} -> unsigned, exit 0, one warning',
          r.returncode == 0 and SEEN[0]['key'] is None and r.stderr.count(WARN) == 1, repr(SEEN) + out)
    check(f'api: {label} -> no key and no key-file path in the output', KEY_FESZEK not in out and kf not in out, out)

# a missing or unset file stays quiet (today's behaviour), and the good file is still accepted
r = msg('feszek', os.path.join(KEYS, 'does-not-exist'))
check('msg: a missing key file -> unsigned and NO warning', r.returncode == 0 and WARN not in r.stderr)
r = msg('feszek', FESZEK_FILE)
check('msg: the valid 0600 own file still signs, no warning',
      r.returncode == 0 and SEEN[0]['key'] == [KEY_FESZEK] and WARN not in r.stderr, repr(SEEN) + r.stderr)
r = api(['directive-verify', '5'], FESZEK_FILE)
check('api: the valid 0600 own file still signs, no warning',
      r.returncode == 0 and SEEN[0]['key'] == [KEY_FESZEK] and WARN not in r.stderr, repr(SEEN) + r.stderr)
# the key passes by stdin: still no key in any curl argv for the signed send
msg('feszek', FESZEK_FILE)
check('msg: the stdin header passing is kept (key absent from argv, present at the server)',
      SEEN[0]['key'] == [KEY_FESZEK] and KEY_FESZEK not in argv_text() and '-H\n@-' in argv_text(), argv_text())

srv.shutdown()
# cleanup via the tempdir module (the unreadable file is restored first so rmtree can walk it)
os.chmod(unreadable, stat.S_IRUSR | stat.S_IWUSR)
shutil.rmtree(SANDBOX, ignore_errors=True)
print(f'---- {N[0] - len(FAILS)}/{N[0]} passed')
sys.exit(1 if FAILS else 0)
