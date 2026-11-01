#!/usr/bin/env python3
"""The old inter-agent helpers carry the two fixes of scripts/agent-msg-close.sh (card d4be011e, from f137f980 B1/B3).

Covers scripts/agent-msg.sh, scripts/agent-msg-get.sh, scripts/marveen-api.sh and scripts/lib/marveen_api.py:
  - B1: every python3 call runs isolated (-I): a planted json.py / os.py / sys.py in the cwd and on PYTHONPATH never
    runs (marker file absent) and the call still works (homoglyph gate, signed send, body building, GET, API verb);
  - B3: the port from MARVEEN_WEB_PORT / WEB_PORT / .env is ASCII digits only, 1-65535, set-but-empty is an error;
    a bad one is refused with a clear message and a non-zero exit BEFORE any request, also when MARVEEN_API_BASE is
    set; 3420 and 65535 are accepted.

No dashboard is involved: the shell helpers run against a curl PATH shim that records its argv and answers 200 with an
id, the Python verb talks to a stub on an ephemeral loopback port (MARVEEN_API_BASE). This process refuses any
non-loopback connect and the live ports 18800/18899/3420 before the connect (Brainy 1769); the self-test uses its own
banned test port 18994.

Run:  python3 scripts/__tests__/agent-msg-isolation.test.py
"""
import http.server
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))

SELFTEST_PORT = 18994
_BANNED_PORTS = (18800, 18899, 3420, SELFTEST_PORT)
_real_connect = socket.socket.connect


def _guarded_connect(self, address):
    host, port = address[0], address[1]
    if host not in ('127.0.0.1', '::1', 'localhost') or port in _BANNED_PORTS:
        raise PermissionError(f'test guard: connect to {host}:{port} refused')
    return _real_connect(self, address)


socket.socket.connect = _guarded_connect
for _addr in (('127.0.0.1', SELFTEST_PORT), ('192.0.2.1', 80)):
    try:
        socket.socket().connect(_addr)
        raise SystemExit(f'guard self-test FAILED: a connect to {_addr} was not refused')
    except PermissionError:
        pass

FAILS = []
N = [0]
SEEN = []
TOKEN = 'test-token-0123456789'
KEY = 'mvak_ISOLkey0123456789abcdefghijklmnopqrstuvwx'


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
        SEEN.append({'method': self.command, 'path': self.path, 'key': self.headers.get_all('X-Agent-Key')})
        out = json.dumps({'id': 5, 'status': 'done', 'ok': True}).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    do_POST = do_GET = do_PUT = _answer

    def log_message(self, *a):
        pass


srv = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Stub)
STUB_PORT = srv.server_address[1]
assert STUB_PORT not in _BANNED_PORTS, 'ephemeral port collided with a banned port; rerun'
threading.Thread(target=srv.serve_forever, daemon=True).start()

SANDBOX = tempfile.mkdtemp(prefix='msgisol.')
INST = os.path.join(SANDBOX, 'install')
BIN = os.path.join(SANDBOX, 'bin')
KEYS = os.path.join(SANDBOX, 'keys')
PLANT = os.path.join(SANDBOX, 'plant')
for d in ('scripts/lib', 'store'):
    os.makedirs(os.path.join(INST, d))
for d in (BIN, KEYS, PLANT):
    os.makedirs(d)
for f in ('agent-msg.sh', 'agent-msg-get.sh', 'marveen-api.sh'):
    shutil.copy(os.path.join(ROOT, 'scripts', f), os.path.join(INST, 'scripts', f))
LIB_SRC = os.path.join(ROOT, 'scripts', 'lib')
for f in os.listdir(LIB_SRC):
    if f.endswith('.py'):
        shutil.copy(os.path.join(LIB_SRC, f), os.path.join(INST, 'scripts', 'lib', f))
with open(os.path.join(INST, 'store', '.dashboard-token'), 'w') as f:
    f.write(TOKEN + '\n')
TOKEN_FILE = os.path.join(INST, 'store', '.dashboard-token')
CURL_LOG = os.path.join(SANDBOX, 'curl.log')
MSG_FILE = os.path.join(SANDBOX, 'content.txt')
with open(MSG_FILE, 'w') as f:
    f.write('igor hex tiszta\n')
KEY_FILE = os.path.join(KEYS, 'iroda')
with open(KEY_FILE, 'w') as f:
    f.write(f'X-Agent-Key: {KEY}\n')
os.chmod(KEY_FILE, 0o600)

# curl shim: records that it ran (any argv), answers 200 with an id; honours -o like agent-msg-get.sh needs
with open(os.path.join(BIN, 'curl'), 'w') as f:
    f.write('''#!/usr/bin/env bash
out=""
printf 'CALL\\n' >> "$CURL_LOG"
while [ $# -gt 0 ]; do
  case "$1" in
    -o) out="$2"; shift 2; continue ;;
    http://*|https://*) printf '%s\\n' "$1" >> "$CURL_LOG" ;;
  esac
  shift
done
body='{"id":1,"status":"pending","content":"x","from_agent":"a","to_agent":"b"}'
if [ -n "$out" ]; then printf '%s' "$body" > "$out"; printf '200'; else printf '%s\\n200' "$body"; fi
''')
os.chmod(os.path.join(BIN, 'curl'), 0o755)
with open(os.path.join(BIN, 'sleep'), 'w') as f:
    f.write('#!/usr/bin/env bash\nexit 0\n')
os.chmod(os.path.join(BIN, 'sleep'), 0o755)

MARK = os.path.join(SANDBOX, 'PLANTED-RAN')
for mod in ('json.py', 'os.py', 'sys.py', 'mixed_script.py', 'marveen_api.py', 'homoglyph.py'):
    with open(os.path.join(PLANT, mod), 'w') as f:
        f.write(f'open({MARK!r}, "a").write("{mod}")\nraise SystemExit(99)\n')


def run(tool, args, extra=None, cwd=None, key=False, unset=('MARVEEN_WEB_PORT', 'WEB_PORT', 'MARVEEN_API_BASE')):
    """Runs a helper from the sandbox install in a clean environment; returns (proc, curl_calls)."""
    for p in (CURL_LOG, MARK):
        if os.path.exists(p):
            os.unlink(p)
    SEEN.clear()
    e = {'PATH': BIN + ':' + os.environ.get('PATH', '/usr/bin:/bin'), 'HOME': SANDBOX, 'TMPDIR': SANDBOX,
         'CURL_LOG': CURL_LOG, 'MARVEEN_TOKEN_FILE': TOKEN_FILE}
    if key:
        e['MARVEEN_AGENT_KEY_FILE'] = KEY_FILE
    for u in unset:
        e.pop(u, None)
    e.update(extra or {})
    if tool.endswith('.py'):
        cmd = [sys.executable, '-I', os.path.join(INST, 'scripts', 'lib', tool)] + args
    else:
        cmd = ['bash', os.path.join(INST, 'scripts', tool)] + args
    r = subprocess.run(cmd, env=e, capture_output=True, text=True, cwd=cwd or SANDBOX, timeout=60)
    calls = open(CURL_LOG).read().count('CALL') if os.path.exists(CURL_LOG) else 0
    return r, calls


# tool -> argument vector; the python verb needs the stub base (see below)
SHELL_TOOLS = (
    ('agent-msg.sh', ['igor', 'hex', 'tiszta']),
    ('agent-msg-get.sh', ['5']),
    ('marveen-api.sh message', ['message', 'igor', 'hex', MSG_FILE]),
)


def tool_run(label, extra=None, **kw):
    name = label.split()[0]
    args = dict(SHELL_TOOLS)[label]
    return run(name, args, extra=extra, **kw)


# ------------------------------------------------------------------ B3: the port table
BAD = (('1@attacker.local', '1@attacker.local'), ('3420/x', '3420/x'), ('empty', ''), ('99999', '99999'),
       ('leading space', ' 3420'), ('trailing space', '3420 '), ('zero', '0'), ('negative', '-1'),
       ('6 digits', '000001'), ('fullwidth digits', '３４２０'),
       ('Arabic-Indic digits', '٣٤٢٠'), ('plus sign', '+3420'), ('hex', '0x10'))
for label, _ in SHELL_TOOLS:
    for var in ('MARVEEN_WEB_PORT', 'WEB_PORT'):
        for what, val in BAD:
            r, calls = tool_run(label, extra={var: val})
            check(f'{label}: {var}={what!r} refused (rc != 0, curl never called)',
                  r.returncode != 0 and calls == 0 and 'port' in r.stderr and 'FAIL' in r.stderr, f'rc={r.returncode} calls={calls} {r.stdout}{r.stderr}')
        # also with a loopback MARVEEN_API_BASE set (the port was not checked then before)
        r, calls = tool_run(label, extra={var: '1@attacker.local', 'MARVEEN_API_BASE': f'http://127.0.0.1:{STUB_PORT}'})
        check(f'{label}: {var} bad is refused even with MARVEEN_API_BASE set',
              r.returncode != 0 and calls == 0 and 'port' in r.stderr, f'rc={r.returncode} calls={calls} {r.stdout}{r.stderr}')
    for val in ('3420', '65535', '1'):
        r, calls = tool_run(label, extra={'MARVEEN_WEB_PORT': val})
        check(f'{label}: MARVEEN_WEB_PORT={val} accepted (one curl call to http://localhost:{val}/)',
              r.returncode == 0 and calls == 1 and f'http://localhost:{val}/' in open(CURL_LOG).read(), f'rc={r.returncode} {r.stdout}{r.stderr}')
    # .env source
    env_path = os.path.join(INST, '.env')
    for val, ok in (('1@attacker.local', False), ('', False), ('99999', False), ('"3420"', True)):
        with open(env_path, 'w') as f:
            f.write(f'WEB_PORT={val}\n')
        r, calls = tool_run(label)
        check(f'{label}: .env WEB_PORT={val!r} {"accepted" if ok else "refused"}',
              (r.returncode == 0 and calls == 1) if ok else (r.returncode != 0 and calls == 0), f'rc={r.returncode} calls={calls} {r.stdout}{r.stderr}')
    os.unlink(env_path)
    r, calls = tool_run(label)
    check(f'{label}: nothing set -> the 3420 default', r.returncode == 0 and 'http://localhost:3420/' in open(CURL_LOG).read())

# the Python verb: refused before any request (the stub sees nothing), also with a loopback base set
BASE = f'http://127.0.0.1:{STUB_PORT}'
for var in ('MARVEEN_WEB_PORT', 'WEB_PORT'):
    for what, val in BAD:
        r, _ = run('marveen_api.py', ['directive-verify', '5'], extra={var: val, 'MARVEEN_API_BASE': BASE})
        check(f'marveen_api.py: {var}={what!r} refused, exit 2, no request',
              r.returncode == 2 and SEEN == [] and 'port' in r.stderr, f'rc={r.returncode} seen={SEEN} {r.stderr}')
        r, _ = run('marveen-api.sh', ['directive-verify', '5'], extra={var: val, 'MARVEEN_API_BASE': BASE})
        check(f'marveen-api.sh directive-verify: {var}={what!r} refused, no request',
              r.returncode == 2 and SEEN == [], f'rc={r.returncode} seen={SEEN} {r.stderr}')
r, _ = run('marveen_api.py', ['directive-verify', '5'], extra={'MARVEEN_WEB_PORT': '3420', 'MARVEEN_API_BASE': BASE})
check('marveen_api.py: a valid port with the stub base is accepted and the request goes to the stub',
      r.returncode == 0 and len(SEEN) == 1, f'rc={r.returncode} seen={SEEN} {r.stderr}')
# web_port() itself, without any request: 3420 and 65535 accepted, the .env source, no isolation break
PROBE = ('import importlib.util, sys\n'
         'spec = importlib.util.spec_from_file_location("m", sys.argv[1])\n'
         'm = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)\n'
         'print(m.web_port()[0] or "ERR")\n')
for val, want in (('3420', '3420'), ('65535', '65535'), ('65536', 'ERR'), ('３４２０', 'ERR'), ('', 'ERR')):
    e = {'PATH': os.environ.get('PATH', '/usr/bin:/bin'), 'HOME': SANDBOX, 'MARVEEN_WEB_PORT': val}
    r = subprocess.run([sys.executable, '-I', '-c', PROBE, os.path.join(INST, 'scripts', 'lib', 'marveen_api.py')],
                       env=e, capture_output=True, text=True, cwd=SANDBOX, timeout=30)
    check(f'web_port(): MARVEEN_WEB_PORT={val!r} -> {want}', r.stdout.strip() == want, r.stdout + r.stderr)
with open(os.path.join(INST, '.env'), 'w') as f:
    f.write('WEB_PORT=3555\n')
e = {'PATH': os.environ.get('PATH', '/usr/bin:/bin'), 'HOME': SANDBOX}
r = subprocess.run([sys.executable, '-I', '-c', PROBE, os.path.join(INST, 'scripts', 'lib', 'marveen_api.py')],
                   env=e, capture_output=True, text=True, cwd=SANDBOX, timeout=30)
check('web_port(): the .env WEB_PORT is the third source', r.stdout.strip() == '3555', r.stdout + r.stderr)
os.unlink(os.path.join(INST, '.env'))

# ------------------------------------------------------------------ B1: planted modules never run
PX = {'PYTHONPATH': PLANT}
r, calls = run('agent-msg.sh', ['igor', 'hex', 'tiszta'], extra=PX, cwd=PLANT, key=True)
check('agent-msg.sh: planted json/os/sys/mixed_script in cwd + PYTHONPATH: marker absent', not os.path.exists(MARK),
      open(MARK).read() if os.path.exists(MARK) else '')
check('agent-msg.sh: still works under -I (homoglyph gate, body, id parse): OK id=1, one curl call',
      r.returncode == 0 and r.stdout.startswith('OK id=1') and calls == 1, f'rc={r.returncode} {r.stdout}{r.stderr}')
check('agent-msg.sh: the homoglyph gate still refuses a contaminated text under -I',
      run('agent-msg.sh', ['igor', 'hex', 'pаssword'], extra=PX, cwd=PLANT)[0].returncode == 3)
check('agent-msg.sh: the send key line was read under -I (no unsigned note, no warning)',
      'WARN' not in r.stderr, r.stderr)
r, calls = run('agent-msg-get.sh', ['5'], extra=PX, cwd=PLANT)
check('agent-msg-get.sh: planted modules never run, still prints the message',
      not os.path.exists(MARK) and r.returncode == 0 and '# msg 1' in r.stdout, f'rc={r.returncode} {r.stdout}{r.stderr}')
r, calls = run('marveen-api.sh', ['message', 'igor', 'hex', MSG_FILE], extra=PX, cwd=PLANT)
check('marveen-api.sh message: planted modules never run, still sends',
      not os.path.exists(MARK) and r.returncode == 0 and r.stdout.startswith('OK id=1'), f'rc={r.returncode} {r.stdout}{r.stderr}')
r, _ = run('marveen-api.sh', ['directive-verify', '5'], extra={**PX, 'MARVEEN_API_BASE': BASE}, cwd=PLANT, key=True)
check('marveen-api.sh verb: planted modules never run, the request reaches the stub signed',
      not os.path.exists(MARK) and r.returncode == 0 and len(SEEN) == 1 and SEEN[0]['key'] == [KEY], f'rc={r.returncode} seen={SEEN} {r.stderr}')

# ------------------------------------------------------------------ static: every python3 call carries -I
for f in ('agent-msg.sh', 'agent-msg-get.sh', 'marveen-api.sh'):
    src = open(os.path.join(ROOT, 'scripts', f)).read()
    bad = [l for l in src.splitlines()
           if 'python3' in l and not l.lstrip().startswith('#') and 'command -v python3' not in l
           and l.count('python3') != len(re.findall(r'python3 -I\b', l))]
    check(f'static: every python3 call in {f} carries -I', not bad, repr(bad))
for f in sorted(os.listdir(os.path.join(ROOT, 'scripts'))):
    if f.startswith('agent-msg') and f.endswith('.sh'):
        src = open(os.path.join(ROOT, 'scripts', f)).read()
        bad = [l for l in src.splitlines()
               if 'python3' in l and not l.lstrip().startswith('#') and 'command -v python3' not in l
               and l.count('python3') != len(re.findall(r'python3 -I\b', l))]
        check(f'static: every python3 call in scripts/{f} carries -I (sibling sweep)', not bad, repr(bad))

srv.shutdown()
shutil.rmtree(SANDBOX, ignore_errors=True)
print(f'---- {N[0] - len(FAILS)}/{N[0]} passed')
sys.exit(1 if FAILS else 0)
