#!/usr/bin/env python3
"""Kontextus-profil előszűrő (Gyuri, 2026-10-11, Telegram 1395).

Feladat-indításkor eldönti, hogy egy Opus-ügynök (tuzvedelem, paragrafus) KÖNNYŰ vagy MÉLY
kontextusos módban dolgozzon, és ennek megfelelően átállítja a kontextus-őrét
(PUT /api/agents/<id>/context-guard; az őr minden körben újraolvassa).

  könnyű: limitTokens 300k (az átadás ~195k-nál), idle-flush 120k / 20 perc
  mély:   limitTokens nincs (1M, az átadás ~650k-nál), idle-flush 450k / 90 perc, 8 óra lejárattal

Használat:
  kontextus-profil.py <ugynok> [--feladat "szöveg"] [fájl|mappa ...]   becslés + beállítás
  kontextus-profil.py <ugynok> --profil konnyu|mely [--ok "miért"]     kézi beállítás
  kontextus-profil.py <ugynok> --vege                                  vissza könnyűre (feladat vége)
  kontextus-profil.py --lejart                                         lejárt mély profilok visszaállítása
  kontextus-profil.py --allapot                                        jelenlegi profilok
  --dry: csak kiírja a döntést, nem állít semmit.
A becslés determinisztikus (szövegkinyerés + karakterszám), modellt nem hív."""
import json, os, re, subprocess, sys, time, urllib.request

ROOT = '/Users/gyorgydecsi/marveen'
STATE = f'{ROOT}/store/kontextus-profil.json'
LOG = f'{ROOT}/store/kontextus-profil.log'
API = 'http://localhost:3420'
UGYNOKOK = ('tuzvedelem', 'paragrafus')
MELY_TTL_S = 8 * 3600

PROFILOK = {
    'konnyu': {'limitTokens': 300_000, 'idleFlushTokens': 120_000, 'idleMinutes': 20},
    'mely': {'limitTokens': None, 'idleFlushTokens': 450_000, 'idleMinutes': 90},
}
# Döntési küszöbök
MELY_TOKEN = 80_000      # becsült anyag-token ettől mély
MELY_DOKUMENTUM = 6      # ennyi olvasható dokumentumtól mély (keresztolvasás)
CHARS_PER_TOKEN = 3.2    # magyar szöveg, óvatos becslés
KEP_TOKEN = 1_600        # egy kép / szkennelt oldal
MAX_FAJL = 500

MELY_SZAVAK = ('tervellenőrz', 'felülvizsgál', 'szakvélemény', 'teljes dokumentáció', 'teljes tervdokumentáció',
               'összevet', 'összehasonlít', 'szerződéscsomag', 'ászf', 'vitás', 'per ', 'peres', 'tervfejezet',
               'kiürítés', 'szimuláció', 'tvmi', 'auditál', 'átvilágít', 'minden dokumentum')
SZOVEG_EXT = {'.txt', '.md', '.csv', '.json', '.html', '.htm', '.xml', '.eml', '.log', '.yaml', '.yml'}
TEXTUTIL_EXT = {'.docx', '.doc', '.rtf', '.odt', '.rtfd', '.webarchive'}
KEP_EXT = {'.jpg', '.jpeg', '.png', '.heic', '.tif', '.tiff', '.webp'}


def api(method, path, body=None):
    tok = open(f'{ROOT}/store/.dashboard-token').read().strip()
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(API + path, data=data, method=method,
                                 headers={'Authorization': f'Bearer {tok}', 'Content-Type': 'application/json'})
    return json.load(urllib.request.urlopen(req, timeout=15))


def run(cmd):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=120).stdout
    except Exception:
        return ''


def fajl_token(p):
    """(token, olvasható?) egy fájlra."""
    ext = os.path.splitext(p)[1].lower()
    try:
        meret = os.path.getsize(p)
    except OSError:
        return 0, False
    if ext == '.pdf':
        m = re.search(r'Pages:\s+(\d+)', run(['pdfinfo', p]))
        oldal = int(m.group(1)) if m else 0
        szoveg = run(['pdftotext', '-l', '400', '-q', p, '-'])
        tok = len(szoveg) / CHARS_PER_TOKEN
        if oldal and len(szoveg.strip()) < 200 * oldal:  # szkennelt / rajz: képként számol
            tok = max(tok, oldal * KEP_TOKEN)
        return int(tok), True
    if ext in TEXTUTIL_EXT:
        return int(len(run(['textutil', '-convert', 'txt', '-stdout', p])) / CHARS_PER_TOKEN), True
    if ext in SZOVEG_EXT:
        return int(meret / CHARS_PER_TOKEN), True
    if ext in ('.xlsx', '.xls', '.ods'):
        return int(min(meret, 2_000_000) / 6), True  # tömörített: durva felső becslés
    if ext in KEP_EXT:
        return KEP_TOKEN, True
    return 0, False  # dwg, zip, stb.: a modell nem olvassa közvetlenül


def becsles(utak):
    fajlok = []
    for u in utak:
        if os.path.isdir(u):
            for gy, mappak, nevek in os.walk(u):
                mappak[:] = [m for m in mappak if not m.startswith('.')]
                fajlok += [os.path.join(gy, n) for n in nevek if not n.startswith('.')]
                if len(fajlok) >= MAX_FAJL:
                    break
        elif os.path.exists(u):
            fajlok.append(u)
        else:
            print(f'figyelem: nem létezik: {u}', file=sys.stderr)
    fajlok = fajlok[:MAX_FAJL]
    ossz, olvashato, kihagyott = 0, 0, 0
    for f in fajlok:
        t, ok = fajl_token(f)
        ossz += t
        olvashato += ok
        kihagyott += not ok
        if ossz >= MELY_TOKEN:  # a döntés már eldőlt: nem olvassuk végig a nagy mappát
            return {'fajl': len(fajlok), 'olvashato': olvashato, 'kihagyott': kihagyott,
                    'becsult_token': ossz, 'reszleges': True}
    return {'fajl': len(fajlok), 'olvashato': olvashato, 'kihagyott': kihagyott, 'becsult_token': ossz}


def dontes(b, feladat):
    szavak = [s for s in MELY_SZAVAK if s in (feladat or '').lower()]
    if b['becsult_token'] >= MELY_TOKEN:
        elo = 'legalább ' if b.get('reszleges') else 'kb. '
        return 'mely', f"az anyag {elo}{b['becsult_token'] // 1000}k token (küszöb {MELY_TOKEN // 1000}k)"
    if b['olvashato'] >= MELY_DOKUMENTUM:
        return 'mely', f"{b['olvashato']} dokumentum keresztolvasása (küszöb {MELY_DOKUMENTUM})"
    if b['fajl'] == 0 and szavak:
        return 'mely', f"nincs megadott anyag, de a feladat jellege mély: {', '.join(szavak)}"
    return 'konnyu', f"az anyag kb. {b['becsult_token'] // 1000}k token, {b['olvashato']} dokumentum"


def allapot_olvas():
    try:
        return json.load(open(STATE))
    except Exception:
        return {}


def beallit(ugynok, profil, ok, extra=None, dry=False):
    cfg = api('GET', f'/api/agents/{ugynok}/context-guard')['contextGuard']
    uj = {**cfg, **PROFILOK[profil]}
    most = int(time.time())
    bejegyzes = {'profil': profil, 'ok': ok, 'ota': most,
                 'lejar': most + MELY_TTL_S if profil == 'mely' else None, **(extra or {})}
    if dry:
        print(json.dumps({'ugynok': ugynok, 'dry': True, **bejegyzes}, ensure_ascii=False))
        return
    mentett = api('PUT', f'/api/agents/{ugynok}/context-guard', uj)['contextGuard']
    for k, v in PROFILOK[profil].items():  # visszaolvasás
        if mentett.get(k) != v:
            sys.exit(f'HIBA: a {k} visszaolvasva {mentett.get(k)!r}, várt {v!r}')
    st = allapot_olvas()
    st[ugynok] = bejegyzes
    tmp = STATE + '.tmp'
    json.dump(st, open(tmp, 'w'), ensure_ascii=False, indent=2)
    os.replace(tmp, STATE)
    with open(LOG, 'a') as f:
        f.write(json.dumps({'ts': most, 'ugynok': ugynok, **bejegyzes}, ensure_ascii=False) + '\n')
    print(f"OK {ugynok}: {profil.upper()} ({ok})")


def main(argv):
    dry = '--dry' in argv
    argv = [a for a in argv if a != '--dry']
    if not argv or argv[0] in ('-h', '--help'):
        print(__doc__)
        return
    if argv[0] == '--allapot':
        print(json.dumps(allapot_olvas(), ensure_ascii=False, indent=2))
        return
    if argv[0] == '--lejart':
        # preCheck-ből fut: soha nem ébreszt modellt (mindig SKIP), csak visszaállít.
        try:
            for u, e in allapot_olvas().items():
                if e.get('profil') == 'mely' and e.get('lejar') and e['lejar'] < time.time():
                    beallit(u, 'konnyu', 'a mély profil 8 órás lejárata letelt', dry=dry)
        finally:
            print('SKIP')
        return
    ugynok, rest = argv[0], argv[1:]
    if ugynok not in UGYNOKOK:
        print(f'figyelem: {ugynok} nincs a profilozott ügynökök között ({", ".join(UGYNOKOK)})', file=sys.stderr)
    if '--vege' in rest:
        beallit(ugynok, 'konnyu', 'feladat vége', dry=dry)
        return
    feladat, ok, profil, utak = '', None, None, []
    i = 0
    while i < len(rest):
        a = rest[i]
        if a in ('--feladat', '--ok', '--profil') and i + 1 < len(rest):
            val = rest[i + 1]
            if a == '--feladat':
                feladat = val
            elif a == '--ok':
                ok = val
            else:
                profil = {'konnyu': 'konnyu', 'könnyű': 'konnyu', 'mely': 'mely', 'mély': 'mely'}.get(val)
                if not profil:
                    sys.exit('a --profil értéke konnyu vagy mely')
            i += 2
            continue
        utak.append(a)
        i += 1
    if profil:
        beallit(ugynok, profil, ok or 'kézi beállítás', dry=dry)
        return
    b = becsles(utak)
    profil, ok = dontes(b, feladat)
    beallit(ugynok, profil, ok, extra={'becsles': b, 'feladat': feladat[:200]}, dry=dry)


if __name__ == '__main__':
    main(sys.argv[1:])
