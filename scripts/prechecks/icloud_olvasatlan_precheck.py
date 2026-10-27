#!/usr/bin/env python3
"""preCheck az icloud-olvasatlan-körhöz (token-optimalizáció, Gyuri 2026-10-11).
Ha az iCloud INBOX-ban nincs olvasatlan levél, stdout "SKIP" (a modell-kör kimarad).
Bármilyen hiba => nincs kimenet => a kör lefut (fail-open). A jelszó a Vaultból jön, nem íródik ki."""
import imaplib, json, urllib.request, urllib.parse
try:
    tok = open('/Users/gyorgydecsi/marveen/store/.dashboard-token').read().strip()
    d = json.load(urllib.request.urlopen(urllib.request.Request(
        'http://localhost:3420/api/vault/' + urllib.parse.quote('APPLE APP SPECIFIKUS PASS'),
        headers={'Authorization': 'Bearer ' + tok}), timeout=10))
    M = imaplib.IMAP4_SSL('imap.mail.me.com', 993, timeout=30)
    M.login('decsi@me.com', d.get('value'))
    M.select('INBOX', readonly=True)
    typ, data = M.search(None, 'UNSEEN')
    M.logout()
    if typ == 'OK' and not (data[0] or b'').split():
        print('SKIP')
except Exception:
    pass
