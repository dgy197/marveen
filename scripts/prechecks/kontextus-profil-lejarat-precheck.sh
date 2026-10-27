#!/usr/bin/env bash
# preCheck: a lejárt (8 óránál régebbi) MÉLY kontextus-profilokat visszaállítja könnyűre.
# Modellt soha nem ébreszt: a szkript mindig SKIP-et ír (hiba esetén is).
python3 "$(dirname "$0")/../kontextus-profil.py" --lejart 2>>/Users/gyorgydecsi/marveen/store/kontextus-profil.log | grep -x SKIP || echo SKIP
exit 0
