#!/usr/bin/env bash
# preCheck wrapper az icloud-olvasatlan-körhöz (fail-open).
python3 "$(dirname "$0")/icloud_olvasatlan_precheck.py" 2>/dev/null || true
exit 0
