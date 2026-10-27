#!/usr/bin/env bash
# preCheck wrapper a kanban-audithoz (fail-open: indítási hiba esetén a kör lefut).
python3 "$(dirname "$0")/kanban_audit_precheck.py" 2>/dev/null || true
exit 0
