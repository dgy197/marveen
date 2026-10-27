#!/usr/bin/env bash
# preCheck wrapper a feszek-gmail-napi-triazs-hoz (fail-open).
python3 -I "$(dirname "$0")/feszek_gmail_triazs_precheck.py" 2>/dev/null || true
exit 0
