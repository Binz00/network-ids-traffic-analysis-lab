#!/usr/bin/env bash
# Count Suricata alerts by signature (most frequent first).
# Usage: sudo ./suricata-alert-summary.sh [path/to/fast.log]
LOG="${1:-/var/log/suricata/fast.log}"
awk -F'\\[\\*\\*\\]' '{print $2}' "$LOG" | sort | uniq -c | sort -rn
