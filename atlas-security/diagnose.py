#!/usr/bin/env python3
"""Diagnostic script to test journal parsing."""
import subprocess
import json
import sys

cmd = ["journalctl", "--output=json", "--no-pager", "-q",
       "-u", "ssh.service", "-u", "sshd.service",
       "-u", "fail2ban.service", "-u", "nginx.service",
       "-k", "--since", "10 min ago"]

print(f"Running: {' '.join(cmd)}")
proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
lines = proc.stdout.strip().split("\n")
print(f"Got {len(lines)} lines")

for line in lines[:5]:
    if not line.strip():
        continue
    try:
        entry = json.loads(line)
        unit = entry.get("_SYSTEMD_UNIT", "none")
        comm = entry.get("_COMM", "none")
        msg = entry.get("MESSAGE", "")[:100]
        print(f"  unit={unit} comm={comm} msg={msg}")
    except json.JSONDecodeError as e:
        print(f"  JSON error: {e}")

sys.path.insert(0, "/opt/atlas")
from security.parsers.journald import parse_journald_entry
hostname = "debian"
total_events = 0
for line in lines:
    if not line.strip():
        continue
    try:
        entry = json.loads(line)
        events = parse_journald_entry(entry, hostname)
        total_events += len(events)
        if events:
            for ev in events:
                print(f"  PARSED: {ev.event_type} {ev.severity} {ev.message[:80]}")
    except Exception as e:
        print(f"  Parse error: {e}")

print(f"\nTotal parsed events: {total_events}")
