#!/usr/bin/env python3
"""Test if atlas-security user can read journal via subprocess."""
import subprocess, json, time, sys

# Simulate what the collector does
cmd = [
    "journalctl", "--follow", "--output=json", "--no-pager", "-q",
    "-u", "ssh.service", "-u", "sshd.service", "-u", "fail2ban.service",
    "-u", "nginx.service", "-k"
]
print(f"Starting: {' '.join(cmd)}")
proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                        text=True, bufsize=1)
print(f"Started with pid={proc.pid}")

import select
print("Waiting for data (10 seconds)...")

for i in range(100):
    readable, _, _ = select.select([proc.stdout], [], [], 0.1)
    if readable:
        line = proc.stdout.readline()
        if line:
            try:
                entry = json.loads(line.strip())
                unit = entry.get("_SYSTEMD_UNIT", "?")
                msg = entry.get("MESSAGE", "?")[:100]
                print(f"  [{i}] unit={unit} msg={msg}")
            except:
                print(f"  [{i}] raw: {line[:100]}")
    # Print a heartbeat every 2 seconds
    if i % 20 == 0:
        print(f"  ... waiting ({i/10:.0f}s)")

proc.terminate()
proc.wait(timeout=5)
print("Done")
