#!/usr/bin/env python3
"""Quick test: run journalctl and check output."""
import subprocess

# Test as root (via sudo)
r = subprocess.run(
    ["journalctl", "--output=json", "--no-pager", "-q",
     "-u", "ssh.service", "--since", "10 min ago"],
    capture_output=True, text=True, timeout=10
)
print(f"Root: stdout={len(r.stdout)} bytes, stderr={len(r.stderr)} bytes")
if r.stdout:
    lines = r.stdout.strip().split("\n")
    print(f"  {len(lines)} lines")
    for l in lines[:3]:
        print(f"  {l[:150]}")
else:
    print(f"  Empty stdout. stderr: {r.stderr[:200]}")

# Test with --follow (what the collector uses)
r2 = subprocess.run(
    ["journalctl", "--output=json", "--no-pager", "-q",
     "-u", "ssh.service", "-k", "--since", "2 min ago"],
    capture_output=True, text=True, timeout=5
)
print(f"\nFollow mode: stdout={len(r2.stdout)} bytes, stderr={len(r2.stderr)} bytes")
if r2.stdout:
    lines = r2.stdout.strip().split("\n")
    print(f"  {len(lines)} lines")
    for l in lines[:3]:
        print(f"  {l[:150]}")
