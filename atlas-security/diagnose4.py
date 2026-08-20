#!/usr/bin/env python3
"""Test journal access as atlas-security user (run inside the service context)."""
import subprocess, os, sys

print(f"User: {os.getuid()}, Groups: {os.getgroups()}")

cmd = ["journalctl", "--follow", "--output=json", "--no-pager", "-q",
       "-u", "ssh.service", "-u", "sshd.service", "-k", "--since", "5 min ago"]
proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                        text=False, bufsize=0)
print(f"Started journalctl pid={proc.pid}")

fd = proc.stdout.fileno()
os.set_blocking(fd, False)

import select
print("Waiting 8 seconds for data...")
got_data = False
for i in range(80):
    readable, _, _ = select.select([fd], [], [], 0.1)
    if readable:
        chunk = os.read(fd, 8192)
        if chunk:
            got_data = True
            lines = chunk.decode("utf-8", errors="replace").split("\n")
            for line in lines:
                line = line.strip()
                if line:
                    print(f"  GOT: {line[:120]}")

if not got_data:
    print("  No data received in 8 seconds")
    # Check stderr
    import select as sel2
    _, stderr_read, _ = sel2.select([proc.stderr.fileno()], [], [], 0.1)
    if stderr_read:
        err = os.read(proc.stderr.fileno(), 4096)
        print(f"  STDERR: {err.decode('utf-8', errors='replace')[:200]}")

proc.terminate()
proc.wait(timeout=5)
