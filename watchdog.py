#!/usr/bin/env python3
import subprocess, sys, time
from collections import deque
from datetime import datetime, timedelta

# Filter for likely security-related log lines
predicate = 'eventMessage CONTAINS[c] "Failed password" OR eventMessage CONTAINS[c] "Accepted " OR process == "sshd" OR process == "sudo" OR eventMessage CONTAINS[c] "SENTINEL_TEST"'
cmd = ["log", "stream", "--style", "syslog", "--predicate", predicate]

# Burst detection settings
WINDOW_SECONDS = 60
THRESHOLD = 5

# Queue of timestamps for recent failures
fails = deque()
start_ts = datetime.now()  # mark when script started
WARMUP_SECONDS = 3  # ignore initial backlog for 3 seconds


def prune(now):
    cutoff = now - timedelta(seconds=WINDOW_SECONDS)
    while fails and fails[0] < cutoff:
        fails.popleft()

with subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1) as proc:
    try:
        for line in proc.stdout:
            line = line.rstrip()
            now = datetime.now()

            # Track failure events
            counting_enabled = (now - start_ts).total_seconds() >= WARMUP_SECONDS
            if "Failed password" in line and counting_enabled:
                fails.append(now)
                prune(now)
                if len(fails) >= THRESHOLD:
                    print(f"ALERT: Fail burst detected — {len(fails)} failures within {WINDOW_SECONDS}s")
                    fails.clear()  # simple cooldown

            if ("Failed password" in line) or ("Accepted " in line) or (" sshd[" in line) or (" sudo" in line) or ("SENTINEL_TEST" in line):
                print(line)

    except KeyboardInterrupt:
        print("\nStopped.")
        sys.exit(0)
