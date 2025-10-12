#!/usr/bin/env python3
import subprocess, sys

# Filter for likely security-related log lines
predicate = 'process == "sshd" OR process == "sudo" OR eventMessage CONTAINS[c] "Failed" OR eventMessage CONTAINS[c] "Accepted" OR eventMessage CONTAINS[c] "SENTINEL_TEST"'
cmd = ["log", "stream", "--style", "syslog", "--predicate", predicate]

with subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1) as proc:
    try:
        for line in proc.stdout:
            print(line.rstrip())
    except KeyboardInterrupt:
        print("\nStopped.")
        sys.exit(0)
