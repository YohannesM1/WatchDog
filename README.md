# WatchDog

WatchDog is a small side project I’m building to learn more about log monitoring and basic threat detection.

The goal is simple: read system logs in real time and print alerts if something suspicious happens (like too many failed logins).

Right now it only supports macOS (using the `log stream` command), but I’m planning to add Linux support soon.

---

## Current Features

- Streams macOS logs live
- Filters for lines that look security-related (`Failed`, `Accepted`, `sudo`, etc.)
- Burst detection: alerts if 5+ "Failed password" lines appear within 60 seconds (with warm-up to avoid startup noise)

---

## How to Run (macOS)

```bash
python3 watchdog.py
