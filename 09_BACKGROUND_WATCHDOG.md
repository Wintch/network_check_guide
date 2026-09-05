# Background Watchdog: Catch It in Days, Not Months

`06_CASE_STUDY_2026-09-05.md` took **3 months** to notice because nobody was looking at the
*pattern* of gateway pings or retransmit counters continuously — only when something already
felt wrong. `scripts/net_watchdog.py` runs the same class of checks from `03_`, `04_`, and
`05_` unattended, for a bounded window, on a recurring schedule, and alerts you the moment it
sees the same signatures that took months to find manually last time.

It is **read-only by default** (ping, `ss -tin`, `iw`, `/sys/class/net/*` reads) — the one
optional exception is `--capture-on-anomaly`, covered in section 4.

## 1. What it actually detects

| Check | Signature it's looking for | Same as |
|---|---|---|
| Continuous gateway ping (`ping -D`) | A single gap larger than `--ping-gap-threshold` (default 1.5s) | `03_WIRED_AND_GATEWAY.md` §2 |
| Ping gap **periodicity** | Several gaps recurring at a regular interval (±25%) | The exact case-study root cause — `03_WIRED_AND_GATEWAY.md` §2/§4 |
| `ss -tin` on tracked hosts | `bytes_retrans` growing for N consecutive samples (default 3) | `05_AI_WORKLOAD_AND_LATENCY.md` |
| Wi-Fi (if a wireless iface is in use) | Signal below `--wifi-signal-threshold` (default -70 dBm), or a burst of new `tx failed` | `04_WIFI.md` §1-2 |
| NIC carrier flap | `/sys/class/net/<iface>/carrier_changes` increases during the run | `03_WIRED_AND_GATEWAY.md` §1 |

Every sample is appended to a JSONL event log; every anomaly is appended to a plain
`alerts.log` (one JSON object per line, human-readable) and, if `notify-send` is available,
raises a desktop notification immediately — you don't have to go looking for it.

## 2. Running it once, by hand

```bash
python3 scripts/net_watchdog.py --duration 300 --hosts api.anthropic.com
```

- `--hosts` is a comma-separated list of hostnames/IPs you actually have (or expect to have)
  live connections to — an AI API host, a work VPN endpoint, whatever this machine's
  long-lived low-latency traffic actually goes to. Without it, the ping-gap/Wi-Fi/carrier
  checks still run, just not the retransmit tracking.
- Gateway and primary interface are auto-detected (`ip route get 8.8.8.8`); a Wi-Fi interface
  is auto-detected as wireless if `--iface` (or the auto-detected one) has
  `/sys/class/net/<iface>/wireless` or `/phy80211`.
- Logs land in `~/.local/state/net_watchdog/` by default (`--log-dir` to change it):
  `events_<run>.jsonl` (every sample), `alerts.log` (append-only, all runs), `summary_<run>.json`
  (verdict + full anomaly list for that run).
- Exit code is `0` if clean, `1` if any anomaly fired — useful if you want to wire this into
  something else (a cron mail, a status check) beyond the notification.

## 3. Running it on a schedule (recommended path)

The point isn't to run this 24/7 — a lightweight periodic burst (e.g. 20 minutes every 3
days) is enough to catch a chronic problem in days instead of months, without leaving
anything running all the time. Install the provided user-level systemd timer:

```bash
mkdir -p ~/.config/systemd/user
cp scripts/net-watchdog.service scripts/net-watchdog.timer ~/.config/systemd/user/
# edit the ExecStart line in net-watchdog.service: set --hosts to what you care about
systemctl --user daemon-reload
systemctl --user enable --now net-watchdog.timer
systemctl --user list-timers net-watchdog.timer   # confirm next run time
```

This runs as a **user** unit (no root needed) so `notify-send` reaches your actual desktop
session. Default schedule is every 3 days at 04:00 local time, ±30 min jitter
(`RandomizedDelaySec`), with `Persistent=true` so a run that was missed because the machine
was off/asleep fires shortly after the next boot instead of silently skipping. Adjust
`OnCalendar` in the `.timer` file to taste (`man systemd.time`).

Check results any time without waiting for a notification:

```bash
tail -f ~/.local/state/net_watchdog/alerts.log        # live-tail alerts across all runs
journalctl --user -u net-watchdog.service --no-pager -n 50   # last run's console output
```

## 4. Optional: capture-on-anomaly (the "sniffer" part)

You don't need raw packet capture for the retransmit/gap detection above — the kernel's own
`ss -tin` counters and ping timing already give you that, no `tcpdump` required. But if you
want a **pcap saved automatically the moment an anomaly fires** (useful for forensic detail
beyond what the counters show — e.g. actually seeing what traffic was in flight during a
periodic gap), pass `--capture-on-anomaly`:

```bash
python3 scripts/net_watchdog.py --duration 1200 --hosts api.anthropic.com --capture-on-anomaly
```

This needs `tcpdump` installed and capture permission. Rather than running the whole
watchdog as root, grant `tcpdump` itself the specific capability it needs, once:

```bash
sudo setcap cap_net_raw,cap_net_admin=eip "$(which tcpdump)"
```

On the first anomaly of a run, it spawns `tcpdump -i <iface> -w <path> -G <capture-seconds> -W 1`
(default 15s window) and records the pcap path in that run's `alerts.log` entry and
`summary_<run>.json`. Only one capture per run — it won't spam captures for every subsequent
alert in the same window. Inspect the result with `tcpdump -r <file>` or Wireshark.

## 5. Safety notes

- Everything except the optional capture is read-only diagnostics — same posture as the rest
  of this guide (see `02_TOOLS.md`).
- The capture writes a bounded, time-limited pcap file to your own log directory — nothing is
  sent anywhere. Delete old captures/logs under `~/.local/state/net_watchdog/` whenever; the
  script doesn't rotate them for you.
- If a run finds something, don't act on it inside the watchdog — go to the relevant guide
  file (`03_`/`04_`/`05_`) and follow the actual diagnostic steps there. This tool's job is
  only to make sure you find out *promptly*, not to fix anything automatically.
