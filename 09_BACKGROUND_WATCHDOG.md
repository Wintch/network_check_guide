# Background Watchdog: Catch It in Days, Not Months

Periodic micro-outages (a gateway that stalls for a second every half minute, a link that
flaps every few hours) are easy to live with for months, because nobody watches the *pattern*
of gateway pings or retransmit counters continuously. People only look when something already
feels wrong. `scripts/net_watchdog.py` runs the same class of checks from `03_`, `04_`, and
`05_` unattended, for a bounded window, on a recurring schedule, and alerts you the moment it
sees those signatures. (`06_CASE_STUDY_PERIODIC_OUTAGE.md` is a worked example of this kind of
long-hidden periodic fault.)

A note on terminology: in this guide, "the watchdog" means this monitoring script,
`net_watchdog.py`. `03_` and `06_` also discuss a *different* kind of watchdog, a script or
cron job that resets a network interface when its own health check fails. That one is
something to audit, not something this document installs.

It is **read-only by default** (ping, `ss -tin`, `iw`, `/sys/class/net/*` reads) — the one
optional exception is `--capture-on-anomaly`, covered in section 4.

## The three modes at a glance

`net_watchdog.py` has a `--mode` switch. Each mode answers a different question, and they are
independent (a hard switch, not additive flags):

| `--mode` | Question it answers | Documented in |
|---|---|---|
| `stability` (default) | Is this link healthy over time? Gateway ping gaps, TCP retransmit growth, Wi-Fi quality, carrier flaps | **This file** |
| `telemetry` | Which ad-tech/analytics/ACR domains is this host talking to? | `12_SECURITY_AND_PARASITIC_TRAFFIC.md` |
| `malware` | What devices are on the LAN, and is any connection oddly shaped? | `12_SECURITY_AND_PARASITIC_TRAFFIC.md` |
| `all` | Everything above in one run | Both |

This file owns installing, running and scheduling the script and the `stability` mode.
Doc 12 owns the other two modes' behavior and limits; the install, schedule and log-location
instructions below apply to every mode.

## 1. What it actually detects (`--mode stability`)

| Check | Signature it's looking for | Same as |
|---|---|---|
| Continuous gateway ping (`ping -D`) | A single gap larger than `--ping-gap-threshold` (default 1.5s) | `03_WIRED_AND_GATEWAY.md` §2 |
| Ping gap **periodicity** | Several gaps recurring at a regular interval (±25%) | The periodic-stall pattern described in `03_WIRED_AND_GATEWAY.md` §2/§4 |
| `ss -tin` on tracked hosts | `bytes_retrans` growing for N consecutive samples (default 3) | `05_AI_WORKLOAD_AND_LATENCY.md` |
| Wi-Fi (if a wireless iface is in use) | Signal below `--wifi-signal-threshold` (default -70 dBm), or a burst of new `tx failed` | `04_WIFI.md` §1-2 |
| NIC carrier flap | `/sys/class/net/<iface>/carrier_changes` increases during the run | `03_WIRED_AND_GATEWAY.md` §1 |

Every sample is appended to a JSONL event log; every anomaly is appended to a plain
`alerts.log` (one JSON object per line, human-readable) and, if `notify-send` is available,
raises a desktop notification immediately — you don't have to go looking for it.

## 2. Running it by hand

The default `--duration` (300s = 5 min) is the **quick pass**: enough to catch a short-period
issue (tens of seconds) without tying up a terminal. Reach for a longer `--duration` (1200s =
20 min, or more) when you actually suspect something and want a **thorough check** — more
samples, more chances to catch something slower or rarer, and worth pairing with
`--capture-on-anomaly` for that one run. From the repository root:

```bash
# quick pass (default, 5 min) -- what the scheduled timer runs
python3 scripts/net_watchdog.py --hosts api.example.com

# full/deep check -- when something feels off and you want to look closer
python3 scripts/net_watchdog.py --duration 1200 --hosts api.example.com --capture-on-anomaly
```

Replace `api.example.com` with a host you actually talk to (see `--hosts` below). Run
`python3 scripts/net_watchdog.py --help` for the full, current option list — the script's own
help text is the source of truth, so this guide does not paste it. When stdout is a terminal
the script also prints a short how-to once at startup.

Options worth knowing:

- `--hosts` is a comma-separated list of hostnames/IPs you actually have (or expect to have)
  live connections to — an AI API host, a work VPN endpoint, whatever this machine's
  long-lived low-latency traffic actually goes to. Without it, the ping-gap/Wi-Fi/carrier
  checks still run, just not the retransmit tracking (the startup block and every report tell
  you plainly when this is the case, so it's never a silent gap). A host that fails DNS at
  start is retried every 30 s while the run lasts, and listed under `unresolved_hosts` in the
  summary if it never resolves.
- `--duration` is an effective limit: the loop checks the deadline between phases, caps the
  nmap sweep to the time left, and bounds reverse-DNS lookups (1.5 s each), so a slow phase
  cannot push the run far past it. One external command already in flight can still finish
  its own timeout (5 s by default) first.
- Gateway and primary interface are auto-detected (`ip route get 8.8.8.8`); a Wi-Fi interface
  is auto-detected as wireless if `--iface` (or the auto-detected one) has
  `/sys/class/net/<iface>/wireless` or `/phy80211`.

While it's running you get a plain-language status line every `--heartbeat` seconds (default
60, `0` disables it) — e.g. `[15:32:50] still checking (✔ all clear) -- ~18m30s left` — so a
foreground run never looks like it hung. The moment an anomaly fires it's printed right
there. At the end (duration elapsed, or Ctrl+C) it always prints the same tidy summary block,
colored on a real terminal and plain text when redirected or logged (`NO_COLOR=1` also drops
the colors). A clean run looks like this (abridged):

```
════════════════════════════════════════════════════════════════
  Network Watchdog -- run summary
════════════════════════════════════════════════════════════════
  What was watched (mode: stability)
  Gateway (ping gaps):         192.168.1.1
  Primary interface:           eth0
  Hosts (TCP retransmits):     api.example.com
  Configured duration:         300s (~5 min)
────────────────────────────────────────────────────────────────
  ✔ OK -- no anomaly detected on this run.
────────────────────────────────────────────────────────────────
  Full detail (JSON) for this run: ~/.local/state/net_watchdog/summary_<run>.json
════════════════════════════════════════════════════════════════
```

If something *was* found, the same block instead lists each anomaly with a timestamp, a
plain-language label, and a pointer to the guide file/section to check next (see the table in
section 1) — followed by a reminder not to change anything blind. You can re-print the exact
block for any past run, without re-running anything:

```bash
python3 scripts/net_watchdog.py --report ~/.local/state/net_watchdog/summary_<run>.json
```

Output files and exit status:

- Logs land in `~/.local/state/net_watchdog/` by default (`--log-dir` to change it):
  `events_<run>.jsonl` (every sample), `alerts.log` (append-only, all runs), and
  `summary_<run>.json` (verdict + full anomaly list for that run, and what `--report` reads
  back).
- The summary's `tool_errors` lists external commands that were missing, timed out or exited
  with an error (`ip`, `nmap`, `iw`, `ss`). An empty section in a report can mean "dependency
  absent", not "nothing found" — check this field before trusting a clean result.
- Exit code is `0` if clean, `1` if any anomaly fired — useful if you want to wire this into
  something else (a cron mail, a status check) beyond the notification.

## 3. Running it on a schedule (recommended path)

The point isn't to run this 24/7 — a lightweight periodic burst (the 5-minute default, about
every 3 days) is enough to catch a chronic problem in days instead of months, without leaving
anything running all the time. Install the provided user-level systemd timer:

```bash
mkdir -p ~/.config/systemd/user
cp scripts/net-watchdog.service scripts/net-watchdog.timer ~/.config/systemd/user/
# edit ~/.config/systemd/user/net-watchdog.service (see the two notes below)
systemctl --user daemon-reload
systemctl --user enable --now net-watchdog.timer
systemctl --user list-timers net-watchdog.timer   # confirm next run time
```

Two things to adjust in the copied `.service` file before enabling it:

- **The clone path.** `ExecStart` points at `scripts/net_watchdog.py` inside the repository
  using a path relative to your home directory (`%h/...`). If you cloned the guide somewhere
  else, edit that path, or the unit will fail with "No such file or directory".
- **`--hosts`.** Set it to the long-lived services you care about (see `--hosts` above).

This runs as a **user** unit (no root needed) so `notify-send` reaches your actual desktop
session. The timer is interval-based rather than clock-based: `OnUnitActiveSec=3d` schedules
each run three days after the previous one started, and `RandomizedDelaySec` adds a random
delay (up to roughly half an hour) so runs don't always land at the same moment.
`OnUnitActiveSec=` has nothing to count from until the service has run once, so an interval
timer also needs a boot-relative trigger such as `OnBootSec=` for the first run; the shipped
`.timer` file's comments say how it handles this. See `man systemd.timer` and
`man systemd.time` to tune any of it. Note that `Persistent=` only applies to calendar
(`OnCalendar=`) timers, so do not rely on it to "catch up" interval timers: if the machine
was off, the next run simply happens after the next boot, per the timer's boot delay.

The script exits with status `1` when it finds an anomaly, so a scheduled run that found
something shows up as a *failed* unit in `systemctl --user status net-watchdog.service`.
That is intentional: it is one more place the finding is visible.

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
python3 scripts/net_watchdog.py --duration 1200 --hosts api.example.com --capture-on-anomaly
```

On the first anomaly of a run, it spawns `tcpdump -i <iface> -w <path> -G <capture-seconds> -W 1`
(default 15s window) and records the pcap path in that run's `alerts.log` entry and
`summary_<run>.json`. Only one capture per run — it won't spam captures for every subsequent
alert in the same window. Inspect the result with `tcpdump -r <file>` or Wireshark. The
script discards tcpdump's own error output, so a capture that lacks permission fails silently
and no pcap appears: test the permission setup below by hand (`tcpdump -i <iface> -c 5`)
before relying on it.

### Granting capture permission without running everything as root

This needs `tcpdump` installed and permission to capture. Don't run the whole watchdog as
root, and **avoid** the common shortcut of running `setcap` on the system's own `tcpdump`
binary: that gives *every local user and process* raw-capture ability (any local account could
then sniff all traffic), and the package manager silently reverts it on the next `tcpdump`
upgrade. Two safer options, with their trade-offs:

**Option A: a dedicated, group-restricted copy of tcpdump.** Only members of one group can
run the capability-enabled copy; the system `tcpdump` stays untouched.

```bash
sudo groupadd --system netcapture
sudo install -d -m 0755 /opt/net-watchdog/bin
sudo install -o root -g netcapture -m 0750 "$(command -v tcpdump)" /opt/net-watchdog/bin/tcpdump
sudo setcap cap_net_raw,cap_net_admin=eip /opt/net-watchdog/bin/tcpdump
sudo usermod -aG netcapture "$USER"          # log out fully and back in (or reboot) for the group to apply
```

The script looks for `tcpdump` on `PATH`, so put the copy first on `PATH` for the watchdog
only, for a manual run:

```bash
PATH=/opt/net-watchdog/bin:$PATH python3 scripts/net_watchdog.py --capture-on-anomaly --hosts api.example.com
```

or in the service unit, with `Environment=PATH=/opt/net-watchdog/bin:/usr/local/bin:/usr/bin:/bin`.
Trade-off: the copy is a snapshot, so it does not receive tcpdump security updates. Re-run the
`install` and `setcap` lines after upgrading the distro package. Capabilities are
file attributes, so some filesystems (and some copy methods) drop them; check with
`getcap /opt/net-watchdog/bin/tcpdump`.

**Option B: a systemd system unit with ambient capabilities.** The capture step then gets the
capabilities only while the unit runs, with nothing granted on disk. The `tcpdump` child
inherits them from the watchdog (as does every other child, such as `ping` and `nmap`). This must be a *system* unit (a user unit generally cannot
be granted capabilities the user manager itself lacks), for example in
`/etc/systemd/system/net-watchdog.service`:

```ini
[Service]
User=youruser
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN
NoNewPrivileges=yes
StateDirectory=net_watchdog
# keep the rest of the shipped unit (Type, Nice, ...) and make ExecStart explicit about
# where logs go, since %h is root's home in a system unit:
ExecStart=/usr/bin/python3 /path/to/network_check_guide/scripts/net_watchdog.py \
    --duration 300 --hosts api.example.com --capture-on-anomaly \
    --log-dir /var/lib/net_watchdog --no-notify
```

Trade-offs: a system unit cannot reach your desktop session, so `notify-send` notifications
do not work (hence `--no-notify`; read `alerts.log` instead), the logs live under
`/var/lib/net_watchdog` instead of your home, and the timer must be installed system-wide
too. Pick this when the watchdog runs on a server or gateway box; pick Option A for a
desktop with the user timer.

## 5. Safety notes

- Everything except the optional capture is read-only diagnostics — same posture as the rest
  of this guide (see `02_TOOLS.md`).
- The capture writes a bounded, time-limited pcap file to your own log directory — nothing is
  sent anywhere. Delete old captures/logs under `~/.local/state/net_watchdog/` whenever; the
  script doesn't rotate them for you. A pcap can contain private payloads, so treat it
  accordingly before sharing it.
- If a run finds something, don't act on it inside the watchdog — go to the relevant guide
  file (`03_`/`04_`/`05_`) and follow the actual diagnostic steps there. This tool's job is
  only to make sure you find out *promptly*, not to fix anything automatically.
