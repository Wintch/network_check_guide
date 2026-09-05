# Background Watchdog: Catch It in Days, Not Months

`06_CASE_STUDY_2026-09-05.md` took **3 months** to notice because nobody was looking at the
*pattern* of gateway pings or retransmit counters continuously — only when something already
felt wrong. `scripts/net_watchdog.py` runs the same class of checks from `03_`, `04_`, and
`05_` unattended, for a bounded window, on a recurring schedule, and alerts you the moment it
sees the same signatures that took months to find manually last time.

It is **read-only by default** (ping, `ss -tin`, `iw`, `/sys/class/net/*` reads) — the one
optional exception is `--capture-on-anomaly`, covered in section 5.

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

## 2. Quick start — pase rápido vs. chequeo completo

The default (`--duration`, 300s = 5 min) is the **quick pass** — enough to catch a short-period
issue (the case study's was ~35s) without tying up a terminal. Reach for a longer `--duration`
(1200s = 20 min, or more) when you actually suspect something and want a **thorough/deep
check** — more samples, more chances to catch something slower or rarer, and worth pairing
with `--capture-on-anomaly` for that one run:

```bash
cd scripts/

# pase rapido (default, 5 min) -- lo que corre el timer cada 3 dias
python3 net_watchdog.py --hosts api.anthropic.com

# chequeo completo/profundo -- cuando algo se siente raro y queres mirar en detalle
python3 net_watchdog.py --duration 1200 --hosts api.anthropic.com --capture-on-anomaly
```

`--help` prints the same cheat-sheet shown below, any time. When stdout is an actual
terminal (not piped, not a systemd log) the script prints it once at startup too, so you
never have to go dig for "how do I run this again":

```
COMO USARLO (guia rapida)
  Pase rapido (default, 5 min), vigilando retransmisiones a la API real:
    python3 net_watchdog.py --hosts api.anthropic.com

  Chequeo completo/profundo (mas tiempo para agarrar patrones lentos):
    python3 net_watchdog.py --duration 1200 --hosts api.anthropic.com --capture-on-anomaly

  Ver el resultado de una corrida anterior en formato legible:
    python3 net_watchdog.py --report ~/.local/state/net_watchdog/summary_<fecha>.json

  Dejarlo instalado para que corra solo cada 3 dias: ver 09_BACKGROUND_WATCHDOG.md.
```

While it's running you get a plain-language status line every `--heartbeat` seconds (default
60, `0` disables it) — e.g. `[15:32:50] sigue chequeando (✔ todo en orden) -- quedan ~18m30s` —
so a foreground run never looks like it hung. The moment an anomaly fires it's printed right
there, no need to be watching. At the end (duration elapsed, or Ctrl+C) it always prints the
same tidy block — colored when on a real terminal, plain text when redirected/logged:

```
════════════════════════════════════════════════════════════════
  Network Watchdog -- resumen de la corrida
════════════════════════════════════════════════════════════════
  Que se vigilo
  Gateway (cortes de ping):    192.168.1.1
  Interfaz principal:          enp5s0
  Wi-Fi vigilada:              no aplica (enlace cableado / sin Wi-Fi detectada)
  Hosts (retransmisiones TCP): api.anthropic.com
  Duracion configurada:        300s (~5 min)
────────────────────────────────────────────────────────────────
  ✔ OK -- no se detecto ninguna anomalia en esta corrida.
  No hay nada que revisar ni que hacer.
────────────────────────────────────────────────────────────────
  Detalle completo (JSON) de esta corrida: ~/.local/state/net_watchdog/summary_20260905T153245.json
  Para releer este mismo resumen mas tarde: --report ~/.local/state/net_watchdog/summary_20260905T153245.json
════════════════════════════════════════════════════════════════
```

If something *was* found, that same block instead lists each anomaly with a timestamp, a
plain-language label, and the exact message telling you which guide file/section to check
next (see the table in section 1) — followed by a "que hacer ahora" reminder not to change
anything blind. **You can always re-print that exact block for any past run**, without
re-running anything:

```bash
python3 net_watchdog.py --report ~/.local/state/net_watchdog/summary_20260905T153245.json
```

## 3. Running it once, by hand (real options)

```bash
python3 scripts/net_watchdog.py --duration 300 --hosts api.anthropic.com
```

- `--hosts` is a comma-separated list of hostnames/IPs you actually have (or expect to have)
  live connections to — an AI API host, a work VPN endpoint, whatever this machine's
  long-lived low-latency traffic actually goes to. Without it, the ping-gap/Wi-Fi/carrier
  checks still run, just not the retransmit tracking (the startup block and every report tell
  you plainly when this is the case, so it's never a silent gap).
- Gateway and primary interface are auto-detected (`ip route get 8.8.8.8`); a Wi-Fi interface
  is auto-detected as wireless if `--iface` (or the auto-detected one) has
  `/sys/class/net/<iface>/wireless` or `/phy80211`.
- Logs land in `~/.local/state/net_watchdog/` by default (`--log-dir` to change it):
  `events_<run>.jsonl` (every sample), `alerts.log` (append-only, all runs), `summary_<run>.json`
  (verdict + full anomaly list for that run, and what `--report` reads back).
- Exit code is `0` if clean, `1` if any anomaly fired — useful if you want to wire this into
  something else (a cron mail, a status check) beyond the notification.
- `NO_COLOR=1` (or piping/redirecting output) drops the ANSI colors automatically — nothing to
  configure for cron/systemd logs, they come out as plain text on their own.

## 4. Running it on a schedule (recommended path)

The point isn't to run this 24/7 — a lightweight periodic burst (the 5-minute default, every
3 days) is enough to catch a chronic problem in days instead of months, without leaving
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

## 5. Optional: capture-on-anomaly (the "sniffer" part)

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

## 6. Safety notes

- Everything except the optional capture is read-only diagnostics — same posture as the rest
  of this guide (see `02_TOOLS.md`).
- The capture writes a bounded, time-limited pcap file to your own log directory — nothing is
  sent anywhere. Delete old captures/logs under `~/.local/state/net_watchdog/` whenever; the
  script doesn't rotate them for you.
- If a run finds something, don't act on it inside the watchdog — go to the relevant guide
  file (`03_`/`04_`/`05_`) and follow the actual diagnostic steps there. This tool's job is
  only to make sure you find out *promptly*, not to fix anything automatically.
