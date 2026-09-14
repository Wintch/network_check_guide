# Tools Inventory

Everything used across this guide, what it's for, and how to get it. All are standard Linux
tools; nothing exotic. Most Debian/Ubuntu systems already have the `iproute2`/`iputils`
basics — the table below flags what's usually missing.

| Tool | Purpose | Package (Debian/Ubuntu) | Usually pre-installed? |
|---|---|---|---|
| `ping` | Latency + loss to one host, timestamps (`-D`), MTU probes (`-M do -s`) | `iputils-ping` | Yes |
| `ip` (`ip route`, `ip -br link`, `ip neigh`) | Routes (v4/v6), interface state, ARP/neighbor table | `iproute2` | Yes |
| `ss` | Live TCP/UDP socket + kernel-measured RTT/retransmit stats (`ss -tin`) | `iproute2` | Yes |
| `curl -w` | Per-phase HTTP timing (DNS/connect/TLS/TTFB/total) | `curl` | Yes |
| `resolvectl` / `dig` | DNS resolver stats, query latency, and upstream server verification | `systemd` / `dnsutils` | Yes (`resolvectl`), `dig` optional |
| `mtr` | Combined traceroute + ping, per-hop loss/latency over time | `mtr-tiny` or `mtr` | **Often missing**, install it |
| `ethtool` | NIC speed/duplex, EEE (802.3az) state, offload flags (TSO/GSO) | `ethtool` | **Often missing**, install it |
| `dmesg` | Kernel log — link up/down, USB re-enumeration, driver errors | built-in | Yes (may need root) |
| `iperf3` | Real sustained-throughput test, client/server | `iperf3` | **Often missing**, install it |
| `tcpdump` | Packet capture — last resort, use when stats alone don't explain it | `tcpdump` | **Often missing**, install it |
| `iw` | Wi-Fi: link quality, scan, channel/band info (modern replacement for `iwconfig`) | `iw` | **Often missing on servers**, usually present on laptops |
| `nmcli` (if NetworkManager is in use) | Wi-Fi: connection state, signal, roaming history | `network-manager` | Depends on setup |
| `/proc/net/wireless` | Quick per-interface Wi-Fi quality snapshot, no tool needed | n/a (kernel file) | Always present if a Wi-Fi driver is loaded |
| `systemctl list-timers` | Reveals scheduled jobs (cron/systemd timers) that might be touching the network | built-in (systemd) | Yes |
| `journalctl -u <service>` | History of what a specific watchdog/service actually did and when | built-in (systemd) | Yes |
| `quick_check.py` | 1-command automated pre-work sanity check in ~20-40s | `scripts/quick_check.py` | Built-in script (Python stdlib) |
| `net_watchdog.py` | Unattended background monitoring (minutes to days): periodic-outage/retransmit detection, ad-tech telemetry tracking, or LAN malware/rogue-device inventory | `scripts/net_watchdog.py` | Built-in script (Python stdlib) |

## Which script: `quick_check.py` vs `net_watchdog.py`

They don't overlap — one is a snapshot, the other a long-running monitor — so use both where
they apply rather than picking one:

| | `quick_check.py` | `net_watchdog.py` |
|---|---|---|
| Runs for | ~20-40s, then exits with a report | Minutes to days (`--duration`, or as a systemd timer) |
| When | Before starting a work session, or whenever something feels off *right now* | Left running to catch something intermittent you can't reproduce on demand |
| Checks | Link health, gateway reachability, DNS latency + local cache, Path MTU, dual-stack, real HTTPS handshake timing — see `01_QUICK_CHECKLIST.md` | Three independent `--mode`s: `stability` (periodic gateway-ping gaps, TCP retransmit growth, Wi-Fi/carrier flaps — `03_`/`04_`/`05_`), `telemetry` (ad-tech/ACR domain matching — `12_`), `malware` (LAN device inventory, C2 ports, bandwidth anomalies — `12_`) — see `09_BACKGROUND_WATCHDOG.md` |
| Output | One human-readable (or `--json`) report, once | Alerts as they happen (desktop notification, log file), plus a JSON summary per run |

**Not worth merging into one script.** They have different failure models to guard against
(a bad *moment* to start work vs. a bad *pattern* over time) and almost disjoint flag surfaces
— `quick_check.py`'s only knob is which host to test against, while `net_watchdog.py` has
~20 tunables across three unrelated detection domains (LAN scanning, telemetry domain lists,
bandwidth thresholds). Combining them would force the 30-second pre-work check to carry the
weight (and startup cost — LAN `nmap` sweep, domain-list loading) of a security monitor most
sessions never need, and would force `net_watchdog.py`'s unattended/systemd use case to carry
one-shot-only checks (Path MTU probing, dual-stack sanity) that don't make sense to repeat
every 5 seconds for hours. Keeping them separate keeps each one's flag surface and runtime
cost matched to what it's actually for.

## One-shot install (Debian/Ubuntu)

```bash
sudo apt update
sudo apt install -y mtr-tiny ethtool iperf3 tcpdump iw
```

## Notes

- **`ss -tin` is the single most underused tool here.** Unlike `ping`/`mtr`/synthetic
  `curl` loops, it reads the kernel's own live measurements (RTT, RTT variance, congestion
  window, retransmitted bytes) for connections that are **already open and doing real
  work** — including a live Claude Code / AI-API session. See
  `05_AI_WORKLOAD_AND_LATENCY.md`.
- `iperf3` needs a server on the other end (`iperf3 -s`) that you control — a public
  speedtest server works for rough bandwidth numbers but is not useful for the
  jitter/shaping diagnosis this guide focuses on. Prefer running your own `iperf3 -s` on a
  box you control on the other side of the link you're testing (e.g. the far side of a
  dual-WAN setup, or a VPS you already have credentials for).
- Anything that changes live network state (routing, firewall, NIC driver rebind, killing a
  watchdog) is **not** in this checklist on purpose — this guide is read-only diagnostics.
  Once you've localized the problem, make the fix as its own deliberate, reversible step
  (see the safety note in `06_CASE_STUDY_2026-09-05.md`).
