# Tools Inventory

Everything used across this guide, what it's for, and how to get it. All are standard Linux
tools; nothing exotic. Most Debian/Ubuntu systems already have the `iproute2`/`iputils`
basics — the table below flags what's usually missing.

| Tool | Purpose | Package (Debian/Ubuntu) | Usually pre-installed? |
|---|---|---|---|
| `ping` | Latency + loss to one host, with timestamps (`-D`) | `iputils-ping` | Yes |
| `ip` (`ip route`, `ip -br link`, `ip neigh`) | Routes, interface state, ARP/neighbor table | `iproute2` | Yes |
| `ss` | Live TCP/UDP socket + kernel-measured RTT/retransmit stats (`ss -tin`) | `iproute2` | Yes |
| `curl -w` | Per-phase HTTP timing (DNS/connect/TLS/TTFB/total) | `curl` | Yes |
| `mtr` | Combined traceroute + ping, per-hop loss/latency over time | `mtr-tiny` or `mtr` | **Often missing**, install it |
| `ethtool` | NIC negotiated speed/duplex, driver info, ring/queue stats | `ethtool` | **Often missing**, install it |
| `dmesg` | Kernel log — link up/down, USB re-enumeration, driver errors | built-in | Yes (may need root) |
| `iperf3` | Real sustained-throughput test, client/server | `iperf3` | **Often missing**, install it |
| `tcpdump` | Packet capture — last resort, use when stats alone don't explain it | `tcpdump` | **Often missing**, install it |
| `iw` | Wi-Fi: link quality, scan, channel/band info (modern replacement for `iwconfig`) | `iw` | **Often missing on servers**, usually present on laptops |
| `nmcli` (if NetworkManager is in use) | Wi-Fi: connection state, signal, roaming history | `network-manager` | Depends on setup |
| `/proc/net/wireless` | Quick per-interface Wi-Fi quality snapshot, no tool needed | n/a (kernel file) | Always present if a Wi-Fi driver is loaded |
| `systemctl list-timers` | Reveals scheduled jobs (cron/systemd timers) that might be touching the network | built-in (systemd) | Yes |
| `journalctl -u <service>` | History of what a specific watchdog/service actually did and when | built-in (systemd) | Yes |

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
