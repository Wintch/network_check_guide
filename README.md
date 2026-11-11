# Network Health Guide — Index

A practical, tool-by-tool guide to validate that your network is good enough for
**low-latency, uninterrupted, AI-assisted work** (an AI coding assistant, any long-lived API session,
remote pairing, etc.) before you start a work session — and to diagnose it fast when
something feels "off" mid-session.

The core lesson: check local infrastructure (gateway, first hop, NIC/driver, Wi-Fi)
*before* blaming the ISP or the remote service. Intermittent problems are very often caused
by something on your own side of the link, and `06_CASE_STUDY_PERIODIC_OUTAGE.md` walks
through one such diagnosis end to end as a worked example.

## Quick Start: 1-Command Pre-Work Check

Before starting real work, run the automated Python checklist:

```bash
python3 scripts/quick_check.py
```

In about 30-90 seconds (the default 20-sample gateway ping dominates; `--full` runs a longer
60-packet ping), it validates link speed, carrier flaps, first-hop gateway latency,
periodic gap signatures, DNS lookup times, and Path MTU (1500 vs 1492 PPPoE). If anything
is degraded, it points you directly to the relevant guide file below.

---

## Symptom Triage: Where to Go First

| What you observe | Most likely root cause | Where to go |
|---|---|---|
| **Periodic, repeating micro-outages** (every ~30-60s) | Watchdog/cron script resetting an interface, USB NIC flap, or Wi-Fi DFS channel switch | [`03_WIRED_AND_GATEWAY.md`](03_WIRED_AND_GATEWAY.md) §2 & [`06_CASE_STUDY_PERIODIC_OUTAGE.md`](06_CASE_STUDY_PERIODIC_OUTAGE.md) |
| **Wi-Fi only: retries, jitter, occasional multi-second drops** (wired is fine) | Weak signal, 2.4GHz congestion, power save, DFS channel switch, or sticky roaming | [`04_WIFI.md`](04_WIFI.md) |
| **Pings are ~5ms, but new API calls/pages take 1-2s to start** | DNS resolver bottleneck, or broken IPv6 dual-stack (Happy Eyeballs fallback delay) | [`01_QUICK_CHECKLIST.md`](01_QUICK_CHECKLIST.md) & [`05_AI_WORKLOAD_AND_LATENCY.md`](05_AI_WORKLOAD_AND_LATENCY.md) |
| **Pings succeed, but large API streams or `git push` stall indefinitely** | Path MTU / PMTUD Black Hole (PPPoE 1492 or VPN MTU dropping fragmentation packets) | [`03_WIRED_AND_GATEWAY.md`](03_WIRED_AND_GATEWAY.md) §6 |
| **Network lags / stutters whenever someone downloads or uploads** | Bufferbloat in the router queue (needs CAKE / fq_codel shaping) | [`08_QOS_TRAFFIC_SHAPING_AND_5GHZ.md`](08_QOS_TRAFFIC_SHAPING_AND_5GHZ.md) |
| **Interactive SSH freezes or disconnects on laptop sleep / Wi-Fi roaming** | Plain SSH vs Mosh / missing persistent keepalives | [`11_SSH_MULTIPLEXING_AND_MOSH.md`](11_SSH_MULTIPLEXING_AND_MOSH.md) |
| **Cloud gaming or VR streaming drops frames / resolution drops silently** | Packet jitter, missing DSCP marking, 2.4GHz interference or Wi-Fi power save | [`07_GAME_AND_VR_STREAMING.md`](07_GAME_AND_VR_STREAMING.md) & [`08_QOS_TRAFFIC_SHAPING_AND_5GHZ.md`](08_QOS_TRAFFIC_SHAPING_AND_5GHZ.md) |
| **Unexplained bandwidth consumption or rogue devices on LAN** | Smart-TV/ACR ad-tech telemetry, piracy STB streaming, or malware C2 traffic | [`12_SECURITY_AND_PARASITIC_TRAFFIC.md`](12_SECURITY_AND_PARASITIC_TRAFFIC.md) |
| **Not sure whether a VPN / "gaming VPN" (GPN) / second link would help** | Route optimization, tunnelling and true multi-WAN bonding solve different problems | [`10_GPN_VS_VPN_AND_MULTI_WAN.md`](10_GPN_VS_VPN_AND_MULTI_WAN.md) |
| **Unattended continuous monitoring** | Catch recurring blips in days rather than months | [`09_BACKGROUND_WATCHDOG.md`](09_BACKGROUND_WATCHDOG.md) |
| **DNS queries visible to your ISP/network, or unsure who's still resolving in plaintext** | No DNS encryption upstream, or a client/host bypassing your resolver | [`13_DNS_ENCRYPTION_AND_LEAK_DETECTION.md`](13_DNS_ENCRYPTION_AND_LEAK_DETECTION.md) |

---

## Files in this guide

1. **[`01_QUICK_CHECKLIST.md`](01_QUICK_CHECKLIST.md)** — the ~2-minute check to run before starting real work.
   Start here every time.
2. **[`02_TOOLS.md`](02_TOOLS.md)** — every tool used in this guide, what it's for, and how to install it.
3. **[`03_WIRED_AND_GATEWAY.md`](03_WIRED_AND_GATEWAY.md)** — validating the physical/first-hop path: NIC health,
   gateway reachability, periodic-outage detection, MTU/PMTUD black holes, EEE/offload quirks.
4. **[`04_WIFI.md`](04_WIFI.md)** — Wi-Fi-specific checks: signal, retries, band/channel, power
   management, roaming, DFS events.
5. **[`05_AI_WORKLOAD_AND_LATENCY.md`](05_AI_WORKLOAD_AND_LATENCY.md)** — how to read *your actual* persistent connections
   to an AI API (or any long-lived HTTPS session) for jitter/retransmission/shaping
   signatures, and how to tell "it's local," "it's the ISP," or "it's the remote service"
   apart.
6. **[`06_CASE_STUDY_PERIODIC_OUTAGE.md`](06_CASE_STUDY_PERIODIC_OUTAGE.md)** — a periodic-outage diagnosis worked end to end, with the
   commands that found and confirmed the root cause. Use it as a template for the next weird one.
7. **[`07_GAME_AND_VR_STREAMING.md`](07_GAME_AND_VR_STREAMING.md)** — bandwidth/latency requirements and diagnostics for
   Parsec, Moonlight/Sunshine, Xbox Cloud Gaming, Boosteroid, and wireless VR streaming.
8. **[`08_QOS_TRAFFIC_SHAPING_AND_5GHZ.md`](08_QOS_TRAFFIC_SHAPING_AND_5GHZ.md)** — bufferbloat testing, `cake`/`fq_codel` traffic
   shaping, DSCP marking to prioritize streaming traffic on a shared link, and 5GHz/6GHz tuning.
9. **[`09_BACKGROUND_WATCHDOG.md`](09_BACKGROUND_WATCHDOG.md)** — Python watchdog (`scripts/net_watchdog.py`) running
   unattended diagnostics on schedule to alert immediately on periodic gaps or packet loss.
10. **[`10_GPN_VS_VPN_AND_MULTI_WAN.md`](10_GPN_VS_VPN_AND_MULTI_WAN.md)** — GPN route optimization vs VPN vs true multi-WAN bonding.
11. **[`11_SSH_MULTIPLEXING_AND_MOSH.md`](11_SSH_MULTIPLEXING_AND_MOSH.md)** — SSH ControlMaster for fast scripted commands (~17x speedup)
    vs Mosh for human typing.
12. **[`12_SECURITY_AND_PARASITIC_TRAFFIC.md`](12_SECURITY_AND_PARASITIC_TRAFFIC.md)** — ad-tech/ACR telemetry detection, unknown LAN devices,
    and sustained anomalous streams.
13. **[`13_DNS_ENCRYPTION_AND_LEAK_DETECTION.md`](13_DNS_ENCRYPTION_AND_LEAK_DETECTION.md)** — encrypting DNS upstream
    (dnscrypt-proxy + dnsmasq) once at the resolver instead of per-device, then auditing with
    `tcpdump` to confirm nothing is still leaking plaintext queries — including Android's
    client-side Private DNS option. `scripts/setup_encrypted_dns.sh` automates the setup on a
    `dhcpcd`-managed Debian host in one non-interactive run, with its own rollback (see also
    [`01_QUICK_CHECKLIST.md`](01_QUICK_CHECKLIST.md) §6).

## Golden rule

**Diagnose closest to home first.** The order that actually works, cheapest and most
conclusive first:

```
your machine's NIC/Wi-Fi  →  first-hop gateway  →  local LAN infra (switches, bridges,
USB NICs, watchdogs, cron)  →  ISP  →  remote API/service
```

Almost every "the AI feels slow/flaky" complaint that isn't a model-side issue is solved
somewhere in the first three hops. Don't jump to "ISP shaping" or "API is degraded" without
ruling those out with real data — see [`05_AI_WORKLOAD_AND_LATENCY.md`](05_AI_WORKLOAD_AND_LATENCY.md) for exactly how.

## Tests

```
python3 -m pytest -q
```

Requires `pytest` (`pip install pytest`). The suite lives in `tests/` and runs without root or
network: the `net_watchdog.py` and `quick_check.py` tests use mocks, and
`scripts/setup_encrypted_dns.sh` is exercised against a sandbox with fake `systemctl`/`dhcpcd`,
including its rollback paths. CI (`.github/workflows/ci.yml`, GitHub Actions on every push and
pull request) byte-compiles both Python scripts, syntax-checks the shell installer
(`bash -n`) and runs the same pytest suite.

## License

MIT — see [`LICENSE`](LICENSE).
