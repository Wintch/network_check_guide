# Network Health Guide — Index

A practical, tool-by-tool guide to validate that your network is good enough for
**low-latency, uninterrupted, AI-assisted work** (Claude Code, any long-lived API session,
remote pairing, etc.) before you start a work session — and to diagnose it fast when
something feels "off" mid-session.

This guide exists because a real incident (see `06_CASE_STUDY_2026-09-05.md`) turned out to
be a **local watchdog script silently killing the entire LAN for 8-9 seconds every ~35
seconds, for 25 days straight** — and it was first misdiagnosed as "maybe the ISP is
throttling us." The lesson: check local infrastructure (gateway, first hop, NIC/driver,
Wi-Fi) *before* blaming the ISP or the remote API.

## Files in this guide

1. **`01_QUICK_CHECKLIST.md`** — the ~2-minute check to run before starting real work.
   Start here every time.
2. **`02_TOOLS.md`** — every tool used in this guide, what it's for, and how to install it.
3. **`03_WIRED_AND_GATEWAY.md`** — validating the physical/first-hop path: NIC health,
   gateway reachability, periodic-outage detection, watchdog/cron sanity checks.
4. **`04_WIFI.md`** — Wi-Fi-specific checks: signal, retries, band/channel, power
   management, roaming, DFS events.
5. **`05_AI_WORKLOAD_AND_LATENCY.md`** — how to read *your actual* persistent connections
   to an AI API (or any long-lived HTTPS session) for jitter/retransmission/shaping
   signatures, and how to tell "it's local," "it's the ISP," or "it's the remote service"
   apart.
6. **`06_CASE_STUDY_2026-09-05.md`** — the real incident, worked end to end, with the exact
   commands and numbers that found and confirmed the root cause. Use it as a template for
   the next weird one.
7. **`07_GAME_AND_VR_STREAMING.md`** — bandwidth/latency requirements and diagnostics for
   Parsec, Moonlight/Sunshine, Xbox Cloud Gaming, Boosteroid, and wireless VR streaming
   (Air Link, Virtual Desktop, ALVR, WiVRn) — what each service auto-adapts vs. what you
   have to set yourself, and what a network problem looks like in each one's own UI.
8. **`08_QOS_TRAFFIC_SHAPING_AND_5GHZ.md`** — bufferbloat testing, `cake`/`fq_codel` traffic
   shaping, DSCP marking to prioritize streaming traffic on a shared link, and 5GHz/6GHz
   Wi-Fi tuning beyond just "connect to the 5GHz SSID."
9. **`09_BACKGROUND_WATCHDOG.md`** — a Python script (`scripts/net_watchdog.py`) that runs
   the same diagnostics from `03_`/`04_`/`05_` unattended, on a schedule, and alerts you the
   moment it sees a periodic gap, growing retransmits, or Wi-Fi degradation — so the next
   version of `06_CASE_STUDY_2026-09-05.md` gets caught in days, not months.
10. **`10_GPN_VS_VPN_AND_MULTI_WAN.md`** — what a "Gaming Private Network" actually is
    (route optimization, not encryption), how it differs technically from a VPN, and whether
    it's worth anything if you already have two WAN links (route optimization vs. real
    bonding/multipath).
11. **`11_SSH_MULTIPLEXING_AND_MOSH.md`** — two different latency fixes for two different
    callers: SSH `ControlMaster`/`ControlPersist` for a script issuing many one-shot commands
    (measured ~17x faster on repeat calls), and Mosh for a human typing in one interactive
    session (instant local echo, survives IP changes/drops). Which one to reach for depends
    entirely on who's connecting, not which is "better."

## Golden rule

**Diagnose closest to home first.** The order that actually works, cheapest and most
conclusive first:

```
your machine's NIC/Wi-Fi  →  first-hop gateway  →  local LAN infra (switches, bridges,
USB NICs, watchdogs, cron)  →  ISP  →  remote API/service
```

Almost every "the AI feels slow/flaky" complaint that isn't a model-side issue is solved
somewhere in the first three hops. Don't jump to "ISP shaping" or "API is degraded" without
ruling those out with real data — see `05_AI_WORKLOAD_AND_LATENCY.md` for exactly how.
