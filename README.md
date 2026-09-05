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
