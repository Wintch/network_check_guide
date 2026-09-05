# Wi-Fi Validation

Wi-Fi adds several failure modes that simply don't exist on wired links. If your low-latency
work happens over Wi-Fi, treat this as mandatory, not optional — a wired-only checklist will
miss most of what actually breaks a wireless session.

## 1. Baseline signal and link quality

```bash
iw dev <wlan-iface> link
```

Look at:
- **Signal (dBm):** roughly, -30 to -50 = excellent, -50 to -67 = good/usable for
  low-latency work, -67 to -75 = marginal (expect retries and occasional drops), below -75 =
  poor, don't rely on it for anything latency-sensitive.
- **tx bitrate:** should be reasonably close to what your AP/adapter is capable of (e.g. an
  AC/AX link doing 6 Mbps instead of hundreds means something is actively wrong — usually
  signal, interference, or a stuck rate adaptation after a bad period).

Quick all-interfaces snapshot, no extra tooling:

```bash
cat /proc/net/wireless
```
Columns of interest: `link` (quality), `level` (signal, dBm), `noise` (dBm, more negative is
quieter/better). A shrinking gap between `level` and `noise` means your effective SNR is
dropping even if `level` alone still looks okay.

## 2. Retries and errors (the jitter/stall culprit)

```bash
iw dev <wlan-iface> station dump | grep -E "tx retries|tx failed|signal"
```

High retry counts mean frames are being resent at the radio layer before your traffic ever
gets to IP — this shows up as *jitter and occasional multi-hundred-ms to multi-second stalls*,
not necessarily as visible packet loss in a simple ping, because retries happen below the
level ping sees. This is one of the most common causes of "my ping average looks fine but
things still feel laggy."

## 3. Channel and interference

```bash
iw dev <wlan-iface> info | grep channel        # what you're currently on
sudo iw dev <wlan-iface> scan | grep -E "SSID|freq|signal" # nearby networks/channels (needs root, briefly disrupts your own connection on some drivers)
```

- **2.4 GHz** has only 3 non-overlapping channels (1/6/11) and is usually far more congested
  (neighbors, Bluetooth, microwaves, baby monitors). Prefer **5 GHz** (or 6 GHz on Wi-Fi 6E)
  for anything latency-sensitive if your AP and adapter both support it and range allows it.
- If you're on 5 GHz and see occasional multi-second full drops, check for **DFS
  (Dynamic Frequency Selection) channel switches** — some 5 GHz channels require the AP to
  vacate immediately if it detects radar-like signals, causing a real, brief (multi-second)
  disconnect. This looks exactly like the "periodic gap" pattern described in
  `03_WIRED_AND_GATEWAY.md`, except the trigger is external (weather radar, another device)
  and not something you can fix — the fix is pinning the AP to a non-DFS channel if your
  region's regulations and channel list allow it.

## 4. Power management (a very common, easy-to-miss cause of latency spikes)

Most Linux Wi-Fi drivers enable power-saving by default, which puts the radio to sleep
between beacons to save battery — great for a phone, bad for latency-sensitive work on a
laptop that's plugged in.

```bash
iw dev <wlan-iface> get power_save
sudo iw dev <wlan-iface> set power_save off      # test — does the jitter go away?
```

If disabling power-save measurably improves jitter/stall frequency, make it persistent (e.g.
a NetworkManager dispatcher script, a udev rule, or your distro's equivalent) rather than
running the command by hand every session.

## 5. Roaming (multi-AP / mesh setups)

If there's more than one AP/mesh node, a client can roam between them — usually seamless, but
a slow or "sticky" roam (client holds onto a weakening AP too long, or roams back and forth —
"ping-pong") causes exactly the kind of stall this guide is about.

```bash
# NetworkManager-based systems: connection/roaming history
journalctl -u NetworkManager --no-pager | grep -iE "roam|associat|disassociat" | tail -30
# or, if using wpa_supplicant directly:
journalctl -u wpa_supplicant --no-pager | tail -50
```

If you see repeated associate/disassociate/roam events clustered in the affected window,
that's your answer. Fixes are AP-side (band steering / roaming aggressiveness settings,
proper AP placement, 802.11k/v/r support) more often than client-side.

## 6. Comparative test — is it Wi-Fi, or everything?

The fastest way to confirm Wi-Fi is the actual culprit: run the exact same test from
`03_WIRED_AND_GATEWAY.md` step 2 (`ping -D -i1 -c 120 <gateway-ip>`) once over Wi-Fi and once
plugged into the same switch/port with a cable, ideally back to back. If the gaps/jitter
disappear on the wired run, you've isolated it to the radio link and everything above
applies. If the same pattern shows up on both, it's not Wi-Fi — go back to
`03_WIRED_AND_GATEWAY.md` and look upstream (shared gateway/switch/LAN infra).

## Quick reference — good vs. investigate

| Metric | Good | Investigate |
|---|---|---|
| Signal | > -60 dBm | < -70 dBm |
| tx bitrate | near adapter/AP max | far below max with good signal |
| tx retries | low, stable | climbing / consistently high |
| Band | 5/6 GHz | 2.4 GHz in a congested area |
| power_save | off (for latency-sensitive work) | on |
| Roam events during the affected window | none | several |
