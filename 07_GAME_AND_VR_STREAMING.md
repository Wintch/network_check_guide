# Game/Desktop Streaming & VR: Bandwidth, Latency, and Diagnostics

Distilled, practical requirements for the streaming stacks people actually run over a home
network: **Parsec**, **Moonlight/Sunshine**, pure cloud-rendered services (**Xbox Cloud
Gaming**, **Boosteroid**), and **wireless VR streaming** (Meta Air Link, Virtual Desktop,
ALVR, WiVRn). Each has a different failure signature and a different set of levers you
actually control — this file tells you which is which before you start tuning blindly. QoS
setup and traffic shaping to protect this traffic on a shared link is in
`08_QOS_TRAFFIC_SHAPING_AND_5GHZ.md`.

## 1. Parsec

Parsec streams from a host machine you (or a friend) control, over its own UDP protocol
("BUD" — DTLS-encrypted, custom congestion control, not WebRTC), and **auto-adapts bitrate
to real-time network conditions** — this is the single most important thing to know before
diagnosing it: quality silently drops before the stream stalls, so "it got blurry" during a
period of congestion is Parsec working as designed, not a bug.

| Scenario | Minimum | Recommended |
|---|---|---|
| Host upload | 10 Mbps | 30 Mbps (50 Mbps if hosting ≥2 guests) |
| Client down/up | 10 Mbps / 2 Mbps | 30 Mbps / 2 Mbps |
| Client ping to host's region | < 30 ms | < 15 ms |
| Decode/encode budget | ≤ 32 ms @ 30fps | ≤ 15 ms @ 60fps |

- **Protocol/ports:** TCP 443 to Parsec's signaling servers (`kessel-*.parsec.app`) — low
  bandwidth, not worth prioritizing. The actual media stream is **UDP**, random by default but
  configurable to a static port/range ("Host Start Port") in Parsec's settings — set this to a
  fixed range if you want to firewall/QoS-match it, or need to port-forward for a
  double-NAT/CGNAT host.
- **NAT traversal:** STUN (UDP 3478) + UPnP hole-punching, ~97% success rate per Parsec's own
  numbers. **There is no consumer relay fallback** — if P2P negotiation fails (errors
  6023/6024), your only options are fixing UPnP/port-forwarding/CGNAT or a mesh VPN (ZeroTier)
  workaround. This matters diagnostically: since Parsec's servers never touch the video
  stream for consumer accounts, almost all consumer lag traces to *your* network or the
  client↔host WAN route, not "Parsec's servers being slow." `tracert`/`mtr` between the two
  WAN IPs (not to Parsec's own servers) is the relevant test.
- **Diagnostic tells (Ctrl+Shift+M overlay):**
  - Yellow "network performance" warning + host console `N:x/y/z` loss counters climbing
    from near-0 → packet loss/congestion, not decode/encode.
  - Yellow "hardware" warning → client-side decode bottleneck (web client has no hardware
    decode at all).
  - Red "software encoding" warning → host has no hardware encoder available.
- **Wi-Fi:** Parsec's own docs explicitly say host = Ethernet (recommended) or 5 GHz minimum;
  client = 5 GHz/Ethernet/LTE. They explicitly call out **Wi-Fi signal boosters, powerline
  adapters, and mesh Wi-Fi as known-bad** on either end — not generic advice, a documented
  warning.
- **Bufferbloat:** Parsec's troubleshooting docs directly recommend a bufferbloat test and
  call out **Intel Puma-chipset routers by name** as a known-bad cause of stream issues.
- Avoid VPNs on either end — flagged as adding latency in their own docs.

## 2. Moonlight (client) + Sunshine (host)

Unlike Parsec, **bitrate here is a fixed number you (or the client's connect-time heuristic)
set — it does not auto-throttle to congestion.** Set it too high for the actual link and you
get sustained packet loss/frame drops instead of graceful quality reduction; set it
conservatively with headroom instead.

| Resolution | 30 fps | 60 fps | 120 fps |
|---|---|---|---|
| 720p | 5 Mbps | 10 Mbps | ~14 Mbps |
| 1080p | 10 Mbps | 20 Mbps | ~28 Mbps |
| 1440p | 20 Mbps | 40 Mbps | ~57 Mbps |
| 4K | 40 Mbps | 80 Mbps | ~113 Mbps |

Add ~20-30% headroom for 10-bit HDR. 4K120 realistically needs wired gigabit + a strong
encoder; 4K60/1080p120 are the practical sweet spots over Wi-Fi.

**Sunshine default ports** (base port 47989, fixed offsets):

| Port | Proto | Purpose |
|---|---|---|
| 47984 | TCP | HTTPS pairing/API |
| 47989 | TCP | HTTP pairing/API |
| 47990 | TCP | Web UI |
| 48010 | TCP | RTSP stream negotiation |
| 47998 | UDP | Video (RTP) |
| 47999 | UDP | Audio (RTP) |
| 48000 | UDP | Control channel |
| 48002 | UDP | Mic/attention (legacy) |
| 5353 | UDP | mDNS auto-discovery (LAN) |

- **FEC (`fec_percentage`, default 20, range 1-255):** redundant parity data per frame so the
  client can reconstruct despite some UDP loss — bandwidth cost scales with the percentage.
  Keep the default on clean wired LAN; **raise toward 50-100% on lossy Wi-Fi/WAN** to kill
  visible micro-corruption/frame drops, accepting the bandwidth tax. Target under 5% packet
  loss and under 1ms jitter for a clean stream before touching FEC.
- **Best practical diagnostic: the in-stream stats overlay.** Press
  **`Ctrl+Alt+Shift+S`** in the Moonlight client to toggle it — shows network latency (frame
  transit time), decode time, and frame-loss stats live. Rising network latency/frame loss =
  link problem; rising decode time = client hardware problem. Sub-10ms network latency is
  achievable on a solid 5GHz/wired LAN — use that as your "healthy" baseline.
- **QoS:** Sunshine already sets `ENET_SOCKOPT_QOS` on its media sockets, but most consumer
  routers ignore untrusted DSCP marks unless configured to trust/re-mark them — see
  `08_QOS_TRAFFIC_SHAPING_AND_5GHZ.md` for actually making this stick with your own DSCP rule
  on the ports above.
- **Wi-Fi:** official guidance is "5GHz 802.11ac/ax strongly recommended," host wired to the
  router "highly recommended." 2.4GHz and powerline adapters are explicitly named in the FAQ
  as unreliable/frame-dropping.
- **LAN vs. WAN:** pair on the LAN first; for remote play, port-forward the table above (or
  use a mesh VPN like Tailscale/ZeroTier instead of manual forwarding) and drop bitrate to at
  least 1 Mbps below your real upload speed, raising FEC to compensate for the extra jitter of
  a longer route.

### Related: SRT vs. RTMP for your own relay/restream node

If you're pushing a stream out over an imperfect network to your own relay (not
Twitch/YouTube, which require RTMP): prefer **SRT** — it's UDP-based with its own
retransmission and stays low-latency and stable under packet loss, where RTMP (TCP) stalls
and buffers on any loss. Keep RTMP only for endpoints that require it.

**GOP/keyframe interval directly drives startup and reconnect latency** for anything
downstream doing HLS/LL-HLS (e.g. OBS → MediaMTX). Dropping the keyframe interval from 8.3s
to 2s cut LAN-observed startup latency from ~8.3s to ~2s and non-LL-HLS fallback latency from
~25s to ~6s, in a real measured setup. Gotcha: **OBS's "Simple" output mode has no keyframe
interval control** — you need "Advanced" output mode (requires an OBS restart to take effect)
to set this.

## 3. Pure cloud-rendered gaming (Xbox Cloud Gaming, Boosteroid)

These render entirely on a remote server — there is **no local host, no user-side
bitrate/FEC/QoS control at all**. Your only real levers are: wired > 5GHz > 2.4GHz, killing
contention from other devices on the link, and picking the best ISP path to their datacenter.
Don't waste time looking for settings that don't exist on these platforms.

| Service | Tier | Min Mbps down | Recommended Mbps | Max ping |
|---|---|---|---|---|
| Xbox Cloud Gaming | Mobile | 10 | 20+ | < 80ms (< 40ms ideal) |
| Xbox Cloud Gaming | 1080p (TV/PC/console) | 20 | 30+ | < 80ms (< 40ms ideal) |
| Boosteroid | 720p 60/120fps | 14 / 18 | 20 / 25 | ≤ 20ms |
| Boosteroid | 1080p 60/120fps | 24 / 30 | 35 / 44 | ≤ 20ms |
| Boosteroid | 1440p 60/120fps | 44 / 55 | 64 / 80 | ≤ 20ms |
| Boosteroid | 4K 60/120fps | 64 / 80 | 93 / 100+ | ≤ 20ms |

- **Xbox Cloud Gaming** has an opt-in **Stats Overlay + Network Quality Indicator** (Feature
  Preview, xbox.com/play and some TV apps) showing FPS, Ping (target <80ms), Decode Time
  (<12ms), Jitter (<20ms), Packet Loss (target 0%) — use it as your live diagnostic instead of
  guessing. A visible "connection quality" warning icon means one of these crossed threshold.
- **Boosteroid** publishes its own connection test on their site (run it twice, 10 minutes
  apart) and gives rare concrete client-side tuning: **MTU 1470 (browser) / 1462 (desktop app)
  / 1500 optimal**, explicitly requires **Ethernet or 5GHz only** (2.4GHz/LTE/DSL unsupported),
  flags **IPv6 as a known cause of connection problems** (prefer IPv4), and asks you to
  disable VPNs/proxies/firewalls.
- **CGNAT/mobile hotspot/VPN** is a known pain point specifically for Xbox Cloud Gaming —
  cellular hotspots and CGNAT (common on 5G home internet) can cause instability; check for it
  with `tracert`/`mtr` looking for private-range hops before your first public IP.

## 4. Wireless VR streaming (Air Link, Virtual Desktop, ALVR, WiVRn)

VR needs an order of magnitude more *sustained* (not bursty) bandwidth than flat-screen
streaming, and a much tighter latency budget, because dropped frames or added latency here
cause visible judder and can trigger motion sickness, not just "the picture got worse."

| Platform | Preset/codec | Bitrate |
|---|---|---|
| Virtual Desktop | Godlike (Wi-Fi 6E+) | 200+ Mbps |
| Virtual Desktop | AV1 / H.264+ | ≤200 Mbps / ≤500 Mbps |
| Meta Air Link | slider | 0 (auto)–500 Mbps, sweet spot ~100-150 |
| ALVR | H.264 | 400-500 Mbps |
| ALVR | HEVC | 100-150 Mbps (fallback ~30 Mbps at reduced res) |
| WiVRn (Linux) | H.264/HEVC | up to 200 Mbps, gains flatten below ~80 Mbps |

- **Latency budget:** commonly cited motion-to-photon target is **≤20ms** (some research wants
  ≤14ms). Real wireless PCVR (ALVR/WiVRn) runs comfortably at 80-100ms effective MTP once
  async timewarp/reprojection masks the wireless hop — but every ms shaved off the raw network
  leg reduces reliance on that compensation and reduces judder. Since only the
  headset↔router hop is wireless, **keep the PC wired** — that removes an entire wireless leg
  from the round trip and is standard advice across all four ecosystems.
- **Wi-Fi setup that actually matters for VR** (more than for flat streaming):
  - **Never 2.4GHz** — its latency floor alone makes VR unplayable. 5GHz or 6GHz only.
  - **Widest available channel width** — 80MHz ceiling on 802.11ac, 160MHz on Wi-Fi 6/6E.
    Some vendors don't default to max width — check and set it explicitly.
  - **Dedicated SSID/band, ideally a dedicated router** — Meta explicitly notes mesh systems
    tend not to work well with Air Link. A cheap standalone AP wired to the PC, in the same
    room, is common advice across VD/Air Link/ALVR/WiVRn.
  - **Quiet the band during sessions** — pause/disable other 5GHz clients; one retransmitting
    neighbor device can spike latency.
  - **Line-of-sight, same room** — headsets have weaker antennas than phones/laptops
    (often 2×2, half a laptop's spectrum capacity).
  - MU-MIMO/OFDMA mainly matters if you can't fully quiet the band; largely moot with the
    headset as the only active client.
- **Linux (WiVRn) specific:** same 5/6GHz-only, dedicated-router, wired-PC, max-channel-width
  advice; one wrinkle — its VAAPI encoder path needs a full server restart to change bitrate,
  while the Vulkan encoder path supports live bitrate changes.
- Foveated encoding (where supported) can cut required bandwidth 30-50% for the same
  perceived quality — worth enabling before assuming you need a bigger router.

## Quick reference — what you actually control, by service

| Service | Bitrate control | FEC/loss resilience | QoS lever | Wi-Fi requirement |
|---|---|---|---|---|
| Parsec | Auto (host adapts) | Built-in, not user-tunable | Fixed UDP port range (user-set) | 5GHz min, host wired preferred |
| Moonlight/Sunshine | Manual, fixed per session | `fec_percentage` (1-255) | Fixed UDP ports 47998-48002 | 5GHz min, host wired preferred |
| Xbox Cloud Gaming | None (server-side) | None | None | Wired/5GHz only, avoid CGNAT |
| Boosteroid | None (server-side, quality preset only) | None | None | Wired/5GHz only, set MTU per their docs |
| VR (Air Link/VD/ALVR/WiVRn) | Manual slider or auto-probe | Reprojection masks latency, not loss per se | Dedicated band/router | 5/6GHz only, PC wired mandatory |
