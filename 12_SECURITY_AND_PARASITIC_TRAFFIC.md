# Security & Parasitic Traffic: Telemetry, Unknown Devices, and Piracy STBs

Everything up to `11_` assumes the traffic on your LAN is traffic you want. This doc is for
the other question: **who else is on this network, and what is quietly calling out that
shouldn't be?** Three concrete things fall under that umbrella, and they need three different
detection approaches:

1. **Telemetry/ad-tech riding along inside apps you do want** — a smart TV's own "Channels"
   app phoning ad networks and video-analytics vendors on every stream start, whether or not
   you opted in.
2. **A device that shouldn't be on the LAN at all** — a new MAC address nobody recognizes, or
   two IPs answering for the same MAC (often normal, sometimes not — see below).
3. **A box quietly consuming bandwidth doing something you'd rather know about** — the classic
   example being a set-top box streaming pirated content, which looks like "a lot of sustained
   traffic to an IP nobody named" from the network's point of view, same as a malware C2
   channel would.

`scripts/net_watchdog.py` now has three modes selectable with `--mode` for exactly this,
built and verified against this LAN on 2026-09-07 (see §5). They're additive to the
`stability` checks from `09_BACKGROUND_WATCHDOG.md`, not a replacement.

## 1. Where this started: an LG smart TV's actual telemetry endpoints

A video on smart-TV ACR (automatic content recognition) spying included a live packet capture
of the **LG Channels** app, showing exactly what it calls out to on every stream start:

| Endpoint | When | What it does |
|---|---|---|
| `pagead2.googlesyndication.com` | stream start | Tells Google an ad-break triggered |
| `imasdk.googleapis.com`, `static.doubleclick.net` | boot / stream start | Google's video-ad SDK + tracking pixels |
| `cdn-media.brightline.tv` | stream start | Brightline TV ads |
| `na-ssp-pix.adstk.io` | boot | Amazon Ads |
| `<per-device-hash>.cws.conviva.com` | stream start, then a held-open persistent connection | Conviva video analytics — the subdomain itself is a per-device fingerprint |
| `api.axiom.co` | stream start | General app logging/telemetry (usually benign — "is the app crashing" — but the same pipe can carry more) |
| `api.ipify.org` | ~1s before the first frame | The TV fetching **its own household's public IP** and phoning it home |

None of this needs a hidden backdoor or malware — it's the advertised, "normal" behavior of a
bundled app. The reason it belongs in a security doc anyway: **this is exactly what parasitic
traffic looks like from the network layer** — small, frequent, low-bandwidth calls to a long
tail of third-party domains, indistinguishable in shape from a lot of things you'd actually
want to catch. `pagead2.googlesyndication.com`, `doubleclick.net`, `conviva.com`, and friends
are now the seed list for `--mode telemetry` (see `DEFAULT_TELEMETRY_DOMAINS` in the script) —
not because LG is uniquely bad, but because this is a real, verified example of the category:
almost every smart TV, streaming stick, and streaming app ships some version of this.

## 2. The three modes

```bash
cd scripts/
python3 net_watchdog.py --mode stability  --duration 300   # unchanged default, see 09_
python3 net_watchdog.py --mode telemetry  --duration 300   # ad-tech/ACR domain matching
python3 net_watchdog.py --mode malware    --duration 300   # LAN inventory + suspicious traffic
python3 net_watchdog.py --mode all        --duration 600   # all three together
```

`--mode` is a hard switch, not additive flags — `telemetry` alone does **not** also run the
ping/retransmit/Wi-Fi checks, and vice versa. Each mode answers a different question, so they
stay independent; `all` is there for when you want the full picture in one run. This mirrors
how the guide already separates "quick pass vs. deep check" in `09_BACKGROUND_WATCHDOG.md` —
pick the tool for the question you actually have.

### `--mode telemetry`: what is this host calling out to?

Every sampling interval, it runs `ss -Htin` (all live TCP connections, not just a tracked
host) and checks each peer IP against domains it resolved at startup (built-in list above,
extendable with `--telemetry-domains-file domains.txt`, one domain per line). A match logs an
alert the first time it's seen and tallies bytes per domain for the rest of the run. At the
end, the report shows a **traffic categorization** table (domain → bytes) and writes a ready
dnsmasq/Pi-hole blocklist snippet to the log dir — see §4.

**Important limitation, stated plainly:** this only sees *this host's own* connections. To
catch a smart TV's or STB's telemetry, run this in `--mode telemetry` on the device itself
if it's Linux-capable, or better, point it at your router/gateway box if that's where this
guide already lives for you (see the "router VM" in `06_CASE_STUDY_2026-09-05.md` — if you
have a Linux box that already sees all LAN egress, that's the right vantage point, not a
random workstation on the same LAN).

### `--mode malware`: what's actually on this LAN, and is anything behaving oddly?

Three independent checks, none of which need root or a threat-intel subscription:

1. **LAN node inventory.** Auto-detects your subnet from the primary interface (or pass
   `--lan-cidr 192.168.1.0/24`), ping-sweeps it with `nmap -sn`, then reads the resulting ARP
   table (`ip neigh`) for IP↔MAC pairs — no elevated privileges needed, same technique used
   manually in §5. Vendor name comes from nmap's local OUI database
   (`/usr/share/nmap/nmap-mac-prefixes`) — no third-party lookup service is ever queried, so
   your LAN's MAC list never leaves the machine. Every run persists what it saw to
   `known_nodes.json` in the log dir; **the first-ever run only establishes the baseline** (it
   would otherwise "discover" your entire existing LAN as new and alert on all of it) —
   `unknown_device` only fires starting from the *second* run, for a MAC that genuinely wasn't
   there before. If you don't recognize a flagged device, that's the single most direct
   security signal this whole guide produces.
2. **Duplicate-MAC detection.** If the same MAC answers on more than one IP in the same scan,
   it's flagged. This is often completely benign (a floating/VRRP IP, a cloned VM template that
   never got its MAC regenerated) but it's also the visible symptom of ARP/MAC spoofing — worth
   one manual look every time, never worth ignoring by default.
3. **Suspicious connections & unidentified high-bandwidth streams**, covered next.

### The "piracy STB" / suspicious-traffic heuristic

Neither malware nor a pirated-content box announces itself with a domain name — most either
skip DNS entirely (raw IP + self-signed TLS or plain HTTP) or use domains too generic to
blocklist. So instead of trying to name the bad thing, the check looks at **shape**:

- **Suspicious ports.** A small built-in list of classic backdoor/C2 ports (23 Telnet, 4444
  Metasploit's default, 6667 IRC-C2, 1337/31337, etc. — see `MALWARE_PORTS` in the script).
  This is explicitly a starter list, not a threat-intel feed — it will miss a modern C2 channel
  riding on port 443, which is most of them now. It catches the cheap, obvious case, nothing
  more.
- **Sustained high-bandwidth stream to an unnamed peer.** If a connection sustains more than
  `--bandwidth-threshold-mbps` (default 15 Mbps) for `--bandwidth-streak-samples` (default 3)
  consecutive samples, and its peer IP matched **neither** the telemetry list nor a malware
  domain, it gets flagged with a reverse-DNS attempt on the peer. This is the actual signature
  of a piracy IPTV/STB box: continuous, high-bitrate, long-lived traffic to a server that has
  no clean hostname and isn't a recognizable CDN. It is **not proof** — a legitimate large
  file transfer or a game download looks the same from the network layer alone — which is why
  the alert always says "check by hand" (which device has that IP, what's
  running on it) instead of naming a verdict.
- **Optional real domain feed.** `--malware-domains-file` lets you point at a blocklist you
  trust (e.g. an export from abuse.ch/URLhaus). Nothing is bundled by default — a stale or
  fabricated "malware domains" list would be actively misleading, worse than not having one.
  `scripts/malware_domains.example.txt` documents the exact `curl`/`awk` one-liner to pull and
  format a live URLhaus export yourself.

### Example domain-list files

Two ready-to-use files ship in `scripts/` for the two `--*-domains-file` flags:

- `scripts/telemetry_domains.example.txt` — repeats the LG-verified list from §1 (clearly
  labeled as the one set here that was actually captured firsthand), then extends it with
  other publicly-documented vendors: Vizio's Inscape, Samsung's ACR, Roku, Nielsen, Amazon Fire
  TV's device-metrics pipeline, and Microsoft's Windows diagnostic-data ("Connected User
  Experiences and Telemetry") endpoints. Everything past the LG section is sourced from public
  writeups/Microsoft's own docs, not captured on this guide's own network — verify against your
  own traffic before assuming a specific device uses exactly these hosts, and for Windows in
  particular, check Microsoft's own current list (search their "Manage connections from Windows
  operating system components to Microsoft services" doc) since it varies by Windows version.
- `scripts/malware_domains.example.txt` — intentionally contains **no domains**, only the
  command to pull a real, current feed (abuse.ch/URLhaus) and point `--malware-domains-file`
  at it. Re-run that command whenever you want to refresh it; nothing here is fetched
  automatically.

```bash
python3 net_watchdog.py --mode telemetry --telemetry-domains-file scripts/telemetry_domains.example.txt
```

## 3. What this can't do (read this before trusting a clean run)

- **Single-vantage-point traffic checks.** `telemetry` and the bandwidth heuristic in
  `malware` only see *this host's* connections — full per-device attribution for every LAN
  member needs either running the watchdog directly on each device of interest, or on your
  gateway/router where all egress actually passes through. The **LAN node inventory** is the
  one part of `malware` mode that genuinely sees the whole LAN, because it's ARP-based, not
  traffic-based.
- **No deep packet inspection.** Nothing here decrypts or inspects payloads — it's purely
  metadata (peer IP/port, byte counters, ARP). A well-behaved-looking connection that happens
  to carry something bad inside an encrypted stream will not be caught by any of this.
- **The port/domain lists are illustrative, not exhaustive.** They will not catch a
  sophisticated, specifically-targeted attacker. They *will* catch the common, lazy cases: an
  ad-tech SDK phoning home on schedule, an unencrypted IoT backdoor on a classic port, a new
  unrecognized MAC joining a LAN that's normally static.
- **No root, no traffic mirroring, no NetFlow/sFlow.** Verified live on 2026-09-07: `nmblookup`
  (NetBIOS name resolution) hung indefinitely against every host on this particular LAN and
  had to be ruled out as an identification method here — don't assume it'll work on yours
  either without checking first.

## 4. Mitigation output: suggestions only, nothing is ever applied automatically

Consistent with `02_TOOLS.md`'s "this guide is read-only diagnostics" stance, both new modes
only ever **write a suggestion file** for you to review — never touch DNS or firewall config
themselves:

- `--mode telemetry`, if it saw any matches: `telemetry_blocklist_<run>.conf` — a dnsmasq
  `address=/domain/0.0.0.0` line per domain actually observed this run (not the whole built-in
  list — only confirmed offenders on your network). Copy into `/etc/dnsmasq.d/` or import into
  Pi-hole as a blocklist, by hand, after reading it.
- `--mode malware`, if it flagged any suspicious connection: `firewall_suggestions_<run>.txt`
  — commented `nft add rule ... drop` lines per flagged IP/port, again for manual review and
  application, never auto-run.

Both paths are echoed in the end-of-run report and saved in `summary_<run>.json`.

## 5. Verified 2026-09-07 against this LAN

Real results, not a hypothetical:

- **Node inventory:** a `nmap -sn 192.168.1.0/24` + `ip neigh` pass found **29 live hosts / 27
  unique MACs** in ~2 seconds, unprivileged. OUI lookup correctly identified a 22-VM Proxmox
  cluster (MAC prefix `bc:24:11`, Proxmox's own vendor block) plus a handful of real hardware
  (two ASUSTek boxes, one Gigabyte motherboard NIC, one ASIX USB-Ethernet adapter — the same
  chipset family implicated in `06_CASE_STUDY_2026-09-05.md`'s original hardware bug).
- **Duplicate-MAC detection worked on real anomalies, not synthetic ones:** two genuine
  duplicate-MAC pairs existed on this LAN at scan time (`.61`/`.62` sharing one Proxmox MAC,
  `.118`/`.119` sharing one locally-administered MAC) and both were caught on the very first
  run.
- **First-run baseline behavior confirmed:** the first-ever `--mode malware` run recorded all
  27 MACs into `known_nodes.json` **without** raising 27 false "new device" alerts; an
  immediate second run against the same LAN correctly reported "0 new this run" for the
  unchanged set, while still re-flagging the two live duplicate-MAC conditions (those aren't
  "new device" events, so the baseline suppression correctly doesn't apply to them).
- **`--mode telemetry` ran clean (0 matches)** on this same host over a short window — expected
  and correct: this particular LAN segment is a Proxmox homelab, not a segment with a smart TV
  or ad-supported streaming device attached, so there was nothing in the built-in list for it
  to legitimately match. A clean run here is not evidence the checks don't work — see §2's
  vantage-point limitation for where to actually point this at a smart TV/STB.
- **No Windows/SMB devices found** on a fast-port fingerprint pass (`nmap -F`) of every
  non-Proxmox host — nothing answered 135/445/3389, and `nmblookup` (NetBIOS name resolution)
  timed out against every target, confirming there was no Windows-style computer name to
  recover here.

## 6. Safety notes

- Same posture as the rest of this guide: detection only. If `malware` mode flags something,
  go confirm by hand (which physical device has that IP/MAC, what's actually running) before
  touching anything — don't unplug or firewall a device off a hunch from one run.
- The LAN scan (`nmap -sn`) is a plain ICMP/ARP ping sweep — the same class of traffic any
  device on the LAN already generates constantly (ARP requests, mDNS). It is not a port scan
  of every host by default; `malware` mode does not probe open ports on other devices unless
  you do that yourself, by hand, as in §5's `nmap -F` fingerprint pass.
- `known_nodes.json` and the telemetry/firewall suggestion files live under the same log dir
  as everything else (`~/.local/state/net_watchdog/` by default) — nothing is sent anywhere.
