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

`scripts/net_watchdog.py` has two modes selectable with `--mode` for exactly this
(`telemetry` and `malware`). They sit alongside the `stability` checks, which
`09_BACKGROUND_WATCHDOG.md` owns (installing, running and scheduling the script, log
locations, capture permissions), and they use the same install and schedule instructions.
This file owns what the `telemetry` and `malware` modes do and where they stop.

## 1. Example: a smart-TV channels app's telemetry endpoints

Smart-TV ACR (automatic content recognition) and ad-tech telemetry is well documented. The
endpoints below were seen in a packet capture of one smart-TV "channels" app (LG Channels),
and show what such an app calls out to on every stream start. Treat them as an example of
the category, and check your own device's traffic before assuming it uses exactly these hosts:

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
not because one vendor is uniquely bad, but because this is a concrete example of the
category: almost every smart TV, streaming stick, and streaming app ships some version of
this.

## 2. The telemetry and malware modes

From the repository root:

```bash
python3 scripts/net_watchdog.py --mode telemetry --duration 300   # ad-tech/ACR domain matching
python3 scripts/net_watchdog.py --mode malware   --duration 300   # LAN inventory + suspicious traffic
python3 scripts/net_watchdog.py --mode all       --duration 600   # stability + both of the above
```

(`--mode stability` is the default; it is covered in `09_BACKGROUND_WATCHDOG.md`, which also
has a table of all modes.) `--mode` is a hard switch, not additive flags: `telemetry` alone
does **not** also run the ping/retransmit/Wi-Fi checks, and vice versa. Each mode answers a
different question, so they stay independent; `all` is there for when you want the full
picture in one run.

### `--mode telemetry`: what is this host calling out to?

Every sampling interval, it runs `ss -Htin` (all live TCP connections, not just a tracked
host) and checks each peer IP against domains it resolved at startup (built-in list above,
extendable with `--telemetry-domains-file domains.txt`, one domain per line). A match logs an
alert the first time it's seen and tallies bytes per domain for the rest of the run. At the
end, the report shows a **traffic categorization** table (domain → bytes) and writes a ready
dnsmasq/Pi-hole blocklist snippet to the log dir — see §4.

**Important limitation, stated plainly:** `ss` only lists sockets that terminate on the
machine running the script, i.e. *this host's own* connections. That includes a router or
gateway: connections it merely forwards or NATs for other devices are not in `ss` output, so
running the script on a gateway does **not** reveal what a smart TV or STB is calling. To
catch a TV's or STB's telemetry you have two options. Run `--mode telemetry` on the device
itself if it runs Linux, or look at the gateway's view of the traffic with tools this script
does not use: the DNS query log of your resolver (e.g. dnsmasq `log-queries`, Pi-hole) or
`conntrack -L`, then match the domains against the list above by hand.

### `--mode malware`: what's actually on this LAN, and is anything behaving oddly?

Three independent checks, none of which need root or a threat-intel subscription:

1. **LAN node inventory.** Auto-detects your subnet from the primary interface (or pass
   `--lan-cidr 192.168.1.0/24`, adjusted to your own subnet), runs a host-discovery sweep with
   `nmap -sn`, then reads the resulting ARP table (`ip neigh`) for IP↔MAC pairs — no elevated
   privileges needed. (Unprivileged, nmap discovers hosts with TCP connection attempts to
   ports 80/443 and the kernel does the ARP resolution as a side effect, which is what fills
   the neighbor table. Run as root, nmap would use ARP/ICMP probes directly.) Vendor name comes from nmap's local OUI database
   (`/usr/share/nmap/nmap-mac-prefixes`) — no third-party lookup service is ever queried, so
   your LAN's MAC list never leaves the machine. Every run persists what it saw to
   `known_nodes.json` in the log dir; **the first-ever run only establishes the baseline** (it
   would otherwise "discover" your entire existing LAN as new and alert on all of it) —
   `unknown_device` only fires starting from the *second* run, for a MAC that genuinely wasn't
   there before. If you don't recognize a flagged device, that's the single most direct
   security signal this whole guide produces.

   **"Known" means "seen in some run", not "present now".** Each entry carries `first_seen` and
   `last_seen`. A device that was in one scan of a run and is missing from the next raises
   `device_gone` (listed in the summary as `gone_devices`), and the summary's
   `absent_from_this_run` lists every known MAC this run did not see, with its last-seen date.
   Treat absence as a hint: the inventory is only this host's neighbor table. An entry can
   linger there after a device leaves until the kernel expires it, and a device that ignores
   ping and ARP probes can be missed entirely.
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

- `scripts/telemetry_domains.example.txt` — repeats the example list from §1, then extends it
  with other publicly-documented vendors: Vizio's Inscape, Samsung's ACR, Roku, Nielsen, Amazon
  Fire TV's device-metrics pipeline, and Microsoft's Windows diagnostic-data ("Connected User
  Experiences and Telemetry") endpoints. Everything past the first section is sourced from
  public writeups/Microsoft's own docs — verify against your own traffic before assuming a
  specific device uses exactly these hosts, and for Windows in particular, check Microsoft's
  own current list (search their "Manage connections from Windows
  operating system components to Microsoft services" doc) since it varies by Windows version.
- `scripts/malware_domains.example.txt` — intentionally contains **no domains**, only the
  command to pull a real, current feed (abuse.ch/URLhaus) and point `--malware-domains-file`
  at it. Re-run that command whenever you want to refresh it; nothing here is fetched
  automatically.

```bash
python3 scripts/net_watchdog.py --mode telemetry --telemetry-domains-file scripts/telemetry_domains.example.txt
```

## 3. What this can't do (read this before trusting a clean run)

- **Single-vantage-point traffic checks.** `telemetry` and the bandwidth heuristic in
  `malware` only see *this host's* connections — full per-device attribution for every LAN
  member needs running the watchdog directly on each device of interest (running it on the
  gateway does not help, because `ss` does not list forwarded flows; see the limitation under
  `--mode telemetry`). The **LAN node inventory** is the one part of `malware` mode that
  genuinely sees the whole LAN, because it's ARP-based, not traffic-based.
- **No deep packet inspection.** Nothing here decrypts or inspects payloads — it's purely
  metadata (peer IP/port, byte counters, ARP). A well-behaved-looking connection that happens
  to carry something bad inside an encrypted stream will not be caught by any of this.
- **The port/domain lists are illustrative, not exhaustive.** They will not catch a
  sophisticated, specifically-targeted attacker. They *will* catch the common, lazy cases: an
  ad-tech SDK phoning home on schedule, an unencrypted IoT backdoor on a classic port, a new
  unrecognized MAC joining a LAN that's normally static.
- **No root, no traffic mirroring, no NetFlow/sFlow.** Without those, the script cannot see
  other hosts' traffic or read their names. For identifying devices by name, `nmblookup`
  (NetBIOS name resolution) can hang indefinitely on some LANs, so check that it works on
  yours before relying on it.

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

## 5. Safety notes

- Same posture as the rest of this guide: detection only. If `malware` mode flags something,
  go confirm by hand (which physical device has that IP/MAC, what's actually running) before
  touching anything — don't unplug or firewall a device off a hunch from one run.
- The LAN scan (`nmap -sn`) is host discovery only. Unprivileged, it makes a TCP connection
  attempt to ports 80 and 443 per address (plus the ARP resolution the kernel does itself);
  as root it would use ARP/ICMP. Either way it is light traffic of the same class any device
  on the LAN already generates, not a port scan of every host: `malware` mode does not probe
  other open ports on other devices unless you do that yourself, by hand, and only on a
  network you own or are authorized to scan.
- `known_nodes.json` and the telemetry/firewall suggestion files live under the same log dir
  as everything else (`~/.local/state/net_watchdog/` by default) — nothing is sent anywhere.
