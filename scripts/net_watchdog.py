#!/usr/bin/env python3
"""Unattended network-health watchdog.

Three independent check families, selected with --mode:

  stability (default, unchanged since 2026-09-05): the checks described in
  03_WIRED_AND_GATEWAY.md, 04_WIFI.md and 05_AI_WORKLOAD_AND_LATENCY.md --
  a periodic or one-off gateway-ping gap, growing TCP retransmitted bytes
  on a tracked connection (ss -tin), Wi-Fi signal/tx-failure bursts, a NIC
  carrier flap.

  telemetry: matches this host's live connections against a built-in list
  of known ad-tech/ACR/video-analytics domains (see
  12_SECURITY_AND_PARASITIC_TRAFFIC.md) and tallies bytes per domain.

  malware: a lightweight LAN node inventory (new/unknown device joining,
  a MAC answering on more than one IP at once), connections to
  classic backdoor/C2 ports, and sustained high-bandwidth connections to
  an unclassified, unnamed peer -- the generic signature of an unattended
  box (e.g. a piracy STB) pulling a large stream nobody is watching for.

  all: runs all three.

Meant to be triggered periodically by a systemd timer (see
09_BACKGROUND_WATCHDOG.md) rather than run as a permanent daemon --
"a while every few days" catches a chronic problem in days instead of
months, without leaving something running 24/7.

Read-only except for the optional --capture-on-anomaly tcpdump capture,
which needs its own explicit permissions (see the doc). telemetry/malware
findings can write a suggested dnsmasq blocklist / nftables snippet to
the log dir for you to review and apply by hand -- nothing is ever
applied automatically.
"""
import argparse
import ipaddress
import json
import os
import re
import shutil
import signal
import socket
import statistics
import subprocess
import sys
import threading
import time
from datetime import datetime
from pathlib import Path

# -- colored/tidy terminal output ---------------------------------------
# ANSI only when stdout is an actual terminal (never when piped to a file
# or captured by systemd/journalctl) and NO_COLOR isn't set -- degrades to
# plain text automatically everywhere else.
_USE_COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
_COLORS = {"green": "32", "yellow": "33", "red": "31", "cyan": "36", "bold": "1"}


def c(text, *styles):
    if not _USE_COLOR:
        return text
    codes = ";".join(_COLORS[s] for s in styles)
    return f"\033[{codes}m{text}\033[0m"


# -- telemetry / malware reference data ---------------------------------
# Ad-tech, ACR (automatic content recognition) and video-analytics domains.
# Seeded from a live packet capture of the LG Channels app (see
# 12_SECURITY_AND_PARASITIC_TRAFFIC.md) plus the usual general-purpose
# ad-tech names that ride along with almost any smart-TV/streaming-box
# app, not just LG's. Not exhaustive -- extend with --telemetry-domains-file.
DEFAULT_TELEMETRY_DOMAINS = [
    # observed live from LG Channels (2026-09), see 12_...md
    "googlesyndication.com",
    "doubleclick.net",
    "imasdk.googleapis.com",
    "brightline.tv",
    "adstk.io",
    "conviva.com",
    "axiom.co",
    "ipify.org",
    # general ad-tech/analytics commonly seen on smart TVs and streaming apps
    "google-analytics.com",
    "googletagmanager.com",
    "googleadservices.com",
    "adservice.google.com",
    "amazon-adsystem.com",
    "scorecardresearch.com",
    "adnxs.com",
    "criteo.com",
    "criteo.net",
    "taboola.com",
    "outbrain.com",
    "ipinfo.io",
]

# Classic backdoor/C2 ports worth a manual look if a LAN device is talking
# on them unexpectedly. This is a small, illustrative starter list -- NOT a
# threat-intel feed. It will not catch a modern C2 channel riding on 443.
MALWARE_PORTS = {
    23: "Telnet (classic Mirai-style IoT botnet target)",
    2323: "Alternate Telnet (common botnet scanner target)",
    4444: "Metasploit's default port / generic backdoors",
    6666: "Alternate IRC (botnet C2)",
    6667: "IRC (classic botnet C2 channel)",
    1337: "\"leet\" port -- classic backdoor/trojan",
    31337: "\"elite\" port -- classic backdoor/trojan",
}


def load_domain_list(path, extra=None):
    domains = list(extra or [])
    if path:
        try:
            with open(path) as f:
                domains += [
                    line.strip()
                    for line in f
                    if line.strip() and not line.strip().startswith("#")
                ]
        except Exception as e:
            print(f"warning: could not read {path}: {e}", file=sys.stderr)
    return domains


def split_host_port(hostport):
    """Split 'ip:port' or '[ipv6]:port' -> (addr, port|None)."""
    m = re.search(r":(\d+)$", hostport)
    if not m:
        return hostport.strip("[]"), None
    return hostport[: m.start()].strip("[]"), int(m.group(1))


def reverse_dns_cached(ip, cache):
    if ip in cache:
        return cache[ip]
    name = None
    try:
        socket.setdefaulttimeout(1.5)
        name = socket.gethostbyaddr(ip)[0]
    except Exception:
        pass
    finally:
        socket.setdefaulttimeout(None)
    cache[ip] = name
    return name


def detect_lan_cidr(iface):
    if not iface:
        return None
    out = sh(["ip", "-o", "-f", "inet", "addr", "show", iface])
    m = re.search(r"inet (\d+\.\d+\.\d+\.\d+/\d+)", out)
    return m.group(1) if m else None


_OUI_CACHE = None


def oui_vendor(mac):
    """Best-effort vendor name from nmap's local OUI database. No network
    calls -- if nmap isn't installed (or the DB file is missing), returns
    'unknown' rather than phoning a third-party lookup service with every
    MAC on the LAN."""
    global _OUI_CACHE
    if _OUI_CACHE is None:
        _OUI_CACHE = {}
        for path in ("/usr/share/nmap/nmap-mac-prefixes",):
            try:
                with open(path) as f:
                    for line in f:
                        parts = line.strip().split(None, 1)
                        if len(parts) == 2:
                            _OUI_CACHE[parts[0].upper()] = parts[1]
            except Exception:
                continue
    prefix = mac.upper().replace(":", "")[:6]
    return _OUI_CACHE.get(prefix, "unknown")


def is_locally_administered(mac):
    try:
        first_octet = int(mac.split(":")[0], 16)
        return bool(first_octet & 0x02)
    except Exception:
        return False


def scan_lan_nodes(cidr, timeout=30):
    """Ping-sweep `cidr` with nmap (populates the kernel ARP cache), then
    read the ARP/neighbor table for IP<->MAC. Returns {mac: [ips]}, or
    None if nmap isn't installed (caller decides how to report that)."""
    if not shutil.which("nmap"):
        return None
    sh(["nmap", "-sn", cidr], timeout=timeout)
    neigh_out = sh(["ip", "neigh", "show"], timeout=5)
    nodes = {}
    for line in neigh_out.splitlines():
        m = re.match(r"(\S+) dev (\S+) lladdr ([0-9a-fA-F:]+) (\S+)", line)
        if not m:
            continue
        ip, _dev, mac, state = m.groups()
        if ":" in ip or state == "FAILED":
            continue
        nodes.setdefault(mac.lower(), []).append(ip)
    return nodes


def load_known_nodes(path):
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return {}


def save_known_nodes(path, data):
    try:
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
    except Exception:
        pass


QUICKSTART = """\
HOW TO USE IT (quick guide)
  Quick STABILITY pass (default, 5 min), watching retransmits to the real
  API -- this is the only thing that ran before the other modes existed,
  still works the same:
    python3 net_watchdog.py --hosts api.anthropic.com

  Full/deep stability check (more time to catch slow patterns):
    python3 net_watchdog.py --duration 1200 --hosts api.anthropic.com --capture-on-anomaly

  Look for telemetry/ad-tech (smart-TV ACR, ad-tech) in THIS host's
  traffic:
    python3 net_watchdog.py --mode telemetry --duration 300

  Look for security issues: new devices on the LAN, suspicious ports,
  unidentified high-consumption streams (a piracy STB, malware calling
  out on a weird port, etc.):
    python3 net_watchdog.py --mode malware --duration 300

  Run all three checks together:
    python3 net_watchdog.py --mode all --duration 600

  Re-print a past run's result in readable form:
    python3 net_watchdog.py --report ~/.local/state/net_watchdog/summary_<date>.json

  Install it to run on its own every 3 days (no need to keep a terminal
  open): see 09_BACKGROUND_WATCHDOG.md.

  While it runs: no need to watch the screen -- if it finds something it
  shows up right here (and as a desktop notification) instantly. The
  final summary, at the end, is always the same block you see below.
  See 12_SECURITY_AND_PARASITIC_TRAFFIC.md for the telemetry/malware
  modes in detail.
"""


def sh(cmd, timeout=5):
    try:
        return subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        ).stdout
    except Exception:
        return ""


def detect_route():
    out = sh(["ip", "route", "get", "8.8.8.8"])
    via_m = re.search(r"via (\S+)", out)
    dev_m = re.search(r"dev (\S+)", out)
    return (via_m.group(1) if via_m else None, dev_m.group(1) if dev_m else None)


def is_wireless(iface):
    if not iface:
        return False
    return os.path.exists(f"/sys/class/net/{iface}/wireless") or os.path.exists(
        f"/sys/class/net/{iface}/phy80211"
    )


def read_carrier_changes(iface):
    try:
        with open(f"/sys/class/net/{iface}/carrier_changes") as f:
            return int(f.read().strip())
    except Exception:
        return None


def sample_ss(ip=None):
    """Parse `ss -Htin [dst <ip>]` into a list of per-connection dicts.

    -H suppresses the header so lines pair up 2-per-connection; see the
    note on this exact gotcha in 05_AI_WORKLOAD_AND_LATENCY.md. With
    ip=None, returns every live TCP connection on this host -- used by the
    telemetry/malware checks, which need to see all traffic, not just a
    tracked host.
    """
    cmd = ["ss", "-Htin"]
    if ip:
        cmd += ["dst", ip]
    out = sh(cmd)
    lines = [l for l in out.splitlines() if l.strip()]
    conns = []
    for i in range(0, len(lines) - 1, 2):
        head, detail = lines[i], lines[i + 1]
        parts = head.split()
        if len(parts) < 5:
            continue
        rtt_m = re.search(r"rtt:([\d.]+)/([\d.]+)", detail)
        cwnd_m = re.search(r"cwnd:(\d+)", detail)
        bytes_retrans_m = re.search(r"bytes_retrans:(\d+)", detail)
        bytes_acked_m = re.search(r"bytes_acked:(\d+)", detail)
        bytes_received_m = re.search(r"bytes_received:(\d+)", detail)
        conns.append(
            {
                "local": parts[3],
                "peer": parts[4],
                "rtt": float(rtt_m.group(1)) if rtt_m else None,
                "rttvar": float(rtt_m.group(2)) if rtt_m else None,
                "cwnd": int(cwnd_m.group(1)) if cwnd_m else None,
                "bytes_retrans": int(bytes_retrans_m.group(1)) if bytes_retrans_m else 0,
                "bytes_acked": int(bytes_acked_m.group(1)) if bytes_acked_m else 0,
                "bytes_received": int(bytes_received_m.group(1)) if bytes_received_m else 0,
            }
        )
    return conns


def sample_wifi(iface):
    link = sh(["iw", "dev", iface, "link"])
    station = sh(["iw", "dev", iface, "station", "dump"])
    sig_m = re.search(r"signal:\s*(-?\d+)\s*dBm", link)
    retries_m = re.search(r"tx retries:\s*(\d+)", station)
    failed_m = re.search(r"tx failed:\s*(\d+)", station)
    return {
        "signal_dbm": int(sig_m.group(1)) if sig_m else None,
        "tx_retries": int(retries_m.group(1)) if retries_m else None,
        "tx_failed": int(failed_m.group(1)) if failed_m else None,
    }


def check_periodicity(gap_times, tolerance=0.25):
    """Return an estimated period if recent gaps recur at a regular
    interval (the case-study signature), else None."""
    if len(gap_times) < 3:
        return None
    recent = gap_times[-6:]
    diffs = [recent[i + 1] - recent[i] for i in range(len(recent) - 1)]
    mean = statistics.mean(diffs)
    if mean <= 0:
        return None
    stdev = statistics.pstdev(diffs) if len(diffs) > 1 else 0
    if stdev / mean < tolerance:
        return mean
    return None


# Plain-language label for each anomaly kind, used in the human-readable
# report -- keep in sync with the `kind` strings passed to alert().
KIND_LABELS = {
    "ping_gap": "One-off gateway ping gap",
    "periodic_gap_pattern": "PERIODIC gap pattern (06_CASE_STUDY signature)",
    "retrans_growth": "TCP retransmits growing steadily",
    "wifi_signal": "Wi-Fi signal below threshold",
    "wifi_tx_failed_burst": "Burst of Wi-Fi tx failures",
    "carrier_flap": "NIC/link went down and came back (carrier flap)",
    "no_gateway": "Could not determine the gateway -- ping monitoring disabled",
    "no_ping": "`ping` binary not found -- ping monitoring disabled",
    "telemetry_match": "Telemetry/ad-tech traffic identified",
    "suspicious_connection": "Connection to a flagged domain or port",
    "unidentified_high_bandwidth": "Sustained high consumption, unidentified (possible piracy STB or other unauthorized traffic)",
    "unknown_device": "New/unknown device on the LAN",
    "duplicate_mac": "One MAC answering on more than one IP at once",
    "no_nmap": "nmap is not installed -- cannot build the LAN node inventory",
}


def human_bytes(n):
    n = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.1f}{unit}"
        n /= 1024


def format_human_report(summary):
    """Render a summary dict (same shape as summary_*.json) as a tidy,
    color-coded (when on a real terminal) human report: what was watched,
    what was found, what to do -- in that order, every time."""
    bar = "─" * 64
    mode = summary.get("mode", "stability")
    L = []
    L.append(c("═" * 64, "cyan"))
    L.append(c("  Network Watchdog -- run summary", "bold", "cyan"))
    L.append(c("═" * 64, "cyan"))
    L.append(c(f"  What was watched (mode: {mode})", "bold"))
    if mode in ("stability", "all"):
        wifi_bit = f"yes ({summary['wlan_iface']})" if summary.get("wlan_iface") else "not applicable (wired link / no Wi-Fi detected)"
        L.append(f"  Gateway (ping gaps):         {summary.get('gateway') or '(not detected)'}")
        L.append(f"  Primary interface:           {summary.get('iface') or '(not detected)'}")
        L.append(f"  Wi-Fi monitored:             {wifi_bit}")
        hosts = summary.get("hosts") or []
        L.append(
            "  Hosts (TCP retransmits):     "
            + (", ".join(hosts) if hosts else "none -- pass --hosts to enable this check")
        )
    if mode in ("malware", "all"):
        L.append(f"  LAN CIDR inventoried:        {summary.get('lan_cidr') or '(not determined)'}")
    dur = summary.get("started_duration_seconds")
    if dur:
        L.append(f"  Configured duration:         {dur}s (~{dur // 60} min)")
    L.append(bar)

    if mode in ("telemetry", "all"):
        hits = summary.get("telemetry_hits") or {}
        L.append(c("  Traffic categorization -- telemetry/ad-tech", "bold"))
        if hits:
            for domain, nbytes in sorted(hits.items(), key=lambda kv: -kv[1]):
                L.append(f"    {domain:<32} {human_bytes(nbytes):>10}")
            bl = summary.get("telemetry_blocklist")
            if bl:
                L.append(f"  Suggested DNS blocklist (dnsmasq/Pi-hole, not applied): {bl}")
        else:
            L.append("  No traffic seen to any known telemetry/ad-tech domain.")
        L.append(bar)

    if mode in ("malware", "all"):
        nodes = summary.get("lan_nodes") or {}
        new_devices = summary.get("new_devices") or []
        L.append(c(f"  LAN nodes ({len(nodes)} known, {len(new_devices)} new this run)", "bold"))
        for mac, info in sorted(nodes.items(), key=lambda kv: kv[1].get("ips", [""])[0]):
            ips = ", ".join(info.get("ips", []))
            tag = c(" NEW", "bold", "yellow") if any(d["mac"] == mac for d in new_devices) else ""
            L.append(f"    {ips:<16} {mac}  {info.get('vendor', 'unknown')}{tag}")
        fw = summary.get("firewall_suggestions")
        if fw:
            L.append(f"  Suggested firewall rules (nftables, not applied): {fw}")
        L.append(bar)

    anomalies = summary.get("anomalies") or []
    if summary.get("verdict") == "OK":
        L.append(c("  ✔ OK", "bold", "green") + " -- no anomaly detected on this run.")
        L.append("  Nothing to review, nothing to do.")
    else:
        L.append(c(f"  ⚠ {len(anomalies)} ISSUE(S) FOUND", "bold", "yellow"))
        L.append("")
        for i, a in enumerate(anomalies, 1):
            label = KIND_LABELS.get(a.get("kind"), a.get("kind", "?"))
            L.append(f"  {i}. " + c(f"[{a.get('ts', '?')}] {label}", "bold", "yellow"))
            L.append(f"     -> {a.get('message', '')}")
            L.append("")
        L.append(bar)
        L.append(c("  What to do now", "bold"))
        L.append("  Don't restart, block, or change anything blindly. Every message above")
        L.append("  already tells you which guide file to follow (03_/04_/05_ for stability,")
        L.append("  12_SECURITY_AND_PARASITIC_TRAFFIC.md for telemetry/malware) and which")
        L.append("  section to check first -- go through that list one item at a time, in order.")
    pcap = summary.get("pcap")
    if pcap:
        L.append("")
        L.append(f"  Packet capture saved: {pcap}")
        L.append("  (open it with `tcpdump -r <file>` or Wireshark)")
    L.append(bar)
    sp = summary.get("_summary_path")
    if sp:
        L.append(f"  Full detail (JSON) for this run: {sp}")
    L.append(f"  To re-read this same summary later: --report {sp or '<summary.json>'}")
    L.append(c("═" * 64, "cyan"))
    return "\n".join(L)


class Watchdog:
    def __init__(self, args):
        self.args = args
        gw, dev = detect_route()
        self.gateway = args.gateway or gw
        self.iface = args.iface or dev
        self.wlan_iface = args.wlan_iface or (
            self.iface if is_wireless(self.iface) else None
        )
        self.hosts = [h.strip() for h in args.hosts.split(",") if h.strip()]
        self.host_ips = {}
        for h in self.hosts:
            try:
                self.host_ips[h] = socket.gethostbyname(h)
            except socket.gaierror:
                print(f"warning: could not resolve {h}, skipping", file=sys.stderr)

        run_id = datetime.now().strftime("%Y%m%dT%H%M%S")
        log_dir = Path(args.log_dir) if args.log_dir else (
            Path.home() / ".local" / "state" / "net_watchdog"
        )
        log_dir.mkdir(parents=True, exist_ok=True)
        self.log_dir = log_dir
        self.run_id = run_id
        self.events_path = log_dir / f"events_{run_id}.jsonl"
        self.alerts_path = log_dir / "alerts.log"
        self.summary_path = log_dir / f"summary_{run_id}.json"

        self.anomalies = []
        self.gap_times = []
        self.periodic_flagged = False
        self.capture_started = False
        self.pcap_path = None
        self.retrans_history = {}  # key -> consecutive-growth counter
        self.carrier_start = read_carrier_changes(self.iface) if self.iface else None
        self.carrier_flagged = False
        self.stop_event = threading.Event()
        self.notify = not args.no_notify

        # -- telemetry / malware mode state ------------------------------
        self.mode = args.mode
        self.telemetry_domains = load_domain_list(args.telemetry_domains_file, DEFAULT_TELEMETRY_DOMAINS)
        self.malware_domains = load_domain_list(args.malware_domains_file, [])
        self.telemetry_ip_map = {}
        self.malware_ip_map = {}
        self.last_dns_refresh = 0.0
        self.bw_history = {}
        self.unclassified_streak = {}
        self.telemetry_hits = {}  # domain -> cumulative bytes seen this run
        self._flagged_conns = set()
        self.malware_alert_targets = set()  # (ip, port, reason) for the firewall-suggestions file
        self._rdns_cache = {}
        self._nmap_warned = False

        self.lan_cidr = None
        if self.mode in ("malware", "all"):
            cidr = args.lan_cidr or detect_lan_cidr(self.iface)
            if cidr:
                try:
                    self.lan_cidr = str(ipaddress.ip_interface(cidr).network)
                except ValueError:
                    print(f"warning: --lan-cidr {cidr!r} is invalid, LAN inventory disabled", file=sys.stderr)
        self.known_nodes_path = log_dir / "known_nodes.json"
        self.known_nodes = load_known_nodes(self.known_nodes_path) if self.mode in ("malware", "all") else {}
        # First-ever run against an empty store: record everything found as
        # the baseline, but don't alert on all of it as "new" -- only
        # devices that show up in a *later* run are actually new.
        self._lan_baseline_run = not bool(self.known_nodes)
        self.last_lan_scan = 0.0
        self.new_devices_this_run = []
        self.lan_nodes_seen = {}

    # -- logging / alerting --------------------------------------------
    def log_event(self, kind, data):
        entry = {"ts": datetime.now().isoformat(), "kind": kind, **data}
        with open(self.events_path, "a") as f:
            f.write(json.dumps(entry) + "\n")

    def alert(self, kind, message, extra=None):
        entry = {"ts": datetime.now().isoformat(), "kind": kind, "message": message}
        if extra:
            entry.update(extra)
        with open(self.alerts_path, "a") as f:
            f.write(json.dumps(entry) + "\n")
        print(f"[ALERT] {message}", file=sys.stderr)
        if self.notify and shutil.which("notify-send"):
            try:
                subprocess.Popen(
                    ["notify-send", "-u", "critical", "Network Watchdog", message]
                )
            except Exception:
                pass
        self.anomalies.append(entry)
        if self.args.capture_on_anomaly and not self.capture_started:
            self.maybe_capture()

    def maybe_capture(self):
        if not shutil.which("tcpdump"):
            return
        self.capture_started = True
        pcap_path = self.log_dir / f"capture_{self.run_id}.pcap"
        try:
            subprocess.Popen(
                [
                    "tcpdump",
                    "-i", self.iface or "any",
                    "-w", str(pcap_path),
                    "-G", str(self.args.capture_seconds),
                    "-W", "1",
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            self.pcap_path = str(pcap_path)
            print(f"anomaly capture started -> {pcap_path}", file=sys.stderr)
        except Exception as e:
            print(f"tcpdump capture failed to start: {e}", file=sys.stderr)

    # -- ping gap watcher (runs in its own thread) -----------------------
    def ping_thread(self):
        if not self.gateway:
            self.alert("no_gateway", "Could not determine default gateway; ping-gap detection disabled.")
            return
        try:
            proc = subprocess.Popen(
                ["ping", "-D", "-i", "1", self.gateway],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                bufsize=1,
            )
        except FileNotFoundError:
            self.alert("no_ping", "`ping` binary not found; ping-gap detection disabled.")
            return
        self._ping_proc = proc
        ts_re = re.compile(r"^\[(\d+\.\d+)\]")
        prev_ts = None
        for line in proc.stdout:
            if self.stop_event.is_set():
                break
            m = ts_re.match(line)
            if not m:
                continue
            ts = float(m.group(1))
            if prev_ts is not None:
                gap = ts - prev_ts
                if gap > self.args.ping_gap_threshold:
                    self.gap_times.append(ts)
                    self.log_event("ping_gap", {"gap_seconds": round(gap, 2)})
                    self.alert(
                        "ping_gap",
                        f"Gateway ping gap of {gap:.1f}s detected (threshold "
                        f"{self.args.ping_gap_threshold}s) -- possible link reset/outage.",
                        {"gap_seconds": round(gap, 2)},
                    )
                    if not self.periodic_flagged:
                        period = check_periodicity(self.gap_times)
                        if period is not None:
                            self.periodic_flagged = True
                            self.alert(
                                "periodic_gap_pattern",
                                f"Gateway ping gaps recur roughly every {period:.1f}s -- "
                                "this is the case-study signature of a local watchdog/NIC "
                                "cycling a link, not random loss. See "
                                "03_WIRED_AND_GATEWAY.md step 4.",
                                {"estimated_period_seconds": round(period, 2)},
                            )
            prev_ts = ts
        try:
            proc.terminate()
        except Exception:
            pass

    # -- telemetry: match live connections against known ad-tech/ACR domains
    def refresh_dns_maps(self):
        now = time.monotonic()
        if self.telemetry_ip_map and now - self.last_dns_refresh < self.args.dns_refresh_interval:
            return
        self.last_dns_refresh = now
        for domain in self.telemetry_domains:
            try:
                _, _, ips = socket.gethostbyname_ex(domain)
                for ip in ips:
                    self.telemetry_ip_map[ip] = domain
            except socket.gaierror:
                continue
        for domain in self.malware_domains:
            try:
                _, _, ips = socket.gethostbyname_ex(domain)
                for ip in ips:
                    self.malware_ip_map[ip] = domain
            except socket.gaierror:
                continue

    def sample_traffic_categories(self):
        """One sampling pass for --mode telemetry/malware/all: classify
        every live connection on this host as telemetry/ad-tech, a
        suspicious port/domain, an unclassified high-bandwidth stream, or
        (implicitly) ordinary traffic."""
        self.refresh_dns_maps()
        now = time.monotonic()
        for conn in sample_ss():
            peer_ip, peer_port = split_host_port(conn["peer"])
            key = (conn["local"], conn["peer"])
            total_bytes = conn["bytes_acked"] + conn["bytes_received"]
            prev = self.bw_history.get(key)
            mbps = None
            if prev is not None:
                dt = now - prev["ts"]
                if dt > 0:
                    mbps = max(0, total_bytes - prev["bytes"]) * 8 / dt / 1_000_000
            self.bw_history[key] = {"bytes": total_bytes, "ts": now}

            domain = self.telemetry_ip_map.get(peer_ip)
            if domain and self.mode in ("telemetry", "all"):
                if domain not in self.telemetry_hits:
                    self.alert(
                        "telemetry_match",
                        f"Telemetry/ad-tech traffic: {conn['peer']} resolves to "
                        f"{domain}. See 12_SECURITY_AND_PARASITIC_TRAFFIC.md.",
                        {"domain": domain, "peer": conn["peer"]},
                    )
                self.telemetry_hits[domain] = self.telemetry_hits.get(domain, 0) + total_bytes
                continue

            mw_domain = self.malware_ip_map.get(peer_ip)
            port_reason = MALWARE_PORTS.get(peer_port)
            if (mw_domain or port_reason) and self.mode in ("malware", "all"):
                flag_key = f"{conn['local']}->{conn['peer']}"
                if flag_key not in self._flagged_conns:
                    self._flagged_conns.add(flag_key)
                    reason = f"flagged domain ({mw_domain})" if mw_domain else f"suspicious port {peer_port} ({port_reason})"
                    self.malware_alert_targets.add((peer_ip, peer_port, reason))
                    self.alert(
                        "suspicious_connection",
                        f"Suspicious connection {conn['local']} -> {conn['peer']}: {reason}. "
                        "Not proof of infection by itself -- confirm by hand.",
                        {"local": conn["local"], "peer": conn["peer"], "reason": reason},
                    )
                continue

            if mbps is not None and self.mode in ("malware", "all"):
                if mbps >= self.args.bandwidth_threshold_mbps:
                    streak = self.unclassified_streak.get(key, 0) + 1
                    self.unclassified_streak[key] = streak
                    if streak == self.args.bandwidth_streak_samples:
                        hostname = reverse_dns_cached(peer_ip, self._rdns_cache)
                        self.alert(
                            "unidentified_high_bandwidth",
                            f"Sustained high consumption (~{mbps:.1f} Mbps) towards {conn['peer']} "
                            f"({hostname or 'no reverse name'}), no match against known lists. "
                            "Could be legitimate streaming/download -- or a piracy STB, or other "
                            "unauthorized traffic. Check by hand (which device has that IP, what "
                            "it's watching/running).",
                            {"peer": conn["peer"], "mbps": round(mbps, 1), "hostname": hostname},
                        )
                else:
                    self.unclassified_streak.pop(key, None)

    # -- malware/security: LAN node inventory ----------------------------
    def maybe_scan_lan(self):
        if not self.lan_cidr:
            return
        now = time.monotonic()
        if self.last_lan_scan and now - self.last_lan_scan < self.args.lan_scan_interval:
            return
        self.last_lan_scan = now
        nodes = scan_lan_nodes(self.lan_cidr, timeout=self.args.lan_scan_timeout)
        if nodes is None:
            if not self._nmap_warned:
                self._nmap_warned = True
                self.alert("no_nmap", "nmap is not installed -- install `nmap` to enable the LAN node inventory (see 02_TOOLS.md).")
            return
        for mac, ips in nodes.items():
            self.lan_nodes_seen[mac] = ips
            vendor = oui_vendor(mac)
            if len(ips) > 1:
                self.alert(
                    "duplicate_mac",
                    f"MAC {mac} ({vendor}) is answering on more than one IP at once: "
                    f"{', '.join(ips)}. Could be normal (floating IP/VRRP, a cloned VM) or a "
                    "sign of ARP/MAC spoofing -- confirm which is the real device.",
                    {"mac": mac, "ips": ips, "vendor": vendor},
                )
            is_new = mac not in self.known_nodes
            if is_new:
                self.new_devices_this_run.append({"mac": mac, "ips": ips, "vendor": vendor})
                if not self._lan_baseline_run:
                    self.alert(
                        "unknown_device",
                        f"New device on the LAN: {mac} ({vendor}) at {', '.join(ips)} -- "
                        "wasn't in the previous run's inventory. If you don't recognize it, "
                        "this is the most direct security signal this check produces.",
                        {"mac": mac, "ips": ips, "vendor": vendor},
                    )
            self.known_nodes[mac] = {
                "vendor": vendor,
                "ips": ips,
                "last_seen": datetime.now().isoformat(),
                "first_seen": self.known_nodes.get(mac, {}).get("first_seen", datetime.now().isoformat()),
            }
        save_known_nodes(self.known_nodes_path, self.known_nodes)

    # -- report-time mitigation suggestions (never applied automatically)
    def write_telemetry_blocklist(self):
        if not self.telemetry_hits:
            return None
        path = self.log_dir / f"telemetry_blocklist_{self.run_id}.conf"
        with open(path, "w") as f:
            f.write("# Telemetry/ad-tech domains seen on this run (dnsmasq format).\n")
            f.write("# Review before applying: copy into /etc/dnsmasq.d/ and restart dnsmasq,\n")
            f.write("# or import as a blocklist in Pi-hole. Never applied automatically.\n")
            for domain in sorted(self.telemetry_hits):
                f.write(f"address=/{domain}/0.0.0.0\n")
        return str(path)

    def write_firewall_suggestions(self):
        if not self.malware_alert_targets:
            return None
        path = self.log_dir / f"firewall_suggestions_{self.run_id}.txt"
        with open(path, "w") as f:
            f.write("# Suggested blocks (nftables) for what was flagged as suspicious on\n")
            f.write("# this run. Review every IP/port by hand before applying --\n")
            f.write("# this is NEVER run automatically.\n")
            for ip, port, reason in sorted(self.malware_alert_targets, key=lambda x: (x[0], x[1] or 0)):
                f.write(f"# {reason}\n")
                if port:
                    f.write(f"nft add rule inet filter output ip daddr {ip} tcp dport {port} drop\n")
                else:
                    f.write(f"nft add rule inet filter output ip daddr {ip} drop\n")
        return str(path)

    # -- periodic sampling (main-thread loop) ----------------------------
    def sample_once(self):
        if self.mode in ("stability", "all"):
            for host, ip in self.host_ips.items():
                for conn in sample_ss(ip):
                    key = (host, conn["local"], conn["peer"])
                    prev = self.retrans_history.get(key, {"bytes": 0, "growth": 0})
                    if conn["bytes_retrans"] > prev["bytes"]:
                        prev["growth"] += 1
                    else:
                        prev["growth"] = 0
                    prev["bytes"] = conn["bytes_retrans"]
                    self.retrans_history[key] = prev
                    self.log_event(
                        "ss_sample",
                        {"host": host, "local": conn["local"], "peer": conn["peer"], **conn},
                    )
                    if prev["growth"] >= self.args.retrans_growth_samples:
                        self.alert(
                            "retrans_growth",
                            f"Retransmitted bytes to {host} ({conn['peer']}) have grown for "
                            f"{prev['growth']} consecutive samples (now {conn['bytes_retrans']} "
                            f"bytes, rtt {conn['rtt']}ms) -- see 05_AI_WORKLOAD_AND_LATENCY.md.",
                            {"host": host, "bytes_retrans": conn["bytes_retrans"], "rtt": conn["rtt"]},
                        )
                        prev["growth"] = 0  # avoid re-alerting every sample

            if self.wlan_iface:
                w = sample_wifi(self.wlan_iface)
                self.log_event("wifi_sample", w)
                if w["signal_dbm"] is not None and w["signal_dbm"] < self.args.wifi_signal_threshold:
                    self.alert(
                        "wifi_signal",
                        f"Wi-Fi signal {w['signal_dbm']} dBm on {self.wlan_iface} is below "
                        f"threshold ({self.args.wifi_signal_threshold} dBm). See 04_WIFI.md.",
                        {"signal_dbm": w["signal_dbm"]},
                    )
                if w["tx_failed"] is not None:
                    prev_failed = getattr(self, "_prev_tx_failed", None)
                    self._prev_tx_failed = w["tx_failed"]
                    if prev_failed is not None:
                        delta = w["tx_failed"] - prev_failed
                        if delta >= self.args.wifi_failed_delta_threshold:
                            self.alert(
                                "wifi_tx_failed_burst",
                                f"{delta} new Wi-Fi tx failures on {self.wlan_iface} since last "
                                "sample. See 04_WIFI.md section 2.",
                                {"delta": delta},
                            )

            if self.iface and not self.carrier_flagged:
                now_cc = read_carrier_changes(self.iface)
                if (
                    self.carrier_start is not None
                    and now_cc is not None
                    and now_cc > self.carrier_start
                ):
                    self.carrier_flagged = True
                    self.alert(
                        "carrier_flap",
                        f"carrier_changes on {self.iface} increased from {self.carrier_start} to "
                        f"{now_cc} during this run -- NIC/link flapped. See "
                        "03_WIRED_AND_GATEWAY.md step 1.",
                        {"from": self.carrier_start, "to": now_cc},
                    )

        if self.mode in ("telemetry", "malware", "all"):
            self.sample_traffic_categories()

        if self.mode in ("malware", "all"):
            self.maybe_scan_lan()

    def print_heartbeat(self, deadline):
        remaining = max(0, int(deadline - time.monotonic()))
        mm, ss = divmod(remaining, 60)
        if not self.anomalies:
            status = c("✔ all clear", "green")
        else:
            status = c(f"⚠ {len(self.anomalies)} anomaly(ies) so far", "yellow", "bold")
        now = datetime.now().strftime("%H:%M:%S")
        print(f"[{now}] still checking ({status}) -- ~{mm}m{ss:02d}s left", flush=True)

    def run(self):
        if sys.stdout.isatty():
            print(QUICKSTART)
        print(c("Starting the network watchdog.", "bold"))
        print(f"  Mode:                         {self.mode}")
        if self.mode in ("stability", "all"):
            print(f"  Gateway (ping gaps):          {self.gateway or c('(not detected -- this check is disabled)', 'yellow')}")
            wifi_line = self.wlan_iface if self.wlan_iface else "not detected (wired link, this check does not apply)"
            print(f"  Interface / Wi-Fi:            {self.iface or '(not detected)'}  |  wifi: {wifi_line}")
            hosts_line = ", ".join(self.host_ips) if self.host_ips else c("none -- pass --hosts to monitor TCP retransmits", "yellow")
            print(f"  Hosts monitored (ss -tin):    {hosts_line}")
        if self.mode in ("telemetry", "all"):
            print(f"  Telemetry domains:            {len(self.telemetry_domains)} (built-in + --telemetry-domains-file)")
        if self.mode in ("malware", "all"):
            print(f"  LAN inventory:                {self.lan_cidr or c('(could not determine the CIDR -- pass --lan-cidr)', 'yellow')}")
            print(f"  Malware domains:              {len(self.malware_domains) or c('none -- pass --malware-domains-file to add a feed', 'yellow')}")
        print(f"  Duration:                     {self.args.duration}s (~{self.args.duration // 60} min)")
        print(f"  Logs / alerts in:             {self.log_dir}")
        print("Running... (Ctrl+C stops early and still writes the summary. An alert")
        print("shows up right here, instantly, as soon as something is detected -- no")
        print("need to keep watching.)")
        print()

        t = None
        if self.mode in ("stability", "all"):
            t = threading.Thread(target=self.ping_thread, daemon=True)
            t.start()

        deadline = time.monotonic() + self.args.duration
        last_heartbeat = time.monotonic()
        try:
            while time.monotonic() < deadline and not self.stop_event.is_set():
                self.sample_once()
                if self.args.heartbeat > 0 and time.monotonic() - last_heartbeat >= self.args.heartbeat:
                    self.print_heartbeat(deadline)
                    last_heartbeat = time.monotonic()
                time.sleep(self.args.interval)
        except KeyboardInterrupt:
            print("\nStopped by hand (Ctrl+C) -- shutting down and still writing the summary.")
        finally:
            self.stop_event.set()
            proc = getattr(self, "_ping_proc", None)
            if proc is not None:
                try:
                    proc.terminate()
                except Exception:
                    pass
            if t is not None:
                t.join(timeout=3)

        verdict = "ISSUES_FOUND" if self.anomalies else "OK"
        summary = {
            "run_id": self.run_id,
            "mode": self.mode,
            "started_duration_seconds": self.args.duration,
            "gateway": self.gateway,
            "iface": self.iface,
            "wlan_iface": self.wlan_iface,
            "hosts": list(self.host_ips),
            "verdict": verdict,
            "anomaly_count": len(self.anomalies),
            "anomalies": self.anomalies,
            "pcap": self.pcap_path,
        }
        if self.mode in ("telemetry", "all"):
            summary["telemetry_hits"] = self.telemetry_hits
            summary["telemetry_blocklist"] = self.write_telemetry_blocklist()
        if self.mode in ("malware", "all"):
            summary["lan_cidr"] = self.lan_cidr
            summary["lan_nodes"] = self.known_nodes
            summary["new_devices"] = self.new_devices_this_run
            summary["firewall_suggestions"] = self.write_firewall_suggestions()
        with open(self.summary_path, "w") as f:
            json.dump(summary, f, indent=2)

        summary["_summary_path"] = str(self.summary_path)
        print("")
        print(format_human_report(summary))
        if self.notify and shutil.which("notify-send"):
            try:
                body = (
                    "OK, nothing found."
                    if verdict == "OK"
                    else f"{len(self.anomalies)} issue(s) found -- see terminal / {self.summary_path}"
                )
                subprocess.Popen(["notify-send", "Network Watchdog -- run finished", body])
            except Exception:
                pass
        return 0 if verdict == "OK" else 1


def parse_args():
    p = argparse.ArgumentParser(
        description=__doc__,
        epilog=QUICKSTART,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "--report",
        metavar="SUMMARY_JSON",
        default=None,
        help="don't run anything -- just pretty-print a previous summary_*.json and exit",
    )
    p.add_argument("--heartbeat", type=float, default=60.0, help="print a plain-language status line every N seconds while running (0 disables, default 60)")
    p.add_argument("--gateway", default=None, help="gateway IP to ping (default: auto-detect)")
    p.add_argument("--iface", default=None, help="primary interface (default: auto-detect)")
    p.add_argument("--wlan-iface", default=None, help="Wi-Fi interface (default: auto-detect if --iface is wireless)")
    p.add_argument("--hosts", default="", help="comma-separated hostnames/IPs to track with ss -tin (e.g. api.anthropic.com)")
    p.add_argument("--duration", type=int, default=300, help="how long to run, seconds (default 300 = 5 min; use a longer value like 1200 for a deeper/thorough check)")
    p.add_argument("--interval", type=float, default=5.0, help="sample interval for ss/wifi/carrier checks, seconds")
    p.add_argument("--ping-gap-threshold", type=float, default=1.5, help="gateway ping gap, seconds, to flag as anomaly")
    p.add_argument("--wifi-signal-threshold", type=int, default=-70, help="dBm below which to flag Wi-Fi signal")
    p.add_argument("--wifi-failed-delta-threshold", type=int, default=50, help="new tx-failed count per interval to flag as a burst")
    p.add_argument("--retrans-growth-samples", type=int, default=3, help="consecutive samples of growing bytes_retrans before alerting")
    p.add_argument("--log-dir", default=None, help="where to write logs (default: ~/.local/state/net_watchdog)")
    p.add_argument("--capture-on-anomaly", action="store_true", help="spawn a short tcpdump capture the first time an anomaly fires (needs tcpdump + capture permissions)")
    p.add_argument("--capture-seconds", type=int, default=15, help="length of the anomaly capture window")
    p.add_argument("--no-notify", action="store_true", help="disable notify-send desktop notifications")
    p.add_argument(
        "--mode",
        choices=["stability", "telemetry", "malware", "all"],
        default="stability",
        help=(
            "which checks to run: stability (default, same as before -- ping/retransmits/"
            "wifi/carrier), telemetry (known ad-tech/ACR/analytics traffic), malware "
            "(new devices on the LAN, suspicious ports/domains, unidentified streams like a "
            "piracy STB), all (all three). See 12_SECURITY_AND_PARASITIC_TRAFFIC.md"
        ),
    )
    p.add_argument("--lan-cidr", default=None, help="LAN CIDR for the node inventory, e.g. 192.168.1.0/24 (default: auto-detected from the primary interface; only used in --mode malware/all)")
    p.add_argument("--lan-scan-interval", type=float, default=120.0, help="seconds between LAN inventory scans (--mode malware/all)")
    p.add_argument("--lan-scan-timeout", type=float, default=30.0, help="timeout for the nmap -sn LAN ping-sweep")
    p.add_argument("--telemetry-domains-file", default=None, help="file with extra telemetry/ad-tech domains to watch, one per line (added to the built-in list; see scripts/telemetry_domains.example.txt and 12_...md)")
    p.add_argument("--malware-domains-file", default=None, help="file with known malicious domains to watch, one per line (empty by default -- bring your own trusted feed, e.g. an abuse.ch/URLhaus export; see scripts/malware_domains.example.txt for the exact command; none are bundled/invented)")
    p.add_argument("--dns-refresh-interval", type=float, default=120.0, help="seconds between DNS re-resolutions of the telemetry/malware lists (ad-tech IPs rotate often)")
    p.add_argument("--bandwidth-threshold-mbps", type=float, default=15.0, help="sustained throughput (Mbps) on an unclassified connection to flag it as unidentified high consumption (--mode malware/all)")
    p.add_argument("--bandwidth-streak-samples", type=int, default=3, help="consecutive samples above the bandwidth threshold before alerting")
    return p.parse_args()


def main():
    args = parse_args()

    if args.report:
        with open(args.report) as f:
            summary = json.load(f)
        summary["_summary_path"] = args.report
        print(format_human_report(summary))
        sys.exit(0 if summary.get("verdict") == "OK" else 1)

    wd = Watchdog(args)

    def handle_term(signum, frame):
        wd.stop_event.set()

    signal.signal(signal.SIGTERM, handle_term)
    signal.signal(signal.SIGINT, handle_term)
    sys.exit(wd.run())


if __name__ == "__main__":
    main()
