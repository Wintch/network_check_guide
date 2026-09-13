#!/usr/bin/env python3
"""quick_check.py - Automated Pre-Work Network Health Checklist (~1-2 minutes).

Runs all essential checks from 01_QUICK_CHECKLIST.md, 03_WIRED_AND_GATEWAY.md,
and 05_AI_WORKLOAD_AND_LATENCY.md in a single safe, non-destructive pass:
  1. Primary interface link health (speed, duplex, carrier flaps, Wi-Fi stats)
  2. Gateway reachability & high-resolution periodic gap detection (ping -D)
  3. DNS resolution latency & stability (local vs remote resolver)
  4. Path MTU & ICMP PMTUD black-hole check (detects 1500 vs 1492/PPPoE vs VPN)
  5. Dual-stack IPv4/IPv6 sanity & public IP detection
  6. Real HTTP/TLS handshake timing to target API (DNS, TCP, TLS, TTFB)
  7. Final colorized triage report with pointers to specific guide files

Safe, read-only: does not modify any routing, interface, or firewall configuration.
Pure Python standard library (no pip packages required). Requires Python 3.10+
(uses PEP 604 `X | None` type hints) — e.g. Debian 12+/Ubuntu 22.04+.
"""

import argparse
import http.client
import json
import os
import re
import socket
import ssl
import subprocess
import sys
import time
from urllib.parse import urlparse

# --- ANSI Terminal Color Support ---
_USE_COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
_COLORS = {
    "green": "\033[32m",
    "yellow": "\033[33m",
    "red": "\033[31m",
    "cyan": "\033[36m",
    "bold": "\033[1m",
    "dim": "\033[2m",
    "reset": "\033[0m",
}


def c(text: str, *styles: str) -> str:
    if not _USE_COLOR:
        return text
    prefix = "".join(_COLORS.get(s, "") for s in styles)
    return f"{prefix}{text}{_COLORS['reset']}"


def badge(status: str) -> str:
    if status == "OK":
        return c("[  OK  ]", "green", "bold")
    elif status == "WARN":
        return c("[ WARN ]", "yellow", "bold")
    elif status == "FAIL":
        return c("[ FAIL ]", "red", "bold")
    elif status == "INFO":
        return c("[ INFO ]", "cyan", "bold")
    return f"[{status:^6}]"


# --- Network Detection Utilities ---


def run_cmd(cmd: list[str], timeout: float = 5.0) -> tuple[int, str, str]:
    """Execute command and return (returncode, stdout, stderr)."""
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
        )
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
    except subprocess.TimeoutExpired:
        return -1, "", "Command timed out"
    except FileNotFoundError:
        return -2, "", f"Command not found: {cmd[0]}"
    except Exception as e:
        return -3, "", str(e)


def detect_gateway_and_iface() -> tuple[str | None, str | None, str | None]:
    """Detect default route IPv4 gateway, interface, and local IP."""
    rc, out, _ = run_cmd(["ip", "route", "get", "8.8.8.8"])
    if rc != 0 or not out:
        return None, None, None

    # Example: 8.8.8.8 via 192.168.1.1 dev enp5s0 src 192.168.1.144 uid 1000
    gw_match = re.search(r"via\s+([0-9.]+)", out)
    dev_match = re.search(r"dev\s+([a-zA-Z0-9_.-]+)", out)
    src_match = re.search(r"src\s+([0-9.]+)", out)

    gw = gw_match.group(1) if gw_match else None
    dev = dev_match.group(1) if dev_match else None
    src = src_match.group(1) if src_match else None
    return gw, dev, src


def detect_ipv6_gateway() -> tuple[str | None, str | None]:
    """Detect default IPv6 route gateway and dev if available."""
    rc, out, _ = run_cmd(["ip", "-6", "route", "get", "2001:4860:4860::8888"])
    if rc != 0 or not out:
        return None, None
    gw_match = re.search(r"via\s+([0-9a-fA-F:]+)", out)
    dev_match = re.search(r"dev\s+([a-zA-Z0-9_.-]+)", out)
    gw = gw_match.group(1) if gw_match else None
    dev = dev_match.group(1) if dev_match else None
    return gw, dev


def get_public_ip(ipv6: bool = False, timeout: float = 3.0) -> str | None:
    """Fetch public IP via external service."""
    host = "api64.ipify.org" if ipv6 else "api.ipify.org"
    url = f"https://{host}"
    try:
        import urllib.request

        req = urllib.request.Request(
            url, headers={"User-Agent": "quick_check/1.0"}
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8").strip()
    except Exception:
        return None


# --- Diagnostic Checks ---


def check_interface(iface: str) -> dict:
    """Check physical/wireless interface health."""
    sys_net = f"/sys/class/net/{iface}"
    result = {
        "iface": iface,
        "is_up": False,
        "speed": None,
        "duplex": None,
        "carrier_flaps": 0,
        "is_wifi": False,
        "wifi_info": {},
        "eee_enabled": None,
        "issues": [],
        "warnings": [],
    }

    if not os.path.exists(sys_net):
        result["issues"].append(f"Interface {iface} not found in sysfs")
        return result

    # Operstate
    oper_path = os.path.join(sys_net, "operstate")
    if os.path.exists(oper_path):
        with open(oper_path, "r") as f:
            state = f.read().strip()
            result["is_up"] = (state == "up")
            if not result["is_up"]:
                result["issues"].append(f"Link operstate is '{state}' (not 'up')")

    # Carrier changes
    flaps_path = os.path.join(sys_net, "carrier_changes")
    if os.path.exists(flaps_path):
        try:
            with open(flaps_path, "r") as f:
                result["carrier_flaps"] = int(f.read().strip())
                if result["carrier_flaps"] > 10:
                    result["warnings"].append(
                        f"High carrier flap count: {result['carrier_flaps']} flaps since boot"
                    )
        except ValueError:
            pass

    # Speed & Duplex
    speed_path = os.path.join(sys_net, "speed")
    if os.path.exists(speed_path):
        try:
            with open(speed_path, "r") as f:
                result["speed"] = int(f.read().strip())
                if result["speed"] == 100:
                    result["warnings"].append(
                        "Negotiated link speed is 100 Mbps (possible degraded gigabit cable/switch port - see 03_WIRED_AND_GATEWAY.md)"
                    )
                elif result["speed"] < 100 and result["speed"] > 0:
                    result["warnings"].append(f"Very low negotiated link speed: {result['speed']} Mbps")
        except (ValueError, OSError):
            pass

    duplex_path = os.path.join(sys_net, "duplex")
    if os.path.exists(duplex_path):
        try:
            with open(duplex_path, "r") as f:
                result["duplex"] = f.read().strip()
                if result["duplex"] == "half":
                    result["issues"].append("Interface negotiated HALF-DUPLEX (severe collision bottleneck)")
        except OSError:
            pass

    # Wi-Fi check
    if os.path.exists(os.path.join(sys_net, "wireless")) or os.path.exists(os.path.join(sys_net, "phy80211")):
        result["is_wifi"] = True
        rc, out, _ = run_cmd(["iw", "dev", iface, "link"])
        if rc == 0 and "Connected to" in out:
            sig_m = re.search(r"signal:\s*(-?[0-9]+)\s*dBm", out)
            rate_m = re.search(r"tx bitrate:\s*([0-9.]+\s*MBit/s)", out)
            if sig_m:
                sig = int(sig_m.group(1))
                result["wifi_info"]["signal_dbm"] = sig
                if sig < -72:
                    result["warnings"].append(f"Wi-Fi signal weak ({sig} dBm) - high risk of retries/drops")
            if rate_m:
                result["wifi_info"]["tx_bitrate"] = rate_m.group(1)

        # Station dump for retries
        rc_sd, out_sd, _ = run_cmd(["iw", "dev", iface, "station", "dump"])
        if rc_sd == 0:
            retries_m = re.search(r"tx retries:\s*([0-9]+)", out_sd)
            failed_m = re.search(r"tx failed:\s*([0-9]+)", out_sd)
            if retries_m:
                result["wifi_info"]["tx_retries"] = int(retries_m.group(1))
            if failed_m:
                result["wifi_info"]["tx_failed"] = int(failed_m.group(1))

    # EEE (Energy Efficient Ethernet) check via ethtool
    rc_et, out_et, _ = run_cmd(["ethtool", "--show-eee", iface])
    if rc_et == 0 and "EEE status: enabled" in out_et:
        result["eee_enabled"] = True
        result["warnings"].append(
            "Energy Efficient Ethernet (802.3az) is active - can induce micro-sleep latency spikes on some NICs"
        )

    return result


def check_gateway_pings(gateway_ip: str, count: int = 25) -> dict:
    """Ping default gateway looking for latency, loss, and periodic gaps."""
    result = {
        "gateway": gateway_ip,
        "transmitted": count,
        "received": 0,
        "loss_pct": 100.0,
        "rtt_min": None,
        "rtt_avg": None,
        "rtt_max": None,
        "rtt_mdev": None,
        "gaps": [],
        "periodic_interval": None,
        "issues": [],
        "warnings": [],
    }

    # Run ping with -D (timestamps), interval 1s, count
    cmd = ["ping", "-D", "-i", "1", "-c", str(count), "-W", "2", gateway_ip]
    rc, out, err = run_cmd(cmd, timeout=count + 5.0)

    timestamps = []
    for line in out.splitlines():
        # Match timestamp prefix e.g. [1726267890.123456]
        m = re.match(r"^\[([0-9.]+)\].*bytes from", line)
        if m:
            timestamps.append(float(m.group(1)))

    result["received"] = len(timestamps)
    if count > 0:
        result["loss_pct"] = round(((count - len(timestamps)) / count) * 100.0, 1)

    # Parse ping summary line
    # rtt min/avg/max/mdev = 0.456/0.789/1.234/0.120 ms
    rtt_m = re.search(r"rtt min/avg/max/mdev = ([0-9.]+)/([0-9.]+)/([0-9.]+)/([0-9.]+)", out)
    if rtt_m:
        result["rtt_min"] = float(rtt_m.group(1))
        result["rtt_avg"] = float(rtt_m.group(2))
        result["rtt_max"] = float(rtt_m.group(3))
        result["rtt_mdev"] = float(rtt_m.group(4))

    # Calculate gaps (> 1.5 seconds between received packets)
    for i in range(1, len(timestamps)):
        delta = timestamps[i] - timestamps[i - 1]
        if delta > 1.6:
            result["gaps"].append(round(delta, 2))

    if result["loss_pct"] > 0:
        if result["loss_pct"] > 5.0:
            result["issues"].append(
                f"Gateway packet loss is {result['loss_pct']}% ({count - len(timestamps)}/{count} lost)"
            )
        else:
            result["warnings"].append(f"Gateway packet loss: {result['loss_pct']}%")

    if result["gaps"]:
        gap_desc = ", ".join(f"{g}s" for g in result["gaps"][:5])
        if len(result["gaps"]) >= 2:
            # Check for recurring periodic gap pattern (Case Study signature)
            result["issues"].append(
                f"DETECTED MULTIPLE RECURRING GAPS: [{gap_desc}]. Strong signature of watchdog loop / NIC reset / DFS switch (see 03_WIRED_AND_GATEWAY.md & 06_CASE_STUDY)"
            )
        else:
            result["warnings"].append(f"Transient gateway ping gap observed: {gap_desc}")

    if result["rtt_avg"] and result["rtt_avg"] > 15.0:
        result["warnings"].append(
            f"High first-hop gateway latency: avg={result['rtt_avg']}ms (wired should be <1ms, Wi-Fi <5ms)"
        )

    return result


def check_dns_health(target_host: str) -> dict:
    """Measure DNS resolution speed and stability across multiple domains."""
    domains = [
        ("target", target_host),
        ("baseline_1", "google.com"),
        ("baseline_2", "cloudflare.com"),
    ]
    result = {
        "target_host": target_host,
        "resolutions": {},
        "target_ms": None,
        "issues": [],
        "warnings": [],
    }

    for label, domain in domains:
        t0 = time.perf_counter()
        try:
            # Force resolution
            info = socket.getaddrinfo(domain, 443, proto=socket.IPPROTO_TCP)
            elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 1)
            ips = list({item[4][0] for item in info})
            result["resolutions"][domain] = {"elapsed_ms": elapsed_ms, "ips": ips, "ok": True}
            if label == "target":
                result["target_ms"] = elapsed_ms
        except Exception as e:
            elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 1)
            result["resolutions"][domain] = {"elapsed_ms": elapsed_ms, "error": str(e), "ok": False}
            result["issues"].append(f"DNS lookup failed for {domain}: {e}")

    if result["target_ms"] is not None:
        if result["target_ms"] > 250.0:
            result["warnings"].append(
                f"Slow DNS resolution for {target_host}: {result['target_ms']}ms (adds perceptible delay to new API sessions)"
            )

    return result


def check_path_mtu(target_ip: str = "8.8.8.8") -> dict:
    """Probe Path MTU to detect fragmentation limits and PMTUD black holes."""
    result = {
        "target": target_ip,
        "max_working_payload": None,
        "effective_mtu": None,
        "is_standard_1500": False,
        "is_pppoe_1492": False,
        "is_vpn_or_tunnel": False,
        "issues": [],
        "warnings": [],
    }

    # Probes: (payload_size, resulting_packet_mtu, label)
    # Payload = MTU - 20 (IPv4 header) - 8 (ICMP header) = MTU - 28
    probes = [
        (1472, 1500, "Standard Ethernet 1500"),
        (1464, 1492, "PPPoE / DSL 1492"),
        (1392, 1420, "WireGuard / VPN 1420"),
        (1200, 1228, "Conservative Minimum"),
    ]

    working_mtu = None
    for payload, mtu, label in probes:
        # ping -M do -> set Don't Fragment flag
        rc, out, err = run_cmd(["ping", "-M", "do", "-s", str(payload), "-c", "2", "-W", "2", target_ip])
        combined = out + "\n" + err
        if rc == 0 and "2 received" in out:
            working_mtu = mtu
            result["max_working_payload"] = payload
            result["effective_mtu"] = mtu
            break
        elif "sendmsg" in combined or "Frag needed" in combined or "Message too long" in combined:
            # Local interface MTU already caps this size (e.g. PPPoE tunnel), or an explicit
            # ICMP PMTUD response was received — both are healthy, expected behavior, not a black hole.
            pass
        elif rc != 0 and "100% packet loss" in combined:
            # No local rejection and no ICMP response at all: the oversized packet left the
            # host but nothing came back — a real silent black hole signature.
            result["warnings"].append(
                f"Silent packet drop at MTU {mtu} (possible ICMP black-hole router filtering fragmentation notifications)"
            )

    if working_mtu == 1500:
        result["is_standard_1500"] = True
    elif working_mtu == 1492:
        result["is_pppoe_1492"] = True
        result["warnings"].append(
            "Path MTU is 1492 (typical of PPPoE fiber/DSL). Verify MSS Clamping is active if large HTTP uploads or git push stall."
        )
    elif working_mtu and working_mtu < 1492:
        result["is_vpn_or_tunnel"] = True
        result["warnings"].append(
            f"Path MTU is reduced to {working_mtu} (VPN, overlay, or tunnel overhead). Ensure client/wireguard MTU matches."
        )
    elif working_mtu is None:
        result["issues"].append(
            "Could not determine Path MTU; even 1200-byte ICMP packets with DF failed to reach target."
        )

    return result


def check_real_api_timings(target_url: str, attempts: int = 3) -> dict:
    """Measure per-phase timing (DNS, TCP, TLS, TTFB, Total) to real API endpoint."""
    parsed = urlparse(target_url)
    host = parsed.hostname or target_url
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    use_ssl = (parsed.scheme == "https" or port == 443)

    result = {
        "url": target_url,
        "host": host,
        "port": port,
        "samples": [],
        "avg_total_ms": None,
        "avg_ttfb_ms": None,
        "issues": [],
        "warnings": [],
    }

    ssl_context = ssl.create_default_context() if use_ssl else None

    for i in range(attempts):
        t0 = time.perf_counter()
        sample = {
            "dns_ms": None,
            "tcp_ms": None,
            "tls_ms": None,
            "ttfb_ms": None,
            "total_ms": None,
            "ok": False,
        }
        try:
            # Phase 1: DNS
            t_dns_start = time.perf_counter()
            ip_addr = socket.gethostbyname(host)
            t_dns_end = time.perf_counter()
            sample["dns_ms"] = round((t_dns_end - t_dns_start) * 1000.0, 1)

            # Phase 2: TCP Connect
            t_tcp_start = time.perf_counter()
            sock = socket.create_connection((ip_addr, port), timeout=5.0)
            t_tcp_end = time.perf_counter()
            sample["tcp_ms"] = round((t_tcp_end - t_tcp_start) * 1000.0, 1)

            # Phase 3: TLS Handshake (if HTTPS)
            if use_ssl and ssl_context:
                t_tls_start = time.perf_counter()
                ssock = ssl_context.wrap_socket(sock, server_hostname=host)
                t_tls_end = time.perf_counter()
                sample["tls_ms"] = round((t_tls_end - t_tls_start) * 1000.0, 1)
                active_sock = ssock
            else:
                active_sock = sock

            # Phase 4: HTTP Request / TTFB
            t_req_start = time.perf_counter()
            req = f"GET {parsed.path or '/'} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: quick_check/1.0\r\nConnection: close\r\n\r\n"
            active_sock.sendall(req.encode("utf-8"))
            # Read first chunk
            data = active_sock.recv(1024)
            t_ttfb_end = time.perf_counter()
            sample["ttfb_ms"] = round((t_ttfb_end - t_req_start) * 1000.0, 1)

            # Drain remainder
            while data:
                data = active_sock.recv(4096)
            active_sock.close()

            sample["total_ms"] = round((time.perf_counter() - t0) * 1000.0, 1)
            sample["ok"] = True
            result["samples"].append(sample)

        except Exception as e:
            sample["error"] = str(e)
            sample["total_ms"] = round((time.perf_counter() - t0) * 1000.0, 1)
            result["samples"].append(sample)
            result["issues"].append(f"HTTP probe #{i+1} failed: {e}")

        time.sleep(0.5)

    valid_totals = [s["total_ms"] for s in result["samples"] if s["ok"]]
    valid_ttfbs = [s["ttfb_ms"] for s in result["samples"] if s["ok"] and s["ttfb_ms"] is not None]
    if valid_totals:
        result["avg_total_ms"] = round(sum(valid_totals) / len(valid_totals), 1)
    if valid_ttfbs:
        result["avg_ttfb_ms"] = round(sum(valid_ttfbs) / len(valid_ttfbs), 1)

    return result


# --- Main CLI Flow & Display ---


def parse_args():
    parser = argparse.ArgumentParser(
        description="Automated Pre-Work Network Health Checklist (~1-2 minutes)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 scripts/quick_check.py
  python3 scripts/quick_check.py --host api.anthropic.com --full
  python3 scripts/quick_check.py --ping-count 30 --json
        """,
    )
    parser.add_argument(
        "--host",
        default="api.anthropic.com",
        help="Target API hostname to test (default: api.anthropic.com)",
    )
    parser.add_argument(
        "--gateway",
        default=None,
        help="Gateway IP to test (default: auto-detected via default route)",
    )
    parser.add_argument(
        "--iface",
        default=None,
        help="Network interface to test (default: auto-detected)",
    )
    parser.add_argument(
        "--ping-count",
        type=int,
        default=20,
        help="Number of gateway ping samples (default: 20, ~20s)",
    )
    parser.add_argument(
        "--full",
        action="store_true",
        help="Run an extended 60-packet ping test for subtle periodic gaps",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI terminal colors",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results in JSON format only",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    if args.no_color:
        global _USE_COLOR
        _USE_COLOR = False

    ping_count = 60 if args.full else args.ping_count

    # 1. Detection
    auto_gw, auto_iface, auto_src = detect_gateway_and_iface()
    gw = args.gateway or auto_gw
    iface = args.iface or auto_iface
    ipv6_gw, ipv6_iface = detect_ipv6_gateway()

    if not args.json:
        print(c("═" * 68, "bold", "cyan"))
        print(c("  Network Health Quick-Check (Pre-Work Checklist)", "bold"))
        print(c("═" * 68, "bold", "cyan"))
        print(f" Target API host:      {c(args.host, 'bold')}")
        print(f" Default gateway:      {c(str(gw), 'bold')}")
        print(f" Primary interface:    {c(str(iface), 'bold')} (Local IP: {auto_src})")
        print(f" IPv6 Dual-Stack:      {'Active (' + str(ipv6_gw) + ')' if ipv6_gw else 'Disabled / No IPv6 route'}")
        print(c("─" * 68, "dim"))
        print(c(" Running diagnostics (~20-40 seconds)...", "dim"))

    # Execute all checks
    iface_report = check_interface(iface) if iface else {"issues": ["No interface detected"], "warnings": []}
    gw_report = check_gateway_pings(gw, count=ping_count) if gw else {"issues": ["No gateway detected"], "warnings": []}
    dns_report = check_dns_health(args.host)
    mtu_report = check_path_mtu("8.8.8.8")
    api_report = check_real_api_timings(f"https://{args.host}")
    public_ip4 = get_public_ip(ipv6=False)

    all_issues = iface_report.get("issues", []) + gw_report.get("issues", []) + dns_report.get("issues", []) + mtu_report.get("issues", []) + api_report.get("issues", [])
    all_warnings = iface_report.get("warnings", []) + gw_report.get("warnings", []) + dns_report.get("warnings", []) + mtu_report.get("warnings", []) + api_report.get("warnings", [])

    if args.json:
        output = {
            "target_host": args.host,
            "gateway": gw,
            "iface": iface,
            "public_ipv4": public_ip4,
            "status": "FAIL" if all_issues else ("WARN" if all_warnings else "OK"),
            "interface": iface_report,
            "gateway_ping": gw_report,
            "dns": dns_report,
            "mtu": mtu_report,
            "api_timing": api_report,
            "issues": all_issues,
            "warnings": all_warnings,
        }
        print(json.dumps(output, indent=2))
        sys.exit(1 if all_issues else 0)

    # Human-readable report
    print("\n" + c("1. Link & Physical Layer", "bold"))
    if iface_report.get("is_up"):
        speed_str = f"{iface_report['speed']} Mbps" if iface_report['speed'] else "unknown speed"
        flaps_str = f"{iface_report['carrier_flaps']} carrier flaps"
        if iface_report.get("is_wifi"):
            wf = iface_report.get("wifi_info", {})
            print(f"  {badge('OK')} Interface {iface} is UP (Wi-Fi, signal={wf.get('signal_dbm')}dBm, rate={wf.get('tx_bitrate')})")
        else:
            print(f"  {badge('OK')} Interface {iface} is UP ({speed_str}, {flaps_str})")
    else:
        print(f"  {badge('FAIL')} Interface {iface} is DOWN or degraded")

    print("\n" + c("2. Gateway Reachability & Gap Analysis", "bold"))
    if gw_report.get("loss_pct", 100.0) == 0.0 and not gw_report.get("gaps"):
        print(f"  {badge('OK')} Gateway {gw}: 0% loss ({gw_report['received']}/{gw_report['transmitted']}), avg RTT: {gw_report.get('rtt_avg')}ms, no gaps")
    elif gw_report.get("gaps") and len(gw_report["gaps"]) >= 2:
        print(f"  {badge('FAIL')} Periodic gateway gaps detected: {gw_report['gaps']}s!")
    elif gw_report.get("loss_pct", 0) > 0:
        print(f"  {badge('WARN')} Gateway packet loss: {gw_report['loss_pct']}%, gaps: {gw_report.get('gaps') or 'none'}")
    else:
        print(f"  {badge('INFO')} Gateway {gw}: avg RTT {gw_report.get('rtt_avg')}ms")

    print("\n" + c("3. DNS Resolution Health", "bold"))
    if dns_report.get("target_ms") is not None and dns_report["target_ms"] < 250:
        print(f"  {badge('OK')} DNS lookup for {args.host}: {dns_report['target_ms']}ms")
    elif dns_report.get("target_ms") is not None:
        print(f"  {badge('WARN')} DNS lookup for {args.host} slow: {dns_report['target_ms']}ms")
    else:
        print(f"  {badge('FAIL')} DNS resolution failed")

    print("\n" + c("4. Path MTU & Black Hole Check", "bold"))
    if mtu_report.get("is_standard_1500"):
        print(f"  {badge('OK')} Path MTU is 1500 (Standard Ethernet, 1472-byte ICMP payload OK)")
    elif mtu_report.get("is_pppoe_1492"):
        print(f"  {badge('INFO')} Path MTU is 1492 (PPPoE / Fiber link - ICMP payload 1464 OK)")
    elif mtu_report.get("effective_mtu"):
        print(f"  {badge('WARN')} Path MTU is reduced to {mtu_report['effective_mtu']} (VPN or Tunnel)")
    else:
        print(f"  {badge('FAIL')} Path MTU check failed")

    print("\n" + c("5. Real API Handshake & TTFB (End-to-End)", "bold"))
    if api_report.get("avg_total_ms"):
        s0 = api_report["samples"][0] if api_report["samples"] else {}
        print(f"  {badge('OK')} https://{args.host}: connect={s0.get('tcp_ms')}ms tls={s0.get('tls_ms')}ms ttfb={s0.get('ttfb_ms')}ms total={api_report['avg_total_ms']}ms")
    else:
        print(f"  {badge('FAIL')} Could not establish HTTPS connection to {args.host}")

    if public_ip4:
        print(f"  {badge('INFO')} Public IPv4: {public_ip4}")

    # Verdict
    print("\n" + c("═" * 68, "bold", "cyan"))
    if not all_issues and not all_warnings:
        print(f"  {c('✔ ALL CLEAR', 'green', 'bold')} — Network is in prime condition for real work.")
        print("  Low first-hop latency, no gaps, healthy DNS, standard MTU.")
    elif all_issues:
        print(f"  {c('✖ ISSUES DETECTED', 'red', 'bold')} — Review findings before starting work:")
        for iss in all_issues:
            print(f"    • {c(iss, 'red')}")
        print("\n  Recommended next action:")
        if any("gaps" in iss.lower() or "watchdog" in iss.lower() for iss in all_issues):
            print("    → See 03_WIRED_AND_GATEWAY.md §2 and 06_CASE_STUDY_2026-09-05.md")
        elif any("dns" in iss.lower() for iss in all_issues):
            print("    → Check local DNS resolver / Pi-hole / router DNS status")
        else:
            print("    → Consult relevant section in the Network Health Guide")
    else:
        print(f"  {c('⚠ MINOR WARNINGS', 'yellow', 'bold')} — Network usable, but keep in mind:")
        for w in all_warnings:
            print(f"    • {c(w, 'yellow')}")
    print(c("═" * 68, "bold", "cyan"))

    sys.exit(1 if all_issues else 0)


if __name__ == "__main__":
    main()
