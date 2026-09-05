#!/usr/bin/env python3
"""Unattended network-health watchdog.

Runs the same class of checks described in 03_WIRED_AND_GATEWAY.md,
04_WIFI.md and 05_AI_WORKLOAD_AND_LATENCY.md continuously for a bounded
window, and alerts (log + optional desktop notification + optional
tcpdump capture) the moment it sees:

  - a periodic gateway-ping gap (the exact signature from
    06_CASE_STUDY_2026-09-05.md: something repeatedly resetting a link)
  - a one-off large gateway-ping gap
  - growing TCP retransmitted bytes on a tracked connection (ss -tin)
  - Wi-Fi signal below threshold, or a burst of new tx failures
  - a NIC carrier flap (carrier_changes counter moving) during the run

Meant to be triggered periodically by a systemd timer (see
09_BACKGROUND_WATCHDOG.md) rather than run as a permanent daemon --
"a while every few days" catches a chronic problem in days instead of
months, without leaving something running 24/7.

Read-only except for the optional --capture-on-anomaly tcpdump capture,
which needs its own explicit permissions (see the doc).
"""
import argparse
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


QUICKSTART = """\
COMO USARLO (guia rapida)
  Prueba corta, 1 minuto, para ver que funciona:
    python3 net_watchdog.py --duration 60 --heartbeat 15

  Corrida real, vigilando ademas retransmisiones a un host puntual:
    python3 net_watchdog.py --duration 1200 --hosts api.anthropic.com

  Ver el resultado de una corrida anterior en formato legible:
    python3 net_watchdog.py --report ~/.local/state/net_watchdog/summary_<fecha>.json

  Dejarlo instalado para que corra solo cada 3 dias (no hace falta
  tenerlo abierto en una terminal): ver 09_BACKGROUND_WATCHDOG.md.

  Mientras corre: no hace falta mirar la pantalla -- si encuentra algo
  aparece ahi mismo (y como notificacion de escritorio) al instante. El
  resumen final, al terminar, es siempre el mismo bloque que ves abajo.
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


def sample_ss(ip):
    """Parse `ss -Htin dst <ip>` into a list of per-connection dicts.

    -H suppresses the header so lines pair up 2-per-connection; see the
    note on this exact gotcha in 05_AI_WORKLOAD_AND_LATENCY.md.
    """
    out = sh(["ss", "-Htin", "dst", ip])
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
        conns.append(
            {
                "local": parts[3],
                "peer": parts[4],
                "rtt": float(rtt_m.group(1)) if rtt_m else None,
                "rttvar": float(rtt_m.group(2)) if rtt_m else None,
                "cwnd": int(cwnd_m.group(1)) if cwnd_m else None,
                "bytes_retrans": int(bytes_retrans_m.group(1)) if bytes_retrans_m else 0,
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
    "ping_gap": "Corte puntual de ping al gateway",
    "periodic_gap_pattern": "Patron de cortes PERIODICOS (firma del caso 06_CASE_STUDY)",
    "retrans_growth": "Retransmisiones TCP en aumento sostenido",
    "wifi_signal": "Senal Wi-Fi por debajo del umbral",
    "wifi_tx_failed_burst": "Rafaga de fallos de transmision Wi-Fi",
    "carrier_flap": "El NIC/enlace se cayo y volvio (carrier flap)",
    "no_gateway": "No se pudo determinar el gateway -- no se puede vigilar el ping",
    "no_ping": "No se encontro el binario `ping` -- no se puede vigilar el ping",
}


def format_human_report(summary):
    """Render a summary dict (same shape as summary_*.json) as a tidy,
    color-coded (when on a real terminal) human report: what was watched,
    what was found, what to do -- in that order, every time."""
    bar = "─" * 64
    L = []
    L.append(c("═" * 64, "cyan"))
    L.append(c("  Network Watchdog -- resumen de la corrida", "bold", "cyan"))
    L.append(c("═" * 64, "cyan"))
    L.append(c("  Que se vigilo", "bold"))
    wifi_bit = f"si ({summary['wlan_iface']})" if summary.get("wlan_iface") else "no aplica (enlace cableado / sin Wi-Fi detectada)"
    L.append(f"  Gateway (cortes de ping):    {summary.get('gateway') or '(no detectado)'}")
    L.append(f"  Interfaz principal:          {summary.get('iface') or '(no detectada)'}")
    L.append(f"  Wi-Fi vigilada:              {wifi_bit}")
    hosts = summary.get("hosts") or []
    L.append(
        "  Hosts (retransmisiones TCP): "
        + (", ".join(hosts) if hosts else "ninguno -- pasa --hosts para activar este chequeo")
    )
    dur = summary.get("started_duration_seconds")
    if dur:
        L.append(f"  Duracion configurada:        {dur}s (~{dur // 60} min)")
    L.append(bar)

    anomalies = summary.get("anomalies") or []
    if summary.get("verdict") == "OK":
        L.append(c("  ✔ OK", "bold", "green") + " -- no se detecto ninguna anomalia en esta corrida.")
        L.append("  No hay nada que revisar ni que hacer.")
    else:
        L.append(c(f"  ⚠ SE ENCONTRARON {len(anomalies)} PROBLEMA(S)", "bold", "yellow"))
        L.append("")
        for i, a in enumerate(anomalies, 1):
            label = KIND_LABELS.get(a.get("kind"), a.get("kind", "?"))
            L.append(f"  {i}. " + c(f"[{a.get('ts', '?')}] {label}", "bold", "yellow"))
            L.append(f"     -> {a.get('message', '')}")
            L.append("")
        L.append(bar)
        L.append(c("  Que hacer ahora", "bold"))
        L.append("  No reinicies ni cambies nada a ciegas. Cada mensaje de arriba ya te")
        L.append("  dice que archivo de la guia seguir (03_/04_/05_) y que seccion mirar")
        L.append("  primero -- segui esa lista de a un item por vez, en orden.")
    pcap = summary.get("pcap")
    if pcap:
        L.append("")
        L.append(f"  Captura de paquetes guardada: {pcap}")
        L.append("  (abrila con `tcpdump -r <archivo>` o Wireshark)")
    L.append(bar)
    sp = summary.get("_summary_path")
    if sp:
        L.append(f"  Detalle completo (JSON) de esta corrida: {sp}")
    L.append(f"  Para releer este mismo resumen mas tarde: --report {sp or '<summary.json>'}")
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

    # -- periodic sampling (main-thread loop) ----------------------------
    def sample_once(self):
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

    def print_heartbeat(self, deadline):
        remaining = max(0, int(deadline - time.monotonic()))
        mm, ss = divmod(remaining, 60)
        if not self.anomalies:
            status = c("✔ todo en orden", "green")
        else:
            status = c(f"⚠ {len(self.anomalies)} anomalia(s) hasta ahora", "yellow", "bold")
        now = datetime.now().strftime("%H:%M:%S")
        print(f"[{now}] sigue chequeando ({status}) -- quedan ~{mm}m{ss:02d}s", flush=True)

    def run(self):
        if sys.stdout.isatty():
            print(QUICKSTART)
        print(c("Arrancando el watchdog de red.", "bold"))
        print("Que se esta vigilando en esta corrida:")
        print(f"  Gateway (cortes de ping):     {self.gateway or c('(no detectado -- este chequeo queda deshabilitado)', 'yellow')}")
        wifi_line = self.wlan_iface if self.wlan_iface else "no detectada (enlace cableado, este chequeo no aplica)"
        print(f"  Interfaz / Wi-Fi:             {self.iface or '(no detectada)'}  |  wifi: {wifi_line}")
        hosts_line = ", ".join(self.host_ips) if self.host_ips else c("ninguno -- pasa --hosts para vigilar retransmisiones TCP", "yellow")
        print(f"  Hosts vigilados (ss -tin):    {hosts_line}")
        print(f"  Duracion:                     {self.args.duration}s (~{self.args.duration // 60} min)")
        print(f"  Logs / alertas en:            {self.log_dir}")
        print("Corriendo... (Ctrl+C corta antes de tiempo y igual escribe el resumen. Una")
        print("alerta aparece aca mismo, al instante, apenas se detecta algo -- no hace")
        print("falta estar mirando.)")
        print()

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
            print("\nCortado a mano (Ctrl+C) -- cerrando y escribiendo el resumen igual.")
        finally:
            self.stop_event.set()
            proc = getattr(self, "_ping_proc", None)
            if proc is not None:
                try:
                    proc.terminate()
                except Exception:
                    pass
            t.join(timeout=3)

        verdict = "ISSUES_FOUND" if self.anomalies else "OK"
        summary = {
            "run_id": self.run_id,
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
        with open(self.summary_path, "w") as f:
            json.dump(summary, f, indent=2)

        summary["_summary_path"] = str(self.summary_path)
        print("")
        print(format_human_report(summary))
        if self.notify and shutil.which("notify-send"):
            try:
                body = (
                    "OK, no se encontro nada."
                    if verdict == "OK"
                    else f"Se encontraron {len(self.anomalies)} problema(s) -- ver terminal / {self.summary_path}"
                )
                subprocess.Popen(["notify-send", "Network Watchdog -- corrida terminada", body])
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
    p.add_argument("--duration", type=int, default=1200, help="how long to run, seconds (default 1200 = 20 min)")
    p.add_argument("--interval", type=float, default=5.0, help="sample interval for ss/wifi/carrier checks, seconds")
    p.add_argument("--ping-gap-threshold", type=float, default=1.5, help="gateway ping gap, seconds, to flag as anomaly")
    p.add_argument("--wifi-signal-threshold", type=int, default=-70, help="dBm below which to flag Wi-Fi signal")
    p.add_argument("--wifi-failed-delta-threshold", type=int, default=50, help="new tx-failed count per interval to flag as a burst")
    p.add_argument("--retrans-growth-samples", type=int, default=3, help="consecutive samples of growing bytes_retrans before alerting")
    p.add_argument("--log-dir", default=None, help="where to write logs (default: ~/.local/state/net_watchdog)")
    p.add_argument("--capture-on-anomaly", action="store_true", help="spawn a short tcpdump capture the first time an anomaly fires (needs tcpdump + capture permissions)")
    p.add_argument("--capture-seconds", type=int, default=15, help="length of the anomaly capture window")
    p.add_argument("--no-notify", action="store_true", help="disable notify-send desktop notifications")
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
