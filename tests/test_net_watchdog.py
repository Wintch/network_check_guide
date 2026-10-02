import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import net_watchdog as w


def test_sample_ss_pairs_by_indentation(monkeypatch):
    out = (
        "ESTAB 0 0 10.0.0.1:1 1.1.1.1:443\n\t cubic rtt:10/2 cwnd:10\n"
        "ESTAB 0 0 10.0.0.1:2 1.1.1.1:443\n"  # head with no detail line
        "ESTAB 0 0 10.0.0.1:3 2.2.2.2:443\n\t rtt:5/1\n"
    )
    monkeypatch.setattr(w, "sh", lambda cmd: out)
    assert [(c["peer"], c["rtt"]) for c in w.sample_ss()] == [
        ("1.1.1.1:443", 10.0),
        ("2.2.2.2:443", 5.0),
    ]


def test_save_known_nodes_atomic(tmp_path):
    p = str(tmp_path / "nodes.json")
    w.save_known_nodes(p, {"a": 1})
    assert json.loads(Path(p).read_text()) == {"a": 1}
    assert not Path(p + ".tmp").exists()


def _bare_watchdog():
    """A Watchdog without __init__ (which probes routes, DNS and the filesystem)."""
    dog = object.__new__(w.Watchdog)
    dog.args = type("A", (), {"dns_refresh_interval": 0, "bandwidth_threshold_mbps": 1.0,
                              "bandwidth_streak_samples": 1})()
    dog.mode = "all"
    dog.telemetry_ip_map, dog.malware_ip_map = {}, {}
    dog.telemetry_hits, dog.malware_alert_targets = {}, set()
    dog.bw_history, dog.unclassified_streak = {}, {}
    dog._flagged_conns, dog._rdns_cache = set(), {}
    dog.last_dns_refresh = 0.0
    dog.deadline = None
    dog.telemetry_domains, dog.malware_domains = [], []
    dog.alerts = []
    dog.alert = lambda kind, msg, extra=None: dog.alerts.append(kind)
    dog.refresh_dns_maps = lambda: None
    return dog


def _conn(acked, recvd=0, local="10.0.0.1:1", peer="9.9.9.9:443"):
    return {"local": local, "peer": peer, "bytes_acked": acked, "bytes_received": recvd}


def test_bw_history_drops_closed_connections(monkeypatch):
    dog = _bare_watchdog()
    monkeypatch.setattr(w, "sample_ss", lambda: [_conn(100)])
    dog.sample_traffic_categories()
    assert len(dog.bw_history) == 1
    monkeypatch.setattr(w, "sample_ss", lambda: [])
    dog.sample_traffic_categories()
    assert dog.bw_history == {} and dog.unclassified_streak == {}


def test_counter_reset_does_not_report_a_rate(monkeypatch):
    dog = _bare_watchdog()
    monkeypatch.setattr(w, "reverse_dns_cached", lambda ip, cache: None)
    clock = iter([0.0, 1.0, 2.0])
    monkeypatch.setattr(w.time, "monotonic", lambda: next(clock))
    seen = []
    for total in (50_000_000, 10, 50_000_000):  # big, reset, big again
        monkeypatch.setattr(w, "sample_ss", lambda t=total: [_conn(t)])
        dog.alerts.clear()
        dog.sample_traffic_categories()
        seen.append(list(dog.alerts))
    assert seen[0] == []                                  # first sample: no baseline yet
    assert seen[1] == []                                  # reset: no rate, streak cleared
    # rebaselined at 10 bytes, so real growth afterwards is measured and does alert
    assert seen[2] == ["unidentified_high_bandwidth"]


def test_sustained_high_bandwidth_alerts(monkeypatch):
    dog = _bare_watchdog()
    monkeypatch.setattr(w, "reverse_dns_cached", lambda ip, cache: None)
    clock = iter([0.0, 1.0])
    monkeypatch.setattr(w.time, "monotonic", lambda: next(clock))
    for total in (0, 50_000_000):
        monkeypatch.setattr(w, "sample_ss", lambda t=total: [_conn(t)])
        dog.sample_traffic_categories()
    assert dog.alerts == ["unidentified_high_bandwidth"]


def test_dns_map_drops_ips_that_left_the_record_set(monkeypatch):
    dog = _bare_watchdog()
    dog.telemetry_domains = ["ads.example"]
    answers = {"ads.example": ["1.1.1.1", "2.2.2.2"]}
    monkeypatch.setattr(w.socket, "gethostbyname_ex", lambda d: (d, [], answers[d]))
    dog.refresh_dns_maps = w.Watchdog.refresh_dns_maps.__get__(dog)
    dog.refresh_dns_maps()
    assert set(dog.telemetry_ip_map) == {"1.1.1.1", "2.2.2.2"}
    answers["ads.example"] = ["2.2.2.2", "3.3.3.3"]      # 1.1.1.1 rotated away
    dog.last_dns_refresh = 0.0
    dog.refresh_dns_maps()
    assert set(dog.telemetry_ip_map) == {"2.2.2.2", "3.3.3.3"}


def test_dns_map_keeps_previous_ips_when_lookup_fails(monkeypatch):
    dog = _bare_watchdog()
    dog.telemetry_domains = ["ads.example"]
    dog.telemetry_ip_map = {"1.1.1.1": "ads.example"}

    def boom(d):
        raise w.socket.gaierror("temporary failure")

    monkeypatch.setattr(w.socket, "gethostbyname_ex", boom)
    dog.refresh_dns_maps = w.Watchdog.refresh_dns_maps.__get__(dog)
    dog.refresh_dns_maps()
    assert dog.telemetry_ip_map == {"1.1.1.1": "ads.example"}


def _lan_dog(tmp_path, known):
    dog = _bare_watchdog()
    dog.lan_cidr = "10.0.0.0/24"
    dog.args.lan_scan_interval = 0
    dog.args.lan_scan_timeout = 1
    dog.last_lan_scan = 0.0
    dog.known_nodes = known
    dog.known_nodes_path = str(tmp_path / "k.json")
    dog._lan_baseline_run = False
    dog.new_devices_this_run, dog.lan_nodes_seen = [], {}
    dog._lan_present, dog.gone_devices_this_run = set(), []
    dog._nmap_warned = False
    return dog


def test_device_that_disappears_between_scans_is_reported(monkeypatch, tmp_path):
    dog = _lan_dog(tmp_path, {})
    monkeypatch.setattr(w, "oui_vendor", lambda m: "Acme")
    scans = iter([{"aa:bb": ["10.0.0.5"]}, {}])
    monkeypatch.setattr(w, "scan_lan_nodes", lambda cidr, timeout=30: next(scans))
    dog.maybe_scan_lan()
    assert dog.gone_devices_this_run == []
    dog.maybe_scan_lan()
    assert [d["mac"] for d in dog.gone_devices_this_run] == ["aa:bb"]
    assert dog.gone_devices_this_run[0]["last_seen"]            # carries the last-presence date
    assert "device_gone" in dog.alerts


# --- P2: unresolved hosts are retried ---

def _host_dog(hosts):
    dog = _bare_watchdog()
    dog.hosts, dog.host_ips = hosts, {}
    dog.last_host_retry = 0.0
    dog.logged = []
    dog.log_event = lambda kind, data: dog.logged.append(kind)
    return dog


def test_unresolved_host_is_retried_until_it_resolves(monkeypatch):
    dog = _host_dog(["api.test"])
    answers = iter([OSError("temporary failure"), "203.0.113.9"])

    def fake(h):
        r = next(answers)
        if isinstance(r, Exception):
            raise r
        return r

    monkeypatch.setattr(w.socket, "gethostbyname", fake)
    dog.retry_unresolved_hosts()
    assert dog.host_ips == {}
    dog.last_host_retry = 0.0
    dog.retry_unresolved_hosts()
    assert dog.host_ips == {"api.test": "203.0.113.9"} and dog.logged == ["host_resolved"]


def test_retry_is_rate_limited(monkeypatch):
    dog = _host_dog(["api.test"])
    dog.last_host_retry = w.time.monotonic()
    monkeypatch.setattr(w.socket, "gethostbyname", lambda h: pytest.fail("retried too soon"))
    dog.retry_unresolved_hosts()


# --- P2: duration is an effective limit ---

def test_expired_deadline_skips_every_phase(monkeypatch):
    dog = _host_dog([])
    dog.deadline = w.time.monotonic() - 1
    dog.wlan_iface, dog.iface = None, None
    dog.lan_cidr = "10.0.0.0/24"
    for name in ("sample_traffic_categories", "maybe_scan_lan"):
        setattr(dog, name, lambda n=name: pytest.fail(f"{n} ran after the deadline"))
    dog.sample_once()


def test_lan_scan_timeout_is_capped_by_time_left(monkeypatch, tmp_path):
    dog = _lan_dog(tmp_path, {})
    dog.args.lan_scan_timeout = 30.0
    dog.deadline = w.time.monotonic() + 5
    seen = []
    monkeypatch.setattr(w, "scan_lan_nodes", lambda cidr, timeout=30: seen.append(timeout) or {})
    dog.maybe_scan_lan()
    assert 1.0 <= seen[0] <= 5.0


def test_call_with_timeout_gives_up_on_a_hung_call():
    import threading
    gate = threading.Event()
    ok, err = w.call_with_timeout(lambda: gate.wait(5), 0.05)
    gate.set()
    assert ok is False and isinstance(err, TimeoutError)


# --- P2: sh() failures are no longer indistinguishable from empty output ---

def test_missing_tool_is_recorded_not_silent(monkeypatch):
    w.TOOL_ERRORS.clear()
    assert w.sh(["definitely-not-installed-xyz"]) == ""
    assert w.TOOL_ERRORS["definitely-not-installed-xyz"] == "not installed"


def test_timeout_and_nonzero_exit_are_recorded():
    w.TOOL_ERRORS.clear()
    rc, out, err = w.run_sh(["sleep", "2"], timeout=0.1)
    assert rc is None and "timed out" in w.TOOL_ERRORS["sleep"]
    rc, out, err = w.run_sh(["ls", "/definitely/not/here"])
    assert rc != 0 and "exit" in w.TOOL_ERRORS["ls"]


def test_successful_command_records_nothing():
    w.TOOL_ERRORS.clear()
    rc, out, _ = w.run_sh(["echo", "hi"])
    assert (rc, out.strip()) == (0, "hi") and w.TOOL_ERRORS == {}
