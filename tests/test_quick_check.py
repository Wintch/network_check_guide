import socket
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import quick_check as q


class FakeSock:
    def __init__(self, recv_exc=None):
        self.closed = False
        self.recv_exc = recv_exc

    def sendall(self, data):
        pass

    def recv(self, n):
        if self.recv_exc:
            raise self.recv_exc
        return b""

    def close(self):
        self.closed = True


def _patch_net(monkeypatch, sock):
    monkeypatch.setattr(q, "resolve_with_timeout", lambda h, p, f, timeout=3.0: "127.0.0.1")
    monkeypatch.setattr(q.socket, "create_connection", lambda addr, timeout=None: sock)
    monkeypatch.setattr(q.time, "sleep", lambda s: None)


def test_socket_closed_when_tls_handshake_fails(monkeypatch):
    sock = FakeSock()
    _patch_net(monkeypatch, sock)

    class Ctx:
        def wrap_socket(self, s, server_hostname=None):
            raise q.ssl.SSLError("handshake failed")

    monkeypatch.setattr(q.ssl, "create_default_context", lambda: Ctx())
    res = q.check_real_api_timings("https://example.test/", attempts=1)
    assert sock.closed
    assert res["samples"][0]["ok"] is False and res["issues"]


def test_socket_closed_when_read_times_out(monkeypatch):
    sock = FakeSock(recv_exc=socket.timeout("timed out"))
    _patch_net(monkeypatch, sock)
    res = q.check_real_api_timings("http://example.test/", attempts=1)
    assert sock.closed
    assert res["samples"][0]["ok"] is False


def test_socket_closed_on_success(monkeypatch):
    sock = FakeSock()
    _patch_net(monkeypatch, sock)
    res = q.check_real_api_timings("http://example.test/", attempts=1)
    assert sock.closed and res["samples"][0]["ok"] is True


def test_ipv6_unavailable_is_reported_not_crashed(monkeypatch):
    monkeypatch.setattr(q, "resolve_with_timeout", lambda h, p, f, timeout=3.0: None)
    monkeypatch.setattr(q.time, "sleep", lambda s: None)
    res = q.check_real_api_timings("https://example.test/", attempts=1, family=socket.AF_INET6)
    assert res["family"] == "IPv6" and res["available"] is False
    assert "no IPv6 address" in res["samples"][0]["error"]


def test_resolve_with_timeout_gives_up(monkeypatch):
    import threading
    gate = threading.Event()
    monkeypatch.setattr(q.socket, "getaddrinfo", lambda *a: (gate.wait(5), [(0, 0, 0, "", ("1.2.3.4", 0))])[1])
    assert q.resolve_with_timeout("slow.test", 443, socket.AF_INET, timeout=0.05) is None
    gate.set()


# --- gateway ping: "could not measure" must not look like 100% loss ---

def test_ping_missing_is_unmeasured_not_100pct_loss(monkeypatch):
    monkeypatch.setattr(q, "run_cmd", lambda cmd, timeout=5.0: (-2, "", "Command not found: ping"))
    r = q.check_gateway_pings("192.168.1.1", count=5)
    assert r["measured"] is False and r["loss_pct"] is None
    assert any("could not be measured" in i for i in r["issues"])


def test_ping_unparseable_output_is_unmeasured(monkeypatch):
    monkeypatch.setattr(q, "run_cmd", lambda cmd, timeout=5.0: (0, "garbage", ""))
    assert q.check_gateway_pings("192.168.1.1", count=5)["measured"] is False


def test_real_total_loss_is_still_reported_as_loss(monkeypatch):
    out = "5 packets transmitted, 0 received, 100% packet loss, time 4090ms"
    monkeypatch.setattr(q, "run_cmd", lambda cmd, timeout=5.0: (1, out, ""))
    r = q.check_gateway_pings("192.168.1.1", count=5)
    assert r["measured"] is True and r["loss_pct"] == 100.0


# --- MTU: binary search finds the exact value, not just one of four buckets ---

def _fake_ping(limit_payload):
    def run(cmd, timeout=5.0):
        size = int(cmd[cmd.index("-s") + 1])
        if size <= limit_payload:
            return 0, "2 packets transmitted, 2 received, 0% packet loss", ""
        return 1, "", "ping: sendmsg: Message too long"
    return run


@pytest.mark.parametrize("mtu", [1500, 1492, 1496, 1420, 1300, 1228])
def test_mtu_search_finds_exact_value(monkeypatch, mtu):
    monkeypatch.setattr(q, "run_cmd", _fake_ping(mtu - 28))
    r = q.check_path_mtu()
    assert r["effective_mtu"] == mtu and r["max_working_payload"] == mtu - 28


def test_mtu_nothing_works_is_an_issue(monkeypatch):
    monkeypatch.setattr(q, "run_cmd", lambda cmd, timeout=5.0: (1, "", "ping: sendmsg: Message too long"))
    r = q.check_path_mtu()
    assert r["effective_mtu"] is None and r["issues"]


def test_mtu_silent_drops_warn(monkeypatch):
    monkeypatch.setattr(q, "run_cmd", lambda cmd, timeout=5.0: (1, "2 packets transmitted, 0 received, 100% packet loss", ""))
    r = q.check_path_mtu()
    assert any("silently" in w for w in r["warnings"])
