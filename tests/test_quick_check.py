import socket
import sys
from pathlib import Path

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
    monkeypatch.setattr(q.socket, "gethostbyname", lambda h: "127.0.0.1")
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
