"""Tests for scanner.py. Run with: pytest -v"""

import json
import socket
import sys
import threading

import pytest

import scanner


# ---------- helpers ----------

def free_port() -> int:
    """Return a port that is currently not in use."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class LocalServer:
    """Tiny TCP server on localhost, optionally sending a banner on connect."""

    def __init__(self, banner: bytes = b""):
        self.banner = banner
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(5)
        self.port = self.sock.getsockname()[1]
        self._running = True
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        self.sock.settimeout(0.2)
        while self._running:
            try:
                conn, _ = self.sock.accept()
            except (socket.timeout, OSError):
                continue
            with conn:
                if self.banner:
                    conn.sendall(self.banner)

    def close(self):
        self._running = False
        self.thread.join(timeout=1)
        self.sock.close()


@pytest.fixture
def server():
    srv = LocalServer()
    yield srv
    srv.close()


@pytest.fixture
def banner_server():
    srv = LocalServer(banner=b"SSH-2.0-TestServer\r\n")
    yield srv
    srv.close()


# ---------- parse_ports ----------

def test_parse_single_port():
    assert scanner.parse_ports("80") == [80]


def test_parse_list_of_ports():
    assert scanner.parse_ports("22,80,443") == [22, 80, 443]


def test_parse_range():
    assert scanner.parse_ports("20-23") == [20, 21, 22, 23]


def test_parse_mixed_and_deduplicated():
    assert scanner.parse_ports("80,20-22,80,21") == [20, 21, 22, 80]


def test_parse_handles_whitespace():
    assert scanner.parse_ports(" 22 , 80 ") == [22, 80]


@pytest.mark.parametrize("bad", ["0", "70000", "100-50", "abc", "", "1-70000"])
def test_parse_invalid_raises(bad):
    with pytest.raises(ValueError):
        scanner.parse_ports(bad)


# ---------- is_private ----------

@pytest.mark.parametrize("ip", ["127.0.0.1", "192.168.1.1", "10.0.0.5", "172.16.0.9"])
def test_private_addresses(ip):
    assert scanner.is_private(ip)


@pytest.mark.parametrize("ip", ["8.8.8.8", "1.1.1.1", "93.184.216.34"])
def test_public_addresses(ip):
    assert not scanner.is_private(ip)


# ---------- resolve_target / service_name ----------

def test_resolve_ip_literal_returns_same_ip():
    assert scanner.resolve_target("127.0.0.1") == "127.0.0.1"


def test_service_name_known_port():
    assert scanner.service_name(80) == "http"


def test_service_name_falls_back_to_unknown(monkeypatch):
    def raise_oserror(port, proto):
        raise OSError("not found")

    monkeypatch.setattr(scanner.socket, "getservbyport", raise_oserror)
    assert scanner.service_name(65000) == "unknown"


# ---------- scan_port ----------

def test_scan_port_detects_open_port(server):
    result = scanner.scan_port("127.0.0.1", server.port, timeout=1, grab_banner=False)
    assert result is not None
    assert result["port"] == server.port
    assert result["banner"] == ""


def test_scan_port_returns_none_for_closed_port():
    result = scanner.scan_port("127.0.0.1", free_port(), timeout=0.5, grab_banner=False)
    assert result is None


def test_scan_port_grabs_banner(banner_server):
    result = scanner.scan_port("127.0.0.1", banner_server.port, timeout=1, grab_banner=True)
    assert result is not None
    assert "SSH-2.0-TestServer" in result["banner"]


def test_scan_port_no_banner_when_disabled(banner_server):
    result = scanner.scan_port("127.0.0.1", banner_server.port, timeout=1, grab_banner=False)
    assert result["banner"] == ""


# ---------- scan ----------

def test_scan_finds_only_open_ports_sorted(server):
    closed = free_port()
    ports = sorted([server.port, closed])
    results = scanner.scan("127.0.0.1", ports, timeout=0.5, threads=10, grab_banner=False)
    assert [r["port"] for r in results] == [server.port]


def test_scan_multiple_open_ports():
    s1, s2 = LocalServer(), LocalServer()
    try:
        ports = [s1.port, s2.port]
        results = scanner.scan("127.0.0.1", ports, timeout=0.5, threads=5, grab_banner=False)
        assert [r["port"] for r in results] == sorted(ports)
    finally:
        s1.close()
        s2.close()


def test_scan_empty_when_nothing_open():
    results = scanner.scan("127.0.0.1", [free_port()], timeout=0.3, threads=2, grab_banner=False)
    assert results == []


# ---------- CLI (main) ----------

def run_main(monkeypatch, args):
    monkeypatch.setattr(sys, "argv", ["scanner.py", *args])
    return scanner.main()


def test_cli_refuses_public_ip_without_permission(monkeypatch, capsys):
    code = run_main(monkeypatch, ["8.8.8.8", "-p", "80"])
    out = capsys.readouterr().out
    assert code == 1
    assert "Refusing to scan" in out


def test_cli_scans_localhost_and_reports_open_port(monkeypatch, capsys, server):
    code = run_main(monkeypatch, ["127.0.0.1", "-p", str(server.port), "-t", "1"])
    out = capsys.readouterr().out
    assert code == 0
    assert str(server.port) in out
    assert "1 open port(s)" in out


def test_cli_reports_no_open_ports(monkeypatch, capsys):
    code = run_main(monkeypatch, ["127.0.0.1", "-p", str(free_port()), "-t", "0.3"])
    out = capsys.readouterr().out
    assert code == 0
    assert "No open ports found" in out


def test_cli_invalid_ports_returns_error(monkeypatch, capsys):
    code = run_main(monkeypatch, ["127.0.0.1", "-p", "99999"])
    assert code == 1
    assert "Error" in capsys.readouterr().out


def test_cli_writes_json_output(monkeypatch, tmp_path, server):
    outfile = tmp_path / "results.json"
    code = run_main(
        monkeypatch,
        ["127.0.0.1", "-p", str(server.port), "-t", "1", "-o", str(outfile)],
    )
    assert code == 0
    data = json.loads(outfile.read_text())
    assert data["ip"] == "127.0.0.1"
    assert data["open_ports"][0]["port"] == server.port