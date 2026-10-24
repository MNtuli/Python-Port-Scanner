import argparse
import ipaddress
import json
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

def parse_ports(spec: str) -> list[int]:
    """we are sorting the post """
    

    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start, end = part.split("-", 1)
            start, end = int(start), int(end)
            if start > end:
                raise ValueError(f"Invalid range: {part}")
            ports.update(range(start, end + 1))
        else:
            ports.add(int(part))
    if not ports or min(ports) < 1 or max(ports) > 65535:
        raise ValueError("Ports must be between 1 and 65535")
    return sorted(ports)

def resolve_target(target: str) -> str:

    # Resolve a hostname or IP string to an IPv4 address.
    return socket.gethostbyname(target)


def is_private(ip: str) -> bool:
    addr = ipaddress.ip_address(ip)
    return addr.is_private or addr.is_loopback


def service_name(port: int) -> str:
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


def scan_port(ip: str, port: int, timeout: float, grab_banner: bool):
    """Return a result dict if the port is open, otherwise None."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            if sock.connect_ex((ip, port)) != 0:
                return None
            banner = ""
            if grab_banner:
                try:
                    sock.settimeout(1.0)
                    banner = sock.recv(128).decode(errors="ignore").strip()
                except (socket.timeout, OSError):
                    pass
            return {"port": port, "service": service_name(port), "banner": banner}
    except OSError:
        return None
