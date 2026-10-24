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
