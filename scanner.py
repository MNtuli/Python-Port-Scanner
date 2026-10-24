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


def scan(ip: str, ports: list[int], timeout: float, threads: int, grab_banner: bool):
    results = []
    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = [pool.submit(scan_port, ip, p, timeout, grab_banner) for p in ports]
        for future in as_completed(futures):
            result = future.result()
            if result:
                results.append(result)
    return sorted(results, key=lambda r: r["port"])


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Simple TCP port scanner (authorized use only)."
    )
    parser.add_argument("target", help="IP address or hostname to scan")
    parser.add_argument(
        "-p", "--ports", default="1-1024",
        help="Ports to scan, e.g. '22,80,443' or '1-1024' (default: 1-1024)",
    )
    parser.add_argument("-t", "--timeout", type=float, default=0.5,
                        help="Connection timeout in seconds (default: 0.5)")
    parser.add_argument("-w", "--threads", type=int, default=100,
                        help="Number of worker threads (default: 100)")
    parser.add_argument("-b", "--banner", action="store_true",
                        help="Try to grab service banners from open ports")
    parser.add_argument("-o", "--output", help="Save results to a JSON file")
    parser.add_argument(
        "--i-have-permission", action="store_true",
        help="Required to scan non-private (public) IP addresses",
    )
    args = parser.parse_args()

    try:
        ports = parse_ports(args.ports)
        ip = resolve_target(args.target)
    except (ValueError, socket.gaierror) as exc:
        print(f"Error: {exc}")
        return 1

    if not is_private(ip) and not args.i_have_permission:
        print(f"Refusing to scan {ip}: it is not a private/local address.")
        print("Only scan systems you own or are authorized to test.")
        print("If you have permission, re-run with --i-have-permission.")
        return 1

    print(f"Scanning {args.target} ({ip}) - {len(ports)} ports")
    start = time.time()
    results = scan(ip, ports, args.timeout, args.threads, args.banner)
    elapsed = time.time() - start

    if results:
        print(f"\n{'PORT':<8}{'SERVICE':<15}BANNER")
        for r in results:
            print(f"{r['port']:<8}{r['service']:<15}{r['banner'][:50]}")
    else:
        print("\nNo open ports found.")
    print(f"\nScan finished in {elapsed:.2f}s - {len(results)} open port(s).")

    if args.output:
        with open(args.output, "w") as f:
            json.dump({"target": args.target, "ip": ip, "open_ports": results}, f, indent=2)
        print(f"Results saved to {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
