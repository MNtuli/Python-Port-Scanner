# Python Port Scanner

WTC-S4KBS3WM

A simple multithreaded TCP port scanner written in Python. I built it to learn how port scanning works and to audit the devices on my own network.

> **Disclaimer:** This tool is for educational use and authorized testing only. Only scan systems you own or have explicit permission to test. Unauthorized scanning may be illegal.

## Features

- Scan single ports, lists, or ranges (`22,80,443`, `1-1024`)
- Multithreaded for speed, with adjustable timeout and thread count
- Service name lookup for open ports
- Optional banner grabbing
- JSON output for later analysis
- Built-in safety guard: refuses to scan public IPs unless `--i-have-permission` is passed
- 33 automated tests that run entirely on localhost

## Requirements

- Python 3.9 or newer
- No external dependencies for the scanner itself
- `pytest` only if you want to run the tests

## Usage

```bash
python scanner.py 192.168.1.1                   # scan ports 1-1024 (default)
python scanner.py 192.168.1.10 -p 1-65535       # scan all ports
python scanner.py localhost -p 22,80,443 -b     # grab banners
python scanner.py 192.168.1.1 -o results.json   # save results to JSON
```

On macOS/Linux, use `python3` instead of `python`.

### Options

| Option | Description | Default |
|---|---|---|
| `target` | IP address or hostname to scan | required |
| `-p`, `--ports` | Ports to scan (`22,80`, `1-1024`) | `1-1024` |
| `-t`, `--timeout` | Connection timeout in seconds | `0.5` |
| `-w`, `--threads` | Number of worker threads | `100` |
| `-b`, `--banner` | Try to grab service banners | off |
| `-o`, `--output` | Save results to a JSON file | none |
| `--i-have-permission` | Allow scanning non-private IPs | off |

### Example output

```
Scanning 192.168.1.1 (192.168.1.1) - 1024 ports

PORT    SERVICE        BANNER
53      domain
80      http
443     https

Scan finished in 2.41s - 3 open port(s).
```

## Running the tests

```bash
python -m pip install pytest
python -m pytest -v
```

The tests start small local servers, so they never touch your real network. They cover port parsing, private/public IP detection, open and closed port detection, banner grabbing, and the command line behavior (including the safety guard and JSON output).

## How it works

The scanner performs a **TCP connect scan**. For each port it tries to complete a full TCP handshake:

- Connection succeeds: the port is **open**
- Connection refused or times out: the port is **closed or filtered**

A thread pool checks many ports at once, which makes scanning much faster than doing them one by one. This approach needs no special privileges, but it is noisier than a SYN scan (Nmap's default as root) because completed connections can show up in the target's logs.

## Defensive takeaways

- Every open port is attack surface. Close or firewall anything you don't need.
- Service banners can leak software names and versions, so consider hiding them.
- Scan your own router and devices regularly and compare the results with `nmap`.

## Project structure

```
.
├── scanner.py        # the port scanner
├── test_scanner.py   # pytest test suite
└── README.md
```

## Roadmap

- [ ] CIDR range scanning (`192.168.1.0/24`)
- [ ] UDP scanning
- [ ] Compare scans over time and alert on new open ports
- [ ] Progress bar and rate limiting
- [ ] GitHub Actions to run tests on every push

## What I learned

- How the TCP handshake works and what "open", "closed" and "filtered" really mean
- Using threads to speed up network I/O
- Why timeouts matter and how scanners get detected
- Writing tests for network code using local servers

## License

MIT (add a `LICENSE` file to your repo if you want to use this license).
