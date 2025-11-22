# netwatch

`netwatch` is a lightweight TCP port scanner implemented with only Python's standard library. It supports scanning individual hosts, CIDR blocks, and explicit IP ranges while providing quick service identification for common ports.

## Features
- TCP connect scanning with configurable port ranges (default 1-1024)
- Target parsing for single IPs, CIDRs, and IP ranges
- Common service detection (HTTP, SSH, DNS, FTP and more)
- JSON output for machine-readable reporting
- Tunable socket timeout and worker threads

## Usage
Install requirements (Python 3.10+ recommended) and run directly:

```bash
python netwatch.py <target> [options]
```

### Examples
- Scan default ports on a single host:
  ```bash
  python netwatch.py 192.168.1.10
  ```
- Scan a CIDR subnet with a custom port list and JSON output:
  ```bash
  python netwatch.py 10.0.0.0/30 -p 22,80,443 --json
  ```
- Scan an explicit IP range with custom timeout and threads:
  ```bash
  python netwatch.py 10.0.0.1-10.0.0.5 --timeout 0.5 --threads 32
  ```

### Options
- `-p, --ports` — Ports to scan (comma-separated single ports and ranges). Default: `1-1024`.
- `--timeout` — Socket timeout in seconds. Default: `1.0`.
- `--threads` — Number of worker threads. Default: `64`.
- `--json` — Emit JSON-formatted results instead of text.

## Output
Text output lists each probed port per host:
```
192.168.1.10:22 open (ssh) [2.1 ms]
192.168.1.10:80 closed
```

JSON output returns an array of result objects:
```json
[
  {"ip": "192.168.1.10", "port": 22, "open": true, "service": "ssh", "latency_ms": 2.1},
  {"ip": "192.168.1.10", "port": 80, "open": false, "service": null, "latency_ms": null}
]
```

## Development
Run the test suite with:
```bash
python -m unittest tests_netwatch.py
```
