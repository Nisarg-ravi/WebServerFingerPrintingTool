#!/usr/bin/env python3
"""
Web Server Fingerprinting Tool — CLI
Usage:
    python cli.py example.com
    python cli.py example.com --ports 80 443 8080
    python cli.py --file hosts.txt
    python cli.py example.com --json
"""

import argparse
import json
import sys
from fingerprinter import probe_host, probe_multiple, PORT_MAP


def print_result(r, verbose=False):
    status = "✓" if r.success else "✗"
    print(f"  {status}  [{r.protocol}] port {r.port:<5}  ", end="")
    if r.success:
        print(f"{r.server_name:15} v{r.server_version:<15}  {r.response_time_ms:6.0f} ms", end="")
        if r.status_code:
            print(f"  HTTP {r.status_code}", end="")
        if r.ssl_info:
            cipher = r.ssl_info.get("cipher", "")
            print(f"  🔒 {cipher}", end="")
        print()
        if verbose and r.headers:
            for k, v in sorted(r.headers.items()):
                print(f"       {k}: {v}")
    else:
        print(f"ERROR: {r.error}")


def main():
    parser = argparse.ArgumentParser(description="Web Server Fingerprinting Tool")
    parser.add_argument("hosts", nargs="*", help="Host(s) to probe")
    parser.add_argument("--file", help="File with one host per line")
    parser.add_argument("--ports", nargs="+", type=int,
                        help="Specific ports to probe (default: 80 443 8080 8443 21)")
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--verbose", "-v", action="store_true")
    parser.add_argument("--json", action="store_true", help="Output JSON")
    parser.add_argument("--workers", type=int, default=10)
    args = parser.parse_args()

    hosts = list(args.hosts)
    if args.file:
        try:
            with open(args.file) as f:
                hosts += [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"Error: file '{args.file}' not found", file=sys.stderr)
            sys.exit(1)

    if not hosts:
        parser.print_help()
        sys.exit(0)

    # Build port map
    if args.ports:
        # Guess protocol from common port numbers
        port_map = []
        for p in args.ports:
            if p == 21:
                port_map.append((p, "FTP", False))
            elif p in (443, 8443):
                port_map.append((p, "HTTPS", True))
            else:
                port_map.append((p, "HTTP", False))
    else:
        port_map = None  # use defaults

    # Run
    if len(hosts) == 1:
        results_map = {hosts[0]: probe_host(hosts[0], port_map, args.timeout)}
    else:
        results_map = probe_multiple(hosts, args.timeout, args.workers)

    if args.json:
        out = {}
        for host, results in results_map.items():
            out[host] = []
            for r in results:
                out[host].append({
                    "port": r.port,
                    "protocol": r.protocol,
                    "server_name": r.server_name,
                    "server_version": r.server_version,
                    "status_code": r.status_code,
                    "response_time_ms": round(r.response_time_ms, 2),
                    "ssl_info": r.ssl_info,
                    "headers": r.headers,
                    "error": r.error,
                })
        print(json.dumps(out, indent=2))
        return

    # Human-readable
    for host, results in results_map.items():
        successful = [r for r in results if r.success]
        print(f"\n{'═'*60}")
        print(f"  HOST: {host}   ({len(successful)}/{len(results)} ports responded)")
        print(f"{'═'*60}")
        for r in results:
            print_result(r, verbose=args.verbose)

        # Accuracy note: highlight if server hidden
        if successful:
            hidden = [r for r in successful if r.server_name == "Unknown"]
            if hidden:
                print(f"\n  ⚠  Server identity hidden on {len(hidden)} port(s) — "
                      f"banner may be stripped or obfuscated.")

    print()


if __name__ == "__main__":
    main()
