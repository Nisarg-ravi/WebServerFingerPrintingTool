#!/usr/bin/env python3
"""
Accuracy Evaluation Script
Tests the fingerprinter against known servers and scores accuracy.
"""

import sys, os
sys.path.insert(0, os.path.dirname(__file__))
from fingerprinter import probe_host

# ── Known test targets (public, no auth required)
# Format: (host, port, protocol, expected_server_keyword)
TEST_CASES = [
    ("httpforever.com",   80,  "HTTP",  False, "Apache"),
    ("nginx.org",         80,  "HTTP",  False, "Nginx"),
    ("nginx.org",         443, "HTTPS", True,  "Nginx"),
    ("example.com",       80,  "HTTP",  False, None),   # Might be hidden — just check connectivity
    ("example.com",       443, "HTTPS", True,  None),
    ("ftp.debian.org",    21,  "FTP",   False, "ProFTPD"),
]

def run_eval():
    print("=" * 60)
    print("  Accuracy Evaluation")
    print("=" * 60)
    total = correct = connectivity_ok = 0
    for host, port, proto, use_ssl, expected in TEST_CASES:
        total += 1
        if proto == "FTP":
            from fingerprinter import grab_ftp
            r = grab_ftp(host, port)
        else:
            from fingerprinter import grab_http
            r = grab_http(host, port, use_ssl)

        if r.success:
            connectivity_ok += 1
            if expected is None:
                print(f"  ✓ CONN  {host}:{port} — server={r.server_name} (expected: any)")
                correct += 1
            elif expected.lower() in r.server_name.lower():
                print(f"  ✓ MATCH {host}:{port} — got '{r.server_name}' (expected '{expected}')")
                correct += 1
            else:
                print(f"  ✗ MISS  {host}:{port} — got '{r.server_name}' (expected '{expected}')")
        else:
            print(f"  ! ERROR {host}:{port} — {r.error}")

    print()
    print(f"  Connectivity : {connectivity_ok}/{total}")
    if connectivity_ok > 0:
        accuracy = correct / total * 100
        print(f"  Accuracy     : {correct}/{total}  ({accuracy:.0f}%)")
    print("=" * 60)

if __name__ == "__main__":
    run_eval()
