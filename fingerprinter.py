import socket
import ssl
import re
import ftplib
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Optional
import time

# ──────────────────────────────────────────────
#  Data model
# ──────────────────────────────────────────────
@dataclass
class FingerprintResult:
    host: str
    port: int
    protocol: str          # HTTP / HTTPS / FTP
    raw_banner: str = ""
    server_name: str = "Unknown"
    server_version: str = "Unknown"
    ssl_info: dict = field(default_factory=dict)
    headers: dict = field(default_factory=dict)
    response_time_ms: float = 0.0
    status_code: str = ""
    error: str = ""

    @property
    def success(self):
        return self.error == ""

    def summary(self):
        if not self.success:
            return f"[ERROR] {self.host}:{self.port} — {self.error}"
        ssl_tag = " [SSL]" if self.ssl_info else ""
        return (f"[{self.protocol}{ssl_tag}] {self.host}:{self.port} → "
                f"{self.server_name}/{self.server_version} "
                f"({self.response_time_ms:.0f} ms)")


# ──────────────────────────────────────────────
#  Known server patterns  (name, regex on banner)
# ──────────────────────────────────────────────
SERVER_PATTERNS = [
    ("Apache",    r"Apache(?:/([\d.]+))?"),
    ("Nginx",     r"nginx(?:/([\d.]+))?"),
    ("IIS",       r"Microsoft-IIS(?:/([\d.]+))?"),
    ("LiteSpeed", r"LiteSpeed(?:/([\d.]+))?"),
    ("Caddy",     r"Caddy(?:/([\d.]+))?"),
    ("Tomcat",    r"Apache-Coyote(?:/([\d.]+))?|Tomcat(?:/([\d.]+))?"),
    ("Node.js",   r"Node\.js"),
    ("Gunicorn",  r"gunicorn(?:/([\d.]+))?"),
    ("OpenResty", r"openresty(?:/([\d.]+))?"),
    ("Tengine",   r"Tengine(?:/([\d.]+))?"),
    ("Cherokee",  r"Cherokee(?:/([\d.]+))?"),
    ("Lighttpd",  r"lighttpd(?:/([\d.]+))?"),
    ("Jetty",     r"Jetty\(?([\d.]+)?\)?"),
    ("Kestrel",   r"Kestrel"),
    ("Werkzeug",  r"Werkzeug(?:/([\d.]+))?"),
    ("FTP-vsftpd",r"vsftpd ([\d.]+)"),
    ("FTP-ProFTPD",r"ProFTPD ([\d.]+)"),
    ("FTP-FileZilla",r"FileZilla Server ([\d.]+)"),
]


def identify_server(banner: str) -> tuple[str, str]:
    """Return (server_name, version) from raw banner text."""
    for name, pattern in SERVER_PATTERNS:
        m = re.search(pattern, banner, re.IGNORECASE)
        if m:
            # Grab first non-None group as version
            version = next((g for g in (m.groups() or []) if g), "Unknown")
            return name, version
    return "Unknown", "Unknown"


def parse_headers(raw: str) -> tuple[dict, str]:
    """Parse HTTP response headers from raw string."""
    headers = {}
    status_code = ""
    lines = raw.split("\r\n") if "\r\n" in raw else raw.split("\n")
    if lines:
        m = re.match(r"HTTP/[\d.]+ (\d{3})", lines[0])
        if m:
            status_code = m.group(1)
    for line in lines[1:]:
        if ":" in line:
            key, _, val = line.partition(":")
            headers[key.strip().lower()] = val.strip()
    return headers, status_code


# ──────────────────────────────────────────────
#  HTTP / HTTPS grabber
# ──────────────────────────────────────────────
def grab_http(host: str, port: int, use_ssl: bool = False,
              timeout: float = 5.0) -> FingerprintResult:
    proto = "HTTPS" if use_ssl else "HTTP"
    result = FingerprintResult(host=host, port=port, protocol=proto)
    try:
        raw_sock = socket.create_connection((host, port), timeout=timeout)
        if use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(raw_sock, server_hostname=host)
            try:
                cert = sock.getpeercert()
                cipher = sock.cipher()
                result.ssl_info = {
                    "cipher": cipher[0] if cipher else "",
                    "protocol": cipher[1] if cipher else "",
                    "subject": dict(x[0] for x in cert.get("subject", [])) if cert else {},
                    "issuer": dict(x[0] for x in cert.get("issuer", [])) if cert else {},
                    "expires": cert.get("notAfter", "") if cert else "",
                }
            except Exception:
                pass
        else:
            sock = raw_sock

        request = (f"HEAD / HTTP/1.1\r\n"
                   f"Host: {host}\r\n"
                   f"User-Agent: Mozilla/5.0 (compatible; ServerFingerprinter/1.0)\r\n"
                   f"Connection: close\r\n\r\n")

        t0 = time.perf_counter()
        sock.sendall(request.encode())
        chunks = []
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
            if len(b"".join(chunks)) > 8192:
                break
        result.response_time_ms = (time.perf_counter() - t0) * 1000
        sock.close()

        raw = b"".join(chunks).decode("utf-8", errors="ignore")
        result.raw_banner = raw
        result.headers, result.status_code = parse_headers(raw)

        # Identify from Server header first, then full banner
        server_header = result.headers.get("server", "")
        if server_header:
            result.server_name, result.server_version = identify_server(server_header)
        if result.server_name == "Unknown":
            result.server_name, result.server_version = identify_server(raw)

    except Exception as e:
        result.error = str(e)
    return result


# ──────────────────────────────────────────────
#  FTP grabber
# ──────────────────────────────────────────────
def grab_ftp(host: str, port: int = 21, timeout: float = 5.0) -> FingerprintResult:
    result = FingerprintResult(host=host, port=port, protocol="FTP")
    try:
        t0 = time.perf_counter()
        sock = socket.create_connection((host, port), timeout=timeout)
        banner = sock.recv(1024).decode("utf-8", errors="ignore")
        result.response_time_ms = (time.perf_counter() - t0) * 1000
        sock.close()
        result.raw_banner = banner
        result.server_name, result.server_version = identify_server(banner)
    except Exception as e:
        result.error = str(e)
    return result


# ──────────────────────────────────────────────
#  Auto-probe: try all common ports/protocols
# ──────────────────────────────────────────────
PORT_MAP = [
    (80,  "HTTP",  False),
    (443, "HTTPS", True),
    (8080,"HTTP",  False),
    (8443,"HTTPS", True),
    (21,  "FTP",   False),
]

def probe_host(host: str, ports: Optional[list] = None,
               timeout: float = 5.0) -> list[FingerprintResult]:
    """Probe a single host on multiple ports, return all results."""
    targets = ports or PORT_MAP
    results = []
    for port, proto, use_ssl in targets:
        if proto == "FTP":
            r = grab_ftp(host, port, timeout)
        else:
            r = grab_http(host, port, use_ssl, timeout)
        results.append(r)
    return results


def probe_multiple(hosts: list[str], timeout: float = 5.0,
                   max_workers: int = 10) -> dict[str, list[FingerprintResult]]:
    """Probe multiple hosts concurrently."""
    all_results = {}
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(probe_host, h, None, timeout): h for h in hosts}
        for fut in as_completed(futures):
            host = futures[fut]
            try:
                all_results[host] = fut.result()
            except Exception as e:
                all_results[host] = [FingerprintResult(host=host, port=0,
                                                        protocol="N/A",
                                                        error=str(e))]
    return all_results
