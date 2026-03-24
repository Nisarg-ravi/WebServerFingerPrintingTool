import socket
import ssl
import re
import sys
import time
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional


# ──────────────────────────────────────────────
#  Result model
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
    note: str = ""

    @property
    def success(self):
        return self.error == ""

    def summary(self):
        if not self.success:
            return f"[ERROR] {self.host}:{self.port} — {self.error}"
        ssl_tag = " [SSL]" if self.ssl_info else ""
        note = f" ({self.note})" if self.note else ""
        return (
            f"[{self.protocol}{ssl_tag}] {self.host}:{self.port} → "
            f"{self.server_name}/{self.server_version} "
            f"HTTP {self.status_code or '-'} "
            f"({self.response_time_ms:.0f} ms){note}"
        )


# ──────────────────────────────────────────────
#  Known banner patterns
# ──────────────────────────────────────────────
SERVER_PATTERNS = [
    ("Apache", r"Apache(?:/([\d.]+))?"),
    ("Nginx", r"nginx(?:/([\d.]+))?"),
    ("IIS", r"Microsoft-IIS(?:/([\d.]+))?"),
    ("LiteSpeed", r"LiteSpeed(?:/([\d.]+))?"),
    ("Caddy", r"Caddy(?:/([\d.]+))?"),
    ("Tomcat", r"Apache-Coyote(?:/([\d.]+))?|Tomcat(?:/([\d.]+))?"),
    ("Node.js", r"Node\.js"),
    ("Gunicorn", r"gunicorn(?:/([\d.]+))?"),
    ("OpenResty", r"openresty(?:/([\d.]+))?"),
    ("Tengine", r"Tengine(?:/([\d.]+))?"),
    ("Cherokee", r"Cherokee(?:/([\d.]+))?"),
    ("Lighttpd", r"lighttpd(?:/([\d.]+))?"),
    ("Jetty", r"Jetty\(?([\d.]+)?\)?"),
    ("Kestrel", r"Kestrel"),
    ("Werkzeug", r"Werkzeug(?:/([\d.]+))?"),
    ("FTP-vsftpd", r"vsftpd ([\d.]+)"),
    ("FTP-ProFTPD", r"ProFTPD ([\d.]+)"),
    ("FTP-FileZilla", r"FileZilla Server ([\d.]+)"),
]


def identify_server(text: str) -> tuple[str, str]:
    """Identify server from raw text/banner."""
    if not text:
        return "Unknown", "Unknown"

    for name, pattern in SERVER_PATTERNS:
        m = re.search(pattern, text, re.IGNORECASE)
        if m:
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


def infer_server_from_headers(headers: dict, raw: str = "") -> tuple[str, str, str]:
    """
    Infer server/CDN/proxy using headers.
    Returns: (name, version, note)
    """
    if not headers:
        name, version = identify_server(raw)
        return name, version, ""

    h = {k.lower(): v for k, v in headers.items()}
    joined = " | ".join(f"{k}: {v}" for k, v in h.items()).lower()

    server_header = h.get("server", "")
    if server_header:
        name, version = identify_server(server_header)
        if name != "Unknown":
            return name, version, ""

    x_powered_by = h.get("x-powered-by", "")
    if x_powered_by:
        low = x_powered_by.lower()
        if "express" in low:
            return "Express", "Unknown", "identified from x-powered-by"
        if "php" in low:
            return "PHP", "Unknown", "identified from x-powered-by"
        if "asp.net" in low:
            return "ASP.NET", "Unknown", "identified from x-powered-by"

    if "cloudflare" in joined or "cf-ray" in h or "cf-cache-status" in h:
        return "Cloudflare", "Unknown", "likely CDN/Proxy"

    if "fastly" in joined or "x-fastly-request-id" in h:
        return "Fastly", "Unknown", "likely CDN/Proxy"

    if "akamai" in joined:
        return "Akamai", "Unknown", "likely CDN/Proxy"

    if "envoy" in joined:
        return "Envoy", "Unknown", "likely reverse proxy"

    if "varnish" in joined or "x-varnish" in h or "via" in h and "varnish" in h.get("via", "").lower():
        return "Varnish", "Unknown", "likely cache/proxy"

    if "gws" in joined or "google" in joined:
        return "Google Frontend", "Unknown", "likely Google infrastructure"

    if "github" in joined:
        return "GitHub Infrastructure", "Unknown", "inferred from headers"

    name, version = identify_server(raw)
    if name != "Unknown":
        return name, version, "identified from raw response"

    return "Unknown", "Unknown", "banner hidden or stripped"


def make_ssl_socket(host: str, port: int, timeout: float):
    raw_sock = socket.create_connection((host, port), timeout=timeout)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx.wrap_socket(raw_sock, server_hostname=host)


def extract_ssl_info(sock) -> dict:
    info = {}
    try:
        cipher = sock.cipher()
        if cipher:
            info["cipher"] = cipher[0]
            info["protocol"] = cipher[1]

        try:
            cert = sock.getpeercert()
            if cert:
                info["subject"] = dict(x[0] for x in cert.get("subject", [])) if cert.get("subject") else {}
                info["issuer"] = dict(x[0] for x in cert.get("issuer", [])) if cert.get("issuer") else {}
                info["expires"] = cert.get("notAfter", "")
        except Exception:
            pass
    except Exception:
        pass

    return info


def receive_response(sock, limit: int = 16384) -> str:
    chunks = []
    total = 0

    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
        if total >= limit:
            break

    return b"".join(chunks).decode("utf-8", errors="ignore")


def send_http_request(host: str, port: int, method: str, use_ssl: bool, timeout: float):
    sock = None
    try:
        if use_ssl:
            sock = make_ssl_socket(host, port, timeout)
        else:
            sock = socket.create_connection((host, port), timeout=timeout)

        request = (
            f"{method} / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: Mozilla/5.0 (compatible; ServerFingerprinter/2.0)\r\n"
            f"Accept: */*\r\n"
            f"Connection: close\r\n\r\n"
        )

        t0 = time.perf_counter()
        sock.sendall(request.encode())
        raw = receive_response(sock)
        elapsed = (time.perf_counter() - t0) * 1000

        ssl_info = extract_ssl_info(sock) if use_ssl else {}
        return raw, elapsed, ssl_info, ""
    except Exception as e:
        return "", 0.0, {}, str(e)
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass


# ──────────────────────────────────────────────
#  HTTP / HTTPS grabber
# ──────────────────────────────────────────────
def grab_http(host: str, port: int, use_ssl: bool = False, timeout: float = 5.0) -> FingerprintResult:
    proto = "HTTPS" if use_ssl else "HTTP"
    result = FingerprintResult(host=host, port=port, protocol=proto)

    try:
        # First try HEAD
        raw, elapsed, ssl_info, err = send_http_request(host, port, "HEAD", use_ssl, timeout)
        if err:
            result.error = err
            return result

        result.raw_banner = raw
        result.response_time_ms = elapsed
        result.ssl_info = ssl_info
        result.headers, result.status_code = parse_headers(raw)

        # Fallback to GET if HEAD is weak or rejected
        if result.status_code in {"405", "403", ""} or not result.headers:
            raw2, elapsed2, ssl_info2, err2 = send_http_request(host, port, "GET", use_ssl, timeout)
            if not err2 and raw2:
                result.raw_banner = raw2
                result.response_time_ms = elapsed2
                if ssl_info2:
                    result.ssl_info = ssl_info2
                result.headers, result.status_code = parse_headers(raw2)

        result.server_name, result.server_version, result.note = infer_server_from_headers(
            result.headers, result.raw_banner
        )

    except Exception as e:
        result.error = str(e)

    return result


# ──────────────────────────────────────────────
#  FTP grabber
# ──────────────────────────────────────────────
def grab_ftp(host: str, port: int = 21, timeout: float = 5.0) -> FingerprintResult:
    result = FingerprintResult(host=host, port=port, protocol="FTP")
    sock = None

    try:
        t0 = time.perf_counter()
        sock = socket.create_connection((host, port), timeout=timeout)
        banner = sock.recv(1024).decode("utf-8", errors="ignore")
        result.response_time_ms = (time.perf_counter() - t0) * 1000
        result.raw_banner = banner
        result.server_name, result.server_version = identify_server(banner)
        if result.server_name == "Unknown":
            result.note = "banner hidden or generic"
    except Exception as e:
        result.error = str(e)
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass

    return result


# ──────────────────────────────────────────────
#  Auto-probe ports
# ──────────────────────────────────────────────
PORT_MAP = [
    (80, "HTTP", False),
    (443, "HTTPS", True),
    (8080, "HTTP", False),
    (8443, "HTTPS", True),
    (21, "FTP", False),
]


def probe_host(host: str, ports: Optional[list] = None, timeout: float = 5.0) -> list[FingerprintResult]:
    targets = ports or PORT_MAP
    results = []

    for port, proto, use_ssl in targets:
        if proto == "FTP":
            r = grab_ftp(host, port, timeout)
        else:
            r = grab_http(host, port, use_ssl, timeout)
        results.append(r)

    return results


def probe_multiple(hosts: list[str], timeout: float = 5.0, max_workers: int = 10) -> dict[str, list[FingerprintResult]]:
    all_results = {}

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(probe_host, h, None, timeout): h for h in hosts}
        for fut in as_completed(futures):
            host = futures[fut]
            try:
                all_results[host] = fut.result()
            except Exception as e:
                all_results[host] = [
                    FingerprintResult(host=host, port=0, protocol="N/A", error=str(e))
                ]

    return all_results


# ──────────────────────────────────────────────
#  CLI output
# ──────────────────────────────────────────────
def format_result_line(r: FingerprintResult) -> str:
    if not r.success:
        return f"  ✗  [{r.protocol}] port {r.port:<5} ERROR: {r.error}"

    name = r.server_name
    version = f"v{r.server_version}" if r.server_version != "Unknown" else "vUnknown"

    status_part = f"HTTP {r.status_code}" if r.status_code else "-"
    tls_part = ""
    if r.ssl_info.get("cipher"):
        tls_part = f"  🔒 {r.ssl_info['cipher']}"

    note_part = f"  ({r.note})" if r.note else ""

    return (
        f"  ✓  [{r.protocol}] port {r.port:<5} "
        f"{name:<15} {version:<12} "
        f"{r.response_time_ms:>6.0f} ms  {status_part}{tls_part}{note_part}"
    )


def print_host_results(host: str, results: list[FingerprintResult]):
    responded = sum(1 for r in results if r.success)
    hidden = sum(1 for r in results if r.success and r.server_name == "Unknown")

    print("\n" + "═" * 60)
    print(f"  HOST: {host}   ({responded}/{len(results)} ports responded)")
    print("═" * 60)

    for r in sorted(results, key=lambda x: x.port):
        print(format_result_line(r))

    if hidden > 0:
        print(f"\n  ⚠  Direct server identity not exposed on {hidden} port(s).")
        print("     It may be behind a CDN, reverse proxy, or banner stripping policy.")


def main():
    if len(sys.argv) < 2:
        print("Usage: python cli.py <host1> <host2> ...")
        sys.exit(1)

    hosts = sys.argv[1:]
    results = probe_multiple(hosts)

    for host in hosts:
        host_results = results.get(host, [])
        print_host_results(host, host_results)


if __name__ == "__main__":
    main()