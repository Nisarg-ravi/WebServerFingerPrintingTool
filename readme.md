# Web Server Fingerprinting Tool

Identify web server type and version by analyzing service banners using TCP socket communication.

## Project Structure

```
web_fingerprint/
├── fingerprinter.py   ← Core engine (banner grab + identification)
├── cli.py             ← Command-line interface
├── gui.py             ← Graphical dashboard (tkinter)
├── evaluate.py        ← Accuracy evaluation script
└── README.md
```

## How It Works

```
You (TCP socket) ──► connect to host:port
                 ◄── server sends banner / HTTP headers
                      └─ parse "Server:" header
                      └─ match regex patterns → Apache / Nginx / IIS …
```

Supported protocols:
- **HTTP** (port 80, 8080) — sends HEAD request, reads response headers
- **HTTPS** (port 443, 8443) — wraps socket in TLS, reads SSL cert info too
- **FTP** (port 21) — reads the welcome banner sent automatically on connect

## Quick Start

### CLI
```bash
# Single host
python cli.py example.com

# Multiple hosts
python cli.py google.com nginx.org apache.org

# Specific ports
python cli.py example.com --ports 80 443 8080

# From file
python cli.py --file hosts.txt

# JSON output
python cli.py example.com --json

# Verbose (show all headers)
python cli.py example.com --verbose
```

### GUI
```bash
python gui.py
```

### Accuracy Evaluation
```bash
python evaluate.py
```

## Requirements

- Python 3.10+
- Only **standard library** — no pip installs needed!
  (`socket`, `ssl`, `re`, `threading`, `tkinter`)

## Key Concepts

| Concept | Description |
|---|---|
| Banner grabbing | Reading the first bytes a server sends / sends back in headers |
| Service identification | Regex matching against known server signature strings |
| TCP socket | Raw network connection using `socket.create_connection()` |
| SSL wrapping | `ssl.SSLContext.wrap_socket()` for HTTPS |
| Concurrent scanning | `ThreadPoolExecutor` for fast multi-host probing |

## Accuracy Notes

- Many servers **hide or spoof** their `Server:` header for security
- Some CDNs (Cloudflare, Fastly) mask the origin server
- FTP banners are highly reliable — servers almost always announce themselves
- HTTPS sites reveal extra info via SSL certificate subject/issuer fields
