# pcap2api

> Analyse network captures against threat intelligence feeds — no SIEM required.

`pcap2api` extracts IPs, domains, and URLs from one or more PCAP/CAP files and cross-references them against seven public threat intelligence feeds plus optional commercial APIs. It is designed to mirror the **IntelMQ Collector → Parser → Output pipeline** in a single, self-contained command-line tool.

```
$ pcap2api capture.pcap

  Loading 6 threat feed(s)…
  [cache] URLhaus (4m ago)       ips:12482  domains:8741  urls:51203
  [fetch] FeodoTracker           ips:892    domains:0      urls:0
  ...

  Unique observables: 134  (89 ips, 31 domains, 14 urls)
  Running lookups across 7 backend(s)…

  ┌─────────────────────┬──────────┬─────────────────┬──────────────────┬───────┐
  │ Observable          │ Kind     │ TI Source       │ Class. Type      │ Conf. │
  ├─────────────────────┼──────────┼─────────────────┼──────────────────┼───────┤
  │ 185.220.101.47      │ ip       │ FeodoTracker    │ c2-server        │  95%  │
  │ malware-cdn.xyz     │ domain   │ URLhaus         │ malware-distrib… │  90%  │
  │ 94.102.49.190       │ ip       │ Blocklist.de    │ brute-force      │  80%  │
  └─────────────────────┴──────────┴─────────────────┴──────────────────┴───────┘
```

---

## Features

### Seven built-in threat intelligence feeds

The tool emulates the IntelMQ **Collector → Parser → Expert → Output** pipeline for each feed, downloading, parsing, and caching the data locally. No API keys are required for any of these.

| Feed | What it detects | TTL |
|---|---|---|
| **URLhaus** (Abuse.ch) | Malware distribution URLs and their hosting IPs | 60 min |
| **Feodo Tracker** (Abuse.ch) | Active botnet C2 IPs (Emotet, TrickBot, QakBot…) | 60 min |
| **PhishTank** | Verified phishing URLs and domains | 60 min |
| **Bambenek Consulting** | C2 domains and DGA (Domain Generation Algorithm) masterlist | 60 min |
| **Blocklist.de** | IPs with a history of SSH/FTP/SMTP brute-force or scanning | 12 h |
| **Emerging Threats** (Proofpoint) | Consolidated botnet and C2 IP blocklist, CIDR-aware | 24 h |
| **AlienVault OTX** | Community threat pulses: IPs, domains, URLs *(free API key required)* | 30 min |

### Observable extraction from PCAP
- **IPs** — from IPv4 and IPv6 headers (source and destination)
- **Domains** — from DNS query names (DNSQR layer)
- **URLs** — reconstructed from HTTP payloads (`Host:` + request line)
- **Ports** — flagged against a known-malicious port list

### Local disk cache with TTL management
Feeds are downloaded once and stored under `~/.cache/pcap2api/`. Each feed's recommended refresh interval is honoured automatically. Subsequent runs reuse the cache; use `--refresh-feeds` to force an immediate re-download.

### Optional remote API backends
For deeper enrichment when API keys are available:

| Backend | Checks |
|---|---|
| **AbuseIPDB** | IP reputation with configurable confidence threshold |
| **VirusTotal** | IPs, domains, and URLs across 70+ security engines |
| **Shodan** | Open ports, dangerous host tags, and infrastructure context |
| **IntelMQ REST API** | Query a live IntelMQ event store directly |

### Local heuristics (no network required)
- DGA-like domain detection (long random labels, cheap TLDs such as `.xyz`, `.tk`, `.ml`)
- Suspicious port flagging (4444, 1337, 31337, 9050, etc.)

### Output formats
- **Rich terminal table** with colour-coded severity (high / medium / low)
- **JSON** — full structured report with metadata
- **CSV** — matches only, ready for spreadsheet or SIEM import
- **Exit code 1** if any threats are found, 0 if clean — suitable for CI/CD pipelines

---

## Installation

### Requirements

- Python 3.10 or later
- `pip` (comes with Python)
- `libpcap` development headers (needed by Scapy)

### Ubuntu / Debian

```bash
sudo apt update
sudo apt install -y python3 python3-pip libpcap-dev
pip3 install scapy requests rich
```

### Fedora / RHEL / CentOS Stream

```bash
sudo dnf install -y python3 python3-pip libpcap-devel
pip3 install scapy requests rich
```

### Arch Linux / Manjaro

```bash
sudo pacman -Sy python python-pip libpcap
pip install scapy requests rich
```

### Get the script

```bash
curl -O https://raw.githubusercontent.com/guilhermegui08/pcap2api/refs/heads/main/pcap2api.py
chmod +x pcap2api.py
```

Or clone the repository:

```bash
git clone https://github.com/guilhermegui08/pcap2api
cd pcap2api
pip3 install -r requirements.txt
```

> **Note on permissions:** Reading PCAP files captured on a live interface may require `sudo` or membership in the `pcap` group, depending on your distribution.

---

## Usage

### Basic — feeds only, no keys needed

```bash
python pcap2api.py capture.pcap
```

### Multiple files

```bash
python pcap2api.py morning.pcap afternoon.cap night.pcapng
```

### Force a fresh feed download (ignore cache)

```bash
python pcap2api.py capture.pcap --refresh-feeds
```

### Add AlienVault OTX (free account at otx.alienvault.com)

```bash
python pcap2api.py capture.pcap --otx-key YOUR_OTX_KEY
```

### Add commercial API backends

```bash
python pcap2api.py capture.pcap \
    --abuseipdb-key YOUR_AIPDB_KEY \
    --virustotal-key YOUR_VT_KEY \
    --shodan-key YOUR_SHODAN_KEY
```

### Export results

```bash
python pcap2api.py capture.pcap \
    --output-json report.json \
    --output-csv  report.csv
```

### Full example — all feeds + APIs + exports

```bash
python pcap2api.py a.pcap b.cap \
    --otx-key       OTX_KEY   \
    --abuseipdb-key AIPDB_KEY \
    --virustotal-key VT_KEY   \
    --output-json report.json \
    --output-csv  report.csv  \
    --verbose
```

### CI/CD — exit non-zero if threats found

```bash
python pcap2api.py capture.pcap --quiet
echo "Exit code: $?"   # 0 = clean, 1 = threats detected
```

### Disable specific feeds you don't need

```bash
python pcap2api.py capture.pcap \
    --no-blocklist-de \
    --no-emerging-threats
```

### Use a custom cache directory

```bash
python pcap2api.py capture.pcap --cache-dir /var/cache/pcap-intel
```

---

## Environment variables

All API keys can be set as environment variables instead of passing them on the command line:

| Variable | Backend |
|---|---|
| `OTX_KEY` | AlienVault OTX |
| `PHISHTANK_KEY` | PhishTank (optional, raises rate limit) |
| `ABUSEIPDB_KEY` | AbuseIPDB |
| `VIRUSTOTAL_KEY` | VirusTotal |
| `SHODAN_KEY` | Shodan |

```bash
export ABUSEIPDB_KEY=your_key
python pcap2api.py capture.pcap
```

---

## Design notes

**Why not just use IntelMQ directly?**
IntelMQ is a full pipeline platform requiring Redis, multiple processes, and configuration files. This tool is aimed at analysts who want quick, ad-hoc PCAP analysis without standing up infrastructure.

**Feed selection rationale**
The seven feeds were chosen to cover the main threat categories without overlap: malware distribution (URLhaus), active botnets/C2 (Feodo Tracker, Bambenek), phishing (PhishTank), opportunistic attackers (Blocklist.de), broad coverage (Emerging Threats), and community intelligence (OTX).

**Cache behaviour**
Each feed is cached as a JSON file on disk. The TTL is set conservatively to match each provider's recommended update frequency and avoid hammering volunteer-operated services like Blocklist.de (12 h) and Emerging Threats (24 h).

**Classification taxonomy**
All matches are tagged using the [IntelMQ Data Harmonisation](https://docs.intelmq.org/latest/dev/data-format/) / [RSIT](https://github.com/enisaeu/Reference-Security-Incident-Taxonomy-Task-Force/) ontology (`classification.type` and `classification.taxonomy`), making output compatible with IntelMQ event stores and MISP.

**Exit codes**

| Code | Meaning |
|---|---|
| `0` | No threats detected |
| `1` | One or more threat matches found |
| `2` | Argument or file error |

---

## Full option reference

```
usage: pcap2api [-h] [--version]
                           [--no-urlhaus] [--no-feodo] [--no-phishtank]
                           [--no-bambenek] [--no-blocklist-de]
                           [--no-emerging-threats]
                           [--otx-key KEY] [--phishtank-key KEY]
                           [--refresh-feeds] [--cache-dir DIR]
                           [--abuseipdb-key KEY] [--abuseipdb-min-score N]
                           [--virustotal-key KEY] [--virustotal-min-detections N]
                           [--shodan-key KEY]
                           [--intelmq-url URL] [--intelmq-user USER]
                           [--intelmq-pass PASS]
                           [--no-heuristics]
                           [--include-private] [--kinds KIND [KIND ...]]
                           [--output-json FILE] [--output-csv FILE]
                           [--rate-limit SECS]
                           [-v] [-q]
                           FILE.pcap [FILE.pcap ...]
```

---

## License

GPLV3 — see [LICENSE](LICENSE).

## Acknowledgements

- [IntelMQ](https://github.com/certtools/intelmq) — for the data harmonisation ontology and feed architecture that inspired this tool
- [Abuse.ch](https://abuse.ch) — URLhaus, Feodo Tracker, MalwareBazaar
- [PhishTank](https://www.phishtank.com)
- [Bambenek Consulting](https://osint.bambenekconsulting.com)
- [Blocklist.de](https://www.blocklist.de)
- [Proofpoint Emerging Threats](https://rules.emergingthreats.net)
- [AlienVault OTX](https://otx.alienvault.com)

## Note

This tool was built with Claude AI (Sonnet 4.6).
