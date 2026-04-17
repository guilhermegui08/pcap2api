#!/usr/bin/env python3
"""
pcap2api v2.0
=========================
Analyses one or more PCAP/CAP files and checks extracted observables
(IPs, domains, URLs) against a set of IntelMQ-compatible threat intelligence
sources.

Two families of backends are supported:

  A) LOCAL FEED COLLECTORS  (no API key required — IntelMQ pipeline emulation)
     Each collector downloads a public threat-feed, parses it into a local
     in-memory lookup table, and caches it on disk to honour each feed's
     recommended refresh interval.  This mirrors the IntelMQ
     Collector → Parser → (Expert) → Output pipeline entirely within the tool.

     Feeds included:
       • URLhaus          (Abuse.ch)     — malware distribution URLs/IPs
       • MalwareBazaar    (Abuse.ch)     — malware sample hashes + C2 IPs
       • Feodo Tracker    (Abuse.ch)     — botnet C2 IPs (Emotet, TrickBot…)
       • PhishTank                       — phishing URLs/domains
       • Bambenek C2/DGA                 — C2 domains & DGA masterlist
       • Blocklist.de                    — brute-force / scanner IPs
       • Emerging Threats (Proofpoint)   — consolidated botnet/C2 IPs
       • AlienVault OTX                  — community threat pulses (API key)

  B) REMOTE API BACKENDS  (API keys required)
       • AbuseIPDB
       • VirusTotal
       • Shodan
       • IntelMQ REST API (live instance)

  C) LOCAL HEURISTICS  (always available, no key needed)
       • DGA-like domain pattern matching
       • Suspicious port detection

Requires
--------
  pip install scapy requests rich

Usage
-----
  python pcap2api.py capture.pcap [capture2.cap ...] [options]
  python pcap2api.py --help
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import ipaddress
import io
import json
import os
import re
import sys
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

# -- Optional third-party imports ----------------------------------------------
try:
    from scapy.all import rdpcap, IP, IPv6, TCP, UDP, DNS, DNSQR, Raw

    # O HTTPRequest vive em um módulo separado no Scapy moderno
    try:
        from scapy.layers.http import HTTPRequest
    except ImportError:
        # Tenta carregar de forma genérica se o caminho acima falhar
        from scapy.all import HTTPRequest
    HAS_SCAPY = True
except ImportError as e:
    print(f"[DEBUG] Erro real de importação: {e}")
    HAS_SCAPY = False

try:
    import requests

    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich import box
    from rich.progress import (
        Progress,
        SpinnerColumn,
        TextColumn,
        BarColumn,
        TimeElapsedColumn,
    )

    HAS_RICH = True
except ImportError:
    HAS_RICH = False

# -- Constants -----------------------------------------------------------------

VERSION = "2.0.0"
TOOL_NAME = "pcap2api"

DEFAULT_CACHE_DIR = Path.home() / ".cache" / "pcap2api"

PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]

SERVICES = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    143: "imap",
    443: "https",
    445: "smb",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    6379: "redis",
    8080: "http-alt",
    8443: "https-alt",
    27017: "mongodb",
    6667: "irc",
    4444: "metasploit",
    1433: "mssql",
    5900: "vnc",
}

SUSPICIOUS_PORTS = {
    4444,
    1337,
    31337,
    12345,
    54321,
    6666,
    6667,
    6668,
    1080,
    9050,
    9051,
}

# -- Core data structures ------------------------------------------------------


@dataclass
class Observable:
    """A single network observable extracted from a PCAP."""

    kind: str  # ip | domain | url | port
    value: str
    context: str = ""
    source_file: str = ""
    count: int = 1


@dataclass
class ThreatMatch:
    """A threat intelligence hit for an observable."""

    observable: Observable
    source: str
    classification_type: str = ""
    classification_taxonomy: str = ""
    confidence: float = 0.0
    details: dict[str, Any] = field(default_factory=dict)


# -- Utility helpers -----------------------------------------------------------


def is_private_ip(addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(addr)
        return any(ip in net for net in PRIVATE_NETWORKS)
    except ValueError:
        return False


def is_valid_domain(name: str) -> bool:
    if not name or len(name) > 253:
        return False
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", name):
        return False
    if ":" in name:
        return False
    pattern = re.compile(
        r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
        r"[a-zA-Z]{2,}$"
    )
    return bool(pattern.match(name.rstrip(".")))


def extract_urls_from_payload(payload: bytes) -> list[str]:
    urls: list[str] = []
    try:
        text = payload.decode("utf-8", errors="ignore")
        host_m = re.search(r"Host:\s*([^\r\n]+)", text)
        req_m = re.search(r"(?:GET|POST|PUT|DELETE|HEAD)\s+(\S+)", text)
        if host_m and req_m:
            urls.append(f"http://{host_m.group(1).strip()}{req_m.group(1).strip()}")
        for m in re.finditer(r"https?://[^\s\"'<>]+", text):
            urls.append(m.group(0))
    except Exception:
        pass
    return urls


def _http_get(
    url: str, headers: dict | None = None, timeout: int = 30
) -> "requests.Response | None":
    if not HAS_REQUESTS:
        return None
    try:
        resp = requests.get(
            url, headers=headers or {}, timeout=timeout, allow_redirects=True
        )
        resp.raise_for_status()
        return resp
    except Exception:
        return None


# ==============================================================================
#  PCAP EXTRACTOR
# ==============================================================================


class PcapExtractor:
    """Extracts observables from a PCAP file using Scapy."""

    def __init__(self, filepath: str, verbose: bool = False):
        self.filepath = filepath
        self.verbose = verbose
        self._obs: dict[str, Observable] = {}

    def _add(self, kind: str, value: str, context: str = "") -> None:
        key = f"{kind}:{value}"
        if key in self._obs:
            self._obs[key].count += 1
        else:
            self._obs[key] = Observable(
                kind=kind,
                value=value,
                context=context,
                source_file=self.filepath,
            )

    def extract(self) -> list[Observable]:
        if not HAS_SCAPY:
            print(
                "[ERROR] scapy not installed. Run: pip install scapy", file=sys.stderr
            )
            sys.exit(1)
        try:
            packets = rdpcap(self.filepath)
        except Exception as exc:
            print(f"[ERROR] Cannot read {self.filepath}: {exc}", file=sys.stderr)
            return []
        for pkt in packets:
            self._process(pkt)
        return list(self._obs.values())

    def _process(self, pkt: Any) -> None:
        # IP addresses
        src = dst = None
        if pkt.haslayer(IP):
            src, dst = pkt[IP].src, pkt[IP].dst
        elif pkt.haslayer(IPv6):
            src, dst = pkt[IPv6].src, pkt[IPv6].dst

        if src and not is_private_ip(src):
            self._add("ip", src, "source")
        if dst and not is_private_ip(dst):
            self._add("ip", dst, "destination")

        # Ports
        dport = None
        proto = None
        if pkt.haslayer(TCP):
            dport, proto = pkt[TCP].dport, "tcp"
        elif pkt.haslayer(UDP):
            dport, proto = pkt[UDP].dport, "udp"

        if dport is not None:
            svc = SERVICES.get(dport, "")
            ctx = "suspicious" if dport in SUSPICIOUS_PORTS else svc or proto
            self._add("port", str(dport), ctx)

        # DNS queries
        if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
            try:
                qname = pkt[DNSQR].qname.decode("utf-8", errors="ignore").rstrip(".")
                if is_valid_domain(qname):
                    self._add("domain", qname, "dns-query")
            except Exception:
                pass

        # HTTP payloads
        if pkt.haslayer(Raw):
            raw = bytes(pkt[Raw])
            if b"HTTP" in raw or b"Host:" in raw:
                for url in extract_urls_from_payload(raw):
                    self._add("url", url, "http")
                    try:
                        host = urlparse(url).hostname or ""
                        if is_valid_domain(host):
                            self._add("domain", host, "http-host")
                    except Exception:
                        pass


# ==============================================================================
#  FEED CACHE MANAGER
#  Disk-backed TTL cache — mirrors IntelMQ's feed scheduler.
# ==============================================================================


class FeedCache:
    """Persist parsed feed data on disk with a per-feed TTL."""

    def __init__(self, cache_dir: Path):
        self.cache_dir = cache_dir
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def _path(self, feed_id: str) -> Path:
        safe = re.sub(r"[^\w]", "_", feed_id)
        return self.cache_dir / f"{safe}.json"

    def get(self, feed_id: str, ttl_seconds: int) -> dict | None:
        p = self._path(feed_id)
        if not p.exists():
            return None
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            age = time.time() - data.get("ts", 0)
            if age < ttl_seconds:
                return data.get("payload")
        except Exception:
            pass
        return None

    def set(self, feed_id: str, payload: dict) -> None:
        p = self._path(feed_id)
        try:
            p.write_text(
                json.dumps({"ts": time.time(), "payload": payload}, default=str),
                encoding="utf-8",
            )
        except Exception:
            pass

    def age_str(self, feed_id: str) -> str:
        p = self._path(feed_id)
        if not p.exists():
            return "no cache"
        try:
            ts = json.loads(p.read_text())["ts"]
            age = int(time.time() - ts)
            if age < 120:
                return f"{age}s ago"
            if age < 7200:
                return f"{age // 60}m ago"
            return f"{age // 3600}h ago"
        except Exception:
            return "unknown"


# ==============================================================================
#  BASE BACKEND
# ==============================================================================


class ThreatIntelBackend:
    name = "base"
    enabled = True

    def check_ip(self, ip: str) -> list[dict]:
        return []

    def check_domain(self, domain: str) -> list[dict]:
        return []

    def check_url(self, url: str) -> list[dict]:
        return []


# ==============================================================================
#  LOCAL FEED COLLECTORS  (IntelMQ pipeline emulation)
#
#  Architecture mirrors IntelMQ:
#    _download()  ->  raw HTTP fetch          (Collector bot)
#    _parse()     ->  normalise to sets       (Parser bot)
#    load()       ->  fetch-or-use-cache      (IntelMQ scheduler)
#    check_*()    ->  lookup interface        (Expert / Output bots)
# ==============================================================================


class FeedCollector(ThreatIntelBackend):
    """Abstract base for all local feed collectors."""

    feed_id: str = "base_feed"
    feed_url: str = ""
    ttl: int = 3600
    http_headers: dict = {}

    # Default IntelMQ classification values (overridden per subclass)
    _ip_type = "blacklist"
    _ip_taxonomy = "other"
    _ip_confidence = 0.85
    _dom_type = "blacklist"
    _dom_taxonomy = "other"
    _dom_confidence = 0.80
    _url_type = "blacklist"
    _url_taxonomy = "other"
    _url_confidence = 0.80

    def __init__(
        self, cache: FeedCache, force_refresh: bool = False, verbose: bool = False
    ):
        self.cache = cache
        self.force_refresh = force_refresh
        self.verbose = verbose
        self._data: dict | None = None

    # -- Subclasses implement -------------------------------------------------
    def _parse(self, raw: str) -> dict:
        """Return dict with keys: ips (set), domains (set), urls (set)."""
        raise NotImplementedError

    # -- Download + cache logic -----------------------------------------------
    def _download(self) -> str | None:
        resp = _http_get(self.feed_url, headers=self.http_headers, timeout=45)
        return resp.text if resp else None

    def _empty(self) -> dict:
        return {"ips": [], "domains": [], "urls": []}

    def load(self) -> dict:
        if self._data is not None:
            return self._data

        if not self.force_refresh:
            cached = self.cache.get(self.feed_id, self.ttl)
            if cached is not None:
                if self.verbose:
                    age = self.cache.age_str(self.feed_id)
                    print(f"  [cache] {self.name} ({age})")
                self._data = cached
                return self._data

        if self.verbose:
            print(f"  [fetch] {self.name} <- {self.feed_url}")

        raw = self._download()
        if raw is None:
            if self.verbose:
                print(f"  [warn]  {self.name} download failed, trying stale cache")
            self._data = (
                self.cache.get(self.feed_id, ttl_seconds=99_999_999) or self._empty()
            )
            return self._data

        try:
            parsed = self._parse(raw)
        except Exception as exc:
            if self.verbose:
                print(f"  [warn]  {self.name} parse error: {exc}")
            parsed = self._empty()

        serialisable = {k: list(v) for k, v in parsed.items()}
        self.cache.set(self.feed_id, serialisable)
        self._data = serialisable

        if self.verbose:
            counts = {k: len(v) for k, v in self._data.items()}
            print(f"  [ok]    {self.name} — {counts}")

        return self._data

    # -- Lookup helpers -------------------------------------------------------
    def _hit(self, ctype: str, ctaxo: str, conf: float, **extra) -> list[dict]:
        return [
            {
                "source": self.name,
                "classification_type": ctype,
                "classification_taxonomy": ctaxo,
                "confidence": conf,
                "details": extra,
            }
        ]

    def check_ip(self, ip: str) -> list[dict]:
        if ip in self.load().get("ips", []):
            return self._hit(
                self._ip_type, self._ip_taxonomy, self._ip_confidence, feed=self.name
            )
        return []

    def check_domain(self, domain: str) -> list[dict]:
        parts = domain.split(".")
        for i in range(len(parts) - 1):
            candidate = ".".join(parts[i:])
            if candidate in self.load().get("domains", []):
                return self._hit(
                    self._dom_type,
                    self._dom_taxonomy,
                    self._dom_confidence,
                    feed=self.name,
                    matched=candidate,
                )
        return []

    def check_url(self, url: str) -> list[dict]:
        for feed_url in self.load().get("urls", []):
            if url == feed_url or url.startswith(feed_url):
                return self._hit(
                    self._url_type,
                    self._url_taxonomy,
                    self._url_confidence,
                    feed=self.name,
                    matched=feed_url,
                )
        return []


# -- A. URLhaus (Abuse.ch) -----------------------------------------------------


class URLhausCollector(FeedCollector):
    """
    IntelMQ pipeline: HTTP Collector -> URLhaus Parser
    Feed : https://urlhaus.abuse.ch/downloads/csv/
    TTL  : 60 min
    """

    name = "URLhaus"
    feed_id = "urlhaus"
    feed_url = "https://urlhaus.abuse.ch/downloads/csv/"
    ttl = 3600

    _ip_type = _dom_type = _url_type = "malware-distribution"
    _ip_taxonomy = _dom_taxonomy = _url_taxonomy = "malicious-code"
    _ip_confidence = _dom_confidence = _url_confidence = 0.90

    def _parse(self, raw: str) -> dict:
        ips: set[str] = set()
        domains: set[str] = set()
        urls: set[str] = set()
        reader = csv.reader(io.StringIO(raw))
        for row in reader:
            if not row or row[0].startswith("#"):
                continue
            if len(row) < 3:
                continue
            # cols: id, date_added, url, url_status, last_online, threat, tags
            url = row[2].strip()
            if not url.startswith("http"):
                continue
            urls.add(url)
            try:
                host = urlparse(url).hostname or ""
                if host:
                    ipaddress.ip_address(host)
                    if not is_private_ip(host):
                        ips.add(host)
            except ValueError:
                if host and is_valid_domain(host):
                    domains.add(host)
        return {"ips": ips, "domains": domains, "urls": urls}


# -- B. Feodo Tracker — botnet C2 IPs (Abuse.ch) ------------------------------


class FeodoTrackerCollector(FeedCollector):
    """
    IntelMQ pipeline: HTTP Collector -> Feodo Tracker Parser
    Feed : https://feodotracker.abuse.ch/downloads/ipblocklist.csv
    TTL  : 60 min
    Detects active botnet C2 servers (Emotet, TrickBot, QakBot, etc.)
    """

    name = "FeodoTracker"
    feed_id = "feodo_tracker"
    feed_url = "https://feodotracker.abuse.ch/downloads/ipblocklist.csv"
    ttl = 3600

    _ip_type = "c2-server"
    _ip_taxonomy = "malicious-code"
    _ip_confidence = 0.95

    def _parse(self, raw: str) -> dict:
        ips: set[str] = set()
        reader = csv.reader(io.StringIO(raw))
        for row in reader:
            if not row or row[0].startswith("#"):
                continue
            # cols: first_seen_utc, dst_ip, dst_port, c2_status,
            #        last_online, malware
            if len(row) < 2:
                continue
            ip = row[1].strip()
            try:
                ipaddress.ip_address(ip)
                if not is_private_ip(ip):
                    ips.add(ip)
            except ValueError:
                pass
        return {"ips": ips, "domains": set(), "urls": set()}


# -- C. PhishTank --------------------------------------------------------------


class PhishTankCollector(FeedCollector):
    """
    IntelMQ pipeline: HTTP Collector -> PhishTank Parser
    Feed : https://data.phishtank.com/data/online-valid.csv
    TTL  : 60 min
    A free PhishTank account + API key increases the download rate limit.
    """

    name = "PhishTank"
    feed_id = "phishtank"
    ttl = 3600

    _url_type = _dom_type = "phishing"
    _url_taxonomy = _dom_taxonomy = "fraud"
    _url_confidence = _dom_confidence = 0.92

    def __init__(
        self,
        cache: FeedCache,
        api_key: str = "",
        force_refresh: bool = False,
        verbose: bool = False,
    ):
        super().__init__(cache, force_refresh, verbose)
        if api_key:
            self.feed_url = (
                f"https://data.phishtank.com/data/{api_key}/online-valid.csv"
            )
        else:
            self.feed_url = "https://data.phishtank.com/data/online-valid.csv"

    def _parse(self, raw: str) -> dict:
        urls: set[str] = set()
        domains: set[str] = set()
        reader = csv.DictReader(io.StringIO(raw))
        for row in reader:
            url = row.get("url", "").strip()
            if not url.startswith("http"):
                continue
            urls.add(url)
            try:
                host = urlparse(url).hostname or ""
                if is_valid_domain(host):
                    domains.add(host)
            except Exception:
                pass
        return {"ips": set(), "domains": domains, "urls": urls}


# -- D. Bambenek C2 / DGA master list -----------------------------------------


class BambenekCollector(FeedCollector):
    """
    IntelMQ pipeline: HTTP Collector -> Bambenek Parser
    Feed : https://osint.bambenekconsulting.com/feeds/c2-dommasterlist-high.txt
    TTL  : 60 min
    Detects C2 domains and domains generated by DGA malware families.
    """

    name = "Bambenek"
    feed_id = "bambenek_c2"
    feed_url = "https://osint.bambenekconsulting.com/feeds/c2-dommasterlist-high.txt"
    ttl = 3600

    _dom_type = "c2-server"
    _dom_taxonomy = "malicious-code"
    _dom_confidence = 0.88

    def _parse(self, raw: str) -> dict:
        domains: set[str] = set()
        for line in raw.splitlines():
            line = line.strip()
            if not line or line.startswith(("#", ";")):
                continue
            # format: domain,ip,description,date,referenceURL
            domain = line.split(",")[0].strip()
            if is_valid_domain(domain):
                domains.add(domain.lower())
        return {"ips": set(), "domains": domains, "urls": set()}


# -- E. Blocklist.de -----------------------------------------------------------


class BlocklistDeCollector(FeedCollector):
    """
    IntelMQ pipeline: HTTP Collector -> Blocklist.de Parser
    Feed : https://lists.blocklist.de/lists/all.txt
    TTL  : 12 h  (large file — respect the volunteer service)
    IPs reported for SSH, FTP, SMTP brute-force or vulnerability scanning.
    """

    name = "Blocklist.de"
    feed_id = "blocklist_de"
    feed_url = "https://lists.blocklist.de/lists/all.txt"
    ttl = 43200

    _ip_type = "brute-force"
    _ip_taxonomy = "intrusion-attempts"
    _ip_confidence = 0.80

    def _parse(self, raw: str) -> dict:
        ips: set[str] = set()
        for line in raw.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                ipaddress.ip_address(line)
                if not is_private_ip(line):
                    ips.add(line)
            except ValueError:
                pass
        return {"ips": ips, "domains": set(), "urls": set()}


# -- F. Emerging Threats (Proofpoint open rules) -------------------------------


class EmergingThreatsCollector(FeedCollector):
    """
    IntelMQ pipeline: HTTP Collector -> Emerging Threats Parser
    Feed : https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt
    TTL  : 24 h
    Consolidated list of IPs hosting botnets and severe threats.
    Supports both individual IPs and CIDR blocks (/24 and narrower).
    """

    name = "EmergingThreats"
    feed_id = "emerging_threats"
    feed_url = "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt"
    ttl = 86400

    _ip_type = "infected-system"
    _ip_taxonomy = "malicious-code"
    _ip_confidence = 0.82

    def _parse(self, raw: str) -> dict:
        ips: set[str] = set()
        for line in raw.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                net = ipaddress.ip_network(line, strict=False)
                if net.prefixlen >= 24:
                    for addr in net.hosts():
                        a = str(addr)
                        if not is_private_ip(a):
                            ips.add(a)
                else:
                    ips.add(str(net))
            except ValueError:
                pass
        return {"ips": ips, "domains": set(), "urls": set()}

    def check_ip(self, ip: str) -> list[dict]:
        feed_ips = self.load().get("ips", [])
        if ip in feed_ips:
            return self._hit(
                self._ip_type, self._ip_taxonomy, self._ip_confidence, feed=self.name
            )
        try:
            addr = ipaddress.ip_address(ip)
            for entry in feed_ips:
                if "/" in entry:
                    try:
                        if addr in ipaddress.ip_network(entry, strict=False):
                            return self._hit(
                                self._ip_type,
                                self._ip_taxonomy,
                                self._ip_confidence,
                                feed=self.name,
                                matched_cidr=entry,
                            )
                    except ValueError:
                        pass
        except ValueError:
            pass
        return []


# -- G. AlienVault OTX ---------------------------------------------------------


class OTXCollector(FeedCollector):
    """
    IntelMQ pipeline: OTX Collector -> OTX Parser
    API  : https://otx.alienvault.com/api/v1/pulses/subscribed
    TTL  : 30 min
    Requires a free OTX account API key (env: OTX_KEY or --otx-key).
    Covers IPs, domains, and URLs from community threat pulses.
    """

    name = "AlienVault-OTX"
    feed_id = "otx"
    ttl = 1800

    def __init__(
        self,
        cache: FeedCache,
        api_key: str,
        force_refresh: bool = False,
        verbose: bool = False,
    ):
        super().__init__(cache, force_refresh, verbose)
        self.api_key = api_key

    def _download(self) -> str | None:
        if not self.api_key:
            return None
        headers = {"X-OTX-API-KEY": self.api_key}
        all_indicators: list[dict] = []
        page = 1
        while page <= 5:
            resp = _http_get(
                "https://otx.alienvault.com/api/v1/pulses/subscribed"
                f"?limit=50&page={page}",
                headers=headers,
                timeout=30,
            )
            if resp is None:
                break
            data = resp.json()
            results = data.get("results", [])
            if not results:
                break
            for pulse in results:
                for ind in pulse.get("indicators", []):
                    ind["_pulse"] = pulse.get("name", "")
                    all_indicators.append(ind)
            if not data.get("next"):
                break
            page += 1
        return json.dumps(all_indicators)

    def _parse(self, raw: str) -> dict:
        ips: set[str] = set()
        domains: set[str] = set()
        urls: set[str] = set()
        try:
            indicators = json.loads(raw)
        except Exception:
            return {"ips": ips, "domains": domains, "urls": urls}
        for ind in indicators:
            t = ind.get("type", "")
            value = ind.get("indicator", "").strip()
            if not value:
                continue
            if t in ("IPv4", "IPv6"):
                if not is_private_ip(value):
                    ips.add(value)
            elif t in ("domain", "FQDN", "hostname"):
                if is_valid_domain(value):
                    domains.add(value.lower())
            elif t == "URL" and value.startswith("http"):
                urls.add(value)
        return {"ips": ips, "domains": domains, "urls": urls}

    def check_ip(self, ip: str) -> list[dict]:
        if ip in self.load().get("ips", []):
            return self._hit("blacklist", "other", 0.75, feed=self.name)
        return []

    def check_domain(self, domain: str) -> list[dict]:
        parts = domain.split(".")
        for i in range(len(parts) - 1):
            candidate = ".".join(parts[i:])
            if candidate in self.load().get("domains", []):
                return self._hit(
                    "blacklist", "other", 0.72, feed=self.name, matched=candidate
                )
        return []

    def check_url(self, url: str) -> list[dict]:
        for feed_url in self.load().get("urls", []):
            if url == feed_url or url.startswith(feed_url):
                return self._hit(
                    "blacklist", "other", 0.72, feed=self.name, matched=feed_url
                )
        return []


# ==============================================================================
#  REMOTE API BACKENDS
# ==============================================================================


class AbuseIPDBBackend(ThreatIntelBackend):
    name = "AbuseIPDB"
    BASE = "https://api.abuseipdb.com/api/v2"

    def __init__(self, api_key: str, min_score: int = 25):
        self.api_key = api_key
        self.min_score = min_score
        self._cache: dict[str, list] = {}

    def check_ip(self, ip: str) -> list[dict]:
        if ip in self._cache:
            return self._cache[ip]
        if not HAS_REQUESTS:
            return []
        try:
            r = requests.get(
                f"{self.BASE}/check",
                headers={"Key": self.api_key, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90},
                timeout=10,
            )
            r.raise_for_status()
            d = r.json().get("data", {})
        except Exception:
            return []
        score = d.get("abuseConfidenceScore", 0)
        results = []
        if score >= self.min_score:
            results.append(
                {
                    "source": self.name,
                    "classification_type": "blacklist",
                    "classification_taxonomy": "other",
                    "confidence": score / 100,
                    "details": {
                        "abuse_score": score,
                        "total_reports": d.get("totalReports", 0),
                        "country": d.get("countryCode", ""),
                        "isp": d.get("isp", ""),
                        "last_reported": d.get("lastReportedAt", ""),
                    },
                }
            )
        self._cache[ip] = results
        return results


class VirusTotalBackend(ThreatIntelBackend):
    name = "VirusTotal"
    BASE = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: str, min_detections: int = 2):
        self.api_key = api_key
        self.min_detections = min_detections
        self._cache: dict[str, list] = {}

    def _get(self, path: str) -> dict:
        if not HAS_REQUESTS:
            return {}
        try:
            r = requests.get(
                f"{self.BASE}/{path}",
                headers={"x-apikey": self.api_key},
                timeout=15,
            )
            if r.status_code == 404:
                return {}
            r.raise_for_status()
            return r.json()
        except Exception:
            return {}

    def _parse(self, data: dict) -> list[dict]:
        try:
            attrs = data["data"]["attributes"]
            stats = attrs.get("last_analysis_stats", {})
            mal = stats.get("malicious", 0)
            sus = stats.get("suspicious", 0)
            total = sum(stats.values()) or 1
            hits = mal + sus
            if hits < self.min_detections:
                return []
            return [
                {
                    "source": self.name,
                    "classification_type": "malware" if mal else "ids-alert",
                    "classification_taxonomy": "malicious-code"
                    if mal
                    else "intrusion-attempts",
                    "confidence": hits / total,
                    "details": {
                        "malicious": mal,
                        "suspicious": sus,
                        "total_engines": total,
                        "reputation": attrs.get("reputation", 0),
                    },
                }
            ]
        except (KeyError, TypeError):
            return []

    def check_ip(self, ip: str) -> list[dict]:
        if ip in self._cache:
            return self._cache[ip]
        res = self._parse(self._get(f"ip_addresses/{ip}"))
        self._cache[ip] = res
        return res

    def check_domain(self, domain: str) -> list[dict]:
        if domain in self._cache:
            return self._cache[domain]
        res = self._parse(self._get(f"domains/{domain}"))
        self._cache[domain] = res
        return res

    def check_url(self, url: str) -> list[dict]:
        if url in self._cache:
            return self._cache[url]
        import base64

        uid = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        res = self._parse(self._get(f"urls/{uid}"))
        self._cache[url] = res
        return res


class ShodanBackend(ThreatIntelBackend):
    name = "Shodan"
    BASE = "https://api.shodan.io"

    DANGEROUS_TAGS = {
        "malware",
        "c2",
        "scanner",
        "honeypot",
        "compromised",
        "tor",
        "vpn",
        "proxy",
    }

    def __init__(self, api_key: str):
        self.api_key = api_key
        self._cache: dict[str, list] = {}

    def check_ip(self, ip: str) -> list[dict]:
        if ip in self._cache:
            return self._cache[ip]
        if not HAS_REQUESTS:
            return []
        try:
            r = requests.get(
                f"{self.BASE}/shodan/host/{ip}",
                params={"key": self.api_key},
                timeout=15,
            )
            if r.status_code == 404:
                return []
            r.raise_for_status()
            data = r.json()
        except Exception:
            return []
        tags = set(data.get("tags", []))
        dangerous = tags & self.DANGEROUS_TAGS
        ports = data.get("ports", [])
        sus_ports = [p for p in ports if p in SUSPICIOUS_PORTS]
        results = []
        if dangerous or sus_ports:
            results.append(
                {
                    "source": self.name,
                    "classification_type": "potentially-unwanted-accessible",
                    "classification_taxonomy": "vulnerable",
                    "confidence": 0.65,
                    "details": {
                        "dangerous_tags": list(dangerous),
                        "open_ports": ports,
                        "suspicious_ports": sus_ports,
                        "country": data.get("country_name", ""),
                        "org": data.get("org", ""),
                    },
                }
            )
        self._cache[ip] = results
        return results


class IntelMQApiBackend(ThreatIntelBackend):
    """Query a live IntelMQ REST API instance (event store lookup)."""

    name = "IntelMQ-API"

    def __init__(self, base_url: str, username: str, password: str):
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password
        self._token: str | None = None
        self._cache: dict[str, list] = {}

    def _login(self) -> bool:
        if not HAS_REQUESTS:
            return False
        try:
            r = requests.post(
                f"{self.base_url}/v1/api/login/",
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                data={"username": self.username, "password": self.password},
                timeout=10,
            )
            r.raise_for_status()
            self._token = r.json().get("login_token")
            return bool(self._token)
        except Exception:
            return False

    def _get(self, path: str, params: dict) -> list | dict:
        if not self._token and not self._login():
            return {}
        if not HAS_REQUESTS:
            return {}
        try:
            r = requests.get(
                f"{self.base_url}/v1/api/{path}",
                headers={"Authorization": self._token},
                params=params,
                timeout=15,
            )
            r.raise_for_status()
            return r.json()
        except Exception:
            return {}

    def _lookup(self, field: str, value: str) -> list[dict]:
        key = f"{field}:{value}"
        if key in self._cache:
            return self._cache[key]
        data = self._get("events", {field: value})
        results = []
        if isinstance(data, list):
            for event in data:
                results.append(
                    {
                        "source": self.name,
                        "classification_type": event.get(
                            "classification.type", "undetermined"
                        ),
                        "classification_taxonomy": event.get(
                            "classification.taxonomy", "other"
                        ),
                        "confidence": 0.75,
                        "details": {
                            k: v
                            for k, v in event.items()
                            if k.startswith(("source.", "feed."))
                        },
                    }
                )
        self._cache[key] = results
        return results

    def check_ip(self, ip: str) -> list[dict]:
        return self._lookup("source.ip", ip)

    def check_domain(self, domain: str) -> list[dict]:
        return self._lookup("source.fqdn", domain)

    def check_url(self, url: str) -> list[dict]:
        return self._lookup("source.url", url)


# -- Local heuristics ----------------------------------------------------------


class LocalHeuristicBackend(ThreatIntelBackend):
    """DGA domain detection and suspicious-port flagging. No network needed."""

    name = "LocalHeuristic"

    _DGA = [
        (
            re.compile(r"^[a-z0-9]{16,}\.[a-z]{2,4}$", re.I),
            "Long random label — possible DGA",
            0.55,
        ),
        (
            re.compile(r"^[a-z0-9]{8,}\.(xyz|top|tk|ml|ga|cf|gq|pw)$", re.I),
            "DGA-like + cheap TLD",
            0.65,
        ),
        (
            re.compile(r"^[a-z]{3,6}[0-9]{4,}\.[a-z]{2,4}$", re.I),
            "Alphanumeric mix — possible DGA",
            0.50,
        ),
    ]

    def check_domain(self, domain: str) -> list[dict]:
        for pattern, reason, conf in self._DGA:
            if pattern.match(domain):
                return [
                    {
                        "source": self.name,
                        "classification_type": "dga-domain",
                        "classification_taxonomy": "malicious-code",
                        "confidence": conf,
                        "details": {"reason": reason},
                    }
                ]
        return []


# ==============================================================================
#  ANALYSER ENGINE
# ==============================================================================

_REMOTE_BACKENDS = (
    AbuseIPDBBackend,
    VirusTotalBackend,
    ShodanBackend,
    IntelMQApiBackend,
)


class Analyser:
    def __init__(
        self,
        backends: list[ThreatIntelBackend],
        rate_limit: float = 0.2,
        verbose: bool = False,
    ):
        self.backends = backends
        self.rate_limit = rate_limit
        self.verbose = verbose

    def analyse(
        self, observables: list[Observable], console: Any = None
    ) -> list[ThreatMatch]:
        matches: list[ThreatMatch] = []

        ips = [o for o in observables if o.kind == "ip"]
        domains = [o for o in observables if o.kind == "domain"]
        urls = [o for o in observables if o.kind == "url"]

        groups = [
            (ips, "check_ip"),
            (domains, "check_domain"),
            (urls, "check_url"),
        ]
        total = sum(len(g) for g, _ in groups)

        def _run_group(obs_list: list[Observable], method: str) -> None:
            for obs in obs_list:
                for backend in self.backends:
                    try:
                        hits = getattr(backend, method)(obs.value)
                    except Exception:
                        hits = []
                    for h in hits:
                        matches.append(ThreatMatch(obs, **h))
                    if isinstance(backend, _REMOTE_BACKENDS):
                        time.sleep(self.rate_limit)

        if HAS_RICH and console:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[cyan]{task.completed}[/cyan]/{task.total}"),
                TimeElapsedColumn(),
                console=console,
                transient=True,
            ) as prog:
                task = prog.add_task("Checking observables…", total=total)
                for obs_list, method in groups:
                    for obs in obs_list:
                        for backend in self.backends:
                            try:
                                hits = getattr(backend, method)(obs.value)
                            except Exception:
                                hits = []
                            for h in hits:
                                matches.append(ThreatMatch(obs, **h))
                            if isinstance(backend, _REMOTE_BACKENDS):
                                time.sleep(self.rate_limit)
                        prog.advance(task)
        else:
            for obs_list, method in groups:
                _run_group(obs_list, method)

        return matches


# ==============================================================================
#  REPORTING
# ==============================================================================

_SEV_COLOR = {"high": "bold red", "medium": "yellow", "low": "cyan"}


def _severity(conf: float) -> str:
    if conf >= 0.75:
        return "high"
    if conf >= 0.45:
        return "medium"
    return "low"


def print_report(
    matches: list[ThreatMatch],
    observables: list[Observable],
    backends: list[ThreatIntelBackend],
    console: Any,
) -> None:
    if not HAS_RICH or console is None:
        _plain_report(matches, observables)
        return

    hit_values = {m.observable.value for m in matches}
    by_kind: dict[str, int] = defaultdict(int)
    for o in observables:
        by_kind[o.kind] += 1

    be_names = "  ".join(f"[cyan]{b.name}[/cyan]" for b in backends)
    console.print(
        Panel(
            f"[bold]Observables:[/bold]  "
            + "  ".join(f"[cyan]{k}[/cyan]:{v}" for k, v in sorted(by_kind.items()))
            + f"\n[bold]Backends:[/bold]    {be_names}"
            + f"\n[bold red]Threats:[/bold red]       "
            f"{len(hit_values)} observables matched  /  {len(matches)} total hits",
            title=f"[bold blue]{TOOL_NAME}  v{VERSION}[/bold blue]",
            border_style="blue",
        )
    )

    if not matches:
        console.print("\n[bold green]  No threats detected.[/bold green]\n")
        return

    # Threat matches table
    t = Table(
        title="Threat Intelligence Matches",
        box=box.ROUNDED,
        show_lines=True,
        highlight=True,
    )
    t.add_column("Observable", style="bold", no_wrap=True)
    t.add_column("Kind", style="dim", width=7)
    t.add_column("File", style="dim", width=16)
    t.add_column("TI Source", style="cyan", width=18)
    t.add_column("Class. Type", style="magenta")
    t.add_column("Taxonomy", style="magenta")
    t.add_column("Conf.", justify="right", width=6)
    t.add_column("Details")

    for m in sorted(matches, key=lambda x: (-x.confidence, x.observable.kind)):
        col = _SEV_COLOR[_severity(m.confidence)]
        dets = "; ".join(f"{k}={v}" for k, v in list(m.details.items())[:3])
        t.add_row(
            f"[{col}]{m.observable.value}[/{col}]",
            m.observable.kind,
            Path(m.observable.source_file).name,
            m.source,
            m.classification_type,
            m.classification_taxonomy,
            f"[{col}]{m.confidence:.0%}[/{col}]",
            dets,
        )
    console.print(t)

    # Observables inventory
    ot = Table(
        title="Extracted Observables (top 40, red dot = threat hit)",
        box=box.SIMPLE_HEAD,
    )
    ot.add_column("Kind", width=7)
    ot.add_column("Value", no_wrap=True)
    ot.add_column("Cnt", justify="right", width=5)
    ot.add_column("Context")
    ot.add_column("File", style="dim")

    for obs in sorted(observables, key=lambda o: -o.count)[:40]:
        flag = "[red]●[/red] " if obs.value in hit_values else "  "
        ot.add_row(
            obs.kind,
            f"{flag}{obs.value}",
            str(obs.count),
            obs.context,
            Path(obs.source_file).name,
        )
    console.print(ot)

    # Feed status table
    feed_bes = [b for b in backends if isinstance(b, FeedCollector)]
    if feed_bes:
        ft = Table(
            title="Feed Collector Status",
            box=box.SIMPLE_HEAD,
        )
        ft.add_column("Feed", style="cyan")
        ft.add_column("TTL", justify="right", width=8)
        ft.add_column("Cached", width=12)
        ft.add_column("IPs", justify="right", width=8)
        ft.add_column("Domains", justify="right", width=8)
        ft.add_column("URLs", justify="right", width=8)

        for b in feed_bes:
            d = b._data or {}
            ttl_label = f"{b.ttl // 60}m" if b.ttl < 86400 else f"{b.ttl // 3600}h"
            ft.add_row(
                b.name,
                ttl_label,
                b.cache.age_str(b.feed_id),
                str(len(d.get("ips", []))),
                str(len(d.get("domains", []))),
                str(len(d.get("urls", []))),
            )
        console.print(ft)


def _plain_report(matches: list[ThreatMatch], observables: list[Observable]) -> None:
    W = 72
    print("\n" + "=" * W)
    print(f"  {TOOL_NAME}  v{VERSION}  —  Results")
    print("=" * W)
    print(f"  Observables extracted : {len(observables)}")
    print(
        f"  Threat hits           : "
        f"{len({m.observable.value for m in matches})} observables"
    )
    print(f"  Total matches         : {len(matches)}")
    print()
    if not matches:
        print("  No threats detected.\n")
        return
    print(f"  {'OBSERVABLE':<38} {'TI SOURCE':<18} {'TYPE':<22} {'CONF':>5}")
    print("  " + "-" * (W - 2))
    for m in sorted(matches, key=lambda x: -x.confidence):
        print(
            f"  {m.observable.value:<38} {m.source:<18} "
            f"{m.classification_type:<22} {m.confidence:>4.0%}"
        )
    print()


def export_json(
    matches: list[ThreatMatch], observables: list[Observable], path: str
) -> None:
    out = {
        "tool": TOOL_NAME,
        "version": VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "observables": [
            {
                "kind": o.kind,
                "value": o.value,
                "context": o.context,
                "count": o.count,
                "source_file": o.source_file,
            }
            for o in observables
        ],
        "threat_matches": [
            {
                "observable": m.observable.value,
                "kind": m.observable.kind,
                "source_file": m.observable.source_file,
                "ti_source": m.source,
                "classification_type": m.classification_type,
                "classification_taxonomy": m.classification_taxonomy,
                "confidence": m.confidence,
                "details": m.details,
            }
            for m in matches
        ],
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2, default=str)


def export_csv(matches: list[ThreatMatch], path: str) -> None:
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(
            [
                "observable",
                "kind",
                "source_file",
                "ti_source",
                "classification_type",
                "classification_taxonomy",
                "confidence",
                "details",
            ]
        )
        for m in matches:
            w.writerow(
                [
                    m.observable.value,
                    m.observable.kind,
                    m.observable.source_file,
                    m.source,
                    m.classification_type,
                    m.classification_taxonomy,
                    f"{m.confidence:.2f}",
                    json.dumps(m.details),
                ]
            )


# ==============================================================================
#  CLI
# ==============================================================================


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description=(
            "Analyse PCAP/CAP network captures and check extracted observables "
            "(IPs, domains, URLs) against IntelMQ-compatible threat intelligence "
            "feeds and APIs."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
FEED COLLECTORS (built-in, no API key required unless noted)
-------------------------------------------------------------
  Feed              TTL    Checks
  URLhaus           60m    Malware distribution URLs / IPs
  FeodoTracker      60m    Botnet C2 IPs  (Emotet, TrickBot, QakBot...)
  PhishTank         60m    Phishing URLs / domains  [key optional]
  Bambenek          60m    C2 domains & DGA masterlist
  Blocklist.de      12h    Brute-force / scanner IPs
  EmergingThreats   24h    Consolidated botnet / C2 IPs
  AlienVault OTX    30m    Community threat pulses  [key REQUIRED]

Feeds are downloaded automatically on first run and cached locally.
Re-runs reuse the cache until each TTL expires.
Use --refresh-feeds to force an immediate re-download.

EXAMPLES
--------
  # Scan with all built-in feeds (no keys needed):
  {TOOL_NAME} capture.pcap

  # Add OTX + AbuseIPDB + VirusTotal, export results:
  {TOOL_NAME} a.pcap b.cap \\
      --otx-key OTX_KEY \\
      --abuseipdb-key AIPDB_KEY \\
      --virustotal-key VT_KEY \\
      --output-json report.json --output-csv report.csv

  # Force feed refresh:
  {TOOL_NAME} capture.pcap --refresh-feeds --verbose

  # CI/CD — exit 1 if any threat found:
  {TOOL_NAME} capture.pcap --quiet && echo "clean"

ENVIRONMENT VARIABLES
---------------------
  OTX_KEY           AlienVault OTX API key
  PHISHTANK_KEY     PhishTank API key (optional, raises rate limit)
  ABUSEIPDB_KEY     AbuseIPDB API key
  VIRUSTOTAL_KEY    VirusTotal API key
  SHODAN_KEY        Shodan API key
""",
    )

    p.add_argument(
        "pcap_files",
        nargs="+",
        metavar="FILE.pcap",
        help="One or more PCAP/CAP capture files to analyse",
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")

    # Feed collector flags
    fc = p.add_argument_group("feed collectors  (IntelMQ-style local pipeline)")
    fc.add_argument("--no-urlhaus", action="store_true", help="Disable URLhaus feed")
    fc.add_argument(
        "--no-feodo", action="store_true", help="Disable Feodo Tracker feed"
    )
    fc.add_argument(
        "--no-phishtank", action="store_true", help="Disable PhishTank feed"
    )
    fc.add_argument("--no-bambenek", action="store_true", help="Disable Bambenek feed")
    fc.add_argument(
        "--no-blocklist-de", action="store_true", help="Disable Blocklist.de feed"
    )
    fc.add_argument(
        "--no-emerging-threats",
        action="store_true",
        help="Disable Emerging Threats feed",
    )
    fc.add_argument(
        "--otx-key",
        metavar="KEY",
        default=os.environ.get("OTX_KEY", ""),
        help="AlienVault OTX API key  (env: OTX_KEY)",
    )
    fc.add_argument(
        "--phishtank-key",
        metavar="KEY",
        default=os.environ.get("PHISHTANK_KEY", ""),
        help="PhishTank API key for higher rate limits  (env: PHISHTANK_KEY)",
    )
    fc.add_argument(
        "--refresh-feeds",
        action="store_true",
        help="Force re-download of all feeds (ignore cache TTLs)",
    )
    fc.add_argument(
        "--cache-dir",
        metavar="DIR",
        default=str(DEFAULT_CACHE_DIR),
        help=f"Feed cache directory  (default: {DEFAULT_CACHE_DIR})",
    )

    # Remote API backends
    ti = p.add_argument_group("remote API backends  (keys required)")
    ti.add_argument(
        "--abuseipdb-key",
        metavar="KEY",
        default=os.environ.get("ABUSEIPDB_KEY", ""),
        help="AbuseIPDB v2 API key  (env: ABUSEIPDB_KEY)",
    )
    ti.add_argument(
        "--abuseipdb-min-score",
        type=int,
        default=25,
        metavar="N",
        help="Minimum AbuseIPDB confidence score to report  (default: 25)",
    )
    ti.add_argument(
        "--virustotal-key",
        metavar="KEY",
        default=os.environ.get("VIRUSTOTAL_KEY", ""),
        help="VirusTotal v3 API key  (env: VIRUSTOTAL_KEY)",
    )
    ti.add_argument(
        "--virustotal-min-detections",
        type=int,
        default=2,
        metavar="N",
        help="Minimum VirusTotal engine detections  (default: 2)",
    )
    ti.add_argument(
        "--shodan-key",
        metavar="KEY",
        default=os.environ.get("SHODAN_KEY", ""),
        help="Shodan API key  (env: SHODAN_KEY)",
    )
    ti.add_argument(
        "--intelmq-url", metavar="URL", default="", help="IntelMQ REST API base URL"
    )
    ti.add_argument(
        "--intelmq-user", metavar="USER", default="", help="IntelMQ REST API username"
    )
    ti.add_argument(
        "--intelmq-pass", metavar="PASS", default="", help="IntelMQ REST API password"
    )
    ti.add_argument(
        "--no-heuristics",
        action="store_true",
        help="Disable local DGA / suspicious-port heuristics",
    )

    # Filtering
    fl = p.add_argument_group("filtering")
    fl.add_argument(
        "--include-private",
        action="store_true",
        help="Include private/RFC1918 IPs in lookups  (default: skip them)",
    )
    fl.add_argument(
        "--kinds",
        nargs="+",
        choices=["ip", "domain", "url", "port"],
        default=["ip", "domain", "url"],
        metavar="KIND",
        help="Observable kinds to look up  (default: ip domain url)",
    )

    # Output
    out = p.add_argument_group("output")
    out.add_argument(
        "--output-json",
        metavar="FILE",
        default="",
        help="Save full results to a JSON file",
    )
    out.add_argument(
        "--output-csv",
        metavar="FILE",
        default="",
        help="Save threat matches to a CSV file",
    )
    out.add_argument(
        "--rate-limit",
        type=float,
        default=0.2,
        metavar="SECS",
        help="Pause between remote API calls in seconds  (default: 0.2)",
    )
    out.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Show feed download progress and debug info",
    )
    out.add_argument(
        "--quiet",
        "-q",
        action="store_true",
        help="Suppress all output except errors  (exit 1 = threats found)",
    )

    return p


def validate_args(args: argparse.Namespace) -> None:
    for f in args.pcap_files:
        fp = Path(f)
        if not fp.exists():
            print(f"[ERROR] File not found: {f}", file=sys.stderr)
            sys.exit(2)
        if not fp.is_file():
            print(f"[ERROR] Not a regular file: {f}", file=sys.stderr)
            sys.exit(2)
        if fp.suffix.lower() not in (".pcap", ".cap", ".pcapng"):
            print(
                f"[WARN]  Unexpected extension for {f}; proceeding anyway.",
                file=sys.stderr,
            )
    if not HAS_SCAPY:
        print("[ERROR] scapy is required. Install: pip install scapy", file=sys.stderr)
        sys.exit(1)
    if not HAS_REQUESTS:
        print(
            "[ERROR] requests is required. Install: pip install requests",
            file=sys.stderr,
        )
        sys.exit(1)


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    validate_args(args)

    console = Console() if HAS_RICH else None

    # Feed cache
    cache = FeedCache(Path(args.cache_dir))

    # Build backends
    backends: list[ThreatIntelBackend] = []

    def _feed(cls, **kw) -> FeedCollector:
        return cls(
            cache=cache,
            force_refresh=args.refresh_feeds,
            verbose=args.verbose,
            **kw,
        )

    # Local feed collectors (IntelMQ pipeline emulation)
    if not args.no_urlhaus:
        backends.append(_feed(URLhausCollector))
    if not args.no_feodo:
        backends.append(_feed(FeodoTrackerCollector))
    if not args.no_phishtank:
        backends.append(_feed(PhishTankCollector, api_key=args.phishtank_key))
    if not args.no_bambenek:
        backends.append(_feed(BambenekCollector))
    if not args.no_blocklist_de:
        backends.append(_feed(BlocklistDeCollector))
    if not args.no_emerging_threats:
        backends.append(_feed(EmergingThreatsCollector))
    if args.otx_key:
        backends.append(_feed(OTXCollector, api_key=args.otx_key))

    # Remote API backends
    if args.abuseipdb_key:
        backends.append(
            AbuseIPDBBackend(
                args.abuseipdb_key,
                args.abuseipdb_min_score,
            )
        )
    if args.virustotal_key:
        backends.append(
            VirusTotalBackend(
                args.virustotal_key,
                args.virustotal_min_detections,
            )
        )
    if args.shodan_key:
        backends.append(ShodanBackend(args.shodan_key))
    if args.intelmq_url and args.intelmq_user:
        backends.append(
            IntelMQApiBackend(
                args.intelmq_url,
                args.intelmq_user,
                args.intelmq_pass,
            )
        )
    if not args.no_heuristics:
        backends.append(LocalHeuristicBackend())

    if not args.quiet and args.verbose:
        print(f"\n  {TOOL_NAME}  v{VERSION}")
        print(f"  Backends : {', '.join(b.name for b in backends)}")
        print(f"  Cache    : {cache.cache_dir}\n")

    # Pre-load all feed collectors (Collector -> Parser -> Cache)
    if not args.quiet:
        feed_backends = [b for b in backends if isinstance(b, FeedCollector)]
        if feed_backends:
            print(f"  Loading {len(feed_backends)} threat feed(s)…")
            for b in feed_backends:
                b.load()
            print()

    # Extract observables from each PCAP
    all_obs: list[Observable] = []
    for pcap in args.pcap_files:
        if not args.quiet:
            print(f"  Extracting: {pcap}")
        obs = PcapExtractor(pcap, verbose=args.verbose).extract()
        obs = [o for o in obs if o.kind in args.kinds]
        if not args.include_private:
            obs = [o for o in obs if o.kind != "ip" or not is_private_ip(o.value)]
        all_obs.extend(obs)
        if not args.quiet:
            print(f"    {len(obs)} observables extracted")

    if not all_obs:
        if not args.quiet:
            print("\n  No analysable observables found in the captures.")
        return 0

    # Deduplicate across files
    deduped: dict[str, Observable] = {}
    for o in all_obs:
        k = f"{o.kind}:{o.value}"
        if k in deduped:
            deduped[k].count += o.count
        else:
            deduped[k] = o
    unique_obs = list(deduped.values())

    if not args.quiet:
        by_kind: dict[str, int] = defaultdict(int)
        for o in unique_obs:
            by_kind[o.kind] += 1
        print(
            f"\n  Unique observables: {len(unique_obs)}  ("
            + ", ".join(f"{v} {k}s" for k, v in sorted(by_kind.items()))
            + ")"
        )
        print(f"  Running lookups across {len(backends)} backend(s)…\n")

    # Analyse
    analyser = Analyser(backends, rate_limit=args.rate_limit, verbose=args.verbose)
    matches = analyser.analyse(unique_obs, console=console)

    # Report
    if not args.quiet:
        print_report(matches, unique_obs, backends, console)

    # Export
    if args.output_json:
        export_json(matches, unique_obs, args.output_json)
        if not args.quiet:
            print(f"\n  JSON  -> {args.output_json}")
    if args.output_csv:
        export_csv(matches, args.output_csv)
        if not args.quiet:
            print(f"  CSV   -> {args.output_csv}")

    # Exit code: 1 = threats found, 0 = clean (CI/CD friendly)
    return 1 if matches else 0


if __name__ == "__main__":
    sys.exit(main())
