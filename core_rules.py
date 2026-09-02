#!/usr/bin/env python3
"""
core_rules.py — PhishAnalyzer v5.0
Analysis engine: combines local static analysis, SSL/TLS checks, WHOIS,
and VirusTotal to produce a unified Risk Score from 0 to 100.
"""

import re
import ssl
import socket
import ipaddress
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests

try:
    import whois  # python-whois
except ImportError:
    whois = None

from config import (
    REQUEST_TIMEOUT,
    DOMAIN_AGE_THRESHOLD_DAYS,
    DOMAIN_AGE_RISK_BOOST,
    VT_API_BASE,
)

# Popular global brands commonly targeted by typosquatting
POPULAR_BRANDS = [
    "google", "facebook", "instagram", "whatsapp", "paypal", "apple",
    "microsoft", "amazon", "netflix", "bankofamerica", "chase", "outlook",
    "gmail", "twitter", "x", "linkedin", "steam", "binance", "coinbase",
]

# Approximate lookup table for common homograph characters used in phishing
HOMOGRAPH_MAP = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c",  # Cyrillic look-alikes
    "ѕ": "s", "х": "x", "у": "y", "і": "i",
}


class URLAnalysisResult:
    def __init__(self, url: str):
        self.url = url
        self.risk_score = 0
        self.findings: list[str] = []
        self.vt_result: dict | None = None
        self.domain_age_days: int | None = None
        self.ssl_valid: bool | None = None

    def add(self, points: int, reason: str) -> None:
        self.risk_score = min(100, self.risk_score + points)
        self.findings.append(f"(+{points}) {reason}")

    def verdict(self) -> str:
        if self.risk_score >= 70:
            return "High Risk \U0001F534"
        if self.risk_score >= 40:
            return "Suspicious \U0001F7E1"
        return "Low Risk \U0001F7E2"


# ---------------------------------------------------------------------------
# 1. Local Static Analysis
# ---------------------------------------------------------------------------

def static_analysis(result: URLAnalysisResult) -> None:
    url = result.url
    parsed = urlparse(url)
    host = parsed.netloc.split(":")[0]

    # Unusually long URL
    if len(url) > 90:
        result.add(10, f"Unusually long URL ({len(url)} characters)")

    # Presence of '@' symbol (hides the real destination after the symbol)
    if "@" in url:
        result.add(20, "URL contains an '@' symbol, often used to hide the real destination")

    # Direct IP address instead of a domain name
    try:
        ipaddress.ip_address(host)
        result.add(25, "URL uses a raw IP address instead of a domain name")
    except ValueError:
        pass

    # Suspicious characters (excessive dashes, heavy URL-encoding)
    if url.count("-") >= 3:
        result.add(8, "Domain name contains an unusually high number of dashes")
    if re.search(r"%[0-9a-fA-F]{2}", url):
        result.add(5, "URL contains URL-encoding that may be hiding content")

    # Excessive number of subdomains
    if host.count(".") >= 4:
        result.add(15, f"Excessive number of subdomains ({host})")

    # Homograph attack: Unicode characters visually similar to Latin letters
    for ch in host:
        if ch in HOMOGRAPH_MAP:
            result.add(30, "Detected Unicode characters visually similar to Latin letters (Homograph Attack)")
            break

    # Typosquatting: strong similarity to a popular brand without an exact match
    domain_core = host.replace("www.", "").split(".")[0].lower()
    for brand in POPULAR_BRANDS:
        if brand == domain_core:
            continue
        if brand in domain_core and domain_core != brand:
            result.add(25, f"Possible impersonation of the popular domain '{brand}' (Typosquatting)")
            break
        if _levenshtein(domain_core, brand) == 1:
            result.add(30, f"Only a single character different from the popular domain '{brand}'")
            break


def _levenshtein(a: str, b: str) -> int:
    if len(a) < len(b):
        return _levenshtein(b, a)
    if len(b) == 0:
        return len(a)
    previous_row = range(len(b) + 1)
    for i, ca in enumerate(a):
        current_row = [i + 1]
        for j, cb in enumerate(b):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (ca != cb)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


# ---------------------------------------------------------------------------
# 2. SSL/TLS Certificate Check
# ---------------------------------------------------------------------------

def check_ssl(result: URLAnalysisResult) -> None:
    parsed = urlparse(result.url)
    host = parsed.netloc.split(":")[0]

    if parsed.scheme != "https":
        result.add(20, "URL does not use HTTPS at all")
        result.ssl_valid = False
        return

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=REQUEST_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()

        not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
        not_after = not_after.replace(tzinfo=timezone.utc)
        if not_after < datetime.now(timezone.utc):
            result.add(25, "SSL certificate has expired")
            result.ssl_valid = False
        else:
            result.ssl_valid = True
            # Note: a valid certificate does not imply the site is trustworthy —
            # free CAs like Let's Encrypt are available to anyone, including attackers.
            # No points are deducted here; a valid cert is treated as neutral,
            # not as strong positive evidence.

    except ssl.SSLCertVerificationError:
        result.add(30, "SSL certificate verification failed (may be self-signed or forged)")
        result.ssl_valid = False
    except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError):
        result.add(10, "Could not connect on port 443 to verify the certificate")
        result.ssl_valid = None


# ---------------------------------------------------------------------------
# 3. Domain Intelligence (WHOIS)
# ---------------------------------------------------------------------------

def check_whois(result: URLAnalysisResult) -> None:
    if whois is None:
        result.findings.append("(!) python-whois is not installed, WHOIS check skipped")
        return

    host = urlparse(result.url).netloc.split(":")[0]

    try:
        w = whois.whois(host)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if creation_date is None:
            result.add(10, "Could not determine the domain creation date via WHOIS")
            return

        if creation_date.tzinfo is None:
            creation_date = creation_date.replace(tzinfo=timezone.utc)

        age_days = (datetime.now(timezone.utc) - creation_date).days
        result.domain_age_days = age_days

        if age_days < DOMAIN_AGE_THRESHOLD_DAYS:
            result.add(
                DOMAIN_AGE_RISK_BOOST,
                f"Recently registered domain ({age_days} days old) — younger than {DOMAIN_AGE_THRESHOLD_DAYS} days",
            )
        else:
            result.findings.append(f"(i) Domain age: {age_days} days (normal)")

    except Exception as e:
        result.add(8, f"WHOIS lookup failed ({type(e).__name__}) — domain age could not be confirmed")


# ---------------------------------------------------------------------------
# 4. Cloud-based Threat Intelligence via VirusTotal
# ---------------------------------------------------------------------------

def check_virustotal(result: URLAnalysisResult, api_key: str) -> None:
    import base64

    url_id = base64.urlsafe_b64encode(result.url.encode()).decode().strip("=")
    headers = {"x-apikey": api_key}

    try:
        resp = requests.get(
            f"{VT_API_BASE}/urls/{url_id}",
            headers=headers,
            timeout=REQUEST_TIMEOUT,
        )

        if resp.status_code == 404:
            # URL is unknown to VT yet; submit it for a live scan
            submit = requests.post(
                f"{VT_API_BASE}/urls",
                headers=headers,
                data={"url": result.url},
                timeout=REQUEST_TIMEOUT,
            )
            submit.raise_for_status()
            result.findings.append("(i) URL is new to VirusTotal, submitted for a live scan (results may take a few minutes)")
            return

        resp.raise_for_status()
        data = resp.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = sum(stats.values()) or 1

        result.vt_result = stats

        if malicious > 0:
            result.add(min(50, malicious * 5), f"{malicious} security vendors flagged this URL as malicious (out of {total})")
        if suspicious > 0:
            result.add(min(20, suspicious * 3), f"{suspicious} security vendors flagged this URL as suspicious")

    except requests.exceptions.RequestException as e:
        result.findings.append(f"(!) Could not reach VirusTotal ({type(e).__name__})")


# ---------------------------------------------------------------------------
# Unified entry point
# ---------------------------------------------------------------------------

def analyze_url(url: str, api_key: str | None = None) -> URLAnalysisResult:
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    result = URLAnalysisResult(url)

    static_analysis(result)
    check_ssl(result)
    check_whois(result)

    if api_key:
        check_virustotal(result, api_key)
    else:
        result.findings.append("(!) No VirusTotal API key provided, cloud scan skipped")

    return result
