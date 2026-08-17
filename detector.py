"""Explainable URL-only phishing risk analysis.

The detector deliberately does not request the page. It scores signals that can
be extracted safely from the submitted URL and explains every point awarded.
"""

from __future__ import annotations

import ipaddress
import math
import re
from dataclasses import dataclass, field
from typing import Literal
from urllib.parse import parse_qsl, unquote, urlparse


RiskLevel = Literal["Low risk", "Elevated risk", "High risk", "Critical risk"]

BRAND_DOMAINS = {
    "amazon": {"amazon.com", "amazon.co.uk", "amazon.in", "amazon.de", "amazon.ca"},
    "apple": {"apple.com"},
    "adobe": {"adobe.com"},
    "docusign": {"docusign.com"},
    "facebook": {"facebook.com", "fb.com"},
    "google": {"google.com"},
    "instagram": {"instagram.com"},
    "linkedin": {"linkedin.com"},
    "microsoft": {"microsoft.com", "live.com", "office.com", "outlook.com"},
    "netflix": {"netflix.com"},
    "paypal": {"paypal.com"},
}

SUSPICIOUS_TLDS = {
    "buzz",
    "cam",
    "click",
    "country",
    "cyou",
    "gq",
    "icu",
    "info",
    "live",
    "link",
    "monster",
    "online",
    "pw",
    "rest",
    "ru",
    "shop",
    "support",
    "top",
    "tk",
    "today",
    "vip",
    "win",
    "work",
    "xyz",
}

SHORTENER_HOSTS = {
    "bit.ly",
    "buff.ly",
    "cutt.ly",
    "is.gd",
    "rb.gy",
    "rebrand.ly",
    "shorturl.at",
    "t.co",
    "tiny.cc",
    "tinyurl.com",
}

URGENT_TERMS = {
    "account",
    "billing",
    "confirm",
    "credential",
    "login",
    "password",
    "payment",
    "recover",
    "secure",
    "signin",
    "unlock",
    "update",
    "verify",
    "wallet",
}


@dataclass
class Signal:
    label: str
    detail: str
    points: int
    severity: Literal["positive", "caution", "danger", "neutral"]


@dataclass
class ScanResult:
    submitted_url: str
    normalized_url: str
    hostname: str
    score: int
    level: RiskLevel
    verdict: str
    signals: list[Signal] = field(default_factory=list)

    @property
    def positives(self) -> list[Signal]:
        return [signal for signal in self.signals if signal.severity == "positive"]

    @property
    def warnings(self) -> list[Signal]:
        return [signal for signal in self.signals if signal.severity in {"caution", "danger"}]


def _clean_url(raw_url: str) -> tuple[str, str]:
    value = raw_url.strip()
    if not value:
        raise ValueError("Enter a URL to scan.")
    if not re.match(r"^[a-z][a-z0-9+.-]*://", value, re.IGNORECASE):
        value = f"https://{value}"
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("Enter a complete web URL, such as https://example.com/login.")
    if not parsed.hostname:
        raise ValueError("That URL does not contain a recognizable domain.")
    return value, parsed.hostname.lower().rstrip(".")


def _is_ip(hostname: str) -> bool:
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def _registered_domain(hostname: str) -> str:
    labels = hostname.split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else hostname


def _brand_mentions(text: str) -> set[str]:
    lower = text.lower()
    return {brand for brand in BRAND_DOMAINS if re.search(rf"\b{re.escape(brand)}\b", lower)}


def _risk_level(score: int) -> RiskLevel:
    if score >= 75:
        return "Critical risk"
    if score >= 50:
        return "High risk"
    if score >= 25:
        return "Elevated risk"
    return "Low risk"


def _verdict(level: RiskLevel) -> str:
    return {
        "Low risk": "No strong phishing indicators were found in this URL.",
        "Elevated risk": "A few signals deserve caution before you continue.",
        "High risk": "This URL has multiple characteristics commonly seen in phishing links.",
        "Critical risk": "Treat this URL as dangerous. Do not sign in, pay, or download anything.",
    }[level]


def scan_url(raw_url: str) -> ScanResult:
    normalized_url, hostname = _clean_url(raw_url)
    parsed = urlparse(normalized_url)
    decoded_url = unquote(normalized_url)
    host_labels = [label for label in hostname.split(".") if label]
    registered_domain = _registered_domain(hostname)
    tld = host_labels[-1] if host_labels else ""
    signals: list[Signal] = []
    score = 0

    def add(label: str, detail: str, points: int, severity: Signal["severity"]) -> None:
        nonlocal score
        score += points
        signals.append(Signal(label, detail, points, severity))

    if parsed.scheme == "https":
        add("Encrypted connection", "HTTPS is enabled for this address.", 0, "positive")
    else:
        add("No HTTPS", "The address is not using an encrypted HTTPS connection.", 18, "danger")

    if _is_ip(hostname):
        add("Raw IP address", "Legitimate sign-in pages usually use a recognizable domain instead of an IP.", 24, "danger")

    if "@" in parsed.netloc:
        add("Hidden destination", "An @ symbol can make a different hostname look like the destination.", 30, "danger")

    if hostname.startswith("xn--") or ".xn--" in hostname:
        add("Punycode domain", "This domain uses encoded characters that can imitate familiar letters.", 22, "danger")

    if len(normalized_url) > 100:
        add("Unusually long URL", f"This address is {len(normalized_url)} characters long.", 15, "caution")
    elif len(normalized_url) > 75:
        add("Long URL", f"This address is {len(normalized_url)} characters long.", 8, "caution")

    if len(host_labels) >= 5:
        add("Deep subdomain chain", "Several nested subdomains can be used to hide the real organization.", 17, "caution")
    elif len(host_labels) == 4:
        add("Nested subdomain", "The host uses multiple subdomains; check the registered domain carefully.", 8, "caution")

    hyphen_count = hostname.count("-")
    if hyphen_count >= 3:
        add("Many hyphens", "Multiple hyphens are common in look-alike or disposable domains.", 14, "caution")
    elif hyphen_count >= 1:
        add("Hyphenated domain", "A hyphenated host can be legitimate, but is worth checking closely.", 4, "caution")

    if tld in SUSPICIOUS_TLDS:
        add("Higher-risk top-level domain", f".{tld} is frequently used by short-lived or abusive domains.", 12, "caution")

    if hostname in SHORTENER_HOSTS or registered_domain in SHORTENER_HOSTS:
        add("Link shortener", "The final destination is hidden behind a URL-shortening service.", 16, "caution")

    if "%" in normalized_url:
        add("Encoded characters", "Encoded characters can obscure words or symbols in the destination.", 8, "caution")

    if parsed.port and parsed.port not in {80, 443}:
        add("Unusual port", f"This address uses port {parsed.port} instead of the standard web ports.", 14, "caution")

    text_for_terms = decoded_url.lower()
    matched_terms = sorted(term for term in URGENT_TERMS if re.search(rf"\b{re.escape(term)}\b", text_for_terms))
    if len(matched_terms) >= 3:
        add("Credential-baiting language", f"Found urgent account language: {', '.join(matched_terms[:5])}.", 19, "danger")
    elif len(matched_terms) >= 1:
        add("Account language", f"Found a sign-in or account-related term: {matched_terms[0]}.", 6, "caution")

    brands = _brand_mentions(decoded_url)
    if brands:
        brand = sorted(brands)[0]
        official_domains = BRAND_DOMAINS[brand]
        if registered_domain not in official_domains:
            add(
                "Possible brand impersonation",
                f"The URL mentions {brand.title()} but is not on a recognized {brand.title()} domain.",
                28,
                "danger",
            )
        else:
            add("Recognized brand domain", f"The registered domain matches a known {brand.title()} web property.", 0, "positive")

    query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
    if len(query_pairs) >= 6:
        add("Dense query string", "Many query parameters can be used to obscure tracking or redirection behavior.", 8, "caution")

    if parsed.path in {"", "/"} and not signals:
        add("Simple host", "No unusual URL structure was detected.", 0, "positive")

    score = max(0, min(score, 100))
    level = _risk_level(score)
    return ScanResult(
        submitted_url=raw_url.strip(),
        normalized_url=normalized_url,
        hostname=hostname,
        score=score,
        level=level,
        verdict=_verdict(level),
        signals=signals,
    )


def confidence_for(result: ScanResult) -> int:
    """Provide a UI-friendly confidence estimate based on signal agreement."""
    danger_count = sum(signal.severity == "danger" for signal in result.signals)
    caution_count = sum(signal.severity == "caution" for signal in result.signals)
    if danger_count >= 2:
        return min(96, 78 + danger_count * 6)
    if caution_count >= 3:
        return min(88, 60 + caution_count * 5)
    return 76 if result.score == 0 else 64


def signal_icon(signal: Signal) -> str:
    return {
        "positive": "PASS",
        "caution": "CHECK",
        "danger": "ALERT",
        "neutral": "INFO",
    }[signal.severity]