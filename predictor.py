# app/ml/predictor.py
"""
Heuristic-based phishing URL classifier.

This module implements a transparent, rule-driven feature extractor that
scores URLs on 12 well-documented signals used by academic phishing-detection
literature (e.g. Abdelhamid et al., 2014; Sahingoz et al., 2019).

Each signal contributes a weighted score:
  positive score → phishing
  negative score → safe

A sigmoid function maps the raw score to a [0, 1] confidence value.
"""

import math
import re
import ipaddress
from dataclasses import dataclass, field
from urllib.parse import urlparse
from typing import Tuple

try:
    import tldextract
    _HAS_TLDEXTRACT = True
except ImportError:
    _HAS_TLDEXTRACT = False


# ── Known-bad signal lists ────────────────────────────────────────────────────

_SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq",  # free ccTLDs abused by phishers
    ".xyz", ".top", ".club", ".work", ".live",
    ".online", ".site", ".website", ".space",
}

_BRAND_KEYWORDS = {
    "paypal", "apple", "amazon", "google", "microsoft", "facebook",
    "instagram", "netflix", "bankofamerica", "wellsfargo", "chase",
    "linkedin", "twitter", "dropbox", "ebay", "dhl", "fedex", "ups",
    "irs", "gov", "secure", "login", "signin", "account", "verify",
    "update", "confirm", "banking", "wallet",
}

_URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "t.co",
    "buff.ly", "adf.ly", "is.gd", "cli.gs", "pic.gd",
}

_SAFE_TLDS = {".com", ".org", ".net", ".edu", ".gov", ".io", ".co"}


# ── Result dataclass ──────────────────────────────────────────────────────────

@dataclass
class PredictionResult:
    label: str           # "safe" | "phishing"
    confidence: float    # 0.0 – 1.0
    reason: str
    signals: list[str] = field(default_factory=list)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _sigmoid(x: float) -> float:
    return 1 / (1 + math.exp(-x))


def _normalise_url(url: str) -> str:
    url = url.strip()
    if not re.match(r"^https?://", url, re.I):
        url = "http://" + url
    return url


def _is_ip_address(hostname: str) -> bool:
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def _get_tld(hostname: str) -> str:
    """Return the TLD with leading dot, e.g. '.com'."""
    parts = hostname.split(".")
    return "." + parts[-1] if parts else ""


def _count_subdomains(hostname: str) -> int:
    if _HAS_TLDEXTRACT:
        ext = tldextract.extract(hostname)
        sub = ext.subdomain
        return len(sub.split(".")) if sub else 0
    # Fallback: count dots minus 1
    parts = hostname.split(".")
    return max(0, len(parts) - 2)


def _entropy(s: str) -> float:
    """Shannon entropy of a string."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((f / n) * math.log2(f / n) for f in freq.values())


# ── Feature extraction ────────────────────────────────────────────────────────

def _extract_features(url: str) -> Tuple[float, list[str]]:
    """
    Returns (raw_score, [signal_descriptions]).
    Positive raw_score → phishing tendency.
    """
    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()
    path = parsed.path or ""
    query = parsed.query or ""
    full = url.lower()

    score = 0.0
    signals: list[str] = []

    # 1. IP address as host (+3.0)
    if _is_ip_address(hostname):
        score += 3.0
        signals.append("IP address used instead of domain name")

    # 2. URL length (+1.5 if > 75, +0.7 if > 54)
    if len(url) > 75:
        score += 1.5
        signals.append(f"Unusually long URL ({len(url)} chars)")
    elif len(url) > 54:
        score += 0.7
        signals.append(f"Long URL ({len(url)} chars)")

    # 3. @ symbol in URL (+2.5)
    if "@" in url:
        score += 2.5
        signals.append("'@' symbol in URL (browser ignores everything before it)")

    # 4. Double slash redirect (+2.0)
    if re.search(r"https?://.*//", url):
        score += 2.0
        signals.append("Double slash redirect detected")

    # 5. Hyphen in domain (+1.0)
    domain_part = hostname.split(".")[0] if hostname else ""
    hyphen_count = domain_part.count("-")
    if hyphen_count >= 2:
        score += 1.5
        signals.append(f"Multiple hyphens in domain ({hyphen_count})")
    elif hyphen_count == 1:
        score += 0.5
        signals.append("Hyphen in domain name")

    # 6. Sub-domain depth (+1.0 per extra level beyond one)
    subdomain_count = _count_subdomains(hostname)
    if subdomain_count > 2:
        score += 2.0
        signals.append(f"Excessive subdomains ({subdomain_count} levels)")
    elif subdomain_count == 2:
        score += 1.0
        signals.append("Multiple subdomains")

    # 7. HTTPS check (-1.5 safe signal)
    if parsed.scheme == "https":
        score -= 1.5
        signals.append("HTTPS in use (safe signal)")
    else:
        score += 1.0
        signals.append("No HTTPS")

    # 8. Suspicious TLD (+1.5)
    tld = _get_tld(hostname)
    if tld in _SUSPICIOUS_TLDS:
        score += 1.5
        signals.append(f"Suspicious TLD '{tld}'")
    elif tld in _SAFE_TLDS:
        score -= 0.5
        signals.append(f"Common TLD '{tld}' (safe signal)")

    # 9. Brand keyword in path/query (not hostname) (+2.0)
    path_query = (path + "?" + query).lower()
    matched_brands = [kw for kw in _BRAND_KEYWORDS if kw in path_query]
    if matched_brands:
        score += 2.0
        signals.append(f"Brand keyword(s) in path/query: {', '.join(matched_brands[:3])}")

    # 10. Brand keyword impersonated in hostname (typosquatting) (+2.5)
    hostname_brands = [kw for kw in _BRAND_KEYWORDS if kw in hostname]
    if hostname_brands:
        score += 2.5
        signals.append(f"Brand keyword in hostname (possible typosquatting): {', '.join(hostname_brands[:3])}")

    # 11. URL shortener (+2.0)
    for shortener in _URL_SHORTENERS:
        if hostname.endswith(shortener) or hostname == shortener.split(".")[0]:
            score += 2.0
            signals.append(f"URL shortener detected ({shortener})")
            break

    # 12. High entropy hostname (+1.5 if > 4.0)
    ent = _entropy(hostname.replace(".", ""))
    if ent > 4.0:
        score += 1.5
        signals.append(f"High hostname entropy ({ent:.2f}) — looks machine-generated")
    elif ent > 3.2:
        score += 0.5

    # 13. Excessive dots in full URL (+1.0 if > 5)
    dot_count = full.count(".")
    if dot_count > 5:
        score += 1.0
        signals.append(f"High number of dots ({dot_count}) in URL")

    # 14. Port present (+1.0)
    if parsed.port and parsed.port not in (80, 443):
        score += 1.0
        signals.append(f"Non-standard port ({parsed.port})")

    # 15. Hex / percent encoding in hostname (+2.0)
    if "%" in hostname:
        score += 2.0
        signals.append("Percent-encoding in hostname")

    return score, signals


# ── Public API ────────────────────────────────────────────────────────────────

def predict(url: str) -> PredictionResult:
    """
    Classify a URL as 'phishing' or 'safe'.

    The decision boundary is score ≥ 2.0 → phishing.
    Confidence is the sigmoid of |score - 2.0| scaled by 0.8, clamped to
    [0.50, 0.99] so we never claim 100 % certainty.
    """
    normalised = _normalise_url(url)
    raw_score, signals = _extract_features(normalised)

    BOUNDARY = 2.0
    is_phishing = raw_score >= BOUNDARY

    # Map distance from boundary to confidence
    distance = abs(raw_score - BOUNDARY)
    confidence = min(0.50 + _sigmoid(distance * 0.9) * 0.49, 0.99)

    if is_phishing:
        label = "phishing"
        top_signals = signals[:3] if signals else ["Multiple suspicious patterns detected"]
        reason = "Phishing indicators detected: " + "; ".join(top_signals) + "."
    else:
        label = "safe"
        safe_signals = [s for s in signals if "safe signal" in s]
        if safe_signals:
            reason = "No significant phishing indicators. " + "; ".join(safe_signals[:2]) + "."
        else:
            reason = "No significant phishing indicators found."

    return PredictionResult(
        label=label,
        confidence=round(confidence, 4),
        reason=reason,
        signals=signals,
    )
