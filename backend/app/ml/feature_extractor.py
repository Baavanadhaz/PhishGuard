# app/ml/feature_extractor.py
import re
import math
from urllib.parse import urlparse, parse_qs
try:
    import tldextract
    HAS_TLDEXTRACT = True
except ImportError:
    HAS_TLDEXTRACT = False

# ── Constants ─────────────────────────────────────────────────────────────────

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "secure", "update", "bank", "free", "reward",
    "account", "confirm", "password", "signin", "webscr", "ebayisapi",
    "paypal", "billing", "support", "alert", "validate",
]

SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq",   # free TLDs heavily abused
    ".xyz", ".top", ".club", ".work",
    ".click", ".link", ".online", ".site",
    ".info", ".biz", ".us", ".cc",
}

BRAND_KEYWORDS = [
    "paypal", "apple", "google", "microsoft", "amazon", "facebook",
    "netflix", "instagram", "twitter", "ebay", "chase", "wellsfargo",
    "bankofamerica", "citibank", "irs", "dropbox", "linkedin",
]

IP_PATTERN = re.compile(
    r"^(\d{1,3}\.){3}\d{1,3}$"
)

# ── Helpers ───────────────────────────────────────────────────────────────────

def _safe_parse(url: str):
    """Return parsed URL, prepending scheme if missing."""
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return urlparse(url)


def _shannon_entropy(s: str) -> float:
    """Compute Shannon entropy of a string."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((f / n) * math.log2(f / n) for f in freq.values())


# ── Main extractor ────────────────────────────────────────────────────────────

def extract_features(url: str) -> dict:
    """
    Extract 20 heuristic features from a URL string.

    Returns a flat dict with deterministic keys (same order every call).
    """
    parsed = _safe_parse(url)
    hostname = parsed.hostname or ""
    path     = parsed.path or ""
    query    = parsed.query or ""
    full_url = url.lower()

    # ── TLD extraction ────────────────────────────────────────────────────────
    if HAS_TLDEXTRACT:
        ext        = tldextract.extract(url)
        tld        = ("." + ext.suffix) if ext.suffix else ""
        subdomains = [s for s in ext.subdomain.split(".") if s] if ext.subdomain else []
        registered_domain = ext.registered_domain or ""
    else:
        # Fallback: naive split
        parts = hostname.split(".")
        tld   = ("." + parts[-1]) if len(parts) > 1 else ""
        subdomains = parts[:-2] if len(parts) > 2 else []
        registered_domain = ".".join(parts[-2:]) if len(parts) >= 2 else hostname

    # ── Feature 1-4: Length-based ─────────────────────────────────────────────
    url_length      = len(url)
    hostname_length = len(hostname)
    path_length     = len(path)
    query_length    = len(query)

    # ── Feature 5-12: Character counts ───────────────────────────────────────
    count_dots      = url.count(".")
    count_hyphens   = url.count("-")
    count_at        = url.count("@")
    count_question  = url.count("?")
    count_equals    = url.count("=")
    count_slash     = url.count("/")
    count_percent   = url.count("%")   # URL encoding (obfuscation signal)
    count_ampersand = url.count("&")

    # ── Feature 13: HTTPS ─────────────────────────────────────────────────────
    has_https = int(parsed.scheme == "https")

    # ── Feature 14: IP address as hostname ───────────────────────────────────
    has_ip = int(bool(IP_PATTERN.match(hostname)))

    # ── Feature 15: Digit ratio in hostname ──────────────────────────────────
    digit_ratio = (
        sum(c.isdigit() for c in hostname) / len(hostname)
        if hostname else 0.0
    )

    # ── Feature 16: Suspicious keyword count ─────────────────────────────────
    suspicious_keyword_count = sum(kw in full_url for kw in SUSPICIOUS_KEYWORDS)

    # ── Feature 17: Suspicious TLD ───────────────────────────────────────────
    tld_is_suspicious = int(tld.lower() in SUSPICIOUS_TLDS)

    # ── Feature 18: Number of subdomains ─────────────────────────────────────
    num_subdomains = len(subdomains)

    # ── Feature 19: Brand keyword in subdomain / path (typosquatting) ────────
    brand_in_subdomain = int(
        any(brand in ".".join(subdomains).lower() for brand in BRAND_KEYWORDS)
    )

    # ── Feature 20: Shannon entropy of hostname (high = obfuscated) ──────────
    hostname_entropy = round(_shannon_entropy(hostname), 4)

    return {
        "url_length":              url_length,
        "hostname_length":         hostname_length,
        "path_length":             path_length,
        "query_length":            query_length,
        "count_dots":              count_dots,
        "count_hyphens":           count_hyphens,
        "count_at":                count_at,
        "count_question":          count_question,
        "count_equals":            count_equals,
        "count_slash":             count_slash,
        "count_percent":           count_percent,
        "count_ampersand":         count_ampersand,
        "has_https":               has_https,
        "has_ip":                  has_ip,
        "digit_ratio":             digit_ratio,
        "suspicious_keyword_count": suspicious_keyword_count,
        "tld_is_suspicious":       tld_is_suspicious,
        "num_subdomains":          num_subdomains,
        "brand_in_subdomain":      brand_in_subdomain,
        "hostname_entropy":        hostname_entropy,
    }
