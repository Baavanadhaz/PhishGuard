# app/ml/predictor.py
"""
Loaded once at import time.
Exposes:  predict_url(url: str) -> dict
"""

import json
import os
import re
from typing import Optional

import joblib
import pandas as pd

from app.ml.feature_extractor import (
    extract_features,
    SUSPICIOUS_KEYWORDS,
    SUSPICIOUS_TLDS,
    BRAND_KEYWORDS,
    IP_PATTERN,
    _safe_parse,
)

# ── Load model artifacts ──────────────────────────────────────────────────────

_BASE_DIR = os.path.dirname(__file__)
_MODEL_PATH   = os.path.join(_BASE_DIR, "ml_model.joblib")
_COLUMNS_PATH = os.path.join(_BASE_DIR, "feature_columns.json")

try:
    _model = joblib.load(_MODEL_PATH)
    with open(_COLUMNS_PATH) as f:
        _feature_columns = json.load(f)
    _model_loaded = True
except FileNotFoundError:
    _model = None
    _feature_columns = []
    _model_loaded = False


# ── Reason builder ────────────────────────────────────────────────────────────

def _build_reason(url: str, features: dict) -> str:
    """
    Produce a human-readable explanation for the prediction.
    Checks signals in priority order; stops at the first strong finding.
    Returns a single sentence.
    """
    reasons = []

    # Hard signals (almost always phishing)
    if features["has_ip"]:
        reasons.append("Uses an IP address instead of a domain name")

    if features["count_at"] > 0:
        reasons.append("Contains '@' character (browser ignores everything before it)")

    # Keyword signals
    kws_found = [kw for kw in SUSPICIOUS_KEYWORDS if kw in url.lower()]
    if kws_found:
        reasons.append(f"Contains suspicious keywords: {', '.join(kws_found[:4])}")

    # Brand impersonation
    brands = [b for b in BRAND_KEYWORDS if b in url.lower()]
    parsed = _safe_parse(url)
    hostname = parsed.hostname or ""
    subdomain_brands = [b for b in BRAND_KEYWORDS if b in hostname.lower()]
    if subdomain_brands:
        reasons.append(f"Brand name '{subdomain_brands[0]}' appears in hostname (possible typosquatting)")

    # TLD
    if features["tld_is_suspicious"]:
        reasons.append(f"Uses a suspicious TLD")

    # Structure signals
    if features["num_subdomains"] >= 3:
        reasons.append(f"Excessive subdomains ({features['num_subdomains']})")

    if features["url_length"] > 75:
        reasons.append(f"Unusually long URL ({features['url_length']} chars)")

    if features["count_hyphens"] >= 4:
        reasons.append(f"Many hyphens ({features['count_hyphens']}) in URL")

    if features["count_percent"] >= 3:
        reasons.append("Heavy URL-encoding (possible obfuscation)")

    if not features["has_https"]:
        reasons.append("No HTTPS")

    if features["hostname_entropy"] > 3.8:
        reasons.append("High-entropy hostname (looks randomly generated)")

    if not reasons:
        if features["has_https"] and features["suspicious_keyword_count"] == 0:
            return "No phishing indicators detected; uses HTTPS and clean domain"
        return "No strong phishing indicators detected"

    return "; ".join(reasons[:3])   # cap at 3 reasons for readability


# ── Public API ────────────────────────────────────────────────────────────────

def predict_url(url: str) -> dict:
    """
    Classify a URL as phishing or safe.

    Returns:
        {
            "url":        str,
            "result":     "phishing" | "safe",
            "confidence": float,   # 0.0 – 1.0
            "reason":     str,
        }
    """
    if not _model_loaded:
        # Graceful fallback: heuristic-only when model isn't trained yet
        return _heuristic_fallback(url)

    features = extract_features(url)
    row = pd.DataFrame([features])[_feature_columns].fillna(0)

    proba      = _model.predict_proba(row)[0]   # [p_safe, p_phishing]
    phish_prob = float(proba[1])
    result     = "phishing" if phish_prob >= 0.5 else "safe"
    confidence = phish_prob if result == "phishing" else (1.0 - phish_prob)

    reason = _build_reason(url, features)

    return {
        "url":        url,
        "result":     result,
        "confidence": round(confidence, 4),
        "reason":     reason,
    }


def _heuristic_fallback(url: str) -> dict:
    """
    Rule-based fallback used before the model is trained.
    Returns the same dict shape as predict_url().
    """
    features = extract_features(url)
    score = 0

    if features["has_ip"]:           score += 3
    if features["count_at"]:         score += 3
    if not features["has_https"]:    score += 1
    score += min(features["suspicious_keyword_count"], 3)
    if features["tld_is_suspicious"]: score += 2
    if features["num_subdomains"] >= 3: score += 1
    if features["url_length"] > 75:  score += 1
    if features["brand_in_subdomain"]: score += 2

    max_score = 12
    confidence = min(score / max_score, 0.99)
    result = "phishing" if score >= 3 else "safe"
    if result == "safe":
        confidence = 1.0 - confidence

    return {
        "url":        url,
        "result":     result,
        "confidence": round(confidence, 4),
        "reason":     _build_reason(url, features) + " [heuristic mode — model not trained yet]",
    }
