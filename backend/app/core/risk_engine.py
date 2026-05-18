# backend/app/core/risk_engine.py
# Updated to include ML score in the weighted risk calculation
import tldextract


def calculate_risk(vt: dict, urlhaus: dict, whois: dict, typo: dict, ml: dict = None) -> dict:
    """
    Combines all intelligence sources into a single risk score (0-100).

    Weights WITH ML model:
    - ML score          : 30 pts
    - VirusTotal        : 30 pts
    - Domain age        : 20 pts
    - URLHaus           : 10 pts
    - Typosquatting     : 10 pts
    - DNS flags         : 10 pts (bonus, score capped at 100)

    Weights WITHOUT ML (fallback):
    - VirusTotal        : 40 pts
    - Domain age        : 25 pts
    - URLHaus           : 20 pts
    - Typosquatting     : 15 pts
    - DNS flags         : 10 pts
    """
    # ── Whitelist — well-known legitimate domains ──────────
    # These are so established that ML false positives should be overridden
    domain = whois.get("domain", "")
    WHITELIST = [
        "google.com", "youtube.com", "facebook.com", "amazon.com",
        "microsoft.com", "apple.com", "twitter.com", "instagram.com",
        "linkedin.com", "github.com", "wikipedia.org", "reddit.com",
        "netflix.com", "whatsapp.com", "yahoo.com", "bing.com"
    ]
    if any(domain.endswith(w) for w in WHITELIST):
        return {
            "score": 0,
            "level": "LOW",
            "prediction": "safe",
            "explanation": "No major threats detected",
            "ml_used": False
        }

    score = 0
    reasons = []
    ml = ml or {}
    # ── ML Score (0-30 points) ─────────────────────────────
    ml_ready = ml.get("ml_ready", False)
    ml_score = ml.get("ml_score", 0.0)

    if ml_ready:
        # Only add ML points if confidence is HIGH (>= 0.75)
        # This reduces false positives like google.com
        if ml_score >= 0.75:
            ml_points = ml_score * 30
            score += ml_points
            reasons.append(
                f"ML model flagged as phishing ({ml.get('ml_confidence')}% confidence)")
        elif ml_score >= 0.5:
            # Medium confidence — add half points, don't add to explanation
            score += ml_score * 15
    # ── VirusTotal (0-30 with ML, 0-40 without) ───────────
    vt_weight = 30 if ml_ready else 40
    vt_malicious = vt.get("malicious_count", 0)
    vt_total = max(vt.get("total_vendors", 1), 1)
    vt_ratio = vt_malicious / vt_total
    vt_points = min(vt_ratio * vt_weight, vt_weight)
    score += vt_points
    if vt_malicious > 0:
        reasons.append(f"Flagged by {vt_malicious} VirusTotal vendors")

    # ── Domain age (0-20 with ML, 0-25 without) ───────────
    age_weight = 20 if ml_ready else 25
    domain_age_days = whois.get("domain_age_days", 365)
    if domain_age_days < 7:
        score += age_weight
        reasons.append(f"Domain is only {domain_age_days} days old")
    elif domain_age_days < 30:
        score += age_weight * 0.6
        reasons.append(
            f"Domain is {domain_age_days} days old (recently registered)")
    elif domain_age_days < 90:
        score += age_weight * 0.2

    # ── URLHaus (0-10 with ML, 0-20 without) ─────────────
    urlhaus_weight = 10 if ml_ready else 20
    if urlhaus.get("is_blacklisted", False):
        score += urlhaus_weight
        reasons.append("URL found in URLHaus malicious database")

    # ── Typosquatting (0-10 with ML, 0-15 without) ────────
    suspicious_keywords = [
        "login",
        "verify",
        "secure",
        "account",
        "bank",
        "paypal",
        "security",
    ]

    url_lower = typo.get("scanned_domain", "").lower()

    keyword_hits = sum(
        1 for word in suspicious_keywords if word in url_lower
    )

    if keyword_hits >= 2:
        score += 25
    reasons.append("Suspicious phishing keywords detected in URL")
    if url_lower.endswith(".xyz"):
        score += 10
    reasons.append("High-risk TLD detected (.xyz)")
    typo_weight = 10 if ml_ready else 15
    typo_is_squat = typo.get("is_typosquat", False)
    typo_distance = typo.get("distance", 99)
    typo_match = typo.get("closest_domain", None)
    if typo_is_squat and typo_distance <= 2:
        score += typo_weight
        reasons.append(
            f"URL resembles '{typo_match}' (possible typosquatting)")
    elif typo_is_squat and typo_distance <= 4:
        score += typo_weight * 0.5

    # ── DNS anomalies (bonus 0-10) ─────────────────────────
    if whois.get("dns_suspicious", False):
        score += 10
        for flag in whois.get("dns_flags", []):
            reasons.append(f"DNS: {flag}")

    # ── Final score capped at 100 ─────────────────────────
    final_score = min(int(score), 100)

    # ── Risk level ────────────────────────────────────────
    if final_score >= 75 or ml.get("ml_score", 0) >= 0.9:
        level = "CRITICAL"
    elif final_score >= 50 or ml.get("ml_score", 0) >= 0.8:
        level = "HIGH"
    elif final_score >= 25:
        level = "MEDIUM"
    else:
        level = "LOW"

    explanation = ". ".join(
        reasons) if reasons else "No major threats detected"
    is_phishing = (
        final_score >= 50
        or ml.get("ml_score", 0) >= 0.8
        or vt.get("malicious_count", 0) >= 5
    )
    return {
        "score": final_score,
        "level": level,
        # "prediction": "phishing" if final_score >= 50 else "safe",
        "prediction": "phishing" if is_phishing else "safe",
        "explanation": explanation,
        "ml_used": ml_ready
    }
