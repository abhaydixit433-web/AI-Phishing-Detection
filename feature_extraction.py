import re
from urllib.parse import urlparse
import tldextract


def extract_features(url):
    """
    Extract 14 numerical features from URL.
    """

    url = str(url).strip()

    # URL parse
    parsed = urlparse(url)

    # Domain information
    ext = tldextract.extract(url)

    features = {}

    # 1. URL length
    features["url_length"] = len(url)

    # 2. HTTPS
    features["https"] = 1 if parsed.scheme.lower() == "https" else 0

    # 3. @ symbol
    features["has_at"] = 1 if "@" in url else 0

    # 4. Hyphen
    features["has_hyphen"] = 1 if "-" in ext.domain else 0

    # 5. Number of dots
    features["dot_count"] = url.count(".")

    # 6. Number of slashes
    features["slash_count"] = url.count("/")

    # 7. Number of digits
    features["digit_count"] = sum(c.isdigit() for c in url)

    # 8. Special characters
    features["special_char_count"] = len(
        re.findall(r'[@#$%^&*()=+{}\[\]|\\:;"\'<>,?]', url)
    )

    # 9. IP address
    ip_pattern = r"(\d{1,3}\.){3}\d{1,3}"
    features["has_ip"] = 1 if re.search(ip_pattern, parsed.netloc) else 0

    # 10. Path length
    features["path_length"] = len(parsed.path)

    # 11. Query length
    features["query_length"] = len(parsed.query)

    # 12. Domain length
    features["domain_length"] = len(ext.domain)

    # 13. Subdomain length
    features["subdomain_length"] = len(ext.subdomain)

    # 14. Suffix length
    features["suffix_length"] = len(ext.suffix)

    return list(features.values())


def get_url_risk_score(url):
    """
    Additional security rules.
    Returns:
        score
        reasons
    """

    url = str(url).strip()
    lower_url = url.lower()

    parsed = urlparse(
        url if url.startswith(("http://", "https://")) else "https://" + url
    )

    score = 0
    reasons = []

    # Suspicious keywords
    suspicious_keywords = [
        "login",
        "verify",
        "verification",
        "update",
        "secure",
        "security",
        "account",
        "confirmation",
        "confirm",
        "payment",
        "bank",
        "wallet",
        "password",
        "signin",
        "sign-in",
        "gift",
        "winner",
        "free",
        "claim",
        "reward",
    ]

    found_keywords = []

    for keyword in suspicious_keywords:
        if keyword in lower_url:
            found_keywords.append(keyword)

    if found_keywords:
        score += min(len(found_keywords), 3)
        reasons.append(
            "Suspicious keywords: " + ", ".join(found_keywords[:5])
        )

    # IP address
    ip_pattern = r"(\d{1,3}\.){3}\d{1,3}"

    if re.search(ip_pattern, parsed.netloc):
        score += 4
        reasons.append("URL uses an IP address instead of a normal domain")

    # @ symbol
    if "@" in url:
        score += 4
        reasons.append("URL contains @ symbol")

    # HTTP
    if parsed.scheme.lower() == "http":
        score += 1
        reasons.append("Connection is not HTTPS")

    # Very long URL
    if len(url) > 100:
        score += 2
        reasons.append("Very long URL")

    # Excessive hyphens
    hyphen_count = parsed.netloc.count("-")

    if hyphen_count >= 2:
        score += 2
        reasons.append("Domain contains multiple hyphens")

    # Excessive subdomains
    host = parsed.hostname or ""
    subdomain_parts = host.split(".")

    if len(subdomain_parts) >= 4:
        score += 2
        reasons.append("Too many subdomain levels")

    # Double slash in path
    if "//" in parsed.path:
        score += 1
        reasons.append("Unusual double slash in path")

    # Suspicious TLD
    suspicious_tlds = [
        ".tk",
        ".ml",
        ".ga",
        ".cf",
        ".gq",
        ".top",
        ".xyz",
        ".click",
        ".download",
        ".win",
    ]

    if any(lower_url.endswith(tld) or f"{tld}/" in lower_url for tld in suspicious_tlds):
        score += 2
        reasons.append("Suspicious domain extension")

    return score, reasons