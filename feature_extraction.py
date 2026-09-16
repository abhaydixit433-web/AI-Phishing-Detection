import re
from urllib.parse import urlparse
import tldextract


def extract_features(url):
    url = str(url).strip()

    features = {}

    # 1. URL Length
    features["url_length"] = len(url)

    # 2. HTTPS
    features["https"] = 1 if url.lower().startswith("https://") else 0

    # 3. @ Symbol
    features["has_at"] = 1 if "@" in url else 0

    # 4. Hyphen
    features["has_hyphen"] = 1 if "-" in url else 0

    # 5. Number of Dots
    features["dot_count"] = url.count(".")

    # 6. Number of Slashes
    features["slash_count"] = url.count("/")

    # 7. Number of Digits
    features["digit_count"] = sum(c.isdigit() for c in url)

    # 8. Special Characters
    features["special_char_count"] = len(
        re.findall(r'[@#$%^&*()=+{}\[\]|\\:;"\'<>,?]', url)
    )

    # 9. IP Address Detection
    ip_pattern = r'(\d{1,3}\.){3}\d{1,3}'
    features["has_ip"] = 1 if re.search(ip_pattern, url) else 0

    # 10. Parse URL
    parsed = urlparse(url)

    features["path_length"] = len(parsed.path)
    features["query_length"] = len(parsed.query)

    # 11. Domain Information
    ext = tldextract.extract(url)

    features["domain_length"] = len(ext.domain)
    features["subdomain_length"] = len(ext.subdomain)
    features["suffix_length"] = len(ext.suffix)

    return list(features.values())