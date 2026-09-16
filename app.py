from flask import Flask, render_template, request
import joblib
import requests
import re
from urllib.parse import urlparse

from feature_extraction import (
    extract_features,
    get_url_risk_score
)

app = Flask(__name__)

# ==========================================
# LOAD ML MODEL
# ==========================================

model = joblib.load("models/model.pkl")


# ==========================================
# TRUSTED HOSTING DOMAINS
# ==========================================

TRUSTED_HOSTING = {
    "vercel.app",
    "netlify.app",
    "github.io",
    "pages.dev",
    "web.app",
    "firebaseapp.com",
    "onrender.com",
    "pythonanywhere.com"
}


# ==========================================
# TRUSTED DOMAINS
# ==========================================

TRUSTED_DOMAINS = {
    "google.com",
    "github.com",
    "microsoft.com",
    "openai.com",
    "wikipedia.org",
    "amazon.in",
    "facebook.com",
    "youtube.com",
    "linkedin.com",
    "stackoverflow.com",
    "vercel.com",
    "netlify.com"
}


# ==========================================
# URL NORMALIZATION
# ==========================================

def normalize_url(url):

    url = url.strip()

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    return url


# ==========================================
# GET DOMAIN
# ==========================================

def get_domain(url):

    url = normalize_url(url)

    parsed = urlparse(url)

    hostname = parsed.hostname

    if not hostname:
        return ""

    return hostname.lower().rstrip(".")


# ==========================================
# CHECK TRUSTED DOMAIN
# ==========================================

def is_trusted_domain(url):

    domain = get_domain(url)

    if not domain:
        return False

    # Exact trusted domains
    if domain in TRUSTED_DOMAINS:
        return True

    # Subdomains of trusted domains
    for trusted in TRUSTED_DOMAINS:

        if domain.endswith("." + trusted):
            return True

    # Trusted hosting platforms
    for hosting in TRUSTED_HOSTING:

        if domain == hosting:
            return True

        if domain.endswith("." + hosting):
            return True

    return False


# ==========================================
# URL VALIDATION
# ==========================================

def validate_url(url):

    if not url:
        return False

    if len(url) > 2048:
        return False

    url = normalize_url(url)

    parsed = urlparse(url)

    if parsed.scheme not in ("http", "https"):
        return False

    if not parsed.hostname:
        return False

    # Basic hostname validation
    hostname = parsed.hostname

    if " " in hostname:
        return False

    return True


# ==========================================
# IP ADDRESS
# ==========================================

def is_ip_address(url):

    domain = get_domain(url)

    pattern = r"^(\d{1,3}\.){3}\d{1,3}$"

    return bool(re.match(pattern, domain))


# ==========================================
# URL EXISTENCE CHECK
# ==========================================

def check_url_exists(url):

    url = normalize_url(url)

    headers = {
        "User-Agent": (
            "Mozilla/5.0 "
            "(Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 "
            "(KHTML, like Gecko) "
            "Chrome/120 Safari/537.36"
        )
    }

    try:

        # HEAD request
        response = requests.head(
            url,
            headers=headers,
            timeout=7,
            allow_redirects=True
        )

        if response.status_code < 500:
            return True

    except requests.exceptions.RequestException:
        pass

    try:

        # GET fallback
        response = requests.get(
            url,
            headers=headers,
            timeout=7,
            allow_redirects=True,
            stream=True
        )

        if response.status_code < 500:
            return True

    except requests.exceptions.RequestException:
        pass

    return False


# ==========================================
# HOME
# ==========================================

@app.route("/")
def home():

    return render_template(
        "index.html"
    )


# ==========================================
# PREDICT
# ==========================================

@app.route("/predict", methods=["POST"])
def predict():

    url = request.form.get(
        "url",
        ""
    ).strip()

    # --------------------------------------
    # EMPTY URL
    # --------------------------------------

    if not url:

        return render_template(
            "index.html",
            url=url,
            result="❌ Please enter a URL",
            safe=0,
            phishing=0,
            suspicious=0,
            reasons=[]
        )

    # --------------------------------------
    # VALIDATE
    # --------------------------------------

    if not validate_url(url):

        return render_template(
            "index.html",
            url=url,
            result="❌ Invalid URL",
            safe=0,
            phishing=0,
            suspicious=0,
            reasons=[
                "Please enter a valid website URL."
            ]
        )

    url = normalize_url(url)

    domain = get_domain(url)

    # --------------------------------------
    # TRUSTED DOMAIN CHECK
    # --------------------------------------

    trusted = is_trusted_domain(url)

    # --------------------------------------
    # IP CHECK
    # --------------------------------------

    ip_url = is_ip_address(url)

    # --------------------------------------
    # LOCAL / PRIVATE IP
    # --------------------------------------

    if ip_url:

        return render_template(
            "index.html",
            url=url,
            result="⚠️ Phishing / Unsafe URL",
            safe=5,
            phishing=95,
            suspicious=95,
            reasons=[
                "Website is using an IP address instead of a domain name."
            ]
        )

    # --------------------------------------
    # EXISTENCE CHECK
    # --------------------------------------

    exists = check_url_exists(url)

    if not exists:

        return render_template(
            "index.html",
            url=url,
            result="❌ URL Does Not Exist / Unreachable",
            safe=0,
            phishing=0,
            suspicious=0,
            reasons=[
                "The website could not be reached."
            ]
        )

    # --------------------------------------
    # TRUSTED WEBSITE
    # --------------------------------------

    if trusted:

        return render_template(
            "index.html",
            url=url,
            result="✅ Safe Website",
            safe=98,
            phishing=2,
            suspicious=0,
            reasons=[
                "Domain belongs to a recognized/trusted domain or hosting platform.",
                "Website is reachable."
            ]
        )

    # --------------------------------------
    # FEATURE EXTRACTION
    # --------------------------------------

    features = extract_features(url)

    # --------------------------------------
    # ML PREDICTION
    # --------------------------------------

    prediction = model.predict(
        [features]
    )[0]

    probability = model.predict_proba(
        [features]
    )[0]

    ml_safe = float(probability[0] * 100)

    ml_phishing = float(probability[1] * 100)

    # --------------------------------------
    # SECURITY RULE SCORE
    # --------------------------------------

    risk_score, reasons = get_url_risk_score(
        url
    )

    # --------------------------------------
    # ADD EXTRA REASONS
    # --------------------------------------

    parsed = urlparse(url)

    if parsed.scheme == "http":

        reasons.append(
            "Website is using HTTP instead of HTTPS."
        )

    # --------------------------------------
    # FINAL DECISION
    # --------------------------------------

    # Strong phishing indicators
    strong_phishing = False

    if "@" in url:
        strong_phishing = True

    if risk_score >= 7:
        strong_phishing = True

    # --------------------------------------
    # PHISHING
    # --------------------------------------

    if strong_phishing:

        result = "⚠️ Phishing Website Detected"

        phishing = max(
            ml_phishing,
            90
        )

        phishing = min(
            phishing,
            99
        )

        safe = 100 - phishing

    # --------------------------------------
    # ML + HIGH RISK
    # --------------------------------------

    elif prediction == 1 and risk_score >= 4:

        result = "⚠️ Phishing Website Detected"

        phishing = max(
            ml_phishing,
            75
        )

        phishing = min(
            phishing,
            95
        )

        safe = 100 - phishing

    # --------------------------------------
    # SUSPICIOUS
    # --------------------------------------

    elif risk_score >= 4 or ml_phishing >= 60:

        result = "🟠 Suspicious Website"

        phishing = round(
            max(
                ml_phishing,
                55
            ),
            2
        )

        safe = round(
            100 - phishing,
            2
        )

    # --------------------------------------
    # SAFE
    # --------------------------------------

    elif prediction == 0 and risk_score <= 2:

        result = "✅ Safe Website"

        safe = round(
            max(
                ml_safe,
                70
            ),
            2
        )

        phishing = round(
            100 - safe,
            2
        )

    # --------------------------------------
    # UNCERTAIN
    # --------------------------------------

    else:

        result = "🟠 Suspicious Website"

        safe = round(
            ml_safe,
            2
        )

        phishing = round(
            ml_phishing,
            2
        )

    # --------------------------------------
    # FINAL RESPONSE
    # --------------------------------------

    return render_template(
        "index.html",
        url=url,
        result=result,
        safe=safe,
        phishing=phishing,
        suspicious=risk_score,
        reasons=reasons
    )


# ==========================================
# RUN
# ==========================================

if __name__ == "__main__":

    app.run(
        debug=True
    )