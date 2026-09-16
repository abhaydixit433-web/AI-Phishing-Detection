from flask import Flask, render_template, request
import joblib
import requests
from feature_extraction import extract_features

app = Flask(__name__)

model = joblib.load("models/model.pkl")


@app.route("/")
def home():
    return render_template("index.html")


def check_url_exists(url):
    """
    Check whether the URL is reachable/existing.
    Returns:
        True  -> URL is reachable
        False -> URL does not exist / cannot be reached
    """

    try:
        # Agar user http/https nahi likhta
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        response = requests.head(
            url,
            timeout=5,
            allow_redirects=True
        )

        # 200-499 ka response means server/domain responded.
        # 404 bhi technically website/server ka response hai,
        # isliye usse completely non-existent nahi maan rahe.
        if response.status_code < 500:
            return True

        return False

    except requests.exceptions.RequestException:
        return False


@app.route("/predict", methods=["POST"])
def predict():

    url = request.form["url"].strip()

    # Empty URL check
    if not url:
        return render_template(
            "index.html",
            url=url,
            result="❌ Please enter a URL",
            safe=0,
            phishing=0
        )

    # URL existence/reachability check
    if not check_url_exists(url):

        return render_template(
            "index.html",
            url=url,
            result="❌ URL Does Not Exist / Unreachable",
            safe=0,
            phishing=0
        )

    # AI/ML prediction
    features = extract_features(url)

    prediction = model.predict([features])[0]

    probability = model.predict_proba([features])[0]

    safe = round(probability[0] * 100, 2)
    phishing = round(probability[1] * 100, 2)

    if prediction == 1:
        result = "⚠️ Phishing Website Detected"
    else:
        result = "✅ Safe Website"

    return render_template(
        "index.html",
        url=url,
        result=result,
        safe=safe,
        phishing=phishing
    )


if __name__ == "__main__":
    app.run(debug=True)