from flask import Flask, render_template, request
import joblib

from feature_extraction import extract_features

app = Flask(__name__)

model = joblib.load("models/model.pkl")


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/predict", methods=["POST"])
def predict():

    url = request.form["url"]

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
        phishing=phishing,
    )


if __name__ == "__main__":
    app.run(debug=True)