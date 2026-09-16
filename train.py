import pandas as pd
import joblib

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report

from feature_extraction import extract_features

print("Loading Dataset...")

# Dataset Load
df = pd.read_csv("dataset/phishing.csv")

print(df.head())

# URL aur Label Columns
urls = df["url"]
labels = df["label"]

print("Extracting Features...")

X = []

for url in urls:
    X.append(extract_features(str(url)))

y = labels

print("Splitting Dataset...")

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42
)

print("Training Model...")

model = RandomForestClassifier(
    n_estimators=200,
    random_state=42
)

model.fit(X_train, y_train)

print("Testing Model...")

prediction = model.predict(X_test)

accuracy = accuracy_score(y_test, prediction)

print("Accuracy :", accuracy)

print(classification_report(y_test, prediction))

joblib.dump(model, "models/model.pkl")

print("Model Saved Successfully!")