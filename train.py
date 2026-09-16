import os
import pandas as pd
import joblib

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report

from feature_extraction import extract_features


print("======================================")
print(" AI PHISHING DETECTION - MODEL TRAINING")
print("======================================")

print("\nLoading Dataset...")

dataset_path = "dataset/phishing.csv"

df = pd.read_csv(dataset_path)

# Basic validation
if "url" not in df.columns or "label" not in df.columns:
    raise ValueError(
        "Dataset must contain 'url' and 'label' columns."
    )

# Remove empty rows
df = df.dropna(subset=["url", "label"])

# Convert values
df["url"] = df["url"].astype(str)
df["label"] = df["label"].astype(int)

print("\nDataset Information:")
print("Total URLs :", len(df))
print("Safe URLs  :", sum(df["label"] == 0))
print("Phishing URLs :", sum(df["label"] == 1))

print("\nExtracting Features...")

X = []

for url in df["url"]:
    X.append(extract_features(url))

y = df["label"]

print("Features extracted:", len(X[0]))

print("\nSplitting Dataset...")

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)

print("Training samples :", len(X_train))
print("Testing samples  :", len(X_test))

print("\nTraining Random Forest Model...")

model = RandomForestClassifier(
    n_estimators=500,
    max_depth=12,
    min_samples_split=2,
    min_samples_leaf=1,
    class_weight="balanced",
    random_state=42,
    n_jobs=-1
)

model.fit(X_train, y_train)

print("\nTesting Model...")

prediction = model.predict(X_test)

accuracy = accuracy_score(y_test, prediction)

print("\n======================================")
print("MODEL RESULT")
print("======================================")

print("Accuracy :", round(accuracy * 100, 2), "%")

print("\nClassification Report:")
print(
    classification_report(
        y_test,
        prediction,
        zero_division=0
    )
)

# Create model directory
os.makedirs("models", exist_ok=True)

# Save model
joblib.dump(model, "models/model.pkl")

print("\nModel Saved Successfully!")
print("Location: models/model.pkl")