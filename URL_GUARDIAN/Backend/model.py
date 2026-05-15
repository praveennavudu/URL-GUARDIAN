import sqlite3
import pandas as pd
import os
import re
import joblib

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATABASE_PATH = os.path.join(BASE_DIR, "url_guardian.db")
MODEL_PATH = os.path.join(os.path.dirname(__file__), "url_model.pkl")


def load_data_from_db():
    conn = sqlite3.connect(DATABASE_PATH)

    df = pd.read_sql_query(
        "SELECT url, threat_type FROM urls WHERE threat_type IS NOT NULL",
        conn
    )

    conn.close()

    df = df.dropna()
    df["url"] = df["url"].astype(str)

    return df


def extract_features(url):
    return {
        "length": len(url),
        "dots": url.count("."),
        "slashes": url.count("/"),
        "digits": sum(c.isdigit() for c in url),
        "special_chars": len(re.findall(r"[?&=]", url)),
        "has_https": 1 if "https" in url else 0,
        "has_ip": 1 if re.search(r"\d+\.\d+\.\d+\.\d+", url) else 0,
        "has_suspicious_words": 1 if re.search(
            r"login|verify|update|free|secure|account|bank",
            url.lower()
        ) else 0,
    }


def explain_url(url):
    reasons = []

    if "@" in url:
        reasons.append("Contains @ symbol")

    if url.count("-") > 3:
        reasons.append("Too many hyphens")

    if len(url) > 75:
        reasons.append("URL length unusually long")

    if url.count(".") > 5:
        reasons.append("Too many subdomains")

    if re.search(r"\d+\.\d+\.\d+\.\d+", url):
        reasons.append("Contains IP address")

    if re.search(r"login|verify|update|free|secure|account|bank", url.lower()):
        reasons.append("Contains suspicious keywords")

    return reasons


def train_model():
    print("Loading data from database...")

    df = load_data_from_db()

    if df.empty:
        print("❌ No data found in database.")
        return

    X = pd.DataFrame(df["url"].apply(extract_features).tolist())
    y = df["threat_type"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )

    model = RandomForestClassifier(n_estimators=150, random_state=42)
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)

    print("\nModel Evaluation:\n")
    print(classification_report(y_test, y_pred))

    joblib.dump(model, MODEL_PATH)
    print("\n✅ Multi-class Model Saved Successfully")


def predict_with_model(url):

    if not os.path.exists(MODEL_PATH):
        raise Exception("Model file not found. Train model first.")

    model = joblib.load(MODEL_PATH)

    features = extract_features(url)
    X = pd.DataFrame([features])

    prediction = model.predict(X)[0]
    probabilities = model.predict_proba(X)[0]

    max_prob = max(probabilities)
    risk_percent = round(max_prob * 100, 2)

    reasons = explain_url(url)

    return prediction, risk_percent, reasons


if __name__ == "__main__":
    train_model()