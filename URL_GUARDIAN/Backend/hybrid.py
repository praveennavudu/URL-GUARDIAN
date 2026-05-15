import sqlite3
import os
import joblib
import pandas as pd
import re
from whitelist import is_trusted_domain

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATABASE_PATH = os.path.join(BASE_DIR, "url_guardian.db")
MODEL_PATH = os.path.join(os.path.dirname(__file__), "url_model.pkl")


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


def check_database(url):
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()

    cursor.execute("SELECT threat_type FROM urls WHERE url=?", (url,))
    result = cursor.fetchone()

    conn.close()
    return result[0] if result else None


def risk_grade(percent):
    if percent <= 30:
        return "LOW"
    elif percent <= 70:
        return "MEDIUM"
    else:
        return "HIGH"


def adaptive_threshold(url):
    if len(url) > 100:
        return 40
    elif url.count("-") > 3:
        return 45
    else:
        return 50


def save_prediction_to_db(url, threat_type):
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()

    cursor.execute(
        "INSERT OR IGNORE INTO urls (url, threat_type) VALUES (?, ?)",
        (url, threat_type)
    )

    conn.commit()
    conn.close()


def predict_with_model(url):
    if not os.path.exists(MODEL_PATH):
        raise Exception("Model not trained. Run model.py first.")

    model = joblib.load(MODEL_PATH)

    features = extract_features(url)
    X = pd.DataFrame([features])

    prediction = model.predict(X)[0]
    probabilities = model.predict_proba(X)[0]

    max_prob = max(probabilities)
    risk_percent = round(max_prob * 100, 2)

    return prediction, risk_percent


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


def hybrid_check(url):

    # Step 1 — Whitelist
    if is_trusted_domain(url):
        return {
            "threat_type": "legit",
            "risk_score": 0,
            "risk_level": "LOW",
            "adaptive_threshold": 0,
            "reason": "Trusted domain (Whitelist)"
        }

    # Step 2 — Database
    db_result = check_database(url)
    if db_result:
        return {
            "threat_type": db_result,
            "risk_score": 100,
            "risk_level": "HIGH",
            "adaptive_threshold": 100,
            "reason": "URL found in database"
        }

    # Step 3 — Machine Learning
    prediction, risk = predict_with_model(url)
    threshold = adaptive_threshold(url)

    if risk > threshold:
        final_prediction = prediction
    else:
        final_prediction = "legit"

    grade = risk_grade(risk)
    reasons = explain_url(url)

    if not reasons:
        reasons = ["No suspicious structural patterns found"]

    # Step 4 — Auto Learning
    save_prediction_to_db(url, final_prediction)

    return {
        "threat_type": final_prediction,
        "risk_score": risk,
        "risk_level": grade,
        "adaptive_threshold": threshold,
        "reason": reasons
    }