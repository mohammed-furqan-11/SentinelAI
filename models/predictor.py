import pandas as pd
import joblib


MODEL_PATH = "models/threat_model.pkl"


def predict_threat(failed_attempts, suspicious_login, risk_score):
    model = joblib.load(MODEL_PATH)

    data = pd.DataFrame([{
        "failed_attempts": failed_attempts,
        "suspicious_login": suspicious_login,
        "risk_score": risk_score
    }])

    prediction = model.predict(data)[0]
    probability = model.predict_proba(data)[0][1]

    return {
        "prediction": int(prediction),
        "threat_probability": round(float(probability) * 100, 2)
    }


if __name__ == "__main__":
    print("--- Suspicious Login Test ---")

    result = predict_threat(
        failed_attempts=1,
        suspicious_login=1,
        risk_score=70
    )

    print(f"Prediction: {result['prediction']}")
    print(f"Threat Probability: {result['threat_probability']}%")