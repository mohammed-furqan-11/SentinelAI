import pandas as pd
from sklearn.ensemble import RandomForestClassifier
import joblib
import os


MODEL_PATH = "models/threat_model.pkl"
DATASET_PATH = "data/training_dataset.csv"


def create_model():
    model = RandomForestClassifier(
        n_estimators=100,
        random_state=42
    )

    return model


def train_model():
    dataset = pd.read_csv(DATASET_PATH)

    features = [
        "failed_attempts",
        "suspicious_login",
        "risk_score"
    ]

    X = dataset[features]
    y = dataset["label"]

    model = create_model()

    model.fit(X, y)

    return model


def save_model(model):
    os.makedirs("models", exist_ok=True)

    joblib.dump(model, MODEL_PATH)

    print(f"Trained model saved to: {MODEL_PATH}")


if __name__ == "__main__":
    print("--- SentinelAI ML Training ---")

    model = train_model()

    save_model(model)

    print("Model training completed successfully.")