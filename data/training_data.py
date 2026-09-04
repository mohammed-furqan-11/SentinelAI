import pandas as pd
import os


def create_training_data():
    data = [
        # failed_attempts, suspicious_login, risk_score, label
        [0, 0, 10, 0],
        [1, 0, 40, 0],
        [2, 0, 40, 0],
        [0, 1, 70, 1],
        [1, 1, 70, 1],
        [3, 1, 70, 1],
        [5, 0, 95, 1],
        [6, 0, 95, 1],
        [8, 0, 95, 1],
        [10, 0, 95, 1],
        [2, 1, 70, 1],
        [0, 0, 10, 0],
        [1, 0, 40, 0],
        [4, 0, 40, 0],
        [7, 0, 95, 1],
        [9, 0, 95, 1]
    ]

    columns = [
        "failed_attempts",
        "suspicious_login",
        "risk_score",
        "label"
    ]

    df = pd.DataFrame(data, columns=columns)

    return df


def save_training_data(df):
    file_path = "data/training_dataset.csv"

    os.makedirs("data", exist_ok=True)

    df.to_csv(file_path, index=False)

    print(f"Training dataset saved to: {file_path}")


if __name__ == "__main__":
    dataset = create_training_data()

    print("--- SentinelAI Training Dataset ---")
    print(dataset)

    print(f"\nTotal training samples: {len(dataset)}")

    save_training_data(dataset)