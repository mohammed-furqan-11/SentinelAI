def calculate_final_risk(rule_score, ml_probability):
    final_score = (rule_score * 0.4) + (ml_probability * 0.6)

    final_score = round(final_score, 2)

    if final_score >= 90:
        risk_level = "CRITICAL"

    elif final_score >= 70:
        risk_level = "HIGH"

    elif final_score >= 30:
        risk_level = "MEDIUM"

    else:
        risk_level = "LOW"

    return {
        "final_risk_score": final_score,
        "risk_level": risk_level
    }


if __name__ == "__main__":
    test_cases = [
        {
            "name": "Normal Login",
            "rule_score": 10,
            "ml_probability": 0
        },
        {
            "name": "Failed Login",
            "rule_score": 40,
            "ml_probability": 0
        },
        {
            "name": "Suspicious Login",
            "rule_score": 70,
            "ml_probability": 95
        },
        {
            "name": "Brute-Force Attack",
            "rule_score": 95,
            "ml_probability": 99
        }
    ]

    print("--- SentinelAI Risk Engine ---")

    for test in test_cases:
        result = calculate_final_risk(
            test["rule_score"],
            test["ml_probability"]
        )

        print(f"\n{test['name']}")
        print(f"Final Score: {result['final_risk_score']}")
        print(f"Risk Level: {result['risk_level']}")
        