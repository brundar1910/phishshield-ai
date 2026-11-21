"""Automated Training and Evaluation Runner."""
import subprocess
import sys

def main():
    print(">>> 1. Training ML models (Logistic Regression, Random Forest, XGBoost)...")
    res1 = subprocess.run([sys.executable, "ml/training/train.py"])
    if res1.returncode != 0:
        sys.exit(res1.returncode)

    print("\n>>> 2. Running Evaluation pipeline...")
    res2 = subprocess.run([sys.executable, "ml/evaluation/evaluate.py"])
    if res2.returncode != 0:
        sys.exit(res2.returncode)

    print("\n>>> Training and Evaluation Completed Successfully!")

if __name__ == "__main__":
    main()
