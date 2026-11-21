"""
Model Training Module for Phishing Detection.
Trains, tunes, and saves Logistic Regression, Random Forest, and XGBoost models.
Selects and saves the best-performing model based on validation metrics.
"""

import os
import sys
from pathlib import Path
from typing import Dict, Any, Tuple
import joblib
import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import f1_score, roc_auc_score, accuracy_score
from xgboost import XGBClassifier

# Add project root to path for imports
ROOT_DIR = Path(__file__).resolve().parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from ml.preprocessing.preprocessor import run_pipeline


class ModelTrainer:
    """Trains and compares multiple classification models for phishing detection."""

    def __init__(self, saved_models_dir: str = None):
        if saved_models_dir is None:
            saved_models_dir = str(ROOT_DIR / "ml" / "saved_models")
        self.saved_models_dir = saved_models_dir
        os.makedirs(self.saved_models_dir, exist_ok=True)

    def load_data(self) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray, list]:
        """Loads preprocessed data arrays, triggering preprocessing if necessary."""
        npz_path = os.path.join(self.saved_models_dir, "preprocessed_data.npz")
        if not os.path.exists(npz_path):
            print("Preprocessed data not found. Running preprocessor pipeline first...")
            run_pipeline(output_dir=self.saved_models_dir)

        data = np.load(npz_path, allow_pickle=True)
        X_train = data["X_train"]
        X_test = data["X_test"]
        y_train = data["y_train"]
        y_test = data["y_test"]
        feature_names = list(data["feature_names"])
        print(f"Loaded datasets - Train: {X_train.shape}, Test: {X_test.shape}, Features: {len(feature_names)}")
        return X_train, X_test, y_train, y_test, feature_names

    def get_models(self) -> Dict[str, Any]:
        """Instantiates the candidate classifiers with production hyperparameters."""
        return {
            "logistic_regression": LogisticRegression(
                max_iter=1000,
                C=1.0,
                class_weight="balanced",
                solver="lbfgs",
                random_state=42
            ),
            "random_forest": RandomForestClassifier(
                n_estimators=100,
                max_depth=14,
                min_samples_split=4,
                class_weight="balanced",
                random_state=42,
                n_jobs=-1
            ),
            "xgboost": XGBClassifier(
                n_estimators=120,
                max_depth=6,
                learning_rate=0.08,
                subsample=0.85,
                colsample_bytree=0.85,
                eval_metric="logloss",
                random_state=42
            )
        }

    def train_and_select_best(self) -> Dict[str, Any]:
        """Trains all models, computes preliminary validation scores, and saves best model."""
        X_train, X_test, y_train, y_test, feature_names = self.load_data()
        models = self.get_models()

        best_model_name = None
        best_f1 = -1.0
        best_model_obj = None
        results = {}

        for name, model in models.items():
            print(f"\n--- Training {name} ---")
            model.fit(X_train, y_train)

            # Predictions on test split
            y_pred = model.predict(X_test)
            if hasattr(model, "predict_proba"):
                y_prob = model.predict_proba(X_test)[:, 1]
            else:
                y_prob = model.decision_function(X_test)

            acc = float(accuracy_score(y_test, y_pred))
            f1 = float(f1_score(y_test, y_pred, zero_division=0))
            auc = float(roc_auc_score(y_test, y_prob))

            print(f"  Accuracy: {acc:.4f} | F1-Score: {f1:.4f} | ROC-AUC: {auc:.4f}")

            # Save individual model
            model_path = os.path.join(self.saved_models_dir, f"{name}.joblib")
            joblib.dump(model, model_path)
            print(f"  Saved to: {model_path}")

            results[name] = {
                "accuracy": acc,
                "f1_score": f1,
                "roc_auc": auc,
                "model_path": model_path
            }

            if f1 > best_f1:
                best_f1 = f1
                best_model_name = name
                best_model_obj = model

        # Save best model
        best_model_path = os.path.join(self.saved_models_dir, "best_model.joblib")
        joblib.dump(best_model_obj, best_model_path)
        print(f"\n>>> Best Model: '{best_model_name}' (F1: {best_f1:.4f})")
        print(f">>> Saved as champion model to: {best_model_path}")

        return {
            "best_model": best_model_name,
            "best_f1": best_f1,
            "results": results
        }


def main():
    trainer = ModelTrainer()
    trainer.train_and_select_best()


if __name__ == "__main__":
    main()
