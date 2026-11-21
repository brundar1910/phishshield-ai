"""
Comprehensive Evaluation Pipeline for Phishing Detection ML Models.
Evaluates Logistic Regression, Random Forest, and XGBoost on the isolated test set.
Computes genuine metrics: Accuracy, Precision, Recall, F1-Score, ROC-AUC, Confusion Matrix,
and feature importances. Saves the complete evaluation report to disk.
"""

import json
import os
import sys
from pathlib import Path
from typing import Any, Dict

import joblib
import numpy as np
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

# Add project root to path
ROOT_DIR = Path(__file__).resolve().parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))


class ModelEvaluator:
    """Evaluates trained classification models and persists verified metrics."""

    def __init__(self, saved_models_dir: str = None):
        if saved_models_dir is None:
            saved_models_dir = str(ROOT_DIR / "ml" / "saved_models")
        self.saved_models_dir = saved_models_dir

    def load_test_data(self):
        """Loads the preprocessed test set and feature names."""
        npz_path = os.path.join(self.saved_models_dir, "preprocessed_data.npz")
        if not os.path.exists(npz_path):
            raise FileNotFoundError(
                f"Preprocessed dataset not found at {npz_path}. Run training or preprocessing first."
            )
        data = np.load(npz_path, allow_pickle=True)
        X_test = data["X_test"]
        y_test = data["y_test"]
        feature_names = list(data["feature_names"])
        return X_test, y_test, feature_names

    def evaluate_model(
        self, model: Any, model_name: str, X_test: np.ndarray, y_test: np.ndarray, feature_names: list
    ) -> Dict[str, Any]:
        """Calculates all key metrics for a given model."""
        y_pred = model.predict(X_test)

        if hasattr(model, "predict_proba"):
            y_prob = model.predict_proba(X_test)[:, 1]
        elif hasattr(model, "decision_function"):
            decision = model.decision_function(X_test)
            y_prob = 1 / (1 + np.exp(-decision))
        else:
            y_prob = y_pred.astype(float)

        acc = float(accuracy_score(y_test, y_pred))
        prec = float(precision_score(y_test, y_pred, zero_division=0))
        rec = float(recall_score(y_test, y_pred, zero_division=0))
        f1 = float(f1_score(y_test, y_pred, zero_division=0))
        auc = float(roc_auc_score(y_test, y_prob))
        cm = confusion_matrix(y_test, y_pred).tolist()
        tn, fp, fn, tp = int(cm[0][0]), int(cm[0][1]), int(cm[1][0]), int(cm[1][1])

        clf_report = classification_report(y_test, y_pred, output_dict=True)

        # Feature importances or coefficients
        feature_importance_dict = {}
        if hasattr(model, "feature_importances_"):
            importances = model.feature_importances_
            ranked_indices = np.argsort(importances)[::-1]
            for idx in ranked_indices[:10]:
                feature_importance_dict[feature_names[idx]] = round(float(importances[idx]), 4)
        elif hasattr(model, "coef_"):
            coefs = model.coef_[0]
            ranked_indices = np.argsort(np.abs(coefs))[::-1]
            for idx in ranked_indices[:10]:
                feature_importance_dict[feature_names[idx]] = round(float(coefs[idx]), 4)

        return {
            "model_name": model_name,
            "accuracy": round(acc, 4),
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1_score": round(f1, 4),
            "roc_auc": round(auc, 4),
            "confusion_matrix": {
                "raw": cm,
                "true_negatives": tn,
                "false_positives": fp,
                "false_negatives": fn,
                "true_positives": tp,
            },
            "top_features": feature_importance_dict,
            "classification_report": clf_report,
        }

    def evaluate_all(self) -> Dict[str, Any]:
        """Loads all saved models, generates metrics, and persists to disk."""
        X_test, y_test, feature_names = self.load_test_data()

        candidate_names = ["logistic_regression", "random_forest", "xgboost"]
        all_metrics = {
            "test_sample_count": int(len(y_test)),
            "test_class_distribution": {
                "benign (0)": int(np.sum(y_test == 0)),
                "phishing (1)": int(np.sum(y_test == 1)),
            },
            "models": {},
        }

        print("\n" + "=" * 70)
        print("          PHISHING DETECTION MODEL BENCHMARK & EVALUATION")
        print("=" * 70)
        print(f"Test Set Size: {len(y_test)} URLs ({np.sum(y_test == 0)} Benign, {np.sum(y_test == 1)} Phishing)")
        print("-" * 70)
        header = f"{'Model':<22} | {'Accuracy':<9} | {'Precision':<9} | {'Recall':<9} | {'F1':<9} | {'ROC-AUC':<9}"
        print(header)
        print("-" * 70)

        for name in candidate_names:
            model_path = os.path.join(self.saved_models_dir, f"{name}.joblib")
            if not os.path.exists(model_path):
                print(f"[WARN] Model file not found: {model_path}. Skipping.")
                continue

            model = joblib.load(model_path)
            metrics = self.evaluate_model(model, name, X_test, y_test, feature_names)
            all_metrics["models"][name] = metrics

            row = (
                f"{name:<22} | "
                f"{metrics['accuracy']:<9.4f} | "
                f"{metrics['precision']:<9.4f} | "
                f"{metrics['recall']:<9.4f} | "
                f"{metrics['f1_score']:<9.4f} | "
                f"{metrics['roc_auc']:<9.4f}"
            )
            print(row)

        print("=" * 70)

        # Identify champion model based on highest F1-Score
        if all_metrics["models"]:
            best_model_name = max(
                all_metrics["models"].keys(),
                key=lambda k: all_metrics["models"][k]["f1_score"],
            )
            all_metrics["champion_model"] = best_model_name
            print(f">>> Champion Model: '{best_model_name}' with F1={all_metrics['models'][best_model_name]['f1_score']}")

        # Persist metrics to JSON
        metrics_file = os.path.join(self.saved_models_dir, "metrics.json")
        with open(metrics_file, "w", encoding="utf-8") as f:
            json.dump(all_metrics, f, indent=2)
        print(f"\n[INFO] Complete evaluation metrics saved to: {metrics_file}")

        return all_metrics


def main():
    evaluator = ModelEvaluator()
    evaluator.evaluate_all()


if __name__ == "__main__":
    main()
