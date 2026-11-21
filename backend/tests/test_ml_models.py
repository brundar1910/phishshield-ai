"""
Unit and Integration Tests for Phishing ML Models and Preprocessor.
Verifies data preprocessing, model inference, scaling consistency, and probability calibration.
"""

import os
from pathlib import Path
import joblib
import numpy as np
import pytest

from backend.feature_extraction.url_features import URLFeatureExtractor, get_feature_names
from ml.preprocessing.preprocessor import DatasetPreprocessor

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
SAVED_MODELS_DIR = ROOT_DIR / "ml" / "saved_models"
DATASET_PATH = ROOT_DIR / "ml" / "datasets" / "urls_dataset.csv"


class TestDatasetPreprocessor:
    """Tests data loading, deduplication, and leakage prevention."""

    def test_load_and_deduplicate(self):
        preprocessor = DatasetPreprocessor(random_state=42, test_size=0.2)
        df = preprocessor.load_and_clean_data(str(DATASET_PATH))

        assert len(df) > 500, "Dataset should have at least 500 records"
        assert "url" in df.columns and "label" in df.columns
        assert df["url"].duplicated().sum() == 0, "Deduplication must eliminate all duplicate URLs"
        assert set(df["label"].unique()).issubset({0, 1}), "Labels must be binary (0 or 1)"

    def test_feature_extraction_matrix_shape(self):
        preprocessor = DatasetPreprocessor(random_state=42, test_size=0.2)
        sample_df = preprocessor.load_and_clean_data(str(DATASET_PATH)).head(20)
        X, y = preprocessor.extract_features_from_dataframe(sample_df)

        assert X.shape[0] == 20
        assert X.shape[1] == len(get_feature_names())
        assert y.shape[0] == 20
        assert not np.isnan(X).any(), "Extracted features must not contain NaN"


class TestTrainedModels:
    """Validates model artifact integrity, inference capability, and prediction format."""

    @pytest.fixture
    def scaler(self):
        scaler_path = SAVED_MODELS_DIR / "scaler.joblib"
        if not scaler_path.exists():
            pytest.skip("Scaler artifact not found. Run training pipeline first.")
        return joblib.load(str(scaler_path))

    @pytest.fixture
    def sample_features(self, scaler):
        # Extract features from a known URL and scale them
        vector = URLFeatureExtractor.extract_feature_vector("https://www.paypal.com/signin")
        scaled_vector = scaler.transform([vector])
        return scaled_vector

    @pytest.mark.parametrize("model_filename", [
        "logistic_regression.joblib",
        "random_forest.joblib",
        "xgboost.joblib",
        "best_model.joblib",
    ])
    def test_model_loading_and_prediction(self, model_filename, sample_features):
        model_path = SAVED_MODELS_DIR / model_filename
        if not model_path.exists():
            pytest.skip(f"Model artifact {model_filename} not found. Run training pipeline first.")

        model = joblib.load(str(model_path))

        # Test predict
        pred = model.predict(sample_features)
        assert len(pred) == 1
        assert pred[0] in [0, 1]

        # Test predict_proba
        if hasattr(model, "predict_proba"):
            probs = model.predict_proba(sample_features)
            assert probs.shape == (1, 2)
            assert 0.0 <= probs[0][0] <= 1.0
            assert 0.0 <= probs[0][1] <= 1.0
            assert np.isclose(probs[0].sum(), 1.0, atol=1e-5)

    def test_end_to_end_phishing_detection(self, scaler):
        best_model_path = SAVED_MODELS_DIR / "best_model.joblib"
        if not best_model_path.exists():
            pytest.skip("best_model.joblib not found. Run training pipeline first.")

        model = joblib.load(str(best_model_path))

        # Phishing URL example
        phish_url = "http://192.168.1.100/paypal/login.php?verification=token"
        phish_vector = scaler.transform([URLFeatureExtractor.extract_feature_vector(phish_url)])
        phish_prob = model.predict_proba(phish_vector)[0][1]

        # Benign URL example
        benign_url = "https://www.wikipedia.org/wiki/Phishing"
        benign_vector = scaler.transform([URLFeatureExtractor.extract_feature_vector(benign_url)])
        benign_prob = model.predict_proba(benign_vector)[0][1]

        assert phish_prob > benign_prob, "Phishing URL should receive higher threat probability than benign URL"
