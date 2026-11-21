"""
Dataset Preprocessor for Phishing Detection.
Loads raw URLs, extracts engineered features, enforces strict train/test isolation,
fits StandardScaler on the training split only, and exports preprocessed sets.
"""

import os
import sys
from pathlib import Path
from typing import Tuple, Dict, Any
import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

# Add project root to path for imports
ROOT_DIR = Path(__file__).resolve().parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from backend.feature_extraction.url_features import URLFeatureExtractor, get_feature_names


class DatasetPreprocessor:
    """Preprocesses raw URL datasets into standardized feature matrices."""

    def __init__(self, random_state: int = 42, test_size: float = 0.2):
        self.random_state = random_state
        self.test_size = test_size
        self.scaler = StandardScaler()
        self.feature_names = get_feature_names()

    def load_and_clean_data(self, csv_path: str) -> pd.DataFrame:
        """Loads and deduplicates the raw URL dataset."""
        df = pd.read_csv(csv_path)
        if "url" not in df.columns or "label" not in df.columns:
            raise ValueError(f"Dataset must contain 'url' and 'label' columns. Found: {list(df.columns)}")

        # Deduplicate by URL to prevent train/test leakage
        initial_len = len(df)
        df = df.dropna(subset=["url", "label"])
        df["url"] = df["url"].astype(str).str.strip()
        df["label"] = df["label"].astype(int)
        df = df.drop_duplicates(subset=["url"]).reset_index(drop=True)
        dedup_len = len(df)
        print(f"Loaded {initial_len} records. Deduplicated to {dedup_len} unique URLs.")
        print(f"Class distribution: {df['label'].value_counts().to_dict()}")
        return df

    def extract_features_from_dataframe(self, df: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray]:
        """Extracts numerical feature matrix from URLs in dataframe."""
        urls = df["url"].tolist()
        labels = df["label"].to_numpy(dtype=np.int32)

        print(f"Extracting {len(self.feature_names)} features for {len(urls)} URLs...")
        feature_rows = []
        for i, url in enumerate(urls):
            vector = URLFeatureExtractor.extract_feature_vector(url)
            feature_rows.append(vector)
            if (i + 1) % 500 == 0 or (i + 1) == len(urls):
                print(f"  Processed {i + 1}/{len(urls)} URLs")

        X = np.array(feature_rows, dtype=np.float32)
        return X, labels

    def prepare_train_test_split(
        self, X: np.ndarray, y: np.ndarray
    ) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
        """
        Stratified train/test split with strict leakage prevention.
        StandardScaler is fitted strictly on X_train, then transforms X_train and X_test.
        """
        X_train, X_test, y_train, y_test = train_test_split(
            X,
            y,
            test_size=self.test_size,
            random_state=self.random_state,
            stratify=y
        )

        print(f"Train set: {X_train.shape[0]} samples | Test set: {X_test.shape[0]} samples")

        # Fit scaler ONLY on X_train to avoid data leakage
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)

        return X_train_scaled, X_test_scaled, y_train, y_test

    def save_artifacts(
        self,
        output_dir: str,
        X_train_scaled: np.ndarray,
        X_test_scaled: np.ndarray,
        y_train: np.ndarray,
        y_test: np.ndarray,
    ) -> Dict[str, str]:
        """Saves scaler and preprocessed matrices."""
        os.makedirs(output_dir, exist_ok=True)
        scaler_path = os.path.join(output_dir, "scaler.joblib")
        data_path = os.path.join(output_dir, "preprocessed_data.npz")

        joblib.dump(self.scaler, scaler_path)
        np.savez_compressed(
            data_path,
            X_train=X_train_scaled,
            X_test=X_test_scaled,
            y_train=y_train,
            y_test=y_test,
            feature_names=np.array(self.feature_names)
        )

        print(f"Saved fitted scaler to: {scaler_path}")
        print(f"Saved preprocessed arrays to: {data_path}")

        return {"scaler_path": scaler_path, "data_path": data_path}


def run_pipeline(
    dataset_path: str = None,
    output_dir: str = None
) -> Dict[str, Any]:
    """Runs end-to-end preprocessing pipeline."""
    if dataset_path is None:
        dataset_path = str(ROOT_DIR / "ml" / "datasets" / "urls_dataset.csv")
    if output_dir is None:
        output_dir = str(ROOT_DIR / "ml" / "saved_models")

    preprocessor = DatasetPreprocessor(random_state=42, test_size=0.2)
    df = preprocessor.load_and_clean_data(dataset_path)
    X, y = preprocessor.extract_features_from_dataframe(df)
    X_train_scaled, X_test_scaled, y_train, y_test = preprocessor.prepare_train_test_split(X, y)

    saved_paths = preprocessor.save_artifacts(
        output_dir=output_dir,
        X_train_scaled=X_train_scaled,
        X_test_scaled=X_test_scaled,
        y_train=y_train,
        y_test=y_test,
    )

    return {
        "num_samples": len(df),
        "train_samples": len(y_train),
        "test_samples": len(y_test),
        "feature_count": len(preprocessor.feature_names),
        **saved_paths
    }


if __name__ == "__main__":
    run_pipeline()
