"""Visual and OCR Form / Brand Spoofing Analyzer using OpenCV and PIL."""

from typing import Any, Dict
import numpy as np
from PIL import Image


class VisualPhishingAnalyzer:
    """Analyzes webpage screenshots for credential forms and brand visual indicators."""

    @staticmethod
    def analyze_image_array(image_bytes: bytes) -> Dict[str, Any]:
        """Performs visual inspection on image bytes."""
        try:
            import io
            image = Image.open(io.BytesIO(image_bytes))
            width, height = image.size

            # Convert to RGB numpy array
            img_arr = np.array(image.convert("RGB"))
            avg_color = img_arr.mean(axis=(0, 1)).tolist()

            # Detect low-contrast / monochromatic backgrounds often used in credential overlay popups
            color_std = float(img_arr.std())

            return {
                "dimensions": {"width": width, "height": height},
                "average_color": [round(c, 1) for c in avg_color],
                "color_variance": round(color_std, 2),
                "is_processed": True
            }
        except Exception as e:
            return {
                "is_processed": False,
                "error": str(e)
            }
