import pickle
import os
import logging

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────
#  MODEL PATHS
# ─────────────────────────────────────────────

BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "../../models/email_model.pkl")
VECT_PATH  = os.path.join(BASE_DIR, "../../models/vectorizer.pkl")

# ─────────────────────────────────────────────
#  LOAD MODEL SAFELY
# ─────────────────────────────────────────────

model      = None
vectorizer = None
_model_loaded = False


def _load_models():
    """
    Loads model and vectorizer from disk.
    Called once on first prediction request — not at import time.
    This prevents the entire backend from crashing if model files are missing.
    """
    global model, vectorizer, _model_loaded

    if _model_loaded:
        return True

    # Check files exist before attempting load
    if not os.path.exists(MODEL_PATH):
        logger.error(f"Model file not found: {MODEL_PATH}")
        return False

    if not os.path.exists(VECT_PATH):
        logger.error(f"Vectorizer file not found: {VECT_PATH}")
        return False

    try:
        with open(MODEL_PATH, "rb") as f:
            model = pickle.load(f)

        with open(VECT_PATH, "rb") as f:
            vectorizer = pickle.load(f)

        _model_loaded = True
        logger.info("ML email model loaded successfully")
        return True

    except Exception as e:
        logger.error(f"Failed to load ML model: {e}")
        return False


def predict_email_probability(subject, body):
    """
    Returns phishing probability between 0.0 and 1.0.
    Returns 0.0 if model is unavailable (fails gracefully).
    
    Args:
        subject: Email subject line
        body:    Email body text
    
    Returns:
        float: Probability score (0.0 = safe, 1.0 = definitely phishing)
    """
    # Attempt to load models if not yet loaded
    if not _load_models():
        logger.warning("ML model unavailable — returning default score 0.0")
        return 0.0

    try:
        # Sanitize inputs
        subject = str(subject).strip() if subject else ""
        body    = str(body).strip()    if body    else ""

        if not subject and not body:
            return 0.0

        # Combine subject and body — subject weighted more (repeated)
        text = f"{subject} {subject} {body}"

        # Vectorize and predict
        vec  = vectorizer.transform([text])
        prob = model.predict_proba(vec)[0][1]

        # Clamp to valid range
        return float(max(0.0, min(1.0, prob)))

    except Exception as e:
        logger.error(f"ML prediction failed: {e}")
        return 0.0


def get_model_info():
    """
    Returns metadata about the loaded model.
    Useful for dashboard and debugging.
    """
    if not _load_models():
        return {"status": "unavailable", "error": "Model files not found"}

    return {
        "status":     "loaded",
        "model_type": type(model).__name__,
        "model_path": MODEL_PATH,
        "vect_path":  VECT_PATH,
    }