from app.db import SessionLocal
from app.models import Detection

def save_prediction(url: str, label: str, score: float, features: dict, model_version: str = "v1") -> str:
    db = SessionLocal()
    try:
        row = Detection(
            url=url,
            prediction_label=label,
            prediction_score=float(score) if score is not None else None,
            features=features,
            model_version=model_version
        )
        db.add(row)
        db.commit()
        db.refresh(row)
        return str(row.id)
    finally:
        db.close()