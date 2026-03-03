from app.db import SessionLocal
from app.models import Detection

db = SessionLocal()

try:
    row = Detection(
        url="https://example.com/login",
        prediction_label="phishing",
        prediction_score=0.92,
        features={"has_ip": False, "url_length": 24},
        model_version="v1"
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    print("✅ Inserted row id:", row.id)
finally:
    db.close()