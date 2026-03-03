# app/routes/predict_routes.py
from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from app import models, schemas
from app.auth import get_current_user
from app.database import get_db
from app.ml.predictor import predict_url

router = APIRouter()


@router.post(
    "/predict",
    response_model=schemas.PredictResponse,
    status_code=status.HTTP_200_OK,
    summary="Analyse a URL for phishing (🔒 requires Bearer token)",
)
def predict(
    payload: schemas.PredictRequest,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    result = predict_url(payload.url)

    scan = models.ScanHistory(
        user_id=current_user.id,
        url=payload.url,
        result=result["result"],
        confidence=result["confidence"],
        reason=result["reason"],
    )
    db.add(scan)
    db.commit()

    return schemas.PredictResponse(
        url=payload.url,
        result=result["result"],
        confidence=result["confidence"],
        reason=result["reason"],
    )