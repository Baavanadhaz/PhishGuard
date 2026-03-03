# app/routes/history_routes.py
from typing import List

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app import models, schemas
from app.auth import get_current_user
from app.database import get_db

router = APIRouter()


@router.get(
    "/",
    response_model=List[schemas.ScanOut],
    summary="Retrieve your last 50 URL scans (🔒 requires Bearer token)",
)
def get_history(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    """
    Returns the authenticated user's last 50 URL scans, newest first.
    """
    scans = (
        db.query(models.ScanHistory)
        .filter(models.ScanHistory.user_id == current_user.id)
        .order_by(models.ScanHistory.created_at.desc())
        .limit(50)
        .all()
    )
    return scans
