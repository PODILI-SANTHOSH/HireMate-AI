
from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ..models.progress import UserProgress
from ..models.user import User
from .auth import AuthenticatedUser, get_authenticated_user, get_db

router = APIRouter(prefix="/progress", tags=["User Progress"])

def get_logged_in_user(
    authenticated_user: AuthenticatedUser = Depends(get_authenticated_user),
):
    return authenticated_user.user


class ProgressCreate(BaseModel):
    feature: str = Field(min_length=1, max_length=50)
    activity_type: str = Field(min_length=1, max_length=100)
    details: dict | None = None


@router.post("")
def save_progress(
    payload: ProgressCreate,
    db: Session = Depends(get_db),
    user: User = Depends(get_logged_in_user),
):
    record = UserProgress(
        user_id=user.id,
        feature=payload.feature,
        activity_type=payload.activity_type,
        details=payload.details,
    )
    db.add(record)
    db.commit()
    db.refresh(record)

    return {
        "message": "Progress saved",
        "id": record.id,
        "feature": record.feature,
        "activity_type": record.activity_type,
        "details": record.details,
        "created_at": record.created_at,
    }


@router.get("")
def get_my_progress(
    db: Session = Depends(get_db),
    user: User = Depends(get_logged_in_user),
):
    records = (
        db.query(UserProgress)
        .filter(UserProgress.user_id == user.id)
        .order_by(UserProgress.created_at.desc())
        .all()
    )

    return [
        {
            "id": record.id,
            "feature": record.feature,
            "activity_type": record.activity_type,
            "details": record.details,
            "created_at": record.created_at,
        }
        for record in records
    ]
