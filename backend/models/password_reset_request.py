from datetime import datetime, timedelta, timezone

from sqlalchemy import Column, DateTime, ForeignKey, Integer, String

from ..database.connection import Base

PASSWORD_RESET_REQUEST_LIFETIME = timedelta(days=2)


def utc_now():
    return datetime.now(timezone.utc)


class PasswordResetRequest(Base):
    __tablename__ = "password_reset_requests"

    request_id = Column(String(64), primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    pending_user_id = Column(
        Integer,
        ForeignKey("users.id"),
        unique=True,
        nullable=True,
    )
    email = Column(String(255), nullable=False)
    new_password_hash = Column(String(255), nullable=True)
    status = Column(String(16), nullable=False, default="pending", index=True)
    requested_at = Column(DateTime(timezone=True), nullable=False, default=utc_now)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    reviewed_by_user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    reviewed_at = Column(DateTime(timezone=True), nullable=True)
