from sqlalchemy import Column, DateTime, String

from ..database.connection import Base


class CaptchaChallenge(Base):
    __tablename__ = "captcha_challenges"

    challenge_id = Column(String(64), primary_key=True)
    answer_hash = Column(String(64), nullable=False)
    requester_hash = Column(String(64), nullable=False, index=True)
    purpose = Column(String(16), nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False, index=True)
    expires_at = Column(DateTime(timezone=True), nullable=False, index=True)
    consumed_at = Column(DateTime(timezone=True), nullable=True)
