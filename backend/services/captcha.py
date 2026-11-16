import base64
import hashlib
import hmac
import io
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Literal

from fastapi import HTTPException, Request
from PIL import Image, ImageDraw, ImageFont
from sqlalchemy import func
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from ..models.captcha_challenge import CaptchaChallenge

CAPTCHA_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
CAPTCHA_LENGTH = 6
CAPTCHA_LIFETIME = timedelta(minutes=3)
CAPTCHA_RATE_WINDOW = timedelta(minutes=10)
CAPTCHA_HOURLY_WINDOW = timedelta(hours=1)
CAPTCHA_MAX_CHALLENGES_PER_WINDOW = 20
CAPTCHA_MAX_CHALLENGES_PER_HOUR = 100
CaptchaPurpose = Literal["registration", "recovery", "password_change"]


def generate_captcha_answer() -> str:
    return "".join(secrets.choice(CAPTCHA_ALPHABET) for _ in range(CAPTCHA_LENGTH))


def _answer_hash(challenge_id: str, answer: str) -> str:
    normalized_answer = answer.strip().upper()
    secret = os.getenv("JWT_SECRET_KEY", "local-captcha-rate-limit-key").encode(
        "utf-8"
    )
    return hmac.new(
        secret,
        f"{challenge_id}:{normalized_answer}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def _requester_hash(request: Request) -> str:
    client_ip = request.client.host if request.client else "unknown"
    secret = os.getenv("JWT_SECRET_KEY", "local-captcha-rate-limit-key").encode(
        "utf-8"
    )
    return hmac.new(secret, client_ip.encode("utf-8"), hashlib.sha256).hexdigest()


def _commit_challenge_change(db: Session) -> None:
    try:
        db.commit()
    except SQLAlchemyError as error:
        db.rollback()
        raise HTTPException(
            status_code=503,
            detail="CAPTCHA verification is temporarily unavailable.",
        ) from error


def _render_captcha(answer: str) -> str:
    width, height = 280, 82
    image = Image.new("RGB", (width, height), "#f1f2ff")
    draw = ImageDraw.Draw(image)
    font = ImageFont.load_default(size=38)

    for _ in range(7):
        draw.line(
            (
                secrets.randbelow(width),
                secrets.randbelow(height),
                secrets.randbelow(width),
                secrets.randbelow(height),
            ),
            fill=(174, 178, 224),
            width=1,
        )

    for _ in range(150):
        x = secrets.randbelow(width)
        y = secrets.randbelow(height)
        draw.point((x, y), fill=(188, 192, 230))

    segment_width = width // (len(answer) + 1)
    for index, character in enumerate(answer):
        character_image = Image.new("RGBA", (48, 62), (0, 0, 0, 0))
        character_draw = ImageDraw.Draw(character_image)
        character_draw.text(
            (5, 6),
            character,
            font=font,
            fill=(
                secrets.randbelow(50) + 45,
                secrets.randbelow(45) + 45,
                secrets.randbelow(55) + 90,
                255,
            ),
        )
        character_image = character_image.rotate(
            secrets.randbelow(19) - 9,
            resample=Image.Resampling.BICUBIC,
            expand=False,
        )
        image.paste(
            character_image,
            (12 + index * segment_width, 10 + secrets.randbelow(9)),
            character_image,
        )

    output = io.BytesIO()
    image.save(output, format="PNG")
    encoded_image = base64.b64encode(output.getvalue()).decode("ascii")
    return f"data:image/png;base64,{encoded_image}"


def create_captcha_challenge(
    db: Session,
    request: Request,
    purpose: CaptchaPurpose,
    previous_challenge_id: str | None = None,
) -> dict[str, str | int]:
    now = datetime.now(timezone.utc)
    requester_hash = _requester_hash(request)

    try:
        db.query(CaptchaChallenge).filter(
            CaptchaChallenge.created_at < now - CAPTCHA_HOURLY_WINDOW
        ).delete(synchronize_session=False)

        recent_count = (
            db.query(func.count(CaptchaChallenge.challenge_id))
            .filter(
                CaptchaChallenge.requester_hash == requester_hash,
                CaptchaChallenge.created_at >= now - CAPTCHA_RATE_WINDOW,
            )
            .scalar()
            or 0
        )
        hourly_count = (
            db.query(func.count(CaptchaChallenge.challenge_id))
            .filter(
                CaptchaChallenge.requester_hash == requester_hash,
                CaptchaChallenge.created_at >= now - CAPTCHA_HOURLY_WINDOW,
            )
            .scalar()
            or 0
        )

        if recent_count >= CAPTCHA_MAX_CHALLENGES_PER_WINDOW:
            db.commit()
            raise HTTPException(
                status_code=429,
                detail="Too many CAPTCHA requests. Please try again later.",
                headers={"Retry-After": str(int(CAPTCHA_RATE_WINDOW.total_seconds()))},
            )
        if hourly_count >= CAPTCHA_MAX_CHALLENGES_PER_HOUR:
            db.commit()
            raise HTTPException(
                status_code=429,
                detail="Too many CAPTCHA requests. Please try again later.",
                headers={"Retry-After": str(int(CAPTCHA_HOURLY_WINDOW.total_seconds()))},
            )

        answer = generate_captcha_answer()
        image = _render_captcha(answer)
        challenge_id = secrets.token_urlsafe(32)
        if previous_challenge_id:
            db.query(CaptchaChallenge).filter(
                CaptchaChallenge.challenge_id == previous_challenge_id,
                CaptchaChallenge.requester_hash == requester_hash,
                CaptchaChallenge.purpose == purpose,
                CaptchaChallenge.consumed_at.is_(None),
            ).update(
                {CaptchaChallenge.consumed_at: now},
                synchronize_session=False,
            )
        challenge = CaptchaChallenge(
            challenge_id=challenge_id,
            answer_hash=_answer_hash(challenge_id, answer),
            requester_hash=requester_hash,
            purpose=purpose,
            created_at=now,
            expires_at=now + CAPTCHA_LIFETIME,
        )
        db.add(challenge)
        db.commit()
    except HTTPException:
        raise
    except SQLAlchemyError as error:
        db.rollback()
        raise HTTPException(
            status_code=503,
            detail="CAPTCHA verification is temporarily unavailable.",
        ) from error

    return {
        "challenge_id": challenge_id,
        "image": image,
        "expires_in": int(CAPTCHA_LIFETIME.total_seconds()),
    }


def consume_captcha_challenge(
    db: Session,
    challenge_id: str,
    answer: str,
    request: Request,
    purpose: CaptchaPurpose,
) -> None:
    now = datetime.now(timezone.utc)
    challenge = (
        db.query(CaptchaChallenge)
        .filter(CaptchaChallenge.challenge_id == challenge_id)
        .with_for_update()
        .first()
    )

    if not challenge:
        raise HTTPException(
            status_code=400,
            detail="CAPTCHA is invalid or has already been used. Refresh and try again.",
        )

    if challenge.purpose != purpose:
        challenge.consumed_at = now
        _commit_challenge_change(db)
        raise HTTPException(
            status_code=400,
            detail="CAPTCHA is invalid or has already been used. Refresh and try again.",
        )

    if not hmac.compare_digest(
        challenge.requester_hash,
        _requester_hash(request),
    ):
        challenge.consumed_at = now
        _commit_challenge_change(db)
        raise HTTPException(
            status_code=400,
            detail="CAPTCHA is invalid or has already been used. Refresh and try again.",
        )

    expires_at = challenge.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if now >= expires_at:
        challenge.consumed_at = now
        _commit_challenge_change(db)
        raise HTTPException(
            status_code=410,
            detail="CAPTCHA has expired. Refresh and try again.",
        )

    if challenge.consumed_at is not None:
        raise HTTPException(
            status_code=400,
            detail="CAPTCHA is invalid or has already been used. Refresh and try again.",
        )

    expected_hash = _answer_hash(challenge_id, answer)
    if not hmac.compare_digest(challenge.answer_hash, expected_hash):
        challenge.consumed_at = now
        _commit_challenge_change(db)
        raise HTTPException(
            status_code=400,
            detail="CAPTCHA did not match. A new challenge is required.",
        )

    consumed = (
        db.query(CaptchaChallenge)
        .filter(
            CaptchaChallenge.challenge_id == challenge_id,
            CaptchaChallenge.answer_hash == expected_hash,
            CaptchaChallenge.consumed_at.is_(None),
            CaptchaChallenge.expires_at > now,
        )
        .update(
            {CaptchaChallenge.consumed_at: now},
            synchronize_session=False,
        )
    )
    if consumed != 1:
        db.rollback()
        raise HTTPException(
            status_code=400,
            detail="CAPTCHA is invalid or has already been used. Refresh and try again.",
        )

    _commit_challenge_change(db)
