import logging
import os
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import jwt
from dotenv import load_dotenv
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, EmailStr, Field
from pwdlib import PasswordHash
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session

from ..database.connection import SessionLocal
from ..models.password_reset_request import (
    PASSWORD_RESET_REQUEST_LIFETIME,
    PasswordResetRequest,
)
from ..models.user import User
from ..services.captcha import (
    CaptchaPurpose,
    consume_captcha_challenge,
    create_captcha_challenge,
)

load_dotenv()

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["Authentication"])

password_hash = PasswordHash.recommended()
bearer_scheme = HTTPBearer()
SECRET_KEY = os.getenv("JWT_SECRET_KEY", "")
if len(SECRET_KEY.strip()) < 32:
    if os.getenv("APP_ENV", "development").strip().lower() == "production":
        raise RuntimeError(
            "JWT_SECRET_KEY must be configured with at least 32 characters in production."
        )
    SECRET_KEY = "dev-secret-key-hiremate-ai-min-32-chars-change-in-prod"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
PASSWORD_RECOVERY_UNAVAILABLE = (
    "Secure self-service password recovery is temporarily unavailable. "
    "Please contact HireMate AI support through an independently verified "
    "support channel."
)
PASSWORD_RESET_REQUESTED = (
    "If an account matches these details, the password reset request has "
    "been submitted for administrator review."
)


class CaptchaRequest(BaseModel):
    challenge_id: str = Field(min_length=1, max_length=64)
    captcha_answer: str = Field(min_length=1, max_length=6)


class RegisterRequest(CaptchaRequest):
    full_name: str = Field(min_length=2, max_length=100)
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)


class ChangePasswordRequest(CaptchaRequest):
    email: EmailStr
    current_password: str = Field(min_length=1, max_length=128)
    new_password: str = Field(min_length=8, max_length=128)
    confirm_new_password: str = Field(min_length=8, max_length=128)


class PasswordResetSubmission(CaptchaRequest):
    email: EmailStr
    new_password: str = Field(min_length=8, max_length=128)
    confirm_new_password: str = Field(min_length=8, max_length=128)


class PasswordRecoveryUnavailableRequest(CaptchaRequest):
    email: EmailStr


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@dataclass(frozen=True)
class AuthenticatedUser:
    user: User
    token_version: int


def create_access_token(user_id: int, token_version: int = 0) -> str:
    expires = datetime.now(timezone.utc) + timedelta(
        minutes=ACCESS_TOKEN_EXPIRE_MINUTES
    )
    payload = {
        "sub": str(user_id),
        "auth_token_version": token_version,
        "exp": expires,
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


@router.get("/health")
def auth_health():
    return {"message": "Authentication API is ready"}


@router.get("/captcha")
def get_captcha(
    request: Request,
    response: Response,
    purpose: CaptchaPurpose,
    previous_challenge_id: str | None = None,
    db: Session = Depends(get_db),
):
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    return create_captcha_challenge(
        db,
        request,
        purpose,
        previous_challenge_id,
    )


@router.post("/register", status_code=201)
def register(
    payload: RegisterRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    consume_captcha_challenge(
        db,
        payload.challenge_id,
        payload.captcha_answer,
        request,
        "registration",
    )

    email = str(payload.email).strip().lower()
    full_name = payload.full_name.strip()
    if len(full_name) < 2:
        raise HTTPException(
            status_code=422,
            detail="Please enter your full name.",
        )

    if db.query(User).filter(User.email == email).first():
        raise HTTPException(
            status_code=409,
            detail="An account with this email already exists.",
        )

    user = User(
        full_name=full_name,
        email=email,
        hashed_password=password_hash.hash(payload.password),
        phone=None,
        is_verified=True,
    )
    db.add(user)

    try:
        db.commit()
    except IntegrityError as error:
        db.rollback()
        raise HTTPException(
            status_code=409,
            detail="An account with this email already exists.",
        ) from error
    except SQLAlchemyError as error:
        db.rollback()
        logger.exception("Could not save registration.")
        raise HTTPException(
            status_code=500,
            detail="Could not create the account. Please try again.",
        ) from error

    return {
        "message": "Account created successfully. You can now log in.",
        "email": email,
    }


@router.post("/login")
def login(
    payload: LoginRequest,
    db: Session = Depends(get_db),
):
    email = str(payload.email).strip().lower()
    user = db.query(User).filter(User.email == email).first()

    if (
        not user
        or not user.hashed_password
        or not password_hash.verify(payload.password, user.hashed_password)
    ):
        raise HTTPException(
            status_code=401,
            detail="Incorrect email or password.",
        )

    if not user.is_verified:
        raise HTTPException(
            status_code=403,
            detail="This account is unavailable. Contact your administrator.",
        )

    token = create_access_token(user.id, user.auth_token_version)
    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        "user": {
            "id": user.id,
            "full_name": user.full_name,
            "email": user.email,
            "phone": user.phone,
            "is_admin": user.is_admin,
        },
    }


@router.post("/password-reset/request", status_code=202)
def request_password_reset(
    payload: PasswordResetSubmission,
    request: Request,
    db: Session = Depends(get_db),
):
    if payload.new_password != payload.confirm_new_password:
        raise HTTPException(status_code=422, detail="New passwords do not match.")

    consume_captcha_challenge(
        db,
        payload.challenge_id,
        payload.captcha_answer,
        request,
        "recovery",
    )

    email = str(payload.email).strip().lower()
    password_digest = password_hash.hash(payload.new_password)
    user = (
        db.query(User)
        .filter(User.email == email, User.is_verified.is_(True))
        .first()
    )
    if not user:
        return {"message": PASSWORD_RESET_REQUESTED}

    now = datetime.now(timezone.utc)
    pending = (
        db.query(PasswordResetRequest)
        .filter(
            PasswordResetRequest.pending_user_id == user.id,
            PasswordResetRequest.status == "pending",
        )
        .with_for_update()
        .first()
    )
    if pending and _as_utc(pending.expires_at) > now:
        return {"message": PASSWORD_RESET_REQUESTED}
    if pending:
        pending.status = "expired"
        pending.pending_user_id = None
        pending.new_password_hash = None

    try:
        db.flush()
        db.add(
            PasswordResetRequest(
                request_id=secrets.token_urlsafe(32),
                user_id=user.id,
                pending_user_id=user.id,
                email=email,
                new_password_hash=password_digest,
                status="pending",
                requested_at=now,
                expires_at=now + PASSWORD_RESET_REQUEST_LIFETIME,
            )
        )
        db.commit()
    except IntegrityError as error:
        db.rollback()
        existing = (
            db.query(PasswordResetRequest.request_id)
            .filter(
                PasswordResetRequest.pending_user_id == user.id,
                PasswordResetRequest.status == "pending",
            )
            .first()
        )
        if existing:
            return {"message": PASSWORD_RESET_REQUESTED}
        logger.exception("Could not save a password-reset request.")
        raise HTTPException(
            status_code=503,
            detail="Could not submit the request. Please try again.",
        ) from error
    except SQLAlchemyError as error:
        db.rollback()
        logger.exception("Could not save a password-reset request.")
        raise HTTPException(
            status_code=503,
            detail="Could not submit the request. Please try again.",
        ) from error

    return {"message": PASSWORD_RESET_REQUESTED}


@router.post("/password-reset/confirm", status_code=410)
def confirm_password_reset(
    payload: PasswordRecoveryUnavailableRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    consume_captcha_challenge(
        db,
        payload.challenge_id,
        payload.captcha_answer,
        request,
        "recovery",
    )
    raise HTTPException(
        status_code=410,
        detail=PASSWORD_RECOVERY_UNAVAILABLE,
    )


def get_authenticated_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> AuthenticatedUser:
    try:
        token_payload = jwt.decode(
            credentials.credentials,
            SECRET_KEY,
            algorithms=[ALGORITHM],
        )
        user_id = int(token_payload["sub"])
        token_version = token_payload.get("auth_token_version", 0)
        if isinstance(token_version, bool) or not isinstance(token_version, int):
            raise ValueError("Invalid token version")
    except (jwt.InvalidTokenError, KeyError, TypeError, ValueError) as error:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from error

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    if token_version != user.auth_token_version:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not user.is_verified:
        raise HTTPException(
            status_code=403,
            detail="This account is unavailable. Contact your administrator.",
        )

    return AuthenticatedUser(user=user, token_version=token_version)


def get_administrator(
    authenticated_user: AuthenticatedUser = Depends(get_authenticated_user),
) -> AuthenticatedUser:
    if not authenticated_user.user.is_admin:
        raise HTTPException(
            status_code=403,
            detail="Administrator access is required.",
        )
    return authenticated_user


def _as_utc(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value


@router.get("/admin/password-reset-requests")
def list_password_reset_requests(
    administrator: AuthenticatedUser = Depends(get_administrator),
    db: Session = Depends(get_db),
):
    now = datetime.now(timezone.utc)
    requests = (
        db.query(PasswordResetRequest)
        .filter(
            PasswordResetRequest.status == "pending",
            PasswordResetRequest.expires_at > now,
        )
        .order_by(PasswordResetRequest.requested_at.asc())
        .all()
    )
    return [
        {
            "request_id": reset_request.request_id,
            "email": reset_request.email,
            "requested_at": _as_utc(reset_request.requested_at).isoformat(),
            "expires_at": _as_utc(reset_request.expires_at).isoformat(),
        }
        for reset_request in requests
    ]


def _get_pending_reset_request(
    db: Session,
    request_id: str,
) -> PasswordResetRequest:
    reset_request = (
        db.query(PasswordResetRequest)
        .filter(PasswordResetRequest.request_id == request_id)
        .with_for_update()
        .first()
    )
    if not reset_request or reset_request.status != "pending":
        raise HTTPException(
            status_code=409,
            detail="This password-reset request is no longer pending.",
        )
    if _as_utc(reset_request.expires_at) <= datetime.now(timezone.utc):
        reset_request.status = "expired"
        reset_request.pending_user_id = None
        reset_request.new_password_hash = None
        try:
            db.commit()
        except SQLAlchemyError as error:
            db.rollback()
            logger.exception("Could not expire a password-reset request.")
            raise HTTPException(
                status_code=503,
                detail="Could not process the request. Please try again.",
            ) from error
        raise HTTPException(
            status_code=410,
            detail="This password-reset request has expired.",
        )
    return reset_request


@router.post("/admin/password-reset-requests/{request_id}/approve")
def approve_password_reset_request(
    request_id: str,
    administrator: AuthenticatedUser = Depends(get_administrator),
    db: Session = Depends(get_db),
):
    reset_request = _get_pending_reset_request(db, request_id)
    if reset_request.user_id == administrator.user.id:
        raise HTTPException(
            status_code=403,
            detail="An administrator cannot approve their own password-reset request.",
        )

    user = (
        db.query(User)
        .filter(
            User.id == reset_request.user_id,
            User.email == reset_request.email,
            User.is_verified.is_(True),
        )
        .with_for_update()
        .first()
    )
    if not user:
        reset_request.status = "rejected"
        reset_request.pending_user_id = None
        reset_request.reviewed_by_user_id = administrator.user.id
        reset_request.reviewed_at = datetime.now(timezone.utc)
        try:
            db.commit()
        except SQLAlchemyError as error:
            db.rollback()
            logger.exception("Could not close an invalid password-reset request.")
            raise HTTPException(
                status_code=503,
                detail="Could not process the request. Please try again.",
            ) from error
        raise HTTPException(
            status_code=409,
            detail="The account is no longer eligible for password recovery.",
        )

    if not reset_request.new_password_hash:
        raise HTTPException(
            status_code=409,
            detail="This password-reset request cannot be approved.",
        )

    user.hashed_password = reset_request.new_password_hash
    user.auth_token_version += 1
    reset_request.status = "approved"
    reset_request.pending_user_id = None
    reset_request.new_password_hash = None
    reset_request.reviewed_by_user_id = administrator.user.id
    reset_request.reviewed_at = datetime.now(timezone.utc)
    try:
        db.commit()
    except SQLAlchemyError as error:
        db.rollback()
        logger.exception("Could not approve a password-reset request.")
        raise HTTPException(
            status_code=503,
            detail="Could not approve the request. Please try again.",
        ) from error

    return {
        "message": (
            "Password reset approved. The user can now log in with the new "
            "password; existing sessions have been invalidated."
        )
    }


@router.post("/admin/password-reset-requests/{request_id}/reject")
def reject_password_reset_request(
    request_id: str,
    administrator: AuthenticatedUser = Depends(get_administrator),
    db: Session = Depends(get_db),
):
    reset_request = _get_pending_reset_request(db, request_id)
    reset_request.status = "rejected"
    reset_request.pending_user_id = None
    reset_request.new_password_hash = None
    reset_request.reviewed_by_user_id = administrator.user.id
    reset_request.reviewed_at = datetime.now(timezone.utc)
    try:
        db.commit()
    except SQLAlchemyError as error:
        db.rollback()
        logger.exception("Could not reject a password-reset request.")
        raise HTTPException(
            status_code=503,
            detail="Could not reject the request. Please try again.",
        ) from error
    return {"message": "Password reset request rejected."}


@router.post("/password/change")
def change_password(
    payload: ChangePasswordRequest,
    request: Request,
    authenticated_user: AuthenticatedUser = Depends(get_authenticated_user),
    db: Session = Depends(get_db),
):
    email = str(payload.email).strip().lower()
    if email != (authenticated_user.user.email or "").strip().lower():
        raise HTTPException(
            status_code=403,
            detail="Email does not match the authenticated account.",
        )

    consume_captcha_challenge(
        db,
        payload.challenge_id,
        payload.captcha_answer,
        request,
        "password_change",
    )

    user = (
        db.query(User)
        .filter(
            User.id == authenticated_user.user.id,
            User.auth_token_version == authenticated_user.token_version,
        )
        .with_for_update()
        .populate_existing()
        .first()
    )
    if not user:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if (
        not user.hashed_password
        or not password_hash.verify(payload.current_password, user.hashed_password)
    ):
        raise HTTPException(
            status_code=401,
            detail="Current password is incorrect.",
        )

    if payload.new_password != payload.confirm_new_password:
        raise HTTPException(
            status_code=422,
            detail="New passwords do not match.",
        )
    if payload.new_password == payload.current_password:
        raise HTTPException(
            status_code=422,
            detail="New password must be different from the current password.",
        )

    user.hashed_password = password_hash.hash(payload.new_password)
    user.auth_token_version += 1
    try:
        db.commit()
    except SQLAlchemyError as error:
        db.rollback()
        logger.exception("Could not update the account password.")
        raise HTTPException(
            status_code=500,
            detail="Could not update the password. Please try again.",
        ) from error

    return {
        "message": "Password updated successfully. Please log in with your new password."
    }


@router.get("/me")
def get_current_user(
    authenticated_user: AuthenticatedUser = Depends(get_authenticated_user),
):
    user = authenticated_user.user
    return {
        "id": user.id,
        "full_name": user.full_name,
        "email": user.email,
        "phone": user.phone,
        "is_admin": user.is_admin,
    }
