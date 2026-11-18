import os

import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import inspect, text

from . import models
from .database.connection import Base, engine, dispose_engine
from .routers import auth, career, job, mock_interview, progress as progress_router
from .routers import resume, roadmap
from .services.groq_config import get_groq_model, is_groq_configured

logger = logging.getLogger(__name__)


def init_db():
    """Safely initialize database tables and apply required schema migrations."""
    is_production = os.getenv("APP_ENV", "development").strip().lower() == "production"
    is_vercel_deployment = bool(os.getenv("VERCEL"))
    create_db_tables = os.getenv("CREATE_DB_TABLES", "").strip().lower() == "true"
    if create_db_tables or (not is_production and not is_vercel_deployment):
        Base.metadata.create_all(bind=engine)
    else:
        models.CaptchaChallenge.__table__.create(bind=engine, checkfirst=True)
        models.AccountRecoveryCode.__table__.create(bind=engine, checkfirst=True)
        models.PasswordResetRequest.__table__.create(bind=engine, checkfirst=True)

    inspector = inspect(engine)
    if inspector.has_table("captcha_challenges"):
        captcha_columns = {
            column["name"]
            for column in inspector.get_columns("captcha_challenges")
        }
        if "purpose" not in captcha_columns:
            with engine.begin() as connection:
                connection.execute(
                    text(
                        "ALTER TABLE captcha_challenges ADD COLUMN "
                        "purpose VARCHAR(16) NOT NULL DEFAULT 'registration'"
                    )
                )

    if inspector.has_table("users"):
        user_columns = {
            column["name"] for column in inspector.get_columns("users")
        }
        if "auth_token_version" not in user_columns:
            with engine.begin() as connection:
                connection.execute(
                    text(
                        "ALTER TABLE users ADD COLUMN "
                        "auth_token_version INTEGER NOT NULL DEFAULT 0"
                    )
                )
        if "is_admin" not in user_columns:
            with engine.begin() as connection:
                connection.execute(
                    text(
                        "ALTER TABLE users ADD COLUMN "
                        "is_admin BOOLEAN NOT NULL DEFAULT FALSE"
                    )
                )


# Safely execute initial schema sync
try:
    init_db()
except Exception as error:
    logger.warning("Initial database schema sync deferred or failed: %s", error)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup phase
    try:
        init_db()
    except Exception as error:
        logger.warning("Startup database check failed: %s", error)
    yield
    # Shutdown phase: Cleanly dispose pooled database connections
    dispose_engine()


app = FastAPI(lifespan=lifespan)

frontend_origin = os.getenv("FRONTEND_ORIGIN", "").strip().rstrip("/")
allowed_origins = [
    "http://localhost:5173",
    "http://localhost:5174",
    "http://localhost:5175",
    "http://localhost:5176",
    "http://127.0.0.1:5173",
    "http://127.0.0.1:5174",
    "http://127.0.0.1:5175",
    "http://127.0.0.1:5176",
    "https://hiremate-ai-mauve.vercel.app",
]
if frontend_origin:
    allowed_origins.append(frontend_origin)


app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def root():
    return {"message": "Welcome to HireMate AI"}


@app.get("/health")
@app.get("/api/health")
def health():
    return {
        "status": "ok",
        "ai": {
            "provider": "Groq",
            "configured": is_groq_configured(),
            "model": get_groq_model(),
        },
    }


# Support both the legacy unprefixed routes used in tests and the /api routes used by the frontend.
app.include_router(resume.router)
app.include_router(job.router)
app.include_router(career.router)
app.include_router(mock_interview.router)
app.include_router(roadmap.router)
app.include_router(auth.router)
app.include_router(progress_router.router)

app.include_router(resume.router, prefix="/api")
app.include_router(job.router, prefix="/api")
app.include_router(career.router, prefix="/api")
app.include_router(mock_interview.router, prefix="/api")
app.include_router(roadmap.router, prefix="/api")
app.include_router(auth.router, prefix="/api")
app.include_router(progress_router.router, prefix="/api")
