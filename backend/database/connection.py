
import os
from pathlib import Path

from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.engine import make_url
from sqlalchemy.orm import declarative_base, sessionmaker

project_root = Path(__file__).resolve().parents[1]
load_dotenv(project_root / ".env")
load_dotenv(project_root / "backend" / ".env")

DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    if os.getenv("APP_ENV", "development").strip().lower() == "production":
        raise RuntimeError("DATABASE_URL must be configured in production.")
    DATABASE_URL = "sqlite:///./hiremate.db"

database_url = make_url(DATABASE_URL)
connect_args = {}

if database_url.drivername in {"postgres", "postgresql"}:
    database_url = database_url.set(drivername="postgresql+psycopg")
elif database_url.drivername in {"mysql", "mysql+pymysql"}:
    database_url = database_url.set(drivername="mysql+pymysql")
    query = dict(database_url.query)
    ssl_mode = query.pop("ssl-mode", query.pop("ssl_mode", None))
    database_url = database_url.set(query=query)
    if ssl_mode:
        normalized_ssl_mode = str(ssl_mode).upper()
        if normalized_ssl_mode == "DISABLED":
            connect_args["ssl_disabled"] = True
        elif normalized_ssl_mode == "REQUIRED":
            connect_args["ssl_verify_cert"] = False
        elif normalized_ssl_mode == "VERIFY_CA":
            connect_args["ssl_verify_cert"] = True
        elif normalized_ssl_mode == "VERIFY_IDENTITY":
            connect_args["ssl_verify_cert"] = True
            connect_args["ssl_verify_identity"] = True
        elif normalized_ssl_mode != "PREFERRED":
            raise RuntimeError("Unsupported MySQL ssl-mode value")
elif database_url.drivername not in {
    "postgresql+psycopg",
    "sqlite",
    "sqlite+pysqlite",
}:
    raise RuntimeError(
        "DATABASE_URL must use PostgreSQL, MySQL, or SQLite"
    )

if database_url.drivername in {"sqlite", "sqlite+pysqlite"}:
    connect_args = {"check_same_thread": False}

engine = create_engine(
    database_url,
    pool_pre_ping=True,
    pool_recycle=1800 if database_url.drivername == "mysql+pymysql" else -1,
    connect_args=connect_args,
)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
)

Base = declarative_base()
