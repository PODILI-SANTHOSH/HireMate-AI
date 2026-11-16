import argparse
import logging
import sys

from sqlalchemy.exc import SQLAlchemyError

from .database.connection import SessionLocal
from .models.user import User

logger = logging.getLogger(__name__)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Grant or revoke the administrator role for an existing user."
    )
    parser.add_argument("action", choices=("grant", "revoke"))
    parser.add_argument("email")
    args = parser.parse_args(argv)
    email = args.email.strip().lower()
    if not email:
        parser.error("email must not be empty")

    db = SessionLocal()
    try:
        user = db.query(User).filter(User.email == email).first()
        if not user:
            print("No matching user account exists.", file=sys.stderr)
            return 1
        if args.action == "grant" and not user.is_verified:
            print("Cannot grant admin access to an unavailable account.", file=sys.stderr)
            return 1

        should_be_admin = args.action == "grant"
        if user.is_admin == should_be_admin:
            print("No role change was needed.")
            return 0

        user.is_admin = should_be_admin
        user.auth_token_version += 1
        db.commit()
        role_change = "granted" if should_be_admin else "revoked"
        print(f"Administrator access {role_change} for user ID {user.id}.")
        return 0
    except SQLAlchemyError:
        db.rollback()
        logger.exception("Could not update the administrator role.")
        return 1
    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())
