import base64
import io
import os
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from PIL import Image

os.environ["DATABASE_URL"] = "sqlite://"
os.environ.setdefault(
    "JWT_SECRET_KEY",
    "test-only-signing-key-with-at-least-32-bytes",
)

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app import app
from backend.database.connection import Base
from backend.models.captcha_challenge import CaptchaChallenge
from backend.models.password_reset_request import PasswordResetRequest
from backend.models.user import User
from backend.routers import auth
from backend.services import captcha


TEST_ENGINE = create_engine(
    "sqlite://",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestSession = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=TEST_ENGINE,
)


def override_get_db():
    db = TestSession()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[auth.get_db] = override_get_db


class AuthApiTests(unittest.TestCase):
    def setUp(self):
        Base.metadata.drop_all(bind=TEST_ENGINE)
        Base.metadata.create_all(bind=TEST_ENGINE)
        self.client = TestClient(app)
        self.original_secret = auth.SECRET_KEY
        auth.SECRET_KEY = "test-only-signing-key-with-at-least-32-bytes"

    def tearDown(self):
        auth.SECRET_KEY = self.original_secret
        self.client.close()

    def create_challenge(self, answer="ABC234", purpose="registration"):
        with patch.object(
            captcha,
            "generate_captcha_answer",
            return_value=answer,
        ):
            response = self.client.get(
                f"/auth/captcha?purpose={purpose}",
            )
        self.assertEqual(response.status_code, 200)
        return response.json()

    def register_payload(self, challenge, **overrides):
        payload = {
            "full_name": "Test Candidate",
            "email": "candidate@example.com",
            "password": "safe-test-password",
            "challenge_id": challenge["challenge_id"],
            "captcha_answer": "ABC234",
        }
        payload.update(overrides)
        return payload

    def create_account(self, email="candidate@example.com"):
        challenge = self.create_challenge()
        response = self.client.post(
            "/auth/register",
            json=self.register_payload(challenge, email=email),
        )
        self.assertEqual(response.status_code, 201)

    def login_headers(self, email="candidate@example.com", password="safe-test-password"):
        response = self.client.post(
            "/auth/login",
            json={"email": email, "password": password},
        )
        self.assertEqual(response.status_code, 200)
        return {"Authorization": f"Bearer {response.json()['access_token']}"}

    def password_reset_payload(self, challenge, **overrides):
        payload = {
            "email": "candidate@example.com",
            "new_password": "updated-test-password",
            "confirm_new_password": "updated-test-password",
            "challenge_id": challenge["challenge_id"],
            "captcha_answer": "ABC234",
        }
        payload.update(overrides)
        return payload

    def grant_admin(self, email="admin@example.com"):
        with TestSession() as db:
            user = db.query(User).filter(User.email == email).one()
            user.is_admin = True
            db.commit()

    def change_password_payload(self, challenge, **overrides):
        payload = {
            "email": "candidate@example.com",
            "current_password": "safe-test-password",
            "new_password": "updated-test-password",
            "confirm_new_password": "updated-test-password",
            "challenge_id": challenge["challenge_id"],
            "captcha_answer": "ABC234",
        }
        payload.update(overrides)
        return payload

    def test_captcha_is_generated_as_an_image_and_refreshes(self):
        with patch.object(
            captcha,
            "generate_captcha_answer",
            side_effect=["ABC234", "DEF567"],
        ):
            first = self.client.get("/auth/captcha?purpose=registration")
            refreshed = self.client.get(
                "/auth/captcha",
                params={
                    "purpose": "registration",
                    "previous_challenge_id": first.json()["challenge_id"],
                },
            )

        self.assertEqual(first.status_code, 200)
        self.assertEqual(refreshed.status_code, 200)
        self.assertIn("no-store", first.headers["cache-control"])
        first_data = first.json()
        refreshed_data = refreshed.json()
        self.assertNotEqual(first_data["challenge_id"], refreshed_data["challenge_id"])
        self.assertNotEqual(first_data["image"], refreshed_data["image"])
        self.assertTrue(first_data["image"].startswith("data:image/png;base64,"))
        self.assertEqual(first_data["expires_in"], 180)
        self.assertEqual(
            set(first_data),
            {"challenge_id", "image", "expires_in"},
        )
        for challenge_data in (first_data, refreshed_data):
            image_data = challenge_data["image"].partition(",")[2]
            image_bytes = base64.b64decode(image_data, validate=True)
            with Image.open(io.BytesIO(image_bytes)) as captcha_image:
                self.assertEqual(captcha_image.format, "PNG")
                self.assertEqual(captcha_image.size, (280, 82))
                self.assertGreater(
                    len(captcha_image.getcolors(maxcolors=280 * 82) or []),
                    1,
                )
        stale_attempt = self.client.post(
            "/auth/register",
            json=self.register_payload(first_data),
        )
        self.assertEqual(stale_attempt.status_code, 400)
        with TestSession() as db:
            previous_challenge = db.get(
                CaptchaChallenge,
                first_data["challenge_id"],
            )
            self.assertIsNotNone(previous_challenge.consumed_at)
            self.assertEqual(db.query(User).count(), 0)

    def test_api_prefixed_auth_routes_are_available(self):
        challenge = self.create_challenge()
        response = self.client.post(
            "/api/auth/register",
            json=self.register_payload(challenge),
        )

        self.assertEqual(response.status_code, 201)
        self.assertNotIn("recovery_code", response.json())

    def test_registration_succeeds_without_email_configuration(self):
        challenge = self.create_challenge()
        response = self.client.post(
            "/auth/register",
            json=self.register_payload(challenge, captcha_answer="abc234"),
        )

        self.assertEqual(response.status_code, 201)
        self.assertNotIn("recovery_code", response.json())
        self.assertIn("log in", response.json()["message"].lower())
        self.assertNotIn("otp", response.json())

        with TestSession() as db:
            user = db.query(User).filter(User.email == "candidate@example.com").one()
            self.assertTrue(user.is_verified)
            self.assertTrue(
                auth.password_hash.verify("safe-test-password", user.hashed_password)
            )

    def test_incorrect_captcha_blocks_registration_and_consumes_challenge(self):
        challenge = self.create_challenge()
        wrong = self.client.post(
            "/auth/register",
            json=self.register_payload(challenge, captcha_answer="ZZZZZZ"),
        )
        self.assertEqual(wrong.status_code, 400)
        self.assertIn("CAPTCHA", wrong.json()["detail"])

        replay = self.client.post(
            "/auth/register",
            json=self.register_payload(challenge),
        )
        self.assertEqual(replay.status_code, 400)
        with TestSession() as db:
            self.assertEqual(db.query(User).count(), 0)
            stored_challenge = db.get(
                CaptchaChallenge,
                challenge["challenge_id"],
            )
            self.assertIsNotNone(stored_challenge)
            self.assertIsNotNone(stored_challenge.consumed_at)

    def test_registration_endpoint_rejects_requests_without_a_captcha(self):
        response = self.client.post(
            "/auth/register",
            json={
                "full_name": "Test Candidate",
                "email": "candidate@example.com",
                "password": "safe-test-password",
            },
        )

        self.assertEqual(response.status_code, 422)
        with TestSession() as db:
            self.assertEqual(db.query(User).count(), 0)

    def test_empty_captcha_is_rejected_without_creating_an_account(self):
        challenge = self.create_challenge()
        response = self.client.post(
            "/auth/register",
            json=self.register_payload(challenge, captcha_answer=""),
        )

        self.assertEqual(response.status_code, 422)
        with TestSession() as db:
            self.assertEqual(db.query(User).count(), 0)

    def test_expired_captcha_is_rejected(self):
        challenge = self.create_challenge()
        with TestSession() as db:
            record = db.get(CaptchaChallenge, challenge["challenge_id"])
            record.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
            db.commit()

        response = self.client.post(
            "/auth/register",
            json=self.register_payload(challenge),
        )
        self.assertEqual(response.status_code, 410)
        self.assertIn("expired", response.json()["detail"].lower())

    def test_login_succeeds_without_captcha(self):
        with TestSession() as db:
            db.add(
                User(
                    full_name="Existing Candidate",
                    email="candidate@example.com",
                    hashed_password=auth.password_hash.hash("safe-test-password"),
                    is_verified=True,
                )
            )
            db.commit()

        response = self.client.post(
            "/auth/login",
            json={
                "email": "candidate@example.com",
                "password": "safe-test-password",
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("access_token", response.json())
        with TestSession() as db:
            self.assertEqual(db.query(CaptchaChallenge).count(), 0)

    def test_change_password_updates_hash_and_invalidates_old_tokens(self):
        self.create_account()
        old_headers = self.login_headers()
        challenge = self.create_challenge(purpose="password_change")

        response = self.client.post(
            "/auth/password/change",
            json=self.change_password_payload(challenge),
            headers=old_headers,
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn("log in", response.json()["message"].lower())
        with TestSession() as db:
            user = db.query(User).filter(User.email == "candidate@example.com").one()
            self.assertTrue(
                auth.password_hash.verify(
                    "updated-test-password",
                    user.hashed_password,
                )
            )
            self.assertFalse(
                auth.password_hash.verify(
                    "safe-test-password",
                    user.hashed_password,
                )
            )
            self.assertEqual(user.auth_token_version, 1)

        self.assertEqual(
            self.client.get("/auth/me", headers=old_headers).status_code,
            401,
        )
        self.assertEqual(
            self.client.get("/progress", headers=old_headers).status_code,
            401,
        )
        self.assertEqual(
            self.client.post(
                "/auth/login",
                json={
                    "email": "candidate@example.com",
                    "password": "safe-test-password",
                },
            ).status_code,
            401,
        )
        new_headers = self.login_headers(password="updated-test-password")
        self.assertEqual(self.client.get("/auth/me", headers=new_headers).status_code, 200)

    def test_change_password_rejects_invalid_password_and_captcha_inputs(self):
        self.create_account()
        headers = self.login_headers()

        wrong_current = self.client.post(
            "/auth/password/change",
            json=self.change_password_payload(
                self.create_challenge(purpose="password_change"),
                current_password="wrong-current-password",
            ),
            headers=headers,
        )
        self.assertEqual(wrong_current.status_code, 401)

        wrong_captcha = self.client.post(
            "/auth/password/change",
            json=self.change_password_payload(
                self.create_challenge(purpose="password_change"),
                captcha_answer="ZZZZZZ",
            ),
            headers=headers,
        )
        self.assertEqual(wrong_captcha.status_code, 400)

        expired_challenge = self.create_challenge(purpose="password_change")
        with TestSession() as db:
            record = db.get(CaptchaChallenge, expired_challenge["challenge_id"])
            record.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
            db.commit()
        expired = self.client.post(
            "/auth/password/change",
            json=self.change_password_payload(expired_challenge),
            headers=headers,
        )
        self.assertEqual(expired.status_code, 410)

        mismatch = self.client.post(
            "/auth/password/change",
            json=self.change_password_payload(
                self.create_challenge(purpose="password_change"),
                confirm_new_password="different-new-password",
            ),
            headers=headers,
        )
        self.assertEqual(mismatch.status_code, 422)

        with TestSession() as db:
            user = db.query(User).filter(User.email == "candidate@example.com").one()
            self.assertTrue(
                auth.password_hash.verify(
                    "safe-test-password",
                    user.hashed_password,
                )
            )
            self.assertEqual(user.auth_token_version, 0)

    def test_change_password_cannot_target_another_users_account(self):
        self.create_account()
        self.create_account(email="other@example.com")
        headers = self.login_headers()
        challenge = self.create_challenge(purpose="password_change")

        response = self.client.post(
            "/auth/password/change",
            json=self.change_password_payload(
                challenge,
                email="other@example.com",
            ),
            headers=headers,
        )

        self.assertEqual(response.status_code, 403)
        with TestSession() as db:
            candidate = db.query(User).filter(User.email == "candidate@example.com").one()
            other = db.query(User).filter(User.email == "other@example.com").one()
            self.assertTrue(
                auth.password_hash.verify(
                    "safe-test-password",
                    candidate.hashed_password,
                )
            )
            self.assertTrue(
                auth.password_hash.verify(
                    "safe-test-password",
                    other.hashed_password,
                )
            )

    def test_change_password_requires_an_authenticated_user_and_its_captcha_purpose(self):
        self.create_account()
        payload = self.change_password_payload(self.create_challenge())
        unauthenticated = self.client.post(
            "/auth/password/change",
            json=payload,
        )
        self.assertEqual(unauthenticated.status_code, 401)

        headers = self.login_headers()
        wrong_purpose = self.client.post(
            "/auth/password/change",
            json=payload,
            headers=headers,
        )
        self.assertEqual(wrong_purpose.status_code, 400)
        with TestSession() as db:
            user = db.query(User).filter(User.email == "candidate@example.com").one()
            self.assertTrue(
                auth.password_hash.verify(
                    "safe-test-password",
                    user.hashed_password,
                )
            )

    def test_captcha_challenges_are_bound_to_their_purpose(self):
        recovery_challenge = self.create_challenge(purpose="recovery")
        response = self.client.post(
            "/auth/register",
            json=self.register_payload(recovery_challenge),
        )
        self.assertEqual(response.status_code, 400)

        registration_challenge = self.create_challenge()
        reset = self.client.post(
            "/auth/password-reset/confirm",
            json=self.password_reset_payload(registration_challenge),
        )
        self.assertEqual(reset.status_code, 400)
        self.assertIn("invalid", reset.json()["detail"].lower())

    def test_captcha_challenge_is_single_use(self):
        challenge = self.create_challenge()
        payload = self.register_payload(challenge)
        self.assertEqual(self.client.post("/auth/register", json=payload).status_code, 201)
        reused = self.client.post("/auth/register", json=payload)
        self.assertEqual(reused.status_code, 400)

    def test_captcha_generation_is_rate_limited(self):
        with patch.object(captcha, "generate_captcha_answer", return_value="ABC234"):
            for _ in range(captcha.CAPTCHA_MAX_CHALLENGES_PER_WINDOW):
                challenge_response = self.client.get(
                    "/auth/captcha?purpose=registration"
                )
                self.assertEqual(challenge_response.status_code, 200)

            limited = self.client.get("/auth/captcha?purpose=registration")

        self.assertEqual(limited.status_code, 429)

    def test_password_reset_request_is_generic_and_does_not_change_password(self):
        self.create_account()
        known = self.client.post(
            "/auth/password-reset/request",
            json=self.password_reset_payload(
                self.create_challenge(purpose="recovery"),
            ),
        )
        unknown = self.client.post(
            "/auth/password-reset/request",
            json=self.password_reset_payload(
                self.create_challenge(purpose="recovery"),
                email="unknown@example.com",
            ),
        )

        self.assertEqual(known.status_code, 202)
        self.assertEqual(unknown.status_code, 202)
        self.assertEqual(known.json(), unknown.json())
        self.assertNotIn("candidate@example.com", known.text)
        self.assertNotIn("unknown@example.com", unknown.text)
        self.assertNotIn("new_password_hash", known.json())

        with TestSession() as db:
            user = db.query(User).filter(User.email == "candidate@example.com").one()
            request = db.query(PasswordResetRequest).one()
            self.assertTrue(
                auth.password_hash.verify(
                    "safe-test-password",
                    user.hashed_password,
                )
            )
            self.assertEqual(request.status, "pending")
            self.assertEqual(request.user_id, user.id)
            self.assertEqual(request.pending_user_id, user.id)
            self.assertNotEqual(request.new_password_hash, "updated-test-password")
            self.assertTrue(
                auth.password_hash.verify(
                    "updated-test-password",
                    request.new_password_hash,
                )
            )

    def test_password_reset_rejects_bad_captcha_and_mismatched_passwords(self):
        self.create_account()
        wrong_captcha = self.client.post(
            "/auth/password-reset/request",
            json=self.password_reset_payload(
                self.create_challenge(purpose="recovery"),
                captcha_answer="ZZZZZZ",
            ),
        )
        mismatch = self.client.post(
            "/auth/password-reset/request",
            json=self.password_reset_payload(
                self.create_challenge(purpose="recovery"),
                confirm_new_password="different-password",
            ),
        )

        self.assertEqual(wrong_captcha.status_code, 400)
        self.assertEqual(mismatch.status_code, 422)
        with TestSession() as db:
            user = db.query(User).filter(User.email == "candidate@example.com").one()
            self.assertEqual(db.query(PasswordResetRequest).count(), 0)
            self.assertTrue(
                auth.password_hash.verify(
                    "safe-test-password",
                    user.hashed_password,
                )
            )

    def test_duplicate_password_reset_requests_do_not_replace_pending_password(self):
        self.create_account()
        first = self.client.post(
            "/auth/password-reset/request",
            json=self.password_reset_payload(
                self.create_challenge(purpose="recovery"),
            ),
        )
        with TestSession() as db:
            original_hash = db.query(PasswordResetRequest).one().new_password_hash

        duplicate = self.client.post(
            "/auth/password-reset/request",
            json=self.password_reset_payload(
                self.create_challenge(purpose="recovery"),
                new_password="different-pending-password",
                confirm_new_password="different-pending-password",
            ),
        )

        self.assertEqual(first.status_code, 202)
        self.assertEqual(duplicate.status_code, 202)
        self.assertEqual(first.json(), duplicate.json())
        with TestSession() as db:
            requests = db.query(PasswordResetRequest).all()
            self.assertEqual(len(requests), 1)
            self.assertEqual(requests[0].new_password_hash, original_hash)

    def test_only_admin_can_approve_and_approval_updates_password_once(self):
        self.create_account()
        self.create_account(email="admin@example.com")
        self.grant_admin()
        old_headers = self.login_headers()
        admin_headers = self.login_headers(email="admin@example.com")
        challenge = self.create_challenge(purpose="recovery")
        submitted = self.client.post(
            "/auth/password-reset/request",
            json=self.password_reset_payload(challenge),
        )
        self.assertEqual(submitted.status_code, 202)

        unauthenticated = self.client.get("/auth/admin/password-reset-requests")
        self.assertEqual(unauthenticated.status_code, 401)
        non_admin = self.client.get(
            "/auth/admin/password-reset-requests",
            headers=old_headers,
        )
        self.assertEqual(non_admin.status_code, 403)
        non_admin_approval = self.client.post(
            "/auth/admin/password-reset-requests/request-id/approve",
            headers=old_headers,
        )
        self.assertEqual(non_admin_approval.status_code, 403)

        requests = self.client.get(
            "/auth/admin/password-reset-requests",
            headers=admin_headers,
        )
        self.assertEqual(requests.status_code, 200)
        self.assertEqual(len(requests.json()), 1)
        self.assertNotIn("new_password_hash", requests.json()[0])
        request_id = requests.json()[0]["request_id"]
        approval = self.client.post(
            f"/auth/admin/password-reset-requests/{request_id}/approve",
            headers=admin_headers,
        )
        self.assertEqual(approval.status_code, 200)
        duplicate_approval = self.client.post(
            f"/auth/admin/password-reset-requests/{request_id}/approve",
            headers=admin_headers,
        )
        self.assertEqual(duplicate_approval.status_code, 409)

        old_session = self.client.get("/auth/me", headers=old_headers)
        self.assertEqual(old_session.status_code, 401)
        old_password = self.client.post(
            "/auth/login",
            json={
                "email": "candidate@example.com",
                "password": "safe-test-password",
            },
        )
        new_password = self.client.post(
            "/auth/login",
            json={
                "email": "candidate@example.com",
                "password": "updated-test-password",
            },
        )
        self.assertEqual(old_password.status_code, 401)
        self.assertEqual(new_password.status_code, 200)

        with TestSession() as db:
            request = db.query(PasswordResetRequest).one()
            user = db.query(User).filter(User.email == "candidate@example.com").one()
            admin = db.query(User).filter(User.email == "admin@example.com").one()
            self.assertEqual(request.status, "approved")
            self.assertEqual(request.reviewed_by_user_id, admin.id)
            self.assertIsNotNone(request.reviewed_at)
            self.assertIsNone(request.pending_user_id)
            self.assertIsNone(request.new_password_hash)
            self.assertEqual(user.auth_token_version, 1)

    def test_reset_request_rejection_and_expiration_never_change_password(self):
        self.create_account()
        self.create_account(email="admin@example.com")
        self.grant_admin()
        admin_headers = self.login_headers(email="admin@example.com")
        self.client.post(
            "/auth/password-reset/request",
            json=self.password_reset_payload(
                self.create_challenge(purpose="recovery"),
            ),
        )
        request_id = self.client.get(
            "/auth/admin/password-reset-requests",
            headers=admin_headers,
        ).json()[0]["request_id"]

        rejected = self.client.post(
            f"/auth/admin/password-reset-requests/{request_id}/reject",
            headers=admin_headers,
        )
        self.assertEqual(rejected.status_code, 200)
        with TestSession() as db:
            request = db.query(PasswordResetRequest).one()
            self.assertEqual(request.status, "rejected")
            self.assertIsNotNone(request.reviewed_at)
            self.assertIsNone(request.new_password_hash)

        self.client.post(
            "/auth/password-reset/request",
            json=self.password_reset_payload(
                self.create_challenge(purpose="recovery"),
            ),
        )
        with TestSession() as db:
            request = db.query(PasswordResetRequest).filter(
                PasswordResetRequest.status == "pending"
            ).one()
            request.expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
            expired_request_id = request.request_id
            db.commit()
        expired_approval = self.client.post(
            f"/auth/admin/password-reset-requests/{expired_request_id}/approve",
            headers=admin_headers,
        )
        self.assertEqual(expired_approval.status_code, 410)
        with TestSession() as db:
            user = db.query(User).filter(User.email == "candidate@example.com").one()
            request = db.query(PasswordResetRequest).filter(
                PasswordResetRequest.request_id == expired_request_id
            ).one()
            self.assertEqual(request.status, "expired")
            self.assertIsNone(request.pending_user_id)
            self.assertTrue(
                auth.password_hash.verify(
                    "safe-test-password",
                    user.hashed_password,
                )
            )

    def test_email_otp_endpoints_are_removed(self):
        self.assertEqual(
            self.client.post(
                "/auth/verify-email",
                json={"email": "candidate@example.com", "otp": "123456"},
            ).status_code,
            404,
        )
        self.assertEqual(
            self.client.post(
                "/auth/resend-otp",
                json={"email": "candidate@example.com"},
            ).status_code,
            404,
        )
        self.assertFalse(hasattr(auth, "send_otp_email"))
        self.assertFalse(hasattr(auth, "send_transactional_email"))


if __name__ == "__main__":
    unittest.main()
