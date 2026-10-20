"""Authentication: single admin account, argon2, signed-cookie sessions, CSRF.

- Password hash from ``LPW_ADMIN_PASSWORD_HASH`` (generate with ``lpw hash-password``).
- Sessions: itsdangerous signed cookies, HttpOnly + SameSite=Strict, rotated on
  login, idle timeout.
- Login failures are rate limited per client IP.
- All mutating forms carry a CSRF token validated with hmac.compare_digest.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import secrets
import time
from dataclasses import dataclass, field
from typing import Any

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHash, VerificationError
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

SESSION_COOKIE = "lpw_session"
CSRF_COOKIE = "lpw_csrf"
CSRF_HEADER = "x-csrftoken"
CSRF_FORM_FIELD = "csrf_token"

logger = logging.getLogger(__name__)

_ph = PasswordHasher()
# load_auth_config's ``secrets`` parameter shadows the module.
_random_secret = secrets.token_urlsafe


class AuthError(RuntimeError):
    pass


@dataclass
class AuthConfig:
    password_hash: str | None
    secret_key: str
    idle_timeout_minutes: int = 120
    login_rate_limit_max_attempts: int = 5
    login_rate_limit_window_seconds: int = 300

    @property
    def enabled(self) -> bool:
        return bool(self.password_hash)


@dataclass
class Session:
    username: str
    issued_at: float
    last_seen: float


class Authenticator:
    def __init__(self, config: AuthConfig) -> None:
        self.config = config
        self._serializer = URLSafeTimedSerializer(config.secret_key, salt="lpw-session")
        self._login_attempts: dict[str, list[float]] = {}

    # ------------------------------------------------------------------
    # password
    # ------------------------------------------------------------------

    def verify_password(self, password: str) -> bool:
        if not self.config.password_hash:
            return False
        try:
            return _ph.verify(self.config.password_hash, password)
        except (VerificationError, InvalidHash):
            return False

    # ------------------------------------------------------------------
    # rate limiting
    # ------------------------------------------------------------------

    def login_blocked(self, client_ip: str) -> bool:
        now = time.time()
        window = self.config.login_rate_limit_window_seconds
        attempts = [t for t in self._login_attempts.get(client_ip, []) if now - t < window]
        self._login_attempts[client_ip] = attempts
        return len(attempts) >= self.config.login_rate_limit_max_attempts

    def record_login_failure(self, client_ip: str) -> None:
        now = time.time()
        self._login_attempts.setdefault(client_ip, []).append(now)

    def clear_login_failures(self, client_ip: str) -> None:
        self._login_attempts.pop(client_ip, None)

    # ------------------------------------------------------------------
    # sessions
    # ------------------------------------------------------------------

    def issue_session(self, username: str) -> str:
        now = time.time()
        payload = {"u": username, "iat": now, "ls": now, "n": secrets.token_hex(4)}
        return self._serializer.dumps(payload)

    def load_session(self, token: str | None) -> Session | None:
        if not token:
            return None
        max_age = self.config.idle_timeout_minutes * 60
        try:
            data = self._serializer.loads(token, max_age=max_age)
        except (BadSignature, SignatureExpired):
            return None
        if not isinstance(data, dict) or not data.get("u"):
            return None
        return Session(
            username=str(data["u"]),
            issued_at=float(data.get("iat") or 0),
            last_seen=float(data.get("ls") or 0),
        )

    def rotate_session(self, token: str | None) -> str | None:
        """Refresh last_seen (sliding idle window); returns a new token."""
        session = self.load_session(token)
        if session is None:
            return None
        return self.issue_session(session.username)

    # ------------------------------------------------------------------
    # CSRF
    # ------------------------------------------------------------------

    def issue_csrf_token(self) -> str:
        return secrets.token_urlsafe(32)

    def check_csrf(self, session_token: str | None, submitted: str | None) -> bool:
        if not submitted:
            return False
        expected = self._csrf_for_session(session_token)
        if not expected:
            return False
        return hmac.compare_digest(expected, submitted)

    def _csrf_for_session(self, session_token: str | None) -> str | None:
        if not session_token:
            return None
        digest = hashlib.sha256(f"csrf|{session_token}".encode()).hexdigest()
        return digest


def load_auth_config(settings: Any, secrets: Any) -> AuthConfig:
    """Build AuthConfig from app settings + env secrets.

    Without ``LPW_SESSION_SECRET`` (env or .env) a random per-process secret is
    used: sessions then do not survive a restart, but cannot be forged.
    """
    secret = getattr(secrets, "session_secret", None) or os_environ("LPW_SESSION_SECRET")
    if not secret:
        logger.warning("LPW_SESSION_SECRET is not set; using a random per-process session secret")
        secret = _random_secret(32)
    return AuthConfig(
        password_hash=secrets.admin_password_hash,
        secret_key=secret,
        idle_timeout_minutes=int(settings.web.session_idle_timeout_minutes),
        login_rate_limit_max_attempts=int(settings.web.login_rate_limit_max_attempts),
        login_rate_limit_window_seconds=int(settings.web.login_rate_limit_window_seconds),
    )


def os_environ(name: str) -> str | None:
    import os

    return os.environ.get(name)
