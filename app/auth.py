"""Authentication and authorization.

- Passwords: scrypt (stdlib), per-user random salt, constant-time comparison.
- Browser: session cookie (random token; only its sha256 is stored), HttpOnly + SameSite=Lax.
- API clients (curl): HTTP Basic auth on every request.
- Authorization: admins see everything; other users see only analyses of teams they belong to.
"""
import base64
import binascii
import hashlib
import hmac
import logging
import os
import re
import secrets
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import timedelta

from fastapi import Depends, HTTPException, Request, Response

from . import db

log = logging.getLogger("pcap-analyzer.auth")

COOKIE_NAME = "pcap_session"
SESSION_TTL = timedelta(hours=int(os.getenv("SESSION_TTL_HOURS", "168")))
COOKIE_SECURE = os.getenv("SESSION_COOKIE_SECURE", "0") == "1"  # set to 1 when served over HTTPS
MIN_PASSWORD_LENGTH = 8
USERNAME_RE = re.compile(r"^[A-Za-z0-9._-]{3,32}$")

# login throttling: max failures per key within the window
MAX_FAILURES = 5
FAILURE_WINDOW = 15 * 60

_SCRYPT = {"n": 2 ** 14, "r": 8, "p": 1}


# ---------------------------------------------------------------- passwords
def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, dklen=32, **_SCRYPT)
    return "scrypt${n}${r}${p}${salt}${hash}".format(
        **_SCRYPT, salt=base64.b64encode(salt).decode(), hash=base64.b64encode(digest).decode())


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, n, r, p, salt, expected = stored.split("$")
        if algo != "scrypt":
            return False
        digest = hashlib.scrypt(password.encode(), salt=base64.b64decode(salt), dklen=32,
                                n=int(n), r=int(r), p=int(p))
        return hmac.compare_digest(digest, base64.b64decode(expected))
    except (ValueError, binascii.Error):
        return False


_DUMMY_HASH = hash_password(secrets.token_urlsafe(16))  # keeps timing similar for unknown usernames


def validate_username(username: str) -> str:
    username = username.strip()
    if not USERNAME_RE.match(username):
        raise HTTPException(422, "username must be 3–32 characters: letters, digits, '.', '_' or '-'")
    return username


def validate_password(password: str) -> str:
    if len(password) < MIN_PASSWORD_LENGTH:
        raise HTTPException(422, f"password must be at least {MIN_PASSWORD_LENGTH} characters")
    return password


# ---------------------------------------------------------------- login throttling
_failures: dict[str, deque] = defaultdict(deque)
_failures_lock = threading.Lock()


def _throttle_keys(username: str, request: Request) -> list[str]:
    ip = request.client.host if request.client else "?"
    return [f"user:{username.lower()}", f"ip:{ip}"]


def _check_throttle(keys: list[str]) -> None:
    now = time.monotonic()
    with _failures_lock:
        for k in keys:
            q = _failures[k]
            while q and now - q[0] > FAILURE_WINDOW:
                q.popleft()
            if len(q) >= MAX_FAILURES:
                raise HTTPException(429, "too many failed login attempts; try again later")


def _record_failure(keys: list[str]) -> None:
    now = time.monotonic()
    with _failures_lock:
        for k in keys:
            _failures[k].append(now)


def _clear_failures(keys: list[str]) -> None:
    with _failures_lock:
        for k in keys:
            _failures.pop(k, None)


def authenticate(username: str, password: str, request: Request) -> dict:
    """Check credentials (throttled). Returns the user row or raises 401/429."""
    keys = _throttle_keys(username, request)
    _check_throttle(keys)
    user = db.get_user_by_name(username.strip())
    ok = verify_password(password, user["password_hash"] if user else _DUMMY_HASH)
    if not (user and ok and user["active"]):
        _record_failure(keys)
        raise HTTPException(401, "invalid username or password")
    _clear_failures(keys)
    return user


# ---------------------------------------------------------------- sessions
def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def start_session(response: Response, user_id: int) -> None:
    token = secrets.token_urlsafe(32)
    db.create_session(_token_hash(token), user_id, SESSION_TTL)
    db.update_user(user_id, last_login_at=db.now())
    response.set_cookie(COOKIE_NAME, token, max_age=int(SESSION_TTL.total_seconds()), httponly=True,
                        samesite="lax", secure=COOKIE_SECURE, path="/")


def end_session(request: Request, response: Response) -> None:
    token = request.cookies.get(COOKIE_NAME)
    if token:
        db.delete_session(_token_hash(token))
    response.delete_cookie(COOKIE_NAME, path="/")


# ---------------------------------------------------------------- current user
@dataclass
class User:
    id: int
    username: str
    is_admin: bool
    team_ids: list[int] = field(default_factory=list)

    def can_access_team(self, team_id: int | None) -> bool:
        return self.is_admin or (team_id is not None and team_id in self.team_ids)

    @property
    def visible_team_ids(self) -> list[int] | None:
        """None = all teams (admin)."""
        return None if self.is_admin else self.team_ids


def _to_user(row: dict) -> User:
    return User(id=row["id"], username=row["username"], is_admin=bool(row["is_admin"]),
                team_ids=db.user_team_ids(row["id"]))


def current_user(request: Request) -> User:
    token = request.cookies.get(COOKIE_NAME)
    if token:
        row = db.get_session_user(_token_hash(token))
        if row:
            return _to_user(row)
    header = request.headers.get("authorization", "")
    if header.lower().startswith("basic "):
        try:
            username, _, password = base64.b64decode(header[6:]).decode().partition(":")
        except (binascii.Error, UnicodeDecodeError):
            raise HTTPException(401, "invalid Authorization header")
        return _to_user(authenticate(username, password, request))
    # No WWW-Authenticate header on purpose: it would make browsers pop up a native login dialog.
    raise HTTPException(401, "not authenticated")


def require_admin(user: User = Depends(current_user)) -> User:
    if not user.is_admin:
        raise HTTPException(403, "admin only")
    return user


# ---------------------------------------------------------------- resource access (404 when not visible)
def analysis_for(user: User, analysis_id: int) -> dict:
    a = db.get_analysis(analysis_id)
    if not a or not user.can_access_team(a["team_id"]):
        raise HTTPException(404, "analysis not found")
    return a


def run_for(user: User, run_id: int) -> dict:
    r = db.get_run(run_id)
    if not r:
        raise HTTPException(404, "run not found")
    a = db.get_analysis(r["analysis_id"])
    if not a or not user.can_access_team(a["team_id"]):
        raise HTTPException(404, "run not found")
    return r


# ---------------------------------------------------------------- bootstrap
def bootstrap_admin() -> None:
    """Create the first admin if there are no users yet."""
    if db.count_users():
        return
    username = os.getenv("ADMIN_USERNAME", "admin")
    password = os.getenv("ADMIN_PASSWORD", "")
    generated = not password
    if generated:
        password = secrets.token_urlsafe(12)
    db.create_user(validate_username(username), hash_password(validate_password(password)), is_admin=True)
    if generated:
        log.warning("=" * 70)
        log.warning("Created admin user '%s' with generated password: %s", username, password)
        log.warning("Log in and change it (or set ADMIN_PASSWORD before the first start).")
        log.warning("=" * 70)
    else:
        log.info("Created admin user '%s' from ADMIN_PASSWORD", username)
