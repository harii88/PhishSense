"""User accounts: registration, login, password changes and profile updates.

Passwords are hashed with bcrypt (salted, adaptive cost). Plain-text passwords
are never stored or logged. Usernames are case-insensitive and stored in
lower case.
"""

from __future__ import annotations

import re

import bcrypt
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from phishsense import config
from phishsense.data.models import User


class AuthError(Exception):
    """Raised for any registration, login or profile problem.

    The message is safe to show to the user.
    """


_USERNAME_RE = re.compile(config.USERNAME_PATTERN)

# Used when the username does not exist, so a failed login takes the same time
# whether or not the account exists (no username enumeration by timing).
_DUMMY_HASH = bcrypt.hashpw(b"timing-equaliser", bcrypt.gensalt(rounds=config.BCRYPT_ROUNDS))

_LOGIN_FAILED = "Incorrect username or password."


# ---------------------------------------------------------------------------
# Password helpers
# ---------------------------------------------------------------------------
def validate_password(password: str) -> None:
    if len(password) < config.PASSWORD_MIN_LENGTH:
        raise AuthError(f"Password must be at least {config.PASSWORD_MIN_LENGTH} characters.")
    if len(password.encode("utf-8")) > config.PASSWORD_MAX_BYTES:
        raise AuthError(f"Password must be at most {config.PASSWORD_MAX_BYTES} bytes.")
    if not re.search(r"[A-Za-z]", password) or not re.search(r"\d", password):
        raise AuthError("Password must contain at least one letter and one digit.")


def hash_password(password: str) -> str:
    # config.BCRYPT_ROUNDS is read at call time so tests can lower it.
    salt = bcrypt.gensalt(rounds=config.BCRYPT_ROUNDS)
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("ascii")


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("ascii"))
    except ValueError:  # malformed hash
        return False


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------
def normalise_username(username: str) -> str:
    return username.strip().lower()


def _validate_username(username: str) -> None:
    if not _USERNAME_RE.fullmatch(username):
        raise AuthError(
            "Username must be 3-32 characters: lower-case letters, digits, '.', '_' or '-'."
        )


def _validate_full_name(full_name: str) -> str:
    full_name = " ".join(full_name.split())
    if not 2 <= len(full_name) <= 100:
        raise AuthError("Full name must be between 2 and 100 characters.")
    return full_name


def _validate_department(department: str) -> None:
    if department not in config.DEPARTMENTS:
        raise AuthError("Please choose a department from the list.")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def get_user_by_username(session: Session, username: str) -> User | None:
    return session.scalar(select(User).where(User.username == normalise_username(username)))


def register_user(
    session: Session,
    *,
    username: str,
    full_name: str,
    department: str,
    password: str,
    role: str = config.ROLE_TRAINEE,
) -> User:
    """Create a new account. Raises :class:`AuthError` on invalid input."""
    username = normalise_username(username)
    _validate_username(username)
    full_name = _validate_full_name(full_name)
    _validate_department(department)
    validate_password(password)
    if role not in config.ROLES:
        raise AuthError(f"Unknown role {role!r}.")

    if get_user_by_username(session, username) is not None:
        raise AuthError("That username is already taken.")

    user = User(
        username=username,
        full_name=full_name,
        department=department,
        role=role,
        password_hash=hash_password(password),
    )
    session.add(user)
    try:
        session.flush()
    except IntegrityError as exc:
        # Lost a race with another registration. The caller's session_scope
        # rolls the transaction back when this propagates.
        raise AuthError("That username is already taken.") from exc
    return user


def authenticate(session: Session, username: str, password: str) -> User:
    """Return the user if the credentials are valid, else raise :class:`AuthError`.

    The error message is identical for unknown users and wrong passwords.
    """
    user = get_user_by_username(session, username)
    if user is None:
        bcrypt.checkpw(password.encode("utf-8"), _DUMMY_HASH)
        raise AuthError(_LOGIN_FAILED)
    if not verify_password(password, user.password_hash):
        raise AuthError(_LOGIN_FAILED)
    if not user.is_active:
        raise AuthError("This account has been deactivated. Contact the administrator.")
    return user


def change_password(session: Session, user: User, current_password: str, new_password: str) -> None:
    if not verify_password(current_password, user.password_hash):
        raise AuthError("Current password is incorrect.")
    if current_password == new_password:
        raise AuthError("The new password must be different from the current one.")
    validate_password(new_password)
    user.password_hash = hash_password(new_password)
    session.flush()


def update_profile(
    session: Session,
    user: User,
    *,
    full_name: str | None = None,
    department: str | None = None,
) -> None:
    if full_name is not None:
        user.full_name = _validate_full_name(full_name)
    if department is not None:
        _validate_department(department)
        user.department = department
    session.flush()
