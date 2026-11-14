from __future__ import annotations

import pytest

from phishsense import config
from phishsense.data.db import session_scope
from phishsense.data.models import User
from phishsense.services import auth
from phishsense.services.auth import AuthError

GOOD = dict(
    username="alice",
    full_name="Alice Example",
    department="Finance",
    password="correct1horse",
)


def register(db, **overrides):
    return auth.register_user(db, **{**GOOD, **overrides})


# ----------------------------------------------------------------- register
def test_register_creates_trainee_with_hashed_password(db):
    user = register(db)
    assert user.id is not None
    assert user.role == config.ROLE_TRAINEE
    assert not user.is_admin
    assert user.password_hash != GOOD["password"]
    assert user.password_hash.startswith("$2")  # bcrypt format
    assert GOOD["password"] not in user.password_hash


def test_same_password_gets_different_hashes(db):
    a = register(db, username="alice")
    b = register(db, username="bob")
    assert a.password_hash != b.password_hash  # unique salt per user


def test_username_is_normalised_and_case_insensitive(db):
    user = register(db, username="  Alice ")
    assert user.username == "alice"
    with pytest.raises(AuthError, match="already taken"):
        register(db, username="ALICE")


@pytest.mark.parametrize("username", ["ab", "a" * 33, "alice smith", "alice!", ""])
def test_invalid_usernames_rejected(db, username):
    with pytest.raises(AuthError, match="Username"):
        register(db, username=username)


@pytest.mark.parametrize(
    "password, message",
    [
        ("short1", "at least"),
        ("onlyletters", "letter and one digit"),
        ("12345678", "letter and one digit"),
        ("a1" * 40, "at most"),
    ],
)
def test_weak_passwords_rejected(db, password, message):
    with pytest.raises(AuthError, match=message):
        register(db, password=password)


def test_unknown_department_rejected(db):
    with pytest.raises(AuthError, match="department"):
        register(db, department="Space Program")


def test_full_name_whitespace_collapsed_and_length_checked(db):
    assert register(db, full_name="  Alice   Example ").full_name == "Alice Example"
    with pytest.raises(AuthError, match="Full name"):
        register(db, username="bob", full_name="A")


def test_unknown_role_rejected(db):
    with pytest.raises(AuthError, match="role"):
        register(db, role="superuser")


def test_admin_role(db):
    assert register(db, role=config.ROLE_ADMIN).is_admin


def test_failed_registration_inside_session_scope_rolls_back(session_factory):
    with session_scope(session_factory) as s:
        register(s)
    with pytest.raises(AuthError):
        with session_scope(session_factory) as s:
            register(s, username="carol")
            register(s, username="carol")  # duplicate aborts the whole unit of work
    with session_scope(session_factory) as s:
        assert {u.username for u in s.query(User)} == {"alice"}


# -------------------------------------------------------------------- login
def test_authenticate_success_is_case_insensitive_on_username(db):
    user = register(db)
    assert auth.authenticate(db, "ALICE", GOOD["password"]) is user


def test_wrong_password_and_unknown_user_give_same_message(db):
    register(db)
    with pytest.raises(AuthError) as wrong:
        auth.authenticate(db, "alice", "wrong-pass1")
    with pytest.raises(AuthError) as unknown:
        auth.authenticate(db, "nobody", "wrong-pass1")
    assert str(wrong.value) == str(unknown.value)


def test_password_is_case_sensitive(db):
    register(db)
    with pytest.raises(AuthError):
        auth.authenticate(db, "alice", GOOD["password"].upper())


def test_inactive_user_cannot_log_in(db):
    user = register(db)
    user.is_active = False
    with pytest.raises(AuthError, match="deactivated"):
        auth.authenticate(db, "alice", GOOD["password"])


def test_verify_password_handles_malformed_hash():
    assert auth.verify_password("anything1", "not-a-bcrypt-hash") is False


# ------------------------------------------------------------------ profile
def test_change_password(db):
    user = register(db)
    auth.change_password(db, user, GOOD["password"], "new-secret9")
    assert auth.authenticate(db, "alice", "new-secret9") is user
    with pytest.raises(AuthError):
        auth.authenticate(db, "alice", GOOD["password"])


def test_change_password_requires_current_and_new_rules(db):
    user = register(db)
    with pytest.raises(AuthError, match="Current password"):
        auth.change_password(db, user, "wrong-pass1", "new-secret9")
    with pytest.raises(AuthError, match="different"):
        auth.change_password(db, user, GOOD["password"], GOOD["password"])
    with pytest.raises(AuthError, match="at least"):
        auth.change_password(db, user, GOOD["password"], "x1")


def test_update_profile(db):
    user = register(db)
    auth.update_profile(db, user, full_name="Alice B. Example", department="IT")
    assert (user.full_name, user.department) == ("Alice B. Example", "IT")
    with pytest.raises(AuthError):
        auth.update_profile(db, user, department="Nowhere")
    assert user.department == "IT"
