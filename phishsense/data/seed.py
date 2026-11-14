"""Create the database, load training content and create the admin account.

Usage::

    python -m phishsense.data.seed                 # prompts for the admin password
    python -m phishsense.data.seed --reset         # delete the database first

Content loading is idempotent: records are matched by their ``code``, missing
ones are inserted and existing ones are updated to match the content files,
so the script can be re-run after editing content without losing user data.
"""

from __future__ import annotations

import argparse
import getpass
import sys
from collections.abc import Iterable
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from phishsense import config
from phishsense.data import content
from phishsense.data.db import create_db_engine, init_db, make_session_factory, session_scope
from phishsense.data.models import Base, Email, QuizQuestion, TrainingModule, User
from phishsense.services import auth


@dataclass
class SyncResult:
    inserted: int = 0
    updated: int = 0
    unchanged: int = 0

    def __str__(self) -> str:
        return f"{self.inserted} inserted, {self.updated} updated, {self.unchanged} unchanged"


def _sync(session: Session, model: type[Base], records: Iterable[dict]) -> SyncResult:
    """Upsert ``records`` into ``model`` keyed by ``code``."""
    result = SyncResult()
    existing = {row.code: row for row in session.scalars(select(model))}
    for record in records:
        row = existing.get(record["code"])
        if row is None:
            session.add(model(**record))
            result.inserted += 1
            continue
        changed = False
        for key, value in record.items():
            if getattr(row, key) != value:
                setattr(row, key, value)
                changed = True
        if changed:
            result.updated += 1
        else:
            result.unchanged += 1
    session.flush()
    return result


def _email_records() -> list[dict]:
    records = []
    for raw in content.EMAILS:
        record = {
            "link_text": None,
            "link_url": None,
            "attachment_name": None,
            **raw,
        }
        record["is_phishing"] = record["category"] != config.CATEGORY_LEGITIMATE
        records.append(record)
    return records


def seed_content(session: Session) -> dict[str, SyncResult]:
    return {
        "emails": _sync(session, Email, _email_records()),
        "training modules": _sync(session, TrainingModule, content.MODULES),
        "quiz questions": _sync(session, QuizQuestion, content.QUESTIONS),
    }


def ensure_admin(
    session: Session,
    *,
    username: str,
    password: str,
    full_name: str = "Platform Administrator",
    department: str = "IT",
) -> User | None:
    """Create an admin account unless one already exists. Returns the new user or None."""
    has_admin = session.scalar(select(User.id).where(User.role == config.ROLE_ADMIN).limit(1))
    if has_admin is not None:
        return None
    return auth.register_user(
        session,
        username=username,
        full_name=full_name,
        department=department,
        password=password,
        role=config.ROLE_ADMIN,
    )


def _prompt_admin_password() -> str:
    while True:
        first = getpass.getpass("Choose a password for the admin account: ")
        try:
            auth.validate_password(first)
        except auth.AuthError as exc:
            print(exc)
            continue
        if getpass.getpass("Repeat the password: ") == first:
            return first
        print("Passwords did not match, try again.")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--reset", action="store_true",
                        help="delete the existing database before seeding (all user data is lost)")
    parser.add_argument("--admin-username", default="admin")
    parser.add_argument("--admin-password",
                        help="admin password (prompted for if omitted and no admin exists)")
    args = parser.parse_args(argv)

    # Validate before touching the database so a typo changes nothing.
    if args.admin_password is not None:
        try:
            auth.validate_password(args.admin_password)
        except auth.AuthError as exc:
            print(f"Invalid admin password: {exc}", file=sys.stderr)
            return 1

    if args.reset and config.DB_PATH.exists():
        config.DB_PATH.unlink()
        print(f"Deleted {config.DB_PATH}")

    engine = create_db_engine()
    try:
        init_db(engine)
        factory = make_session_factory(engine)
        # One transaction: content and admin are committed together or not at all.
        with session_scope(factory) as session:
            for name, result in seed_content(session).items():
                print(f"{name:>17}: {result}")

            admin_exists = session.scalar(
                select(User.id).where(User.role == config.ROLE_ADMIN).limit(1)
            )
            if admin_exists is None:
                password = args.admin_password or _prompt_admin_password()
                ensure_admin(session, username=args.admin_username, password=password)
                print(f"Created admin account '{auth.normalise_username(args.admin_username)}'.")
            else:
                print("Admin account already exists; left unchanged.")
    except auth.AuthError as exc:
        print(f"Could not create admin: {exc}", file=sys.stderr)
        return 1
    finally:
        engine.dispose()

    print(f"Database ready at {config.DB_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
