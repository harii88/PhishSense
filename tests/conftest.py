from __future__ import annotations

import pytest

from phishsense import config
from phishsense.data.db import IN_MEMORY_URL, create_db_engine, init_db, make_session_factory


@pytest.fixture(autouse=True)
def fast_bcrypt(monkeypatch):
    """bcrypt's minimum cost keeps the suite fast; hashing logic is unchanged."""
    monkeypatch.setattr(config, "BCRYPT_ROUNDS", 4)


@pytest.fixture
def ml_env(tmp_path, monkeypatch):
    """Isolated model directory and smaller, faster training runs."""
    from phishsense.services.ml import registry

    monkeypatch.setattr(config, "MODELS_DIR", tmp_path / "models")
    monkeypatch.setattr(config, "SYNTHETIC_USERS", 300)
    monkeypatch.setattr(config, "RF_N_ESTIMATORS", 60)
    registry.clear_cache()
    yield tmp_path / "models"
    registry.clear_cache()


@pytest.fixture
def engine():
    engine = create_db_engine(IN_MEMORY_URL)
    init_db(engine)
    yield engine
    engine.dispose()


@pytest.fixture
def session_factory(engine):
    return make_session_factory(engine)


@pytest.fixture
def db(session_factory):
    session = session_factory()
    yield session
    session.rollback()
    session.close()
