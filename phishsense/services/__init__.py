"""Service layer: application logic with no GUI dependencies.

Services receive a SQLAlchemy ``Session`` and only flush; the caller commits
(see :mod:`phishsense.data.db`).
"""
