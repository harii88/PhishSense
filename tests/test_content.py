"""Integrity checks on the static training content.

The most important property: every phishing email carries at least one cue a
careful trainee can detect inside the app (an untrusted sender or link domain,
or a dangerous attachment type), and no genuine email carries one. Without
this, the behaviour we measure would be guessing, not judgement.
"""

from __future__ import annotations

from collections import Counter
from urllib.parse import urlsplit

import pytest

from phishsense import config
from phishsense.data.content import (
    DANGEROUS_EXTENSIONS,
    EMAILS,
    MODULES,
    QUESTIONS,
    is_trusted_host,
)

PHISHING = [e for e in EMAILS if e["category"] != config.CATEGORY_LEGITIMATE]
GENUINE = [e for e in EMAILS if e["category"] == config.CATEGORY_LEGITIMATE]


def sender_host(email: dict) -> str:
    return email["sender_address"].rsplit("@", 1)[1]


def link_host(email: dict) -> str | None:
    return urlsplit(email["link_url"]).hostname if email.get("link_url") else None


def is_dangerous_file(name: str | None) -> bool:
    return bool(name) and name.lower().endswith(DANGEROUS_EXTENSIONS)


def ids(items):
    return [i["code"] for i in items]


# ------------------------------------------------------------------ emails
def test_codes_unique_everywhere():
    for collection in (EMAILS, MODULES, QUESTIONS):
        dupes = [c for c, n in Counter(ids(collection)).items() if n > 1]
        assert not dupes


def test_vocabularies():
    for e in EMAILS:
        assert e["category"] in config.EMAIL_CATEGORIES
        assert e["difficulty"] in config.LEVELS


@pytest.mark.parametrize("vector", config.VECTORS)
@pytest.mark.parametrize("level", config.LEVELS)
def test_two_phishing_emails_per_vector_and_level(vector, level):
    # Lets the adaptive engine serve a level twice before repeating an email.
    n = sum(1 for e in PHISHING if e["category"] == vector and e["difficulty"] == level)
    assert n >= 2


def test_enough_genuine_emails_at_every_level():
    assert len(GENUINE) >= 3 * config.SESSION_LEGITIMATE_COUNT
    assert {e["difficulty"] for e in GENUINE} == set(config.LEVELS)


@pytest.mark.parametrize("email", EMAILS, ids=ids(EMAILS))
def test_link_placeholder_consistency(email):
    has_link = bool(email.get("link_url"))
    assert email["body"].count("{link}") == (1 if has_link else 0)
    assert bool(email.get("link_text")) == has_link


@pytest.mark.parametrize("email", EMAILS, ids=ids(EMAILS))
def test_body_has_no_active_or_credential_html(email):
    body = email["body"].lower()
    for forbidden in ("<script", "<form", "<input", "<iframe", "javascript:", "<img"):
        assert forbidden not in body


@pytest.mark.parametrize("email", PHISHING, ids=ids(PHISHING))
def test_phishing_email_is_detectable(email):
    cues = [
        not is_trusted_host(sender_host(email)),
        link_host(email) is not None and not is_trusted_host(link_host(email)),
        is_dangerous_file(email.get("attachment_name")),
    ]
    assert any(cues), "no in-app cue a trainee could use to detect this email"
    assert len(email["indicators"]) >= 2


@pytest.mark.parametrize("email", GENUINE, ids=ids(GENUINE))
def test_genuine_email_has_no_phishing_cue(email):
    assert is_trusted_host(sender_host(email))
    if email.get("link_url"):
        assert is_trusted_host(link_host(email))
        assert urlsplit(email["link_url"]).scheme == "https"
    assert not is_dangerous_file(email.get("attachment_name"))
    assert email["indicators"]


def test_vector_specific_payloads():
    for e in PHISHING:
        if e["category"] == config.VECTOR_ATTACHMENT:
            assert is_dangerous_file(e.get("attachment_name")), e["code"]
        else:
            assert e.get("link_url"), e["code"]
        if e["category"] == config.VECTOR_URL_SPOOFING:
            assert not is_trusted_host(link_host(e)), e["code"]


def test_url_looking_link_text_mismatch_only_on_phishing():
    for e in EMAILS:
        text = e.get("link_text") or ""
        if text.startswith("http"):
            mismatch = urlsplit(text).hostname != link_host(e)
            assert mismatch == (e["category"] != config.CATEGORY_LEGITIMATE), e["code"]


def test_is_trusted_host_reads_domain_from_the_right():
    assert is_trusted_host("portal.corvane.com")
    assert is_trusted_host("CORVANE.COM.")
    assert not is_trusted_host("portal.corvane.com.reset-account.info")
    assert not is_trusted_host("corvane.co")
    assert not is_trusted_host("evilcorvane.com")
    assert not is_trusted_host(None)


# ----------------------------------------------------------------- modules
def test_module_for_every_vector_level_and_behaviour_topic():
    pairs = {(m["topic"], m["level"]) for m in MODULES}
    for vector in config.VECTORS:
        for level in config.LEVELS:
            assert (vector, level) in pairs
    assert (config.TOPIC_PAUSE_INSPECT, 1) in pairs
    assert (config.TOPIC_REPORTING, 1) in pairs
    assert len(pairs) == len(MODULES)  # (topic, level) is unique


def test_modules_well_formed():
    for m in MODULES:
        assert m["topic"] in config.TOPICS
        assert m["level"] in config.LEVELS
        assert m["title"] and m["summary"] and "<h3>" in m["lesson"]


# --------------------------------------------------------------- questions
@pytest.mark.parametrize("topic", config.TOPICS)
def test_every_topic_can_fill_a_quiz(topic):
    assert sum(1 for q in QUESTIONS if q["topic"] == topic) >= config.QUIZ_LENGTH


@pytest.mark.parametrize("vector", config.VECTORS)
def test_vector_questions_cover_every_level(vector):
    assert {q["level"] for q in QUESTIONS if q["topic"] == vector} == set(config.LEVELS)


@pytest.mark.parametrize("q", QUESTIONS, ids=ids(QUESTIONS))
def test_question_well_formed(q):
    assert q["topic"] in config.TOPICS
    assert q["kind"] in config.QUIZ_KINDS
    assert q["level"] in config.LEVELS
    assert len(q["options"]) >= 2
    assert len(set(q["options"])) == len(q["options"])
    assert 0 <= q["correct_index"] < len(q["options"])
    assert len(q["explanation"]) > 20
    if q["kind"] == config.QUIZ_KIND_JUDGE:
        assert q["options"] == ["Phishing", "Legitimate"]


def test_answer_positions_are_varied():
    # Guard against a bank where "always pick B" scores well.
    multi = [q["correct_index"] for q in QUESTIONS if len(q["options"]) > 2]
    most_common_share = Counter(multi).most_common(1)[0][1] / len(multi)
    assert most_common_share < 0.75
