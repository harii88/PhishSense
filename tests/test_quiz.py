from __future__ import annotations

import random

import pytest
from sqlalchemy import select

from phishsense import config
from phishsense.data.models import QuizQuestion, QuizResult, TrainingAssignment, TrainingModule
from phishsense.data.seed import seed_content
from phishsense.services import quiz, simulation
from phishsense.services.quiz import QuizError
from tests.helpers import make_trainee


@pytest.fixture
def ctx(db):
    seed_content(db)
    user = make_trainee(db, "alice")
    module = db.scalar(select(TrainingModule).where(
        TrainingModule.topic == config.VECTOR_URL_SPOOFING, TrainingModule.level == 1))
    assignment = TrainingAssignment(user_id=user.id, module_id=module.id, reason="r", mandatory=True)
    db.add(assignment)
    db.flush()
    return db, user, assignment


def answer_all(db, user, attempt, n_correct):
    for i, q in enumerate(attempt.questions):
        choice = q.correct_index if i < n_correct else (q.correct_index + 1) % len(q.options)
        quiz.answer(db, user, attempt, q, choice, time_ms=4000)


def test_start_selects_topic_questions_at_module_level(ctx):
    db, user, assignment = ctx
    attempt = quiz.start_quiz(db, user, assignment, rng=random.Random(0))
    assert attempt.attempt == assignment.attempts == 1
    assert len(attempt.questions) == config.QUIZ_LENGTH
    assert {q.topic for q in attempt.questions} == {config.VECTOR_URL_SPOOFING}
    levels = [q.level for q in attempt.questions]
    n_level_1 = db.query(QuizQuestion).filter_by(topic=config.VECTOR_URL_SPOOFING, level=1).count()
    assert levels[:n_level_1] == [1] * n_level_1          # module level first
    assert levels == sorted(levels)                       # then nearest levels


def test_answer_gives_instant_feedback(ctx):
    db, user, assignment = ctx
    attempt = quiz.start_quiz(db, user, assignment, rng=random.Random(0))
    q = attempt.questions[0]
    good = quiz.answer(db, user, attempt, q, q.correct_index)
    assert good.correct and good.explanation == q.explanation
    q2 = attempt.questions[1]
    wrong_choice = (q2.correct_index + 1) % len(q2.options)
    bad = quiz.answer(db, user, attempt, q2, wrong_choice)
    assert not bad.correct and bad.correct_option == q2.options[q2.correct_index]
    stored = db.scalars(select(QuizResult).order_by(QuizResult.id)).all()
    assert [(r.correct, r.attempt) for r in stored] == [(True, 1), (False, 1)]


def test_answer_validation(ctx):
    db, user, assignment = ctx
    attempt = quiz.start_quiz(db, user, assignment, rng=random.Random(0))
    q = attempt.questions[0]
    with pytest.raises(QuizError, match="listed answers"):
        quiz.answer(db, user, attempt, q, len(q.options))
    quiz.answer(db, user, attempt, q, 0)
    with pytest.raises(QuizError, match="already answered"):
        quiz.answer(db, user, attempt, q, 0)
    outsider = db.scalar(select(QuizQuestion).where(QuizQuestion.topic != q.topic).limit(1))
    with pytest.raises(QuizError, match="not part"):
        quiz.answer(db, user, attempt, outsider, 0)


def test_other_users_and_stale_attempts_rejected(ctx):
    db, user, assignment = ctx
    attempt = quiz.start_quiz(db, user, assignment, rng=random.Random(0))
    bob = make_trainee(db, "bob")
    with pytest.raises(QuizError, match="another user"):
        quiz.start_quiz(db, bob, assignment)
    quiz.start_quiz(db, user, assignment, rng=random.Random(1))   # newer attempt
    with pytest.raises(QuizError, match="newer"):
        quiz.answer(db, user, attempt, attempt.questions[0], 0)


def test_finish_requires_all_answers(ctx):
    db, user, assignment = ctx
    attempt = quiz.start_quiz(db, user, assignment, rng=random.Random(0))
    answer_all(db, user, type(attempt)(attempt.assignment, attempt.attempt, attempt.questions[:4]), 4)
    with pytest.raises(QuizError, match="Answer all"):
        quiz.finish_quiz(db, user, attempt)


def test_pass_completes_assignment(ctx):
    db, user, assignment = ctx
    attempt = quiz.start_quiz(db, user, assignment, rng=random.Random(0))
    answer_all(db, user, attempt, 4)
    outcome = quiz.finish_quiz(db, user, attempt)
    assert (outcome.correct, outcome.total, outcome.passed) == (4, 5, True)
    assert outcome.score == pytest.approx(0.8)
    assert assignment.completed_at is not None and assignment.quiz_score == pytest.approx(0.8)
    with pytest.raises(QuizError, match="already completed"):
        quiz.start_quiz(db, user, assignment)


def test_fail_keeps_assignment_open_and_retry_avoids_solved_questions(ctx):
    db, user, assignment = ctx
    first = quiz.start_quiz(db, user, assignment, rng=random.Random(0))
    answer_all(db, user, first, 3)                        # 60% < 70%
    outcome = quiz.finish_quiz(db, user, first)
    assert not outcome.passed and assignment.completed_at is None

    solved = {q.id for q in first.questions[:3]}
    second = quiz.start_quiz(db, user, assignment, rng=random.Random(0))
    assert second.attempt == 2
    assert solved.isdisjoint(q.id for q in second.questions)
    answer_all(db, user, second, 2)                       # worse attempt
    quiz.finish_quiz(db, user, second)
    assert assignment.quiz_score == pytest.approx(0.6)    # best score kept


def test_passing_mandatory_quiz_unblocks_simulation(ctx):
    db, user, assignment = ctx
    with pytest.raises(simulation.SimulationError, match="required training"):
        simulation.start_session(db, user)
    attempt = quiz.start_quiz(db, user, assignment, rng=random.Random(0))
    answer_all(db, user, attempt, 5)
    quiz.finish_quiz(db, user, attempt)
    assert simulation.start_session(db, user) is not None


@pytest.mark.parametrize("topic", config.TOPICS)
def test_every_module_can_run_a_full_quiz(db, topic):
    seed_content(db)
    user = make_trainee(db, "alice")
    for module in db.scalars(select(TrainingModule).where(TrainingModule.topic == topic)):
        a = TrainingAssignment(user_id=user.id, module_id=module.id, reason="r")
        db.add(a)
        db.flush()
        attempt = quiz.start_quiz(db, user, a, rng=random.Random(0))
        assert len({q.id for q in attempt.questions}) == config.QUIZ_LENGTH
