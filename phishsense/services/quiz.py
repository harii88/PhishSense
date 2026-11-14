"""Module quizzes with instant feedback (DESIGN.md section 8).

Flow: ``start_quiz`` -> ``answer`` for each question (stored immediately,
returns feedback with the explanation) -> ``finish_quiz`` (scores the
attempt; >= QUIZ_PASS_SCORE completes the assignment).

Question selection for a module of topic T and level L ranks every question
of topic T by:
  1. already answered correctly by this user (those go last),
  2. distance from level L,
  3. how often the user has seen it,
  4. random.
So a first attempt gets questions at the module's level, and a retry after a
failed attempt brings new questions plus the ones the user got wrong.
"""

from __future__ import annotations

import random
from collections import Counter
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from phishsense import config
from phishsense.data.models import (
    QuizQuestion,
    QuizResult,
    TrainingAssignment,
    User,
    utcnow,
)


class QuizError(Exception):
    """User-facing quiz problem."""


@dataclass(frozen=True)
class QuizAttempt:
    assignment: TrainingAssignment
    attempt: int
    questions: list[QuizQuestion]


@dataclass(frozen=True)
class AnswerFeedback:
    correct: bool
    correct_index: int
    correct_option: str
    explanation: str


@dataclass(frozen=True)
class QuizOutcome:
    correct: int
    total: int
    passed: bool
    best_score: float

    @property
    def score(self) -> float:
        return self.correct / self.total


def _owned_open_assignment(user: User, assignment: TrainingAssignment) -> None:
    if assignment.user_id != user.id:
        raise QuizError("This training is assigned to another user.")
    if assignment.completed_at is not None:
        raise QuizError("This training is already completed.")


def select_questions(
    session: Session, user: User, topic: str, level: int, rng: random.Random
) -> list[QuizQuestion]:
    pool = list(session.scalars(select(QuizQuestion).where(QuizQuestion.topic == topic)))
    if not pool:
        raise QuizError("No questions are loaded for this topic. Run the seed script.")
    history = session.execute(
        select(QuizResult.question_id, QuizResult.correct).where(QuizResult.user_id == user.id)
    ).all()
    seen = Counter(qid for qid, _ in history)
    solved = {qid for qid, correct in history if correct}
    ranked = sorted(
        pool,
        key=lambda q: (q.id in solved, abs(q.level - level), seen[q.id], rng.random()),
    )
    return ranked[: config.QUIZ_LENGTH]


def start_quiz(
    session: Session, user: User, assignment: TrainingAssignment,
    *, rng: random.Random | None = None,
) -> QuizAttempt:
    _owned_open_assignment(user, assignment)
    questions = select_questions(
        session, user, assignment.module.topic, assignment.module.level, rng or random.Random()
    )
    assignment.attempts += 1
    session.flush()
    return QuizAttempt(assignment, assignment.attempts, questions)


def answer(
    session: Session, user: User, attempt: QuizAttempt, question: QuizQuestion,
    chosen_index: int, *, time_ms: int | None = None,
) -> AnswerFeedback:
    assignment = attempt.assignment
    _owned_open_assignment(user, assignment)
    if attempt.attempt != assignment.attempts:
        raise QuizError("This quiz attempt has been replaced by a newer one.")
    if question.id not in {q.id for q in attempt.questions}:
        raise QuizError("That question is not part of this quiz.")
    if not 0 <= chosen_index < len(question.options):
        raise QuizError("Please choose one of the listed answers.")
    already = session.scalar(select(QuizResult.id).where(
        QuizResult.assignment_id == assignment.id,
        QuizResult.attempt == attempt.attempt,
        QuizResult.question_id == question.id,
    ))
    if already is not None:
        raise QuizError("You have already answered this question.")

    correct = chosen_index == question.correct_index
    session.add(QuizResult(
        user_id=user.id, assignment_id=assignment.id, attempt=attempt.attempt,
        question_id=question.id, chosen_index=chosen_index, correct=correct, time_ms=time_ms,
    ))
    session.flush()
    return AnswerFeedback(
        correct=correct,
        correct_index=question.correct_index,
        correct_option=question.options[question.correct_index],
        explanation=question.explanation,
    )


def finish_quiz(session: Session, user: User, attempt: QuizAttempt) -> QuizOutcome:
    assignment = attempt.assignment
    _owned_open_assignment(user, assignment)
    results = list(session.scalars(select(QuizResult).where(
        QuizResult.assignment_id == assignment.id, QuizResult.attempt == attempt.attempt,
    )))
    if len(results) < len(attempt.questions):
        raise QuizError(f"Answer all {len(attempt.questions)} questions first.")

    correct = sum(r.correct for r in results)
    score = correct / len(results)
    passed = score >= config.QUIZ_PASS_SCORE
    assignment.quiz_score = max(score, assignment.quiz_score or 0.0)
    if passed:
        assignment.completed_at = utcnow()
    session.flush()
    return QuizOutcome(correct, len(results), passed, assignment.quiz_score)
