"""Static training content: simulated emails, lessons and quiz questions.

Everything here is fictional. The trainee's employer is "Corvane Technologies"
(corvane.com); outside services are "Meridian Trust Bank" (meridiantrust.com),
"Nimbus Drive" (nimbusdrive.com) and "SwiftParcel" (swiftparcel.com). None of
these names refer to real organisations, and the application never opens any
URL listed here: links are data shown on hover, nothing more.

Every record has a stable ``code`` so the seed script can insert or update it
idempotently.
"""

from phishsense.data.content.emails import EMAILS
from phishsense.data.content.modules import MODULES
from phishsense.data.content.questions import QUESTIONS

# The only genuine domains in the fictional world. A host belongs to one of
# them if it equals the domain or ends with "." + domain.
TRUSTED_DOMAINS = ("corvane.com", "meridiantrust.com", "nimbusdrive.com", "swiftparcel.com")

# Baseline assessment: identical for every user so baselines are comparable.
# Two phishing emails per vector (levels 1 and 2) and four genuine emails, in a
# fixed interleaved inbox order.
BASELINE_EMAIL_CODES = (
    "leg-1-allhands",
    "url-1-bank-verify",
    "imp-2-salary-letter",
    "att-1-invoice-exe",
    "leg-2-payslip",
    "urg-1-mailbox-delete",
    "url-2-password-portal",
    "leg-1-maintenance",
    "imp-1-ceo-giftcards",
    "urg-2-payroll-confirm",
    "leg-2-bank-statement",
    "att-2-holiday-xlsm",
)

# File extensions that can run code or hide code that runs.
DANGEROUS_EXTENSIONS = (
    ".exe", ".scr", ".bat", ".js", ".vbs", ".zip", ".rar", ".7z",
    ".xlsm", ".docm", ".html", ".htm", ".iso", ".img", ".lnk",
)


def is_trusted_host(host: str | None) -> bool:
    if not host:
        return False
    host = host.lower().rstrip(".")
    return any(host == d or host.endswith("." + d) for d in TRUSTED_DOMAINS)


__all__ = [
    "EMAILS",
    "MODULES",
    "QUESTIONS",
    "TRUSTED_DOMAINS",
    "BASELINE_EMAIL_CODES",
    "DANGEROUS_EXTENSIONS",
    "is_trusted_host",
]
