"""Quiz question bank.

Each topic has at least ``config.QUIZ_LENGTH`` questions so any module's quiz
can be filled. Vector topics have questions at every level; the quiz service
(Module 4) prefers the module's level and falls back to neighbouring levels.

Kinds: ``judge`` (phishing or legitimate?), ``url`` (where does this link
really go / which address is genuine?), ``flag`` (spot the red flag or choose
the right response).
"""

from __future__ import annotations

from phishsense import config

_URL = config.VECTOR_URL_SPOOFING
_URG = config.VECTOR_URGENCY
_IMP = config.VECTOR_IMPERSONATION
_ATT = config.VECTOR_ATTACHMENT
_PAUSE = config.TOPIC_PAUSE_INSPECT
_REPORT = config.TOPIC_REPORTING

_J = config.QUIZ_KIND_JUDGE
_U = config.QUIZ_KIND_URL
_F = config.QUIZ_KIND_FLAG

_PHISH_OR_LEGIT = ["Phishing", "Legitimate"]


def _q(code, topic, level, kind, prompt, options, correct_index, explanation) -> dict:
    return dict(
        code=code,
        topic=topic,
        level=level,
        kind=kind,
        prompt=prompt,
        options=list(options),
        correct_index=correct_index,
        explanation=explanation,
    )


QUESTIONS: list[dict] = [
    # ================================================================ URL
    _q("q-url-01", _URL, 1, _U,
       "Which organisation owns this address?<br><code>http://meridian-trust-secure.net/login</code>",
       ["Meridian Trust Bank", "Whoever registered meridian-trust-secure.net",
        "Corvane IT", "It cannot be told from the address"],
       1,
       "The domain is meridian-trust-secure.net. Adding words like 'secure' to a brand "
       "makes a new domain that anyone can register; the bank's domain is meridiantrust.com."),
    _q("q-url-02", _URL, 1, _F,
       "A link says <b>Verify my account</b>. What is the most reliable way to see where it goes?",
       ["Trust the link text", "Hover and read the address in the status bar",
        "Click it and check the page that opens", "Check that the email has a logo"],
       1,
       "Link text is only a label. Hovering shows the real destination without visiting it; "
       "clicking first is exactly what the attacker wants."),
    _q("q-url-03", _URL, 1, _J,
       "Email from <code>no-reply@nimbus-drive-share.co</code>: '3 documents were shared with you, "
       "sign in before they expire'. The link goes to <code>http://nimbus-drive-share.co/view</code>.",
       _PHISH_OR_LEGIT, 0,
       "The real service is nimbusdrive.com. The sender and link use a look-alike domain, the "
       "page is plain http, and it does not say who shared what."),
    _q("q-url-04", _URL, 2, _U,
       "Which organisation controls this address?<br>"
       "<code>https://portal.corvane.com.reset-account.info/password</code>",
       ["corvane.com", "portal.corvane.com", "reset-account.info", "password"],
       2,
       "Read the domain from the right, up to the first single slash: the owner is "
       "reset-account.info. Everything to its left is a subdomain the attacker chose."),
    _q("q-url-05", _URL, 2, _U,
       "Which of these links really belongs to SwiftParcel (swiftparcel.com)?",
       ["https://swiftparcel.delivery-reschedule.com/track",
        "https://track-swiftparcel.com/SP4471829",
        "https://www.swiftparcel.com/track/SP4471829",
        "https://swiftparcel.com.tracking-help.net/SP4471829"],
       2,
       "Only www.swiftparcel.com/track/... ends with the swiftparcel.com domain. The others are "
       "owned by delivery-reschedule.com, track-swiftparcel.com and tracking-help.net."),
    _q("q-url-06", _URL, 2, _F,
       "The visible link reads <code>https://portal.corvane.com/password</code> but the status "
       "bar shows a different address. What does that tell you?",
       ["Nothing - link text and target often differ",
        "The link text was written to mislead you; treat the email as phishing",
        "The company portal has moved", "Your browser is out of date"],
       1,
       "When a link displays one address but points to another, the mismatch is deliberate. "
       "Genuine emails that show an address link to that same address."),
    _q("q-url-07", _URL, 3, _U,
       "Your bank is meridiantrust.com. Which address is <b>not</b> the bank?",
       ["https://online.meridiantrust.com/statements",
        "https://meridiantrust.com/help",
        "https://online.meridiantrvst.com/statements",
        "https://www.meridiantrust.com"],
       2,
       "meridiantrvst.com swaps the 'u' for a 'v' (typosquatting). At reading speed it looks "
       "identical, which is why sign-in links should be avoided altogether."),
    _q("q-url-08", _URL, 3, _J,
       "Email from <code>sso-alerts@corvane.co</code> reporting a new sign-in from Lisbon, with a "
       "'Review recent activity' link to <code>https://sso.corvane.co/activity</code>.",
       _PHISH_OR_LEGIT, 0,
       "Corvane's domain is corvane.com. corvane.co differs only in the ending, and a worrying "
       "sign-in alert is designed to make you act fast."),
    # ============================================================ URGENCY
    _q("q-urg-01", _URG, 1, _J,
       "'URGENT!!! Your mailbox will be DELETED in 24 hours. Click IMMEDIATELY to keep it.' "
       "From <code>admin@mail-quota-center.com</code>.",
       _PHISH_OR_LEGIT, 0,
       "Shouting, a 24-hour threat and an unknown external sender. Mailbox limits are handled "
       "by your own IT department."),
    _q("q-urg-02", _URG, 1, _F,
       "What is the purpose of a short deadline in a phishing email?",
       ["To help you plan your day", "To make you act before you check",
        "It is required by law", "To prove the sender is official"],
       1,
       "Time pressure makes people skip verification. A genuine problem still exists after "
       "you take a minute to check it through a known channel."),
    _q("q-urg-03", _URG, 1, _F,
       "An email threatens legal action today over an unpaid invoice but gives no invoice number "
       "or amount. What should you do?",
       ["Pay quickly to avoid fees", "Reply asking for details",
        "Report it and do not use its links", "Forward it to colleagues to warn them"],
       2,
       "Missing specifics plus a threat is a strong phishing sign. Replying confirms your "
       "address is active; forwarding spreads it. Report it instead."),
    _q("q-urg-04", _URG, 2, _J,
       "From <code>payroll-update@corvane-hr.com</code>: 'Confirm your bank details by 5 PM today "
       "or your salary may be delayed.'",
       _PHISH_OR_LEGIT, 0,
       "The sender is not on corvane.com, and a same-day deadline about your salary is a "
       "classic lever. Payroll changes are announced well in advance."),
    _q("q-urg-05", _URG, 2, _F,
       "Which detail most strongly suggests an urgent work email is genuine?",
       ["It uses your first name", "It has the company logo",
        "It refers to an earlier announcement and is sent from corvane.com",
        "It says 'this is not phishing'"],
       2,
       "Names and logos are easy to copy. A real company domain plus a reference you can "
       "verify independently are much stronger signals."),
    _q("q-urg-06", _URG, 2, _J,
       "From <code>it-support@corvane.com</code>: 'Following the policy update announced at the "
       "all-hands, change your password by Friday. Type portal.corvane.com yourself or use the "
       "link (https://portal.corvane.com/password). Questions: ext. 4400.'",
       _PHISH_OR_LEGIT, 1,
       "Urgent-sounding but genuine: correct sender and link domain, a verifiable announcement, "
       "an invitation to type the address yourself and an internal phone extension."),
    _q("q-urg-07", _URG, 3, _F,
       "Accounts Payable asks you to approve a supplier's new bank account before the 3 PM "
       "payment run. What is the right response?",
       ["Approve it - the payment run is today",
        "Approve it if the email signature looks right",
        "Call the supplier on a number you already have to confirm the change",
        "Reply to the email asking whether it is genuine"],
       2,
       "Bank-detail changes must be verified out-of-band. Replying reaches the attacker, and "
       "signatures are trivial to copy."),
    _q("q-urg-08", _URG, 3, _J,
       "Calm, well-written email from <code>benefits@corvane-benefits.com</code>: 'Enrolment closes "
       "today at 6 PM; otherwise you get the basic plan for a year.' HR said enrolment is on "
       "hr.corvane.com.",
       _PHISH_OR_LEGIT, 0,
       "The tone is calm but the deadline and lasting penalty are pressure. The domain is not "
       "corvane.com and contradicts what HR announced."),
    # ======================================================= IMPERSONATION
    _q("q-imp-01", _IMP, 1, _F,
       "An email shows the name <b>Daniel Okafor CEO</b>. What should you check first?",
       ["The email address behind the name", "Whether the CEO's photo is shown",
        "The time it was sent", "The font"],
       0,
       "Display names can be set to anything. Only the address shows who actually sent it."),
    _q("q-imp-02", _IMP, 1, _J,
       "'I'm in a meeting and can't talk. Buy 5 gift cards for a client and send me the codes. "
       "Keep it confidential.' From <code>d.okafor.ceo@quickmail.net</code>.",
       _PHISH_OR_LEGIT, 0,
       "Executives do not use free webmail for company business, and gift cards plus secrecy "
       "plus 'can't talk' is a well-known scam."),
    _q("q-imp-03", _IMP, 1, _U,
       "Which sender address can genuinely belong to Corvane's HR team?",
       ["hr@corvane-hr-dept.org", "hr@corvane.com", "corvane.hr@quickmail.net",
        "hr@corvane.co"],
       1,
       "Only addresses ending in @corvane.com are internal. The others are look-alike or "
       "free-mail domains."),
    _q("q-imp-04", _IMP, 2, _J,
       "From 'Priya Nair (HR)' <code>priya.nair@corvane-hr.com</code>: 'Your salary revision letter "
       "is ready, please acknowledge by end of week.'",
       _PHISH_OR_LEGIT, 0,
       "The name is a real colleague but the domain is corvane-hr.com, not corvane.com. Salary "
       "is chosen because people want to open it."),
    _q("q-imp-05", _IMP, 2, _F,
       "The IT Service Desk asks you to confirm ticket #48213, which you never raised. "
       "The sender is <code>servicedesk@corvane-support.com</code>. Best action?",
       ["Confirm it so it is closed", "Report the email",
        "Reply 'I did not raise this'", "Ignore it"],
       1,
       "An unexpected request from a non-company domain should be reported. Replying engages "
       "the attacker; ignoring leaves colleagues exposed."),
    _q("q-imp-06", _IMP, 2, _J,
       "From 'Nimbus Drive' <code>no-reply@nimbusdrive.com</code>: 'Sofia Marin "
       "(sofia.marin@corvane.com) shared Sprint 42 retrospective'. Link goes to nimbusdrive.com. "
       "Your team uses Nimbus Drive and Sofia is your teammate.",
       _PHISH_OR_LEGIT, 1,
       "Sender and link are on the real service domain, the colleague is real and the document "
       "matches your work. No urgency, no password request."),
    _q("q-imp-07", _IMP, 3, _U,
       "Which address is the real Finance Director, Marcus Lee?",
       ["marcus.lee@c0rvane.com", "marcus.lee@corvane.co",
        "marcus.lee@corvane.com", "marcus.lee@corvane-finance.com"],
       2,
       "c0rvane.com uses a zero, corvane.co a different ending, corvane-finance.com an extra "
       "word. Only corvane.com is the company."),
    _q("q-imp-08", _IMP, 3, _F,
       "A well-written email from your CEO mentions the real Project Halcyon and asks you to check "
       "a board deck tonight. What makes it spear phishing rather than a normal request?",
       ["It mentions a project", "It comes from daniel.okafor@corvane.co and links to that domain",
        "It is sent in the evening", "It says 'thanks'"],
       1,
       "Real project names are easy to find. The giveaway is the .co domain on both the sender "
       "and the link."),
    # ========================================================== ATTACHMENT
    _q("q-att-01", _ATT, 1, _F,
       "What type of file is <code>Invoice_88231.pdf.exe</code>?",
       ["A PDF document", "A program", "A spreadsheet", "An image"],
       1,
       "The last extension decides the type. .exe is a program; '.pdf' is part of the name to "
       "fool you."),
    _q("q-att-02", _ATT, 1, _J,
       "From <code>fax@efax-service-mail.com</code>: 'You have received a 2 page fax. Open the "
       "attachment.' Attachment: <code>Fax_Scan_0921.zip</code>.",
       _PHISH_OR_LEGIT, 0,
       "An unexpected .zip from an unknown service with no details. Archives are often used to "
       "hide malware."),
    _q("q-att-03", _ATT, 1, _F,
       "Which attachment is the safest to open from a known colleague who told you it was coming?",
       ["report.pdf", "report.pdf.scr", "report.zip", "report.js"],
       0,
       "A plain .pdf with a single extension, from a sender you expected, is low risk. .scr and "
       ".js are executable and .zip can hide them."),
    _q("q-att-04", _ATT, 2, _F,
       "A spreadsheet asks you to click <b>Enable Content</b> to see the data. Why is that "
       "dangerous?",
       ["It uses more memory", "It lets macros (code) in the file run",
        "It shares the file publicly", "It is not dangerous"],
       1,
       "Enable Content allows embedded macros to run, which is how macro malware infects a "
       "computer. Normal data never needs it."),
    _q("q-att-05", _ATT, 2, _J,
       "From <code>labels@swiftparcel-mail.com</code>: 'Your return label is attached. Open it in "
       "your browser and sign in to print.' Attachment: <code>Shipping_Label_Print.html</code>.",
       _PHISH_OR_LEGIT, 0,
       "An .html attachment can display a fake sign-in page. You did not request a label and "
       "the domain is not swiftparcel.com."),
    _q("q-att-06", _ATT, 2, _U,
       "Which of these attachment types can contain code that runs when opened?",
       ["notes.txt", "photo.jpg", "budget.xlsm", "minutes.pdf"],
       2,
       "The 'm' in .xlsm and .docm means macro-enabled. Plain .txt and .jpg cannot run code."),
    _q("q-att-07", _ATT, 3, _J,
       "'RE: Purchase order 4471 - updated pricing' from <code>ana.ruiz@corvane-procure.com</code>, "
       "attachment <code>PO_4471_revised.docm</code>. You have never discussed PO 4471.",
       _PHISH_OR_LEGIT, 0,
       "A fake 'RE:' thread, a macro-enabled document and a look-alike domain."),
    _q("q-att-08", _ATT, 3, _F,
       "Why would an attacker send <code>Q3_Review_Package.iso</code> instead of a document?",
       ["ISO files are smaller", "Disk images can carry malware past email filters",
        "ISO is the standard format for HR files", "To make printing easier"],
       1,
       "Disk images and shortcut files are used to smuggle executables past filters. HR reviews "
       "are shared in the HR portal."),
    # ====================================================== PAUSE & INSPECT
    _q("q-pause-01", _PAUSE, 1, _F,
       "What is the first step of the 10-second routine before clicking a link in an email?",
       ["Click to see where it goes", "Check the sender's real address",
        "Reply to the sender", "Forward to IT"],
       1,
       "Sender, then link, then request. Checking the address first catches most impersonation."),
    _q("q-pause-02", _PAUSE, 1, _F,
       "You hover a link and the address does not match the organisation in the email. Next step?",
       ["Click anyway, it is probably a tracking link", "Do not click; report the email",
        "Copy the link into your browser", "Ask a colleague to click it"],
       1,
       "A mismatch between organisation and link domain is a phishing sign. Copying the link "
       "or asking someone else to open it has the same risk."),
    _q("q-pause-03", _PAUSE, 1, _F,
       "Which of these is a warning sign in the <b>request</b> step?",
       ["The email thanks you", "The email asks you to sign in with your password",
        "The email has a signature", "The email was sent during working hours"],
       1,
       "Requests for credentials, money or urgent action are the high-risk part of any email."),
    _q("q-pause-04", _PAUSE, 1, _F,
       "Why does clicking within a couple of seconds of opening an email increase risk?",
       ["Fast clicks use more bandwidth", "There is no time to check the sender, link or request",
        "Emails need to load fully", "It does not increase risk"],
       1,
       "Phishing relies on reflexes. A short pause to inspect is the single most effective habit."),
    _q("q-pause-05", _PAUSE, 1, _F,
       "For your bank or work account, what is the safest way to act on an email that says you "
       "must sign in?",
       ["Use the link in the email", "Open the site from a bookmark or by typing the address",
        "Reply with your details", "Call the number in the email"],
       1,
       "Going to the site yourself avoids both fake links and fake phone numbers inside the email."),
    # =========================================================== REPORTING
    _q("q-report-01", _REPORT, 1, _F,
       "You notice a phishing email but did not click anything. What should you do?",
       ["Delete it - you are safe", "Report it",
        "Forward it to your team to warn them", "Leave it in the inbox"],
       1,
       "Reporting lets security remove it from everyone's inbox and block the sender. "
       "Forwarding spreads the dangerous email."),
    _q("q-report-02", _REPORT, 1, _F,
       "Why is reporting useful even if you are sure you would never click?",
       ["It improves your score only", "Colleagues probably received the same email",
        "It deletes the sender's account", "It is not useful"],
       1,
       "Campaigns target many people at once. One early report can protect everyone else."),
    _q("q-report-03", _REPORT, 1, _F,
       "You are not sure whether an email is phishing. What is the best choice?",
       ["Click the link to find out", "Ignore it", "Report it - a false alarm costs little",
        "Reply and ask the sender"],
       2,
       "Security teams prefer a false alarm to a missed attack. Asking the sender reaches the "
       "attacker if it is phishing."),
    _q("q-report-04", _REPORT, 1, _F,
       "You already clicked a phishing link. What now?",
       ["Say nothing and hope", "Report it immediately and tell IT you clicked",
        "Clear your browser history", "Change your desktop wallpaper"],
       1,
       "Speed matters. Reporting a click quickly lets IT reset passwords and contain the damage. "
       "Nobody is blamed for reporting honestly."),
    _q("q-report-05", _REPORT, 1, _F,
       "Which action should you <b>avoid</b> with a suspicious email?",
       ["Using Report phishing", "Checking the sender's address",
        "Replying to the sender to ask if it is real", "Hovering over links"],
       2,
       "Replying confirms your address is active and starts a conversation with the attacker."),
]
