"""Training modules: one per (vector, level) plus two behaviour modules.

Lessons are short HTML documents rendered in the Training page. Each ends with
a quiz drawn from the questions with the same topic (see questions.py).
"""

from __future__ import annotations

from phishsense import config

_URL = config.VECTOR_URL_SPOOFING
_URG = config.VECTOR_URGENCY
_IMP = config.VECTOR_IMPERSONATION
_ATT = config.VECTOR_ATTACHMENT

MODULES: list[dict] = [
    # ------------------------------------------------------------------ URL
    dict(
        code="mod-url-1",
        topic=_URL,
        level=1,
        title="Reading a link before you click",
        summary="Hover to see where a link really goes, and find the real domain.",
        lesson=(
            "<h3>The text of a link is just a label</h3>"
            "<p>Anyone can write <i>Verify my account</i> or even a correct-looking web "
            "address as the visible text of a link. Where the link actually goes is "
            "separate, and you can only see it by <b>hovering</b> over the link and "
            "looking at the address shown at the bottom of the window.</p>"
            "<h3>Find the real domain</h3>"
            "<ol>"
            "<li>Hover over the link and read the address in the status bar.</li>"
            "<li>Find the first single <code>/</code> after <code>https://</code>. The domain "
            "is the part just before it.</li>"
            "<li>Read the domain from the <b>right</b>: the last two parts "
            "(<code>meridiantrust.com</code>) decide who owns it.</li>"
            "</ol>"
            "<h3>Quick red flags</h3>"
            "<ul>"
            "<li>The domain is different from the sender's organisation.</li>"
            "<li>Extra words added to a brand: <code>meridian-trust-secure.net</code>.</li>"
            "<li><code>http://</code> instead of <code>https://</code> on a sign-in page.</li>"
            "</ul>"
            "<p><b>Habit:</b> for banking and work accounts, type the address yourself or "
            "use a bookmark instead of clicking links in email.</p>"
        ),
    ),
    dict(
        code="mod-url-2",
        topic=_URL,
        level=2,
        title="Subdomain tricks",
        summary="Spot brand names placed in front of an attacker's domain.",
        lesson=(
            "<h3>Who owns the address?</h3>"
            "<p>Everything to the left of the real domain is a <b>subdomain</b>, and the "
            "owner of the domain can put any words there. "
            "<code>portal.corvane.com.reset-account.info</code> belongs to "
            "<code>reset-account.info</code>, not to Corvane.</p>"
            "<h3>Common patterns</h3>"
            "<ul>"
            "<li><code>brand.attacker.com</code> - the brand as a subdomain.</li>"
            "<li><code>brand.com.attacker.info</code> - the full real domain used as a "
            "prefix.</li>"
            "<li><code>attacker.com/brand.com/login</code> - the brand in the path, after "
            "the first single slash.</li>"
            "</ul>"
            "<h3>Practice rule</h3>"
            "<p>Cover everything left of the last dot-separated pair before the first "
            "<code>/</code>. Whatever remains is the owner. If it is not the organisation "
            "you expect, do not click and report the email.</p>"
        ),
    ),
    dict(
        code="mod-url-3",
        topic=_URL,
        level=3,
        title="Look-alike and typosquatted domains",
        summary="Catch domains that differ by a single character or ending.",
        lesson=(
            "<h3>One character is enough</h3>"
            "<p>Convincing attacks register domains that look right at a glance:</p>"
            "<ul>"
            "<li>Swapped letters: <code>meridiantrvst.com</code> (v for u).</li>"
            "<li>Digits for letters: <code>c0rvane.com</code> (zero for o), "
            "<code>merid1antrust.com</code> (one for i).</li>"
            "<li>Different ending: <code>corvane.co</code> instead of "
            "<code>corvane.com</code>.</li>"
            "<li>Letter pairs that look like one letter: <code>rn</code> vs <code>m</code>.</li>"
            "</ul>"
            "<h3>Why careful people still fall for it</h3>"
            "<p>The email itself can be perfect: your name, a correct logo, normal tone. "
            "The only clue is in the address. Reading it slowly, character by character, "
            "is the defence.</p>"
            "<h3>Habit</h3>"
            "<p>For anything that asks you to sign in, do not use the link at all - open the "
            "site from a bookmark. If the email was genuine, the same message will be "
            "waiting there.</p>"
        ),
    ),
    # -------------------------------------------------------------- urgency
    dict(
        code="mod-urg-1",
        topic=_URG,
        level=1,
        title="Pressure is a warning sign",
        summary="Recognise threats and deadlines designed to stop you thinking.",
        lesson=(
            "<h3>Why attackers rush you</h3>"
            "<p>When we feel time pressure, we skip checks. Phishing uses this on purpose: "
            "<i>account deleted in 24 hours</i>, <i>legal action today</i>, <i>final "
            "notice</i>.</p>"
            "<h3>Signs of manufactured urgency</h3>"
            "<ul>"
            "<li>A short deadline combined with a threat or loss.</li>"
            "<li>CAPITAL LETTERS and multiple exclamation marks!!!</li>"
            "<li>No specific details (invoice number, amount, contact name).</li>"
            "</ul>"
            "<h3>What to do</h3>"
            "<p>Stop. A real problem will still be real in five minutes. Check through a "
            "channel you already know - the organisation's website typed by hand, or a "
            "phone number from your records - never through the email itself.</p>"
        ),
    ),
    dict(
        code="mod-urg-2",
        topic=_URG,
        level=2,
        title="Urgency that targets work and pay",
        summary="Deadlines tied to salary, permits and accounts at work.",
        lesson=(
            "<h3>Familiar topics, invented deadlines</h3>"
            "<p>More careful attacks use topics you care about at work - payroll, parking, "
            "access, holidays - and add a same-day deadline. The tone is polite, so the "
            "pressure is easier to miss.</p>"
            "<h3>Questions to ask</h3>"
            "<ul>"
            "<li>Was this change announced before through official channels?</li>"
            "<li>Is the sender on the company domain <code>corvane.com</code>?</li>"
            "<li>Does the link go to an internal system you already use?</li>"
            "</ul>"
            "<p>If any answer is <i>no</i>, contact the department using the details on the "
            "intranet, not those in the email.</p>"
        ),
    ),
    dict(
        code="mod-urg-3",
        topic=_URG,
        level=3,
        title="Business process pressure",
        summary="Quarter-end, payment runs and approvals used as leverage.",
        lesson=(
            "<h3>The calm emergency</h3>"
            "<p>The most effective urgency sounds like normal business: <i>approve before "
            "the 3 PM payment run</i>, <i>enrolment closes today</i>. There are no capital "
            "letters - just a real-sounding process with a deadline.</p>"
            "<h3>High-risk requests</h3>"
            "<ul>"
            "<li>Changing a supplier's or employee's bank details.</li>"
            "<li>Approving payments or releasing purchase orders.</li>"
            "<li>Confirming benefits, payroll or tax information.</li>"
            "</ul>"
            "<h3>Rule</h3>"
            "<p>These requests always need <b>out-of-band verification</b>: call the person "
            "or supplier on a number you already have. A legitimate process allows time "
            "for that check.</p>"
        ),
    ),
    # -------------------------------------------------------- impersonation
    dict(
        code="mod-imp-1",
        topic=_IMP,
        level=1,
        title="Who really sent this?",
        summary="Check the address, not just the display name.",
        lesson=(
            "<h3>Display name vs address</h3>"
            "<p>The name you see (<i>Daniel Okafor CEO</i>) can be set to anything. The "
            "<b>email address</b> behind it is what matters. Open the sender details and "
            "read it.</p>"
            "<h3>Red flags</h3>"
            "<ul>"
            "<li>A colleague or executive writing from a free webmail address.</li>"
            "<li>A department name on a domain that is not <code>corvane.com</code>.</li>"
            "<li>Requests for gift cards, secrecy, or 'I can't talk right now'.</li>"
            "</ul>"
            "<h3>What to do</h3>"
            "<p>Contact the person through a channel you already trust - their number in the "
            "company directory or a chat message - before doing anything.</p>"
        ),
    ),
    dict(
        code="mod-imp-2",
        topic=_IMP,
        level=2,
        title="Look-alike internal senders",
        summary="Domains that borrow the company name: corvane-hr.com and friends.",
        lesson=(
            "<h3>Borrowed company names</h3>"
            "<p>Attackers register domains such as <code>corvane-hr.com</code> or "
            "<code>corvane-support.com</code> and send from real colleagues' names. The "
            "only genuine company domain is <code>corvane.com</code>.</p>"
            "<h3>Context check</h3>"
            "<ul>"
            "<li>Did you raise this ticket or expect this document?</li>"
            "<li>Would this team normally send it by email, or post it in a portal?</li>"
            "<li>Is the request unusual for this person?</li>"
            "</ul>"
            "<p>An unexpected request plus a non-company domain is enough to report.</p>"
        ),
    ),
    dict(
        code="mod-imp-3",
        topic=_IMP,
        level=3,
        title="Spear phishing and executive impersonation",
        summary="Targeted emails that use real names, projects and deadlines.",
        lesson=(
            "<h3>Built for you</h3>"
            "<p>Spear phishing uses details that are easy to find - your manager's name, a "
            "project name, an upcoming board meeting - to look like a normal internal "
            "message. Writing style and context can be perfect.</p>"
            "<h3>What still gives it away</h3>"
            "<ul>"
            "<li>The address: <code>corvane.co</code>, <code>c0rvane.com</code>.</li>"
            "<li>A link or file on a domain that is not the company's own.</li>"
            "<li>A tight personal deadline ('tonight', 'before tomorrow').</li>"
            "</ul>"
            "<h3>Rule</h3>"
            "<p>The more senior the sender and the more confidential the topic, the more "
            "important it is to verify through a second channel before opening anything.</p>"
        ),
    ),
    # ----------------------------------------------------------- attachment
    dict(
        code="mod-att-1",
        topic=_ATT,
        level=1,
        title="Dangerous file types",
        summary="Recognise executable and double-extension attachments.",
        lesson=(
            "<h3>The last extension wins</h3>"
            "<p><code>Invoice_88231.pdf.exe</code> is a program (<code>.exe</code>), not a "
            "PDF. Windows may hide known extensions, so turn on 'File name extensions' in "
            "File Explorer.</p>"
            "<h3>Never open from unknown senders</h3>"
            "<ul>"
            "<li>Programs and scripts: <code>.exe .scr .bat .js .vbs</code></li>"
            "<li>Archives that can hide them: <code>.zip .rar .7z</code></li>"
            "<li>Unexpected attachments with vague messages ('see attached').</li>"
            "</ul>"
        ),
    ),
    dict(
        code="mod-att-2",
        topic=_ATT,
        level=2,
        title="Macros and HTML attachments",
        summary="Office macros and attachments that open fake sign-in pages.",
        lesson=(
            "<h3>Macro-enabled documents</h3>"
            "<p><code>.xlsm</code> and <code>.docm</code> files can contain code. Malware "
            "authors ask you to <b>Enable Editing</b> and <b>Enable Content</b> so the code "
            "can run. A normal document never needs that.</p>"
            "<h3>HTML attachments</h3>"
            "<p>An <code>.html</code> or <code>.htm</code> file opens in your browser and can "
            "show a perfect copy of a sign-in page that sends your password to the "
            "attacker.</p>"
            "<h3>Rule</h3>"
            "<p>If an attachment asks you to enable content or to sign in, close it and "
            "report the email.</p>"
        ),
    ),
    dict(
        code="mod-att-3",
        topic=_ATT,
        level=3,
        title="Attachments in convincing threads",
        summary="Fake replies, disk images and documents you were half expecting.",
        lesson=(
            "<h3>Fake conversations</h3>"
            "<p>A subject starting with <i>RE:</i> suggests you are already talking with the "
            "sender. Check that the conversation really exists.</p>"
            "<h3>Container files</h3>"
            "<p><code>.iso</code>, <code>.img</code> and <code>.vhd</code> disk images, and "
            "<code>.lnk</code> shortcut files, are used to get malware past email filters. "
            "Business documents almost never arrive this way.</p>"
            "<h3>Rule</h3>"
            "<p>Sensitive documents such as reviews and pay letters are shared through "
            "company portals. An attachment that should have been in a portal is a red "
            "flag on its own.</p>"
        ),
    ),
    # ------------------------------------------------------ behaviour topics
    dict(
        code="mod-pause-1",
        topic=config.TOPIC_PAUSE_INSPECT,
        level=1,
        title="Pause and inspect",
        summary="A 10-second routine before every click.",
        lesson=(
            "<h3>Your recent behaviour</h3>"
            "<p>You have been clicking links quickly, often before looking at where they "
            "go. Most phishing is caught in the few seconds between reading and "
            "clicking.</p>"
            "<h3>The 10-second routine</h3>"
            "<ol>"
            "<li><b>Sender</b> - open the details. Is the domain the one you expect?</li>"
            "<li><b>Link</b> - hover. Does the real address match the organisation?</li>"
            "<li><b>Request</b> - is there a deadline, a threat, or a request for "
            "credentials or money?</li>"
            "</ol>"
            "<p>If any step fails, do not click - report.</p>"
        ),
    ),
    dict(
        code="mod-report-1",
        topic=config.TOPIC_REPORTING,
        level=1,
        title="Why and how to report",
        summary="Ignoring a phishing email leaves colleagues exposed.",
        lesson=(
            "<h3>Your recent behaviour</h3>"
            "<p>You have been leaving suspicious emails without action. Not clicking is "
            "good, but the same email has probably reached your colleagues too.</p>"
            "<h3>Why reporting matters</h3>"
            "<ul>"
            "<li>The security team can block the sender and remove the email from every "
            "inbox.</li>"
            "<li>Early reports stop an attack before someone else clicks.</li>"
            "<li>A wrong report costs a few seconds; a missed one can cost much more.</li>"
            "</ul>"
            "<h3>How</h3>"
            "<p>Use <b>Report phishing</b>. Do not forward the email to colleagues, and do "
            "not reply to the sender.</p>"
        ),
    ),
]
