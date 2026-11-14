"""Simulated inbox content.

Conventions
-----------
* ``body`` is HTML. ``{link}`` marks where the link anchor is rendered; it is
  present exactly once when ``link_url`` is set and absent otherwise.
* ``link_text`` is what the reader sees; ``link_url`` is the real target that
  the inbox shows in its status bar only while the pointer hovers the link.
* ``difficulty`` 1 = obvious, 2 = plausible, 3 = convincing. For genuine
  emails it means how suspicious they *look* (3 = genuine but alarming).
* ``indicators``: for phishing, the red flags; for genuine mail, the cues that
  show it is safe. Shown in feedback after a decision.
"""

from __future__ import annotations

from phishsense import config

_URL = config.VECTOR_URL_SPOOFING
_URG = config.VECTOR_URGENCY
_IMP = config.VECTOR_IMPERSONATION
_ATT = config.VECTOR_ATTACHMENT
_LEG = config.CATEGORY_LEGITIMATE

EMAILS: list[dict] = [
    # =====================================================================
    # URL spoofing: the visible link and the real destination differ.
    # =====================================================================
    dict(
        code="url-1-bank-verify",
        category=_URL,
        difficulty=1,
        sender_name="Meridian Trust Security",
        sender_address="alerts@meridian-trust-secure.net",
        subject="Verify your account information",
        body=(
            "<p>Dear Valued Customer,</p>"
            "<p>We have detected unusual activity on you account. To avoid suspension "
            "you must verify your informations by clicking the link below.</p>"
            "<p>{link}</p>"
            "<p>Thank you,<br>Meridian Trust Security Team</p>"
        ),
        link_text="Verify my account",
        link_url="http://meridian-trust-secure.net/login.php?id=88412",
        indicators=[
            "Generic greeting ('Dear Valued Customer') instead of your name.",
            "Sender domain meridian-trust-secure.net is not the bank's domain meridiantrust.com.",
            "The link goes to an unencrypted http:// page on the same look-alike domain.",
            "Spelling and grammar errors ('you account', 'informations').",
        ],
    ),
    dict(
        code="url-1-drive-shared",
        category=_URL,
        difficulty=1,
        sender_name="Nimbus Drive",
        sender_address="no-reply@nimbus-drive-share.co",
        subject="You have 3 new shared files",
        body=(
            "<p>Hello,</p>"
            "<p>3 documents have been shared with you. Sign in to view them before they "
            "expire.</p>"
            "<p>{link}</p>"
            "<p>Nimbus Drive</p>"
        ),
        link_text="View documents",
        link_url="http://nimbus-drive-share.co/view?session=ab12f9",
        indicators=[
            "Sender domain nimbus-drive-share.co is not nimbusdrive.com.",
            "It does not say who shared the files or what they are.",
            "The link points to the look-alike domain over plain http://.",
        ],
    ),
    dict(
        code="url-2-password-portal",
        category=_URL,
        difficulty=2,
        sender_name="Corvane IT",
        sender_address="noreply@corvane-it.com",
        subject="Your password expires in 3 days",
        body=(
            "<p>Hi,</p>"
            "<p>Your Corvane network password will expire in 3 days. Please update it "
            "using the self-service portal:</p>"
            "<p>{link}</p>"
            "<p>Regards,<br>Corvane IT Service Desk</p>"
        ),
        link_text="https://portal.corvane.com/password",
        link_url="https://portal.corvane.com.reset-account.info/password",
        indicators=[
            "The link text shows portal.corvane.com but the real address ends in "
            "reset-account.info - the domain is read from the right-hand end.",
            "Sender domain corvane-it.com is not the company domain corvane.com.",
            "IT password reminders normally tell you to open the portal yourself.",
        ],
    ),
    dict(
        code="url-2-parcel-reschedule",
        category=_URL,
        difficulty=2,
        sender_name="SwiftParcel",
        sender_address="delivery@swiftparcel-notice.com",
        subject="We missed you - reschedule your delivery",
        body=(
            "<p>Hello,</p>"
            "<p>Our courier attempted to deliver your parcel today but nobody was "
            "available. Choose a new delivery slot here:</p>"
            "<p>{link}</p>"
            "<p>Parcels not rescheduled within 48 hours are returned to sender.</p>"
        ),
        link_text="Reschedule delivery",
        link_url="https://swiftparcel.delivery-reschedule.com/track",
        indicators=[
            "The real link domain is delivery-reschedule.com; 'swiftparcel' is only a subdomain.",
            "Sender domain swiftparcel-notice.com is not swiftparcel.com.",
            "No tracking number or order details are given.",
            "A deadline is used to rush you.",
        ],
    ),
    dict(
        code="url-3-bank-statement",
        category=_URL,
        difficulty=3,
        sender_name="Meridian Trust Bank",
        sender_address="statements@meridiantrust.com",
        subject="Your October statement is available",
        body=(
            "<p>Dear Alex,</p>"
            "<p>Your statement for October is now available in Online Banking. For your "
            "security we never include account numbers in email.</p>"
            "<p>{link}</p>"
            "<p>Kind regards,<br>Meridian Trust Bank Customer Service</p>"
        ),
        link_text="https://online.meridiantrust.com/statements",
        link_url="https://online.meridiantrvst.com/statements",
        indicators=[
            "Hovering reveals meridiantrvst.com - a 'v' replaces the 'u' (typosquatting).",
            "The email looks polished and personal; only the real link address gives it away.",
            "Safe habit: open banking by typing the address or using a saved bookmark.",
        ],
    ),
    dict(
        code="url-3-sso-signin",
        category=_URL,
        difficulty=3,
        sender_name="Corvane Single Sign-On",
        sender_address="sso-alerts@corvane.co",
        subject="New sign-in to your Corvane account",
        body=(
            "<p>Hi,</p>"
            "<p>We noticed a new sign-in to your Corvane account from Chrome on Windows "
            "(Lisbon, Portugal). If this was you, no action is needed. If not, review "
            "your recent activity:</p>"
            "<p>{link}</p>"
            "<p>Corvane Identity Team</p>"
        ),
        link_text="Review recent activity",
        link_url="https://sso.corvane.co/activity/review",
        indicators=[
            "The domain is corvane.co, not corvane.com - only the last letters differ.",
            "The sender uses the same look-alike domain.",
            "It plays on worry about an unknown sign-in so that you act quickly.",
        ],
    ),
    # =====================================================================
    # Urgency: pressure and deadlines push the reader to act without checking.
    # =====================================================================
    dict(
        code="urg-1-mailbox-delete",
        category=_URG,
        difficulty=1,
        sender_name="Mailbox Administrator",
        sender_address="admin@mail-quota-center.com",
        subject="URGENT!!! Your mailbox will be DELETED in 24 hours",
        body=(
            "<p>ATTENTION USER,</p>"
            "<p>Your mailbox has exceeded its storage limit and WILL BE DELETED in 24 "
            "hours. All emails will be lost permanently!!!</p>"
            "<p>Click below IMMEDIATELY to keep your mailbox active:</p>"
            "<p>{link}</p>"
        ),
        link_text="KEEP MY MAILBOX",
        link_url="http://mail-quota-center.com/upgrade",
        indicators=[
            "Capital letters, exclamation marks and a 24-hour threat.",
            "Unknown sender domain mail-quota-center.com.",
            "Mailbox limits are handled by your own IT department, not a stranger.",
        ],
    ),
    dict(
        code="urg-1-invoice-legal",
        category=_URG,
        difficulty=1,
        sender_name="Accounts Recovery Dept",
        sender_address="billing@accounts-collect.biz",
        subject="FINAL NOTICE: unpaid invoice - legal action today",
        body=(
            "<p>Final notice.</p>"
            "<p>Your invoice remains unpaid. If payment is not received TODAY your case "
            "will be passed to our legal team and additional fees applied.</p>"
            "<p>{link}</p>"
        ),
        link_text="Pay outstanding balance",
        link_url="http://accounts-collect.biz/pay",
        indicators=[
            "Threat of legal action 'today' with no invoice number, amount or company name.",
            "Unknown .biz sender with a generic name.",
            "You have no relationship with this sender.",
        ],
    ),
    dict(
        code="urg-2-payroll-confirm",
        category=_URG,
        difficulty=2,
        sender_name="Corvane Payroll",
        sender_address="payroll-update@corvane-hr.com",
        subject="Action required by 5 PM today: confirm payroll details",
        body=(
            "<p>Hello,</p>"
            "<p>Due to a change in our payroll provider, all employees must confirm their "
            "bank details by 5 PM today. Staff who do not confirm may experience a delay "
            "in this month's salary.</p>"
            "<p>{link}</p>"
            "<p>Corvane Payroll Team</p>"
        ),
        link_text="Confirm payroll details",
        link_url="https://corvane-hr.com/payroll/confirm",
        indicators=[
            "A same-day deadline tied to your salary.",
            "Sender domain corvane-hr.com is not corvane.com.",
            "A payroll provider change would be announced in advance through official channels.",
        ],
    ),
    dict(
        code="urg-2-parking-permit",
        category=_URG,
        difficulty=2,
        sender_name="Corvane Facilities",
        sender_address="facilities@corvane-services.com",
        subject="Your parking permit expires tonight",
        body=(
            "<p>Hi,</p>"
            "<p>Our records show your staff parking permit expires at midnight. Vehicles "
            "without a valid permit will be clamped from tomorrow morning. Renew now to "
            "avoid a fine:</p>"
            "<p>{link}</p>"
            "<p>Facilities Management</p>"
        ),
        link_text="Renew parking permit",
        link_url="https://corvane-services.com/parking/renew",
        indicators=[
            "Deadline of 'tonight' with a penalty attached.",
            "Sender domain corvane-services.com is not corvane.com.",
            "The renewal link goes to the same external domain.",
        ],
    ),
    dict(
        code="urg-3-vendor-bank-change",
        category=_URG,
        difficulty=3,
        sender_name="Accounts Payable",
        sender_address="ap@corvane-finance.com",
        subject="Quarter-end close: approve vendor bank update before 3 PM",
        body=(
            "<p>Hi,</p>"
            "<p>As part of the quarter-end close, Harlow Logistics has updated its remittance "
            "account. The change needs an approver before the 3 PM payment run, otherwise "
            "their invoices slip into next quarter.</p>"
            "<p>{link}</p>"
            "<p>Thanks for the quick turnaround,<br>Accounts Payable</p>"
        ),
        link_text="Approve in vendor portal",
        link_url="https://corvane-finance.com/vendor/approve?ref=HL-2231",
        indicators=[
            "Changing a supplier's bank account under time pressure is a classic fraud pattern.",
            "Sender domain corvane-finance.com is not corvane.com.",
            "Bank-detail changes should be verified by phoning the supplier on a known number.",
        ],
    ),
    dict(
        code="urg-3-benefits-close",
        category=_URG,
        difficulty=3,
        sender_name="Corvane Benefits",
        sender_address="benefits@corvane-benefits.com",
        subject="Reminder: benefits enrolment closes today",
        body=(
            "<p>Hi,</p>"
            "<p>This is a reminder that the annual benefits enrolment window closes today "
            "at 6 PM. If you do not confirm your selections, you will be enrolled in the "
            "basic plan for the whole of next year.</p>"
            "<p>{link}</p>"
            "<p>Corvane People Team</p>"
        ),
        link_text="Confirm my benefits",
        link_url="https://corvane-benefits.com/enrol",
        indicators=[
            "The tone is calm, but a hard same-day deadline with a lasting penalty is meant to rush you.",
            "Sender domain corvane-benefits.com is not corvane.com.",
            "HR announced that enrolment happens on the internal HR portal (hr.corvane.com).",
        ],
    ),
    # =====================================================================
    # Sender impersonation: pretends to be someone you trust.
    # =====================================================================
    dict(
        code="imp-1-ceo-giftcards",
        category=_IMP,
        difficulty=1,
        sender_name="Daniel Okafor CEO",
        sender_address="d.okafor.ceo@quickmail.net",
        subject="Are you available? Need a favour",
        body=(
            "<p>Hello,</p>"
            "<p>I am in a meeting and can't talk. I need you to buy 5 gift cards for a "
            "client surprise. I will reimburse you today. Use the link below and send me "
            "the codes. Keep this confidential.</p>"
            "<p>{link}</p>"
            "<p>Daniel<br>Sent from my mobile</p>"
        ),
        link_text="Gift card purchase page",
        link_url="https://giftcard-express-buy.com/order",
        indicators=[
            "The CEO is writing from a free webmail address, not corvane.com.",
            "Request for gift cards plus secrecy is a well-known scam pattern.",
            "'Can't talk' stops you from checking by phone.",
        ],
    ),
    dict(
        code="imp-1-hr-handbook",
        category=_IMP,
        difficulty=1,
        sender_name="HR Department",
        sender_address="hr@corvane-hr-dept.org",
        subject="Sign the updated employee handbook",
        body=(
            "<p>Dear employee,</p>"
            "<p>All staff must sign the updated employee handbook. Sign in with your "
            "company email and password to view and sign it.</p>"
            "<p>{link}</p>"
            "<p>Human Resource Department</p>"
        ),
        link_text="Sign handbook",
        link_url="http://corvane-hr-dept.org/sign-in",
        indicators=[
            "Sender domain corvane-hr-dept.org is not corvane.com.",
            "Asks for your company password on an external site.",
            "Impersonal greeting and no named HR contact.",
        ],
    ),
    dict(
        code="imp-2-salary-letter",
        category=_IMP,
        difficulty=2,
        sender_name="Priya Nair (HR)",
        sender_address="priya.nair@corvane-hr.com",
        subject="Your salary revision letter",
        body=(
            "<p>Hi,</p>"
            "<p>Following the annual review, your salary revision letter is ready. "
            "Please review and acknowledge it by end of week.</p>"
            "<p>{link}</p>"
            "<p>Best,<br>Priya Nair<br>HR Business Partner</p>"
        ),
        link_text="Open salary letter",
        link_url="https://corvane-hr.com/docs/salary-letter",
        indicators=[
            "The display name matches a real colleague, but the address is @corvane-hr.com.",
            "Salary topics are chosen because people want to open them.",
            "The document is hosted on the same look-alike domain.",
        ],
    ),
    dict(
        code="imp-2-servicedesk-ticket",
        category=_IMP,
        difficulty=2,
        sender_name="IT Service Desk",
        sender_address="servicedesk@corvane-support.com",
        subject="Ticket #48213 is waiting for your confirmation",
        body=(
            "<p>Hello,</p>"
            "<p>Ticket #48213 (VPN access request) is waiting for your confirmation. If "
            "you do not confirm, the ticket will be closed automatically.</p>"
            "<p>{link}</p>"
            "<p>Corvane IT Service Desk</p>"
        ),
        link_text="Confirm ticket",
        link_url="https://corvane-support.com/tickets/48213/confirm",
        indicators=[
            "You did not raise a VPN ticket.",
            "Sender domain corvane-support.com is not corvane.com.",
            "Real tickets appear in the internal service-desk portal.",
        ],
    ),
    dict(
        code="imp-3-ceo-halcyon",
        category=_IMP,
        difficulty=3,
        sender_name="Daniel Okafor",
        sender_address="daniel.okafor@corvane.co",
        subject="Halcyon - board deck before tomorrow",
        body=(
            "<p>Hi,</p>"
            "<p>Ahead of tomorrow's board session I've put the latest Project Halcyon deck "
            "on the shared area. Could you check the figures on slides 6-9 against your "
            "numbers and let me know tonight if anything looks off?</p>"
            "<p>{link}</p>"
            "<p>Thanks,<br>Daniel</p>"
        ),
        link_text="Halcyon board deck (confidential)",
        link_url="https://share.corvane.co/halcyon/board-deck",
        indicators=[
            "The address is daniel.okafor@corvane.co - '.co', not '.com'.",
            "It mentions a real internal project to look believable (spear phishing).",
            "The shared area is on the same look-alike domain.",
        ],
    ),
    dict(
        code="imp-3-finance-director",
        category=_IMP,
        difficulty=3,
        sender_name="Marcus Lee",
        sender_address="marcus.lee@c0rvane.com",
        subject="Supplier reconciliation - need your view",
        body=(
            "<p>Hi,</p>"
            "<p>I'm reviewing the supplier reconciliation for the audit. I've uploaded the "
            "working file - could you check the entries you processed and confirm by "
            "tomorrow morning?</p>"
            "<p>{link}</p>"
            "<p>Regards,<br>Marcus Lee<br>Finance Director</p>"
        ),
        link_text="Supplier reconciliation workbook",
        link_url="https://c0rvane.com/files/reconciliation",
        indicators=[
            "The address uses a zero instead of the letter 'o' (c0rvane.com).",
            "Polished, plausible request - only checking the sender address exposes it.",
            "The file link uses the same misspelled domain.",
        ],
    ),
    # =====================================================================
    # Attachments: dangerous file types disguised as documents.
    # =====================================================================
    dict(
        code="att-1-invoice-exe",
        category=_ATT,
        difficulty=1,
        sender_name="Accounts Department",
        sender_address="accounts@invoice-dept.biz",
        subject="Invoice 88231 attached",
        body=(
            "<p>Hello,</p>"
            "<p>Please see attached invoice for payment.</p>"
            "<p>Regards</p>"
        ),
        attachment_name="Invoice_88231.pdf.exe",
        indicators=[
            "The file ends in .exe - it is a program, not a PDF (double extension).",
            "Unknown sender and no details about what the invoice is for.",
        ],
    ),
    dict(
        code="att-1-fax-zip",
        category=_ATT,
        difficulty=1,
        sender_name="eFax Service",
        sender_address="fax@efax-service-mail.com",
        subject="You have received a new fax (2 pages)",
        body=(
            "<p>You have received a 2 page fax.</p>"
            "<p>Open the attachment to view your document.</p>"
        ),
        attachment_name="Fax_Scan_0921.zip",
        indicators=[
            "Corvane does not use an external fax service.",
            "Compressed .zip attachments from strangers often hide malware.",
            "No sender name or fax number is given.",
        ],
    ),
    dict(
        code="att-2-holiday-xlsm",
        category=_ATT,
        difficulty=2,
        sender_name="HR Notices",
        sender_address="hr-notice@corvane-hr.com",
        subject="Revised holiday schedule 2027",
        body=(
            "<p>Hi all,</p>"
            "<p>Attached is the revised holiday schedule for 2027. Please enable editing "
            "and content to see your department's dates.</p>"
            "<p>HR</p>"
        ),
        attachment_name="Holiday_Schedule_2027.xlsm",
        indicators=[
            ".xlsm is a macro-enabled spreadsheet that can run code.",
            "Asking you to 'enable content' is how macro malware gets permission to run.",
            "Sender domain corvane-hr.com is not corvane.com.",
        ],
    ),
    dict(
        code="att-2-label-html",
        category=_ATT,
        difficulty=2,
        sender_name="SwiftParcel",
        sender_address="labels@swiftparcel-mail.com",
        subject="Your shipping label is ready to print",
        body=(
            "<p>Hello,</p>"
            "<p>Your return shipping label is attached. Open it in your browser and sign "
            "in to print.</p>"
            "<p>SwiftParcel</p>"
        ),
        attachment_name="Shipping_Label_Print.html",
        indicators=[
            "An .html attachment opens a local web page that can show a fake sign-in form.",
            "You did not request a return label.",
            "Sender domain swiftparcel-mail.com is not swiftparcel.com.",
        ],
    ),
    dict(
        code="att-3-po-docm",
        category=_ATT,
        difficulty=3,
        sender_name="Ana Ruiz",
        sender_address="ana.ruiz@corvane-procure.com",
        subject="RE: Purchase order 4471 - updated pricing",
        body=(
            "<p>Hi,</p>"
            "<p>Following up on our thread - the supplier sent the revised pricing for PO "
            "4471. I've marked the changed lines in the attached document; can you sign "
            "off so we can release it this week?</p>"
            "<p>Thanks,<br>Ana Ruiz<br>Procurement</p>"
        ),
        attachment_name="PO_4471_revised.docm",
        indicators=[
            "'RE:' suggests an existing thread that you never had.",
            ".docm is a macro-enabled Word document.",
            "Sender domain corvane-procure.com is not corvane.com.",
        ],
    ),
    dict(
        code="att-3-review-iso",
        category=_ATT,
        difficulty=3,
        sender_name="People Operations",
        sender_address="people-ops@corvane.co",
        subject="Q3 performance review package",
        body=(
            "<p>Hi,</p>"
            "<p>Your Q3 performance review package, including your manager's comments, is "
            "attached. Please read it before your 1:1 next week.</p>"
            "<p>People Operations</p>"
        ),
        attachment_name="Q3_Review_Package.iso",
        indicators=[
            ".iso disk-image files are used to smuggle malware past email filters.",
            "The sender domain is corvane.co, not corvane.com.",
            "Performance reviews are shared in the HR portal, not as email attachments.",
        ],
    ),
    # =====================================================================
    # Legitimate emails: correct action is to proceed / mark as safe.
    # =====================================================================
    dict(
        code="leg-1-allhands",
        category=_LEG,
        difficulty=1,
        sender_name="Corvane Internal Comms",
        sender_address="internal-comms@corvane.com",
        subject="All-hands meeting this Thursday",
        body=(
            "<p>Hi everyone,</p>"
            "<p>Our quarterly all-hands is this Thursday at 3 PM in the main auditorium and "
            "online. The agenda is on the intranet:</p>"
            "<p>{link}</p>"
            "<p>See you there,<br>Internal Communications</p>"
        ),
        link_text="All-hands agenda",
        link_url="https://intranet.corvane.com/events/all-hands",
        indicators=[
            "Sender and link both use the real company domain corvane.com.",
            "Expected, routine event with no pressure and no request for data.",
        ],
    ),
    dict(
        code="leg-1-canteen",
        category=_LEG,
        difficulty=1,
        sender_name="Corvane Facilities",
        sender_address="facilities@corvane.com",
        subject="Canteen menu for next week",
        body=(
            "<p>Hello,</p>"
            "<p>Next week's canteen menu is printed on the noticeboard by the lifts. "
            "Wednesday is curry day.</p>"
            "<p>Facilities</p>"
        ),
        indicators=[
            "Internal sender on corvane.com.",
            "No link, no attachment and nothing is asked of you.",
        ],
    ),
    dict(
        code="leg-1-maintenance",
        category=_LEG,
        difficulty=1,
        sender_name="Corvane IT Service Desk",
        sender_address="it-support@corvane.com",
        subject="Planned maintenance Saturday 22:00-02:00",
        body=(
            "<p>Hi,</p>"
            "<p>Email and VPN will be unavailable during planned maintenance on Saturday "
            "from 22:00 to 02:00. No action is needed. Live status is on the status page:</p>"
            "<p>{link}</p>"
            "<p>IT Service Desk</p>"
        ),
        link_text="IT status page",
        link_url="https://status.corvane.com",
        indicators=[
            "Real IT address and status page on corvane.com.",
            "Informational only - it explicitly says no action is needed.",
        ],
    ),
    dict(
        code="leg-2-bank-statement",
        category=_LEG,
        difficulty=2,
        sender_name="Meridian Trust Bank",
        sender_address="statements@meridiantrust.com",
        subject="Your September statement is available",
        body=(
            "<p>Dear Alex,</p>"
            "<p>Your September statement is ready. Sign in to Online Banking as usual to "
            "view it. We will never ask for your password or PIN by email.</p>"
            "<p>{link}</p>"
            "<p>Meridian Trust Bank</p>"
        ),
        link_text="https://online.meridiantrust.com",
        link_url="https://online.meridiantrust.com",
        indicators=[
            "Visible link and real destination are identical and on meridiantrust.com.",
            "Addresses you by name, no deadline, no request for credentials.",
        ],
    ),
    dict(
        code="leg-2-parcel-tracking",
        category=_LEG,
        difficulty=2,
        sender_name="SwiftParcel",
        sender_address="notifications@swiftparcel.com",
        subject="Your parcel SP4471829 is out for delivery",
        body=(
            "<p>Hello,</p>"
            "<p>Your parcel SP4471829 from Northfield Office Supplies is out for delivery "
            "and should arrive between 13:00 and 15:00.</p>"
            "<p>{link}</p>"
        ),
        link_text="Track SP4471829",
        link_url="https://www.swiftparcel.com/track/SP4471829",
        indicators=[
            "Sender and link are on swiftparcel.com.",
            "Gives a specific tracking number and the shop the order came from.",
            "No payment or login request, no threat.",
        ],
    ),
    dict(
        code="leg-2-payslip",
        category=_LEG,
        difficulty=2,
        sender_name="Corvane Payroll",
        sender_address="payroll@corvane.com",
        subject="Your October payslip is available",
        body=(
            "<p>Hi,</p>"
            "<p>Your October payslip is available in the HR portal.</p>"
            "<p>{link}</p>"
            "<p>Payroll Team</p>"
        ),
        link_text="https://hr.corvane.com/payslips",
        link_url="https://hr.corvane.com/payslips",
        indicators=[
            "Sent from corvane.com and links to the internal HR portal.",
            "Monthly, expected message with no pressure.",
        ],
    ),
    dict(
        code="leg-3-mandatory-password",
        category=_LEG,
        difficulty=3,
        sender_name="Corvane IT Service Desk",
        sender_address="it-support@corvane.com",
        subject="Mandatory password change by Friday",
        body=(
            "<p>Hi,</p>"
            "<p>Following the security policy update announced at the all-hands, all staff "
            "must change their network password by Friday. Please go to the self-service "
            "portal yourself by typing portal.corvane.com, or use the link below. We will "
            "never ask for your current password by email.</p>"
            "<p>{link}</p>"
            "<p>IT Service Desk - ext. 4400</p>"
        ),
        link_text="https://portal.corvane.com/password",
        link_url="https://portal.corvane.com/password",
        indicators=[
            "Urgent-sounding but genuine: sender and link are both on corvane.com.",
            "It refers to an announcement you can check and invites you to type the address yourself.",
            "It gives an internal phone extension for questions.",
        ],
    ),
    dict(
        code="leg-3-ceo-results",
        category=_LEG,
        difficulty=3,
        sender_name="Daniel Okafor",
        sender_address="daniel.okafor@corvane.com",
        subject="Q3 results - thank you",
        body=(
            "<p>Hi all,</p>"
            "<p>Q3 closed ahead of plan. Thank you for the work behind it. The full results "
            "summary is on the intranet, and we'll go through it at Thursday's all-hands.</p>"
            "<p>{link}</p>"
            "<p>Daniel</p>"
        ),
        link_text="Q3 results summary",
        link_url="https://intranet.corvane.com/news/q3-results",
        indicators=[
            "The CEO's real address on corvane.com.",
            "Sent to everyone, asks nothing of you, links to the intranet.",
        ],
    ),
    dict(
        code="leg-3-benefits-guide",
        category=_LEG,
        difficulty=3,
        sender_name="Corvane People Team",
        sender_address="hr@corvane.com",
        subject="Benefits guide 2027 attached",
        body=(
            "<p>Hi,</p>"
            "<p>As announced last week, enrolment for 2027 benefits opens on Monday in the HR "
            "portal. The attached PDF summarises the options so you can decide in advance.</p>"
            "<p>People Team</p>"
        ),
        attachment_name="Benefits_Guide_2027.pdf",
        indicators=[
            "Sent from hr@corvane.com and refers to a previous announcement.",
            "A plain .pdf with a single extension, and enrolment itself happens in the HR portal.",
            "No deadline pressure.",
        ],
    ),
    dict(
        code="leg-3-drive-share",
        category=_LEG,
        difficulty=3,
        sender_name="Nimbus Drive",
        sender_address="no-reply@nimbusdrive.com",
        subject="Sofia Marin shared 'Sprint 42 retrospective' with you",
        body=(
            "<p>Sofia Marin (sofia.marin@corvane.com) shared a document with you:</p>"
            "<p><b>Sprint 42 retrospective</b></p>"
            "<p>{link}</p>"
        ),
        link_text="Open in Nimbus Drive",
        link_url="https://nimbusdrive.com/d/7Hq2Lx9/sprint-42-retrospective",
        indicators=[
            "Sent from nimbusdrive.com and links to nimbusdrive.com.",
            "Names a colleague on corvane.com and a document that matches your team's work.",
            "No urgency and no request to re-enter your password.",
        ],
    ),
]
