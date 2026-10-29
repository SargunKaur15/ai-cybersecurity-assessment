"""Synthetic phishing-like / legitimate message generator (Task 14).

All content is fabricated from templates. Every URL uses reserved or
example-only domains (example.com / .net / .org, .test, .invalid), so nothing
here points at a real host. No real names, credentials or logs are used.

Two datasets are produced:

* ``synthetic_messages.csv`` - the main dataset (workplace-email style templates
  ``P*`` = phishing-like, ``L*`` = legitimate).
* ``shifted_messages.csv``   - a separate set built from *different* templates and
  vocabulary (short SMS / consumer style, ``SP*`` / ``SL*``). It is never used for
  training and exists only to probe distribution shift.

Run:  python src/generate_dataset.py
"""

from __future__ import annotations

import argparse
import random
from pathlib import Path

import pandas as pd

SEED = 42
PHISHING = "phishing"
LEGITIMATE = "legitimate"
COLUMNS = ["message_id", "text", "label", "category", "template_id"]

# --------------------------------------------------------------------------
# Slot pools. Greetings, sign-offs and dates are shared by both classes so they
# carry no label information on their own.
# --------------------------------------------------------------------------
NAMES = ["Alex", "Sam", "Jordan", "Priya", "Chen", "Maria", "Omar", "Taylor", "Lena", "Ravi", "Nina", "Diego"]
SERVICES = ["email", "cloud storage", "payroll portal", "VPN", "company intranet", "online banking",
            "video-conferencing", "shared drive"]
MONTHS = ["January", "February", "March", "April", "May", "June", "July", "August", "September",
          "October", "November", "December"]
WEEKDAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"]
CLOSES = ["Thank you.", "Thanks,", "Kind regards.", "Best regards.", ""]
ROOMS = ["B12", "3.04", "Orion", "Atlas", "2A"]
AGENDAS = ["roadmap review", "budget check-in", "sprint planning", "onboarding update", "quarterly goals"]
DOCNAMES = ["budget summary", "project plan", "team roster", "policy update", "meeting notes", "vendor list"]
PRIZES = ["gift voucher", "new phone", "holiday package", "cash reward"]

# Phishing-like URLs: some obvious, some lookalikes that embed a trusted-looking name.
BAD_URLS = [
    "http://account-verify.example.net/login",
    "https://secure-signin.example.invalid/confirm",
    "http://mail-support.test/verify",
    "https://login-update.example.net/secure",
    "https://portal.example.com.session-check.example.net/signin",
    "http://docs-viewer.example.invalid/open",
    "https://example.com-helpdesk.example.org/reset",
    "http://payroll-update.test/form",
]
# Legitimate URLs: mostly the "internal" domain, but some third-party style hosts too.
GOOD_URLS = [
    "https://intranet.example.com/it/password",
    "https://portal.example.com/hr/benefits",
    "https://support.example.com/tickets",
    "https://www.example.com/orders/track",
    "https://calendar.example.com/event",
    "https://docs.example.com/policies",
    "https://payments.example.net/receipts",
    "https://news.example.org/newsletter",
]


def _fmt_greet(rng: random.Random) -> str:
    return rng.choice(["Hello {n},", "Hi {n},", "Dear {n},", "Good morning {n},", "Hello,"]).format(n=rng.choice(NAMES))


SLOT_FUNCS = {
    "greet": _fmt_greet,
    "close": lambda r: r.choice(CLOSES),
    "name": lambda r: r.choice(NAMES),
    "colleague": lambda r: r.choice(NAMES),
    "service": lambda r: r.choice(SERVICES),
    "hours": lambda r: r.choice(["2", "6", "12", "24", "48"]),
    "days": lambda r: r.choice(["3", "5", "7", "14", "30"]),
    "n": lambda r: r.choice(["2", "3", "4", "5", "6"]),
    "invoice": lambda r: f"INV-{r.randint(1000, 9999)}",
    "order": lambda r: f"A{r.randint(10000, 99999)}",
    "ticket": lambda r: f"TCK-{r.randint(100, 999)}",
    "amount": lambda r: f"${r.randint(40, 4800)}.{r.randint(0, 99):02d}",
    "small_amount": lambda r: f"${r.randint(1, 9)}.{r.randint(0, 99):02d}",
    "date": lambda r: f"{r.randint(1, 28)} {r.choice(MONTHS)}",
    "month": lambda r: r.choice(MONTHS),
    "weekday": lambda r: r.choice(WEEKDAYS),
    "time": lambda r: f"{r.randint(8, 16)}:{r.choice(['00', '15', '30', '45'])}",
    "time2": lambda r: f"{r.randint(17, 20)}:{r.choice(['00', '30'])}",
    "room": lambda r: r.choice(ROOMS),
    "agenda": lambda r: r.choice(AGENDAS),
    "docname": lambda r: r.choice(DOCNAMES),
    "prize": lambda r: r.choice(PRIZES),
    "bad_url": lambda r: r.choice(BAD_URLS),
    "good_url": lambda r: r.choice(GOOD_URLS),
    "code": lambda r: f"{r.randint(100000, 999999)}",
    "bank": lambda r: r.choice(["Northfield Bank", "Example Credit Union", "Harbor Savings"]),
    "coin": lambda r: r.choice(["wallet", "exchange account"]),
    "short": lambda r: r.choice(["now", "today", "asap"]),
}


class _Slots(dict):
    """Lazily fills template slots; the same slot name stays consistent within one message."""

    def __init__(self, rng: random.Random):
        super().__init__()
        self._rng = rng

    def __missing__(self, key: str) -> str:
        value = SLOT_FUNCS[key](self._rng)
        self[key] = value
        return value


# --------------------------------------------------------------------------
# Main-dataset templates: (template_id, category, text)
# --------------------------------------------------------------------------
PHISHING_TEMPLATES = [
    ("P01", "account_suspension", "{greet} URGENT: your {service} account will be suspended in {hours} hours unless you verify your identity. Sign in here: {bad_url}"),
    ("P02", "routine_review", "{greet} as part of a routine review, we ask all staff to confirm their {service} sign-in details. It only takes a minute: {bad_url} Thank you for your cooperation."),
    ("P03", "password_expiry", "{greet} your {service} password has expired. To keep access, reset it using this link: {bad_url} {close}"),
    ("P04", "invoice", "{greet} invoice {invoice} for {amount} is overdue. Open the secure document to review payment details: {bad_url}"),
    ("P05", "delivery_fee", "{greet} we could not deliver your parcel. Pay the redelivery fee of {small_amount} within {hours} hours to avoid return: {bad_url}"),
    ("P06", "gift_card_fraud", "{greet} are you at your desk? I am in a meeting and need a favour. Please buy {n} gift cards for a client and send me the codes. Keep this between us for now."),
    ("P07", "payment_change", "{greet} please update the bank details for our supplier before today's payment run. The new account details are in my previous message. Do not call, I cannot take calls right now."),
    ("P08", "prize", "{greet} you have been selected to receive a {prize}. Claim it before it expires: {bad_url}"),
    ("P09", "shared_document", "{greet} {colleague} shared a document with you: '{docname}'. View it by signing in with your {service} credentials: {bad_url}"),
    ("P10", "mfa_prompt", "{greet} we detected a new sign-in to your {service} account. If this was not you, cancel the request by entering your one-time code at {bad_url}"),
    ("P11", "payroll_update", "{greet} payroll records for {month} need re-confirmation. Submit your bank and ID details through the form: {bad_url} {close}"),
    ("P12", "macro_attachment", "{greet} please find the attached scan of the signed contract. Enable macros to view the content. {close}"),
    ("P13", "refund", "{greet} you are eligible for a refund of {amount}. Confirm your card details to receive it: {bad_url}"),
    ("P14", "security_alert_polite", "{greet} our security team noticed unusual activity on your {service} account. Please review and confirm your details at {bad_url} so we can keep your account safe."),
]

LEGITIMATE_TEMPLATES = [
    ("L01", "password_reminder", "{greet} reminder: your {service} password expires in {days} days. You can change it from the company portal at {good_url}. IT will never ask for your password by email. {close}"),
    ("L02", "maintenance_urgent", "{greet} URGENT: scheduled maintenance on {service} tonight from 22:00 to 23:30. Expect short downtime; no action is required."),
    ("L03", "invoice", "{greet} invoice {invoice} for {amount} is attached. Payment is due on {date}. Questions can be sent to the accounts team. {close}"),
    ("L04", "order_shipped", "{greet} your order {order} has shipped and should arrive on {date}. Track it here: {good_url}"),
    ("L05", "meeting", "{greet} reminder: team meeting on {weekday} at {time} in room {room}. Agenda: {agenda}. {close}"),
    ("L06", "hr_benefits", "{greet} open enrolment for benefits closes on {date}. Review your options at {good_url}. {close}"),
    ("L07", "security_awareness", "{greet} this month's security tip: be careful with unexpected links and never share your {service} password or one-time codes with anyone, including IT staff."),
    ("L08", "new_device_notice", "{greet} we noticed a new sign-in to your {service} account from a new device. If this was you, no action is needed. If not, contact the service desk on the internal extension."),
    ("L09", "newsletter", "{greet} the {month} newsletter is out: new starters, an office move update and the quarterly results summary. Read it at {good_url}"),
    ("L10", "ticket_resolved", "{greet} your support ticket {ticket} has been resolved. Reply to this message within {days} days if the problem persists."),
    ("L11", "expenses", "{greet} please submit your expense report for {month} by {date}. Instructions are on the finance page: {good_url} {close}"),
    ("L12", "personal", "{greet} are you free for lunch on {weekday}? I was thinking of the place near the office. Let me know."),
    ("L13", "shared_document", "{greet} {colleague} shared the document '{docname}' with you in the shared drive. Open it from your normal workspace at {good_url}"),
    ("L14", "deadline_urgent", "{greet} urgent: the project report is due {weekday} at {time}. Please send your sections to me today so we can review them."),
    ("L15", "payment_received", "{greet} we have received your payment of {amount}. Thank you. A receipt is available in your account area at {good_url}"),
    ("L16", "attendance_verify", "{greet} please verify your attendance for the {month} training session by replying yes or no. Places are limited."),
    ("L17", "account_closure", "{greet} as requested, your {service} account will be closed in {days} days. Your data can be exported until then from {good_url}"),
    ("L18", "courier_notice", "{greet} a courier will deliver your parcel on {date} between {time} and {time2}. No payment is required. {close}"),
]

# --------------------------------------------------------------------------
# Shifted-set templates: different channel (SMS / consumer), topics and wording.
# Written independently of the main templates; never used for training.
# --------------------------------------------------------------------------
SHIFT_PHISHING_TEMPLATES = [
    ("SP01", "bank_card_blocked", "{bank}: your card has been blocked after suspicious activity. Restore access {short}: {bad_url}"),
    ("SP02", "crypto", "Your {coin} shows a pending withdrawal of {amount}. If you did not request it, secure your holdings here: {bad_url}"),
    ("SP03", "tax_refund", "The tax office has calculated a refund of {amount} for you. Submit your account number to receive the payment: {bad_url}"),
    ("SP04", "social_login", "Someone tried to log in to your social profile. Confirm it is you to keep your page active: {bad_url}"),
    ("SP05", "job_offer", "Congratulations, you have been shortlisted for a remote role paying {amount} per week. Send a copy of your ID and your bank details to start {short}."),
    ("SP06", "toll_fee", "Final notice: an unpaid toll of {small_amount} is outstanding. Pay online to avoid a late fee: {bad_url}"),
    ("SP07", "family_emergency", "Hi, it's me, I lost my phone and I'm stuck abroad. Can you transfer {amount} to this account {short}? I will pay you back."),
    ("SP08", "subscription", "Your streaming subscription could not be renewed. Update your payment card within {hours} hours to avoid cancellation: {bad_url}"),
]

SHIFT_LEGITIMATE_TEMPLATES = [
    ("SL01", "bank_alert", "{bank}: a payment of {amount} was made with your card ending 4821. Thank you for banking with us. No action is needed."),
    ("SL02", "otp", "Your verification code is {code}. It expires in 10 minutes. Never share this code with anyone."),
    ("SL03", "appointment", "Reminder: you have an appointment on {date} at {time}. Reply C to confirm or call the clinic reception to change it."),
    ("SL04", "package_ok", "Your package {order} is out for delivery today. Track its progress at {good_url}"),
    ("SL05", "club", "The book club meets on {weekday} at {time}. We are reading a new title this month; bring a friend!"),
    ("SL06", "utility", "Your electricity bill for {month} is ready. You can view it in your online account at {good_url}"),
    ("SL07", "school", "School notice: the parents' evening is on {date}. Please book a slot with the form teacher through the school office."),
    ("SL08", "friend", "Running late, I will be there in {n} minutes. Save me a seat!"),
]


def _perturb(text: str, rng: random.Random) -> str:
    """Surface noise applied identically to both classes (so it carries no label signal)."""
    if rng.random() < 0.15:
        text = text.lower()
    if rng.random() < 0.10 and text.endswith("."):
        text = text[:-1]
    if rng.random() < 0.10:
        text = "FW: " + text
    return text


def _render(template: str, rng: random.Random) -> str:
    text = template.format_map(_Slots(rng))
    text = " ".join(text.split())  # collapse blanks left by empty slots
    return _perturb(text, rng)


def _generate(phish_templates, legit_templates, n_total: int, phishing_fraction: float,
              seed: int, id_prefix: str) -> pd.DataFrame:
    if n_total < 2:
        raise ValueError("n_total must be at least 2")
    if not 0.0 < phishing_fraction < 1.0:
        raise ValueError("phishing_fraction must be strictly between 0 and 1")

    rng = random.Random(seed)
    n_phish = round(n_total * phishing_fraction)
    plan = [(PHISHING, phish_templates)] * n_phish + [(LEGITIMATE, legit_templates)] * (n_total - n_phish)

    rows, seen = [], set()
    for label, templates in plan:
        for _ in range(200):  # retry to keep every text unique (no exact duplicates)
            template_id, category, template = rng.choice(templates)
            text = _render(template, rng)
            if text not in seen:
                seen.add(text)
                rows.append((text, label, category, template_id))
                break
        else:
            raise RuntimeError("Could not generate enough unique messages; reduce n_total")

    rng.shuffle(rows)
    df = pd.DataFrame(rows, columns=["text", "label", "category", "template_id"])
    df.insert(0, "message_id", [f"{id_prefix}{i:04d}" for i in range(1, len(df) + 1)])
    return df[COLUMNS]


def generate_dataset(n_total: int = 1000, phishing_fraction: float = 0.4, seed: int = SEED) -> pd.DataFrame:
    """Main synthetic dataset (workplace-email style)."""
    return _generate(PHISHING_TEMPLATES, LEGITIMATE_TEMPLATES, n_total, phishing_fraction, seed, "M")


def generate_shifted_dataset(n_total: int = 200, phishing_fraction: float = 0.4, seed: int = SEED + 1) -> pd.DataFrame:
    """Out-of-distribution set: different channel, topics and templates."""
    return _generate(SHIFT_PHISHING_TEMPLATES, SHIFT_LEGITIMATE_TEMPLATES, n_total, phishing_fraction, seed, "S")


def main(argv=None) -> int:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description="Generate the synthetic phishing/legitimate datasets.")
    parser.add_argument("--out-dir", type=Path, default=root / "data")
    parser.add_argument("--n-total", type=int, default=1000)
    parser.add_argument("--n-shifted", type=int, default=200)
    parser.add_argument("--phishing-fraction", type=float, default=0.4)
    parser.add_argument("--seed", type=int, default=SEED)
    args = parser.parse_args(argv)

    args.out_dir.mkdir(parents=True, exist_ok=True)
    main_df = generate_dataset(args.n_total, args.phishing_fraction, args.seed)
    shifted_df = generate_shifted_dataset(args.n_shifted, args.phishing_fraction, args.seed + 1)
    main_df.to_csv(args.out_dir / "synthetic_messages.csv", index=False)
    shifted_df.to_csv(args.out_dir / "shifted_messages.csv", index=False)
    print(f"Wrote {len(main_df)} messages to {args.out_dir / 'synthetic_messages.csv'}")
    print(main_df["label"].value_counts().to_string())
    print(f"Wrote {len(shifted_df)} messages to {args.out_dir / 'shifted_messages.csv'}")
    print(shifted_df["label"].value_counts().to_string())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
