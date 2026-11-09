"""Rule-based scam analysis with an explanation for every score."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from urllib.parse import urlparse


@dataclass(frozen=True)
class Finding:
    label: str
    detail: str
    evidence: str
    points: int
    severity: str


@dataclass(frozen=True)
class LinkCheck:
    url: str
    domain: str
    status: str
    note: str


@dataclass(frozen=True)
class SenderCheck:
    email: str
    domain: str
    status: str
    note: str


RISK_RULES = (
    (
        "Artificial urgency",
        "A short deadline reduces the time you have to think or verify.",
        r"\b(urgent|immediately|within \d+ (?:hours?|minutes?)|act now|today only|final warning|time.?sensitive)\b",
        18,
        "high",
    ),
    (
        "Threat or negative consequence",
        "The message threatens closure, suspension, penalties, or loss to push compliance.",
        r"\b(suspend(?:ed|sion)?|closed?|terminate(?:d)?|legal action|penalt(?:y|ies)|lose access|warrant|arrest)\b",
        16,
        "high",
    ),
    (
        "Sensitive information request",
        "Legitimate organizations rarely ask for passwords, verification codes, or identity details by message.",
        r"\b(password|passcode|one.?time code|otp|social security|ssn|bank details|credit card|full name and|date of birth)\b",
        24,
        "high",
    ),
    (
        "Unusual payment method",
        "Gift cards, cryptocurrency, wires, and payment apps are difficult to reverse.",
        r"\b(gift cards?|bitcoin|crypto(?:currency)?|wire transfer|western union|moneygram|zelle|cash app|venmo)\b",
        24,
        "high",
    ),
    (
        "Advance-fee promise",
        "A promised reward, prize, refund, or job may be bait for an upfront payment or personal data.",
        r"\b(prize|winner|inheritance|refund|reward|commission|easy money|guaranteed income|processing fee|equipment check)\b",
        15,
        "medium",
    ),
    (
        "Move off-platform",
        "The sender is trying to move the conversation away from a platform's protections.",
        r"\b(whatsapp|telegram|signal|text me at|personal email)\b",
        10,
        "medium",
    ),
    (
        "Secrecy request",
        "Requests to keep a transaction secret are a strong manipulation signal.",
        r"\b(keep (?:this|it) (?:private|secret)|don.?t tell|do not tell|between us)\b",
        20,
        "high",
    ),
    (
        "Generic greeting",
        "A vague greeting can indicate a bulk message rather than a real account notice.",
        r"\b(dear (?:customer|user|applicant|sir|madam)|valued customer)\b",
        6,
        "low",
    ),
    (
        "Pressure to click or reply",
        "The call to action asks you to use the message rather than a trusted channel.",
        r"\b(click (?:here|below|the link)|confirm (?:now|your account)|reply with|verify (?:now|your identity|your account)|open the attachment)\b",
        10,
        "medium",
    ),
)

URL_PATTERN = re.compile(r"https?://[^\s<>()\]]+", re.IGNORECASE)
SENDER_PATTERN = re.compile(
    r"(?im)^\s*(?:from|sender)\s*:\s*(?:[^<\n]*<)?([^<>\s@]+@([^<>\s@]+))"
)
LOOKALIKE_PATTERN = re.compile(
    r"(?:paypa1|micros0ft|amaz0n|g00gle|appleid|secure-?login|verify-?account|account-?verify)",
    re.IGNORECASE,
)
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "rb.gy", "is.gd"}


def _excerpt(content: str, match: re.Match[str], limit: int = 160) -> str:
    """Return the sentence around a match without cutting through words."""
    sentence_breaks = ".!?\n"
    start = max(content.rfind(mark, 0, match.start()) for mark in sentence_breaks) + 1
    end_candidates = [content.find(mark, match.end()) for mark in sentence_breaks]
    end_candidates = [position + 1 for position in end_candidates if position != -1]
    end = min(end_candidates, default=len(content))
    excerpt = re.sub(r"\s+", " ", content[start:end]).strip()

    if len(excerpt) <= limit:
        return excerpt

    match_offset = match.start() - start
    crop_start = max(0, match_offset - 45)
    if crop_start:
        next_space = excerpt.find(" ", crop_start)
        crop_start = next_space + 1 if next_space != -1 else crop_start
    cropped = excerpt[crop_start : crop_start + limit].strip()
    if crop_start + limit < len(excerpt):
        last_space = cropped.rfind(" ")
        if last_space > 0:
            cropped = cropped[:last_space]
    return cropped


def _check_link(raw_url: str) -> LinkCheck:
    url = raw_url.rstrip(".,;!?")
    parsed = urlparse(url)
    domain = (parsed.hostname or "").lower().removeprefix("www.")
    if not domain:
        return LinkCheck(url, "Invalid link", "warning", "The link is malformed and should not be opened.")

    is_ip = bool(re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", domain))
    if is_ip or LOOKALIKE_PATTERN.search(domain):
        note = (
            "Uses a raw IP address instead of a recognizable organization domain."
            if is_ip
            else "Contains look-alike or verification wording often used for impersonation."
        )
        return LinkCheck(url, domain, "warning", note)

    if domain in SHORTENERS or parsed.scheme != "https" or domain.count("-") >= 2:
        if domain in SHORTENERS:
            note = "Shortened links hide the final destination."
        elif parsed.scheme != "https":
            note = "The link does not use encrypted HTTPS."
        else:
            note = "The domain structure is unusually complex; verify it independently."
        return LinkCheck(url, domain, "caution", note)

    return LinkCheck(
        url,
        domain,
        "clear",
        "No obvious formatting risk detected, but the destination is not independently verified.",
    )


def _risk_label(score: int, findings: list[Finding]) -> tuple[str, str]:
    if score >= 70:
        return "High risk", "Strong signs of impersonation or manipulation."
    if score >= 35:
        return "Suspicious", "Several details deserve verification."
    domain_warning = next(
        (
            finding
            for finding in findings
            if finding.label in {"High-risk link pattern", "Suspicious sender domain"}
        ),
        None,
    )
    if domain_warning:
        subject = "link domain" if domain_warning.label == "High-risk link pattern" else "sender domain"
        return "Suspicious", f"Limited evidence — suspicious {subject} detected."
    return "Low risk", "Few common scam signals were detected."


def _message_type(content: str) -> str:
    if re.search(r"\b(job|position|hiring|interview|salary|recruiter)\b", content, re.I):
        return "Job listing"
    if re.search(r"\b(from:|subject:|@)", content, re.I):
        return "Email"
    return "Message"


def analyze_message(content: str) -> dict:
    """Analyze content and return an explainable score plus evidence."""
    findings: list[Finding] = []
    for label, detail, pattern, points, severity in RISK_RULES:
        match = re.search(pattern, content, re.IGNORECASE)
        if match:
            findings.append(Finding(label, detail, _excerpt(content, match), points, severity))

    links = [_check_link(url) for url in dict.fromkeys(URL_PATTERN.findall(content))]

    sender_checks: list[SenderCheck] = []
    sender_match = SENDER_PATTERN.search(content)
    if sender_match:
        sender_email = sender_match.group(1).rstrip(".,;")
        sender_domain = sender_match.group(2).rstrip(".,;").lower()
        suspicious_sender = bool(
            re.search(r"(?:paypa1|micros0ft|amaz0n|g00gle|secure|verify|support|billing)", sender_domain)
        )
        sender_checks.append(
            SenderCheck(
                sender_email,
                sender_domain,
                "warning" if suspicious_sender else "caution",
                (
                    "This domain contains brand-like or security wording often used in impersonation. "
                    "Verify the sender independently."
                    if suspicious_sender
                    else "A pasted address cannot authenticate who sent the message. Verify it using "
                    "contact information from the organization's official website or app."
                ),
            )
        )
        if suspicious_sender:
            findings.append(
                Finding(
                    "Suspicious sender domain",
                    "The sender address uses brand-like or security wording that may imitate a trusted organization.",
                    sender_domain,
                    18,
                    "high",
                )
            )

    risky = [link for link in links if link.status == "warning"]
    cautious = [link for link in links if link.status == "caution"]
    if risky:
        findings.append(
            Finding(
                "High-risk link pattern",
                f"{len(risky)} link{'s' if len(risky) != 1 else ''} {'use' if len(risky) != 1 else 'uses'} a misleading, numeric, or malformed destination.",
                risky[0].domain,
                min(28, 20 + (len(risky) - 1) * 4),
                "high",
            )
        )
    elif cautious:
        findings.append(
            Finding(
                "Link needs caution",
                f"{len(cautious)} link{'s' if len(cautious) != 1 else ''} hide the destination or use an unusual structure.",
                cautious[0].domain,
                12,
                "medium",
            )
        )

    score = min(100, sum(finding.points for finding in findings))
    level, summary = _risk_label(score, findings)
    kind = _message_type(content)
    if not findings:
        findings.append(
            Finding(
                "No common warning signs found",
                "This automated check did not match the most common scam tactics. Continue to verify unexpected requests independently.",
                "",
                0,
                "low",
            )
        )

    return {
        "kind": kind,
        "score": score,
        "level": level,
        "summary": summary,
        "findings": [asdict(item) for item in findings],
        "links": [asdict(item) for item in links],
        "senderChecks": [asdict(item) for item in sender_checks],
    }
