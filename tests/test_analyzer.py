from app.analyzer import analyze_message


def test_high_risk_message_explains_score():
    result = analyze_message(
        "URGENT: verify your account within 2 hours at "
        "https://paypa1-secure-login.com/verify and reply with your one-time code."
    )
    assert result["score"] >= 70
    assert result["level"] == "High risk"
    assert sum(item["points"] for item in result["findings"]) >= result["score"]
    assert any(item["label"] == "High-risk link pattern" for item in result["findings"])


def test_benign_message_is_low_risk():
    result = analyze_message(
        "Hi Jordan, our project meeting is scheduled for Tuesday at 10. "
        "The agenda is in the shared team folder."
    )
    assert result["score"] < 35
    assert result["level"] == "Low risk"


def test_job_listing_is_classified():
    result = analyze_message(
        "We are hiring for a remote position. Contact our recruiter on Telegram "
        "and deposit the equipment check today."
    )
    assert result["kind"] == "Job listing"
    assert result["score"] > 0


def test_safe_link_has_clear_status():
    result = analyze_message(
        "Read the meeting notes and background information at "
        "https://docs.python.org/3/library/urllib.parse.html"
    )
    assert result["links"][0]["status"] == "clear"


def test_sender_domain_is_shown_but_not_claimed_verified():
    result = analyze_message(
        "From: Jordan <jordan@example.com>\n"
        "Hi, please review the attached document when you have time."
    )
    assert result["senderChecks"] == [
        {
            "email": "jordan@example.com",
            "domain": "example.com",
            "status": "caution",
            "note": (
                "A pasted address cannot authenticate who sent the message. Verify it using "
                "contact information from the organization's official website or app."
            ),
        }
    ]
    assert result["score"] == 0


def test_suspicious_sender_domain_is_warned_and_scored():
    result = analyze_message(
        "From: PayPal <account@paypa1-verify.net>\n"
        "Please review this message at your convenience."
    )
    assert result["senderChecks"][0]["status"] == "warning"
    assert result["senderChecks"][0]["domain"] == "paypa1-verify.net"
    assert any(item["label"] == "Suspicious sender domain" for item in result["findings"])
    assert result["score"] == 18


def test_email_in_message_body_is_not_treated_as_sender():
    result = analyze_message(
        "Contact account@support.example.com if you have questions about this ordinary meeting."
    )
    assert result["senderChecks"] == []


def test_link_only_warning_is_not_labeled_low_risk():
    result = analyze_message("https://paypa1-secure-login.example/verify")
    assert result["score"] == 20
    assert result["level"] == "Suspicious"
    assert result["summary"] == "Limited evidence — suspicious link domain detected."
    assert result["links"][0]["status"] == "warning"


def test_security_topic_without_pressure_is_not_scored():
    result = analyze_message(
        "Our security team published the monthly account safety guide in the staff handbook."
    )
    assert result["score"] == 0
    assert result["level"] == "Low risk"


def test_evidence_excerpt_starts_on_a_word_boundary():
    result = analyze_message(
        "This introduction contains several ordinary words before the request. "
        "Please act now to review the account notice before tomorrow."
    )
    evidence = next(
        item["evidence"]
        for item in result["findings"]
        if item["label"] == "Artificial urgency"
    )
    assert evidence.startswith("Please act now")
