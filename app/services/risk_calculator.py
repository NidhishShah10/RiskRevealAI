def calculate_risk(language_score, link_score, sender_score):

    # Weighted combination
    weighted_score = (
        (language_score * 0.40) +
        (link_score * 0.35) +
        (sender_score * 0.25)
    )

    # Boost if multiple signals fire together
    signals_fired = sum([
        language_score >= 20,
        link_score >= 20,
        sender_score >= 20
    ])

    if signals_fired == 2:
        weighted_score = min(weighted_score + 10, 100)
    elif signals_fired == 3:
        weighted_score = min(weighted_score + 20, 100)

    final_score = min(int(weighted_score), 100)

    if final_score >= 70:
        risk_level = "High"
    elif final_score >= 40:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    verdict = "Phishing" if final_score >= 40 else "Legitimate"

    return {
        "final_score": final_score,
        "risk_level": risk_level,
        "verdict": verdict,
        "score_breakdown": {
            "language": language_score,
            "links": link_score,
            "sender": sender_score
        }
    }