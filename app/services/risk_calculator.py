def calculate_risk(
    language_score,
    link_score,
    sender_score
):


    if (
        language_score >= 80
        and
        link_score >= 100
        and
        sender_score >= 80
    ):

        return {

            "final_score": 100,

            "risk_level": "High",

            "verdict": "Phishing Detected",

            "score_breakdown": {

                "language": language_score,

                "links": link_score,

                "sender": sender_score
            }
        }


    weighted_score = (

        (language_score * 0.40)

        +

        (link_score * 0.35)

        +

        (sender_score * 0.25)
    )


    signals_fired = sum([

        language_score >= 20,

        link_score >= 20,

        sender_score >= 20
    ])

    if signals_fired == 2:

        weighted_score += 10

    elif signals_fired == 3:

        weighted_score += 20

    if link_score == 100:

        weighted_score += 10

    if sender_score >= 80:

        weighted_score += 8

    final_score = min(
        int(weighted_score),
        100
    )

    if final_score >= 75:

        risk_level = "High"

        verdict = "Phishing Detected"

    elif final_score >= 45:

        risk_level = "Medium"

        verdict = "Suspicious"

    else:

        risk_level = "Low"

        verdict = "Likely Legitimate"

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