from fastapi import APIRouter
from pydantic import BaseModel

from app.services.language_detector import (
    detect_suspicious_language
)

from app.services.link_analyzer import (
    analyze_links
)

from app.services.sender_checker import (
    check_sender
)

from app.services.risk_calculator import (
    calculate_risk
)

router = APIRouter()


class EmailRequest(BaseModel):
    message: str


@router.post("/analyze")
async def analyze_email(data: EmailRequest):

    message = data.message

    language_result = detect_suspicious_language(
        message
    )

    link_result = analyze_links(
        message
    )

    sender_result = check_sender(
        message
    )


    all_links_suspicious = False

    if link_result["urls_found"]:

        suspicious_count = sum(

            1 for url in link_result["urls_found"]

            if len(url["flags"]) > 0
        )

        if (
            suspicious_count ==
            len(link_result["urls_found"])
        ):
            all_links_suspicious = True

    if all_links_suspicious:

        link_result["link_score"] = 100

    risk_result = calculate_risk(

        language_result["risk_score"],

        link_result["link_score"],

        sender_result["sender_score"]
    )

    return {

        "risk_score":
            risk_result["final_score"],

        "risk_level":
            risk_result["risk_level"],

        "verdict":
            risk_result["verdict"],

        "score_breakdown":
            risk_result["score_breakdown"],

        "detected_patterns":
            language_result["detected_patterns"],

        "urls_found":
            link_result["urls_found"],

        "url_count":
            link_result["url_count"],

        "sender_domain":
            sender_result["domain"],

        "sender_flags":
            sender_result["flags"]
    }