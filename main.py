from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from dotenv import load_dotenv

from app.services.language_detector import detect_suspicious_language
from app.services.link_analyzer import analyze_links
from app.services.sender_checker import check_sender
from app.services.risk_calculator import calculate_risk
from app.services.highlighter import highlight_suspicious

import os
import requests

load_dotenv()

app = FastAPI(title="Risk Reveal AI")

app.mount(
    "/static",
    StaticFiles(directory="static"),
    name="static"
)


@app.get("/")
async def home():
    return FileResponse("templates/index.html")


class EmailRequest(BaseModel):
    message: str



def generate_explanation(
    risk_result,
    detected_patterns,
    link_flags,
    sender_flags
):

    api_key = os.getenv("GROQ_API_KEY")

    if not api_key:
        return (
            "Explanation unavailable — "
            "Groq API key not set."
        )

    patterns_text = ", ".join([
        f"{p['category']}: '{p['phrase']}'"
        for p in detected_patterns
    ]) or "none"

    links_text = ", ".join(link_flags) or "none"

    sender_text = ", ".join(sender_flags) or "none"

    prompt = f"""
You are a cybersecurity phishing detection assistant.

Analyze the phishing scan results below and explain WHY the message may be dangerous or legitimate.

Mention:
- suspicious sender domains
- impersonation attempts
- urgency tactics
- suspicious links
- scam wording

Keep the explanation:
- simple
- professional
- easy for non-technical users
- 2-4 sentences max

Risk Score: {risk_result['final_score']}%
Risk Level: {risk_result['risk_level']}
Verdict: {risk_result['verdict']}

Language threats detected:
{patterns_text}

Link flags:
{links_text}

Sender flags:
{sender_text}

Start with:
"This email..."
"""

    try:

        response = requests.post(
            "https://api.groq.com/openai/v1/chat/completions",

            headers={
                "Authorization":
                    f"Bearer {api_key}",

                "Content-Type":
                    "application/json"
            },

            json={

                "model":
                    "llama-3.3-70b-versatile",

                "messages": [
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],

                "max_tokens": 180,

                "temperature": 0.4
            },

            timeout=12
        )

        if response.status_code != 200:

            print(
                f"GROQ ERROR STATUS: "
                f"{response.status_code}"
            )

            print(response.text)

            return (
                "Explanation unavailable "
                "at this time."
            )

        result = response.json()

        return (
            result["choices"][0]
            ["message"]["content"]
        )

    except Exception as e:

        print(f"GROQ ERROR: {e}")

        return (
            "Explanation unavailable "
            "at this time."
        )



@app.post("/analyze")
async def analyze_email(data: EmailRequest):

    message = data.message.strip()


    language_result = detect_suspicious_language(
        message
    )
    safe_keywords = [

        "order confirmation",
        "invoice",
        "receipt",
        "shopify",
        "google workspace",
        "microsoft 365",
        "slack",
        "zoom",
        "calendar",
        "meeting",
        "your account",
        "notification",
        "admin/orders",
        "admin/settings"
    ]

    message_lower = message.lower()

    safe_hits = sum(
        1 for word in safe_keywords
        if word in message_lower
    )
    if safe_hits >= 2:

        language_result["risk_score"] = max(

            0,

            int(
                language_result["risk_score"] * 0.45
            )
        )
        
        print(f"SAFE KEYWORDS: {safe_hits} hits, language score reduced to {language_result['risk_score']}")

    link_result = analyze_links(
        message
    )

    sender_result = check_sender(
        message
    )

    all_links_safe = all(
        len(url["flags"]) == 0
        for url in link_result["urls_found"]
    )

    if (
        all_links_safe
        and link_result["url_count"] > 0
    ):
        language_result["risk_score"] = int(
            language_result["risk_score"] * 0.55
        )
        print(f"CALIBRATION: Language score reduced to {language_result['risk_score']} (all links safe)")

    suspicious_urls = sum(

        1 for url in link_result["urls_found"]

        if len(url["flags"]) > 0
    )

    if (
        link_result["url_count"] > 0
        and
        suspicious_urls ==
        link_result["url_count"]
    ):

        link_result["link_score"] = 100


    if (
        "Possible spoofing" in
        " ".join(sender_result["flags"])
        and
        sender_result["sender_score"] >= 70
    ):

        sender_result["sender_score"] = 100


    risk_result = calculate_risk(

        language_result["risk_score"],

        link_result["link_score"],

        sender_result["sender_score"]
    )


    boost_score = 0

    if (
        sender_result["sender_score"] >= 40
        and
        link_result["link_score"] >= 40
    ):
        boost_score += 8

    if (
        sender_result["sender_score"] >= 30
        and
        language_result["risk_score"] >= 40
    ):
        boost_score += 5

    if suspicious_urls >= 2:
        boost_score += 4

    if suspicious_urls >= 3:
        boost_score += 6


    if (
        language_result["risk_score"] >= 60
        and
        link_result["link_score"] >= 90
        and
        sender_result["sender_score"] >= 80
    ):

        risk_result["final_score"] = 100

    else:

        risk_result["final_score"] = min(
            100,
            risk_result["final_score"]
            + boost_score
        )


    risk_result["score_breakdown"] = {

        "language":
            language_result["risk_score"],

        "links":
            link_result["link_score"],

        "sender":
            sender_result["sender_score"]
    }


    final_score = risk_result["final_score"]

    if final_score >= 75:

        risk_result["risk_level"] = "High"

        risk_result["verdict"] = (
            "Phishing Detected"
        )

    elif final_score >= 45:

        risk_result["risk_level"] = "Medium"

        risk_result["verdict"] = (
            "Suspicious"
        )

    else:

        risk_result["risk_level"] = "Low"

        risk_result["verdict"] = (
            "Likely Legitimate"
        )


    highlighted = highlight_suspicious(

        message,

        language_result[
            "detected_patterns"
        ]
    )


    explanation = generate_explanation(

        risk_result,

        language_result[
            "detected_patterns"
        ],

        link_result[
            "link_flags"
        ],

        sender_result[
            "flags"
        ]
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
            language_result[
                "detected_patterns"
            ],

        "urls_found":
            link_result[
                "urls_found"
            ],

        "url_count":
            link_result[
                "url_count"
            ],

        "link_flags":
            link_result[
                "link_flags"
            ],

        "sender_domain":
            sender_result[
                "domain"
            ],

        "sender_flags":
            sender_result[
                "flags"
            ],

        "sender_score":
            sender_result[
                "sender_score"
            ],

        "highlighted_message":
            highlighted,

        "explanation":
            explanation
    }