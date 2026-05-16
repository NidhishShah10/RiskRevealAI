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
app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/")
async def home():
    return FileResponse("templates/index.html")

class EmailRequest(BaseModel):
    message: str

def generate_explanation(risk_result, detected_patterns, link_flags, sender_flags):
    api_key = os.getenv("GROQ_API_KEY")
    if not api_key:
        return "Explanation unavailable — Groq API key not set."

    patterns_text = ", ".join([f"{p['category']}: '{p['phrase']}'" for p in detected_patterns]) or "none"
    links_text = ", ".join(link_flags) or "none"
    sender_text = ", ".join(sender_flags) or "none"

    prompt = f"""You are a cybersecurity assistant. Analyze this phishing detection result and explain it clearly in 2-3 sentences for a non-technical user.

Risk Score: {risk_result['final_score']}%
Risk Level: {risk_result['risk_level']}
Verdict: {risk_result['verdict']}
Language threats detected: {patterns_text}
Link flags: {links_text}
Sender flags: {sender_text}

Write a clear, simple explanation of why this email is or is not suspicious. Start with 'This email...'"""

    try:
        response = requests.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json"
            },
            json={
                "model": "llama-3.3-70b-versatile",
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": 150
            },
            timeout=10
        )
        print(f"GROQ STATUS: {response.status_code}")
        print(f"GROQ RESPONSE: {response.text}")
        return response.json()["choices"][0]["message"]["content"]
    except Exception as e:
        print(f"GROQ ERROR: {e}")
        return "Explanation unavailable at this time."


@app.post("/analyze")
async def analyze_email(data: EmailRequest):
    language_result = detect_suspicious_language(data.message)
    link_result = analyze_links(data.message)
    sender_result = check_sender(data.message)

    risk_result = calculate_risk(
        language_result["risk_score"],
        link_result["link_score"],
        sender_result["sender_score"]
    )

    highlighted = highlight_suspicious(
        data.message,
        language_result["detected_patterns"]
    )

    explanation = generate_explanation(
        risk_result,
        language_result["detected_patterns"],
        link_result["link_flags"],
        sender_result["flags"]
    )

    return {
        "risk_score": risk_result["final_score"],
        "risk_level": risk_result["risk_level"],
        "verdict": risk_result["verdict"],
        "score_breakdown": risk_result["score_breakdown"],
        "detected_patterns": language_result["detected_patterns"],
        "urls_found": link_result["urls_found"],
        "url_count": link_result["url_count"],
        "link_flags": link_result["link_flags"],
        "sender_domain": sender_result["domain"],
        "sender_flags": sender_result["flags"],
        "sender_score": sender_result["sender_score"],
        "highlighted_message": highlighted,
        "explanation": explanation
    }