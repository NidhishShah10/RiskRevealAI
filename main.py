from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from dotenv import load_dotenv
from app.services.language_detector import detect_suspicious_language
from app.services.link_analyzer import analyze_links
from app.services.sender_checker import check_sender

load_dotenv()

app = FastAPI(title="Risk Reveal AI")

app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/")
async def home():
    return FileResponse("templates/index.html")

class EmailRequest(BaseModel):
    message: str

@app.post("/analyze")
async def analyze_email(data: EmailRequest):
    language_result = detect_suspicious_language(data.message)
    link_result = analyze_links(data.message)
    sender_result = check_sender(data.message)

    language_score = language_result["risk_score"]
    link_score = link_result["link_score"]
    sender_score = sender_result["sender_score"]

    # Combine all three scores
    combined_score = min(language_score + link_score + sender_score, 100)

    # Boost if multiple signals present
    signals = sum([language_score > 0, link_score > 0, sender_score > 0])
    if signals >= 2:
        combined_score = min(combined_score + 10, 100)

    verdict = "Phishing" if combined_score >= 40 else "Legitimate"

    return {
        "risk_score": combined_score,
        "verdict": verdict,
        "detected_patterns": language_result["detected_patterns"],
        "message_length": language_result["message_length"],
        "urls_found": link_result["urls_found"],
        "url_count": link_result["url_count"],
        "link_flags": link_result["link_flags"],
        "sender_domain": sender_result["domain"],
        "sender_flags": sender_result["flags"],
        "sender_score": sender_score
    }