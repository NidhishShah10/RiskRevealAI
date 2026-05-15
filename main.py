from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from dotenv import load_dotenv
from app.services.language_detector import detect_suspicious_language
from app.services.link_analyzer import analyze_links

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
    # Run both services
    language_result = detect_suspicious_language(data.message)
    link_result = analyze_links(data.message)

    language_score = language_result["risk_score"]
    link_score = link_result["link_score"]

    # Base score from language
    combined_score = language_score

    # Add link score on top
    combined_score = min(combined_score + link_score, 100)

    # Boost if both signals present
    if language_score > 0 and link_score > 0:
        combined_score = min(combined_score + 15, 100)

    verdict = "Phishing" if combined_score >= 40 else "Legitimate"

    return {
        "risk_score": combined_score,
        "verdict": verdict,
        "detected_patterns": language_result["detected_patterns"],
        "message_length": language_result["message_length"],
        "urls_found": link_result["urls_found"],
        "url_count": link_result["url_count"],
        "link_flags": link_result["link_flags"]
    }