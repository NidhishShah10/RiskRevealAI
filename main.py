from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from dotenv import load_dotenv

load_dotenv()

app = FastAPI(title="Risk Reveal AI")

# Mount static files
app.mount("/static", StaticFiles(directory="static"), name="static")


# Serve homepage
@app.get("/")
async def home():
    return FileResponse("templates/index.html")


# Request model
class EmailRequest(BaseModel):
    message: str


# Analyze route
@app.post("/analyze")
async def analyze_email(data: EmailRequest):

    message = data.message.lower()

    suspicious_words = [
        "urgent",
        "verify",
        "password",
        "bank",
        "suspended",
        "click now",
        "limited time",
        "account locked"
    ]

    detected_words = []

    for word in suspicious_words:
        if word in message:
            detected_words.append(word)

    # Simple scoring logic
    risk_score = len(detected_words) * 15

    if risk_score > 100:
        risk_score = 100

    return {
        "risk_score": risk_score,
        "detected_words": detected_words
    }