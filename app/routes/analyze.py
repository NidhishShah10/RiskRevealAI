from fastapi import APIRouter
from pydantic import BaseModel

from app.services.language_detector import detect_suspicious_language

router = APIRouter()


class EmailRequest(BaseModel):
    message: str


@router.post("/analyze")
async def analyze_email(data: EmailRequest):

    result = detect_suspicious_language(data.message)

    return result