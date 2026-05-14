from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from dotenv import load_dotenv

load_dotenv()

app = FastAPI(title="Risk Reveal AI")

# Mount static files
app.mount("/static", StaticFiles(directory="static"), name="static")

# Serve index.html directly
@app.get("/")
async def home():
    return FileResponse("templates/index.html")