from fastapi import FastAPI
from fastapi.templating import Jinja2Templates
from fastapi.responses import RedirectResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
import os 
from dotenv import load_dotenv


load_dotenv()

app = FastAPI("Risk Reveal AI")
templates = Jinja2Templates(directory="templates")

st.subheader("Smart Phishing Detection Assistant")

message = st.text_area("Paste Email or Message")

if st.button("Analyze"):
    st.write("Analyzing message...")
