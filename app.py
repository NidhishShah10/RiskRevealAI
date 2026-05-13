import streamlit as st
import os 
from dotenv import load_dotenv

load_dotenv()

st.title("Risk Reveal AI")

st.subheader("Smart Phishing Detection Assistant")

message = st.text_area("Paste Email or Message")

if st.button("Analyze"):
    st.write("Analyzing message...")
