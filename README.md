# 🛡️ Risk Reveal AI - Smart Phishing Detection Assistant

## 📌 Problem Statement

Phishing is by far the leading cause of cybersecurity attacks, but most detection systems barely categorize emails as either malicious or not with no explanation at all. As such, even though people are alerted to potentially suspicious emails, they still do not know what makes the email suspicious, therefore they remain as vulnerable to attacks as ever when the next phishing email arrives. Risk Reveal AI is a unique solution for phishing that goes beyond detection by identifying phishing attacks and providing clear explanations on the grounds for such labeling. The proposed project combines machine learning and explainable AI to achieve this goal.

---


## 💡 Project Idea: Smart Phishing Detection Assistant with Explainable AI

Risk Reveal AI is an intelligent phishing assistant that scans the contents of emails and messages using four core components: message body scanning, sender verification, link analysis, and language pattern detection. Based on factors such as urgency, impersonation techniques, suspicious URLs, and fake sender domains, a weighted risk score will be calculated, which represents the degree of threat posed by the message. Not only will Risk Reveal AI identify any suspicious components within the message but it will also highlight the actual message highlight that led to the risk score calculation.

---


## 🚀 Project Goals

- Build a functional full-stack AI-powered phishing detection web application
- Detect phishing emails across four core components: message body, sender, links, and language patterns
- Generate a weighted risk score representing the overall threat level of a message
- Highlight the exact suspicious parts of the message that contributed to the score
- Provide a plain explanation of why the message/text was flagged
- Evaluate detection and explanation quality using standard NLP and security metrics

---


## ✍️ Contributors

- Nidhish Shah
- Terence Pierson
- Anton Shemshur
---

## ⭐ Features

- Real-time phishing detection
- AI-generated explanations
- Sender authenticity verification
- URL reputation analysis
- Suspicious phrase highlighting
- Interactive UI
- Explainable AI outputs
---
## ⚙️ Setup & Installation

## 1. Clone the Repository

```bash
git clone https://github.com/NidhishShah10/risk-reveal-ai.git
cd risk-reveal-ai
```

## 2. Create & Activate Virtual Environment

## Windows

```bash
python -m venv venv
venv\Scripts\activate
```

## macOS / Linux

```bash
python3 -m venv venv
source venv/bin/activate
```

## 3. Install Dependencies

```bash
pip install -r requirements.txt
```

## 4. Configure Environment Variables

Create a `.env` file in the project root:

```env
GROQ_API_KEY=your_groq_api_key
GOOGLE_SAFE_BROWSING_API_KEY=your_google_api_key
```

## 5. Run the Application

```bash
uvicorn main:app --reload
```


## 6. Open in Browser

```txt
http://127.0.0.1:8000
```

---

## 🛠️ Tech Stack

## Frontend

- HTML5
- CSS3
- JavaScript
- Canvas API Animations

## Backend

- Python
- FastAPI
- Uvicorn

## AI & Machine Learning

- HuggingFace Transformers
- BERT-based phishing classifier
- Scikit-learn
- LIME
- SHAP

## APIs

- Groq API / LLM API
- Google Safe Browsing API
- ---
