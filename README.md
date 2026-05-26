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

# 🧠 Technologies Used

## Backend
- Python
- FastAPI
- Uvicorn

## Frontend
- HTML
- CSS
- JavaScript

## Machine Learning
- Hugging Face Transformers
- DistilBERT
- PyTorch
- Scikit-learn

## Security & Analysis
- DNSPython
- TLDExtract
- Python-Levenshtein

## Data Processing
- Pandas
- NumPy

## Explainable AI
- Groq API (Explanation generation only)

---

# 📊 Data Training

The phishing classifier was fine-tuned using DistilBERT on multiple phishing and spam datasets including:

- CEAS 2008
- Enron Spam Dataset
- SpamAssassin
- Nazario Phishing Corpus
- Nigerian Fraud Dataset
- Phishing Email Dataset
- Ling Spam Dataset

## Training Pipeline

1. Dataset cleaning and preprocessing
2. Label balancing
3. Tokenization using DistilBERT tokenizer
4. Fine-tuning for binary classification
5. Evaluation using:
   - Accuracy
   - Precision
   - Recall
   - F1-score
6. Saving the trained model for deployment

---

## 📁 Model Files

The trained DistilBERT model files are not included in this repository due to GitHub file size limits.

To run the project locally:

1. Train the model using the datasets
2. Save the trained model inside:

app/models/phishing_model/

3. Ensure the folder contains:
- config.json
- tokenizer files
- model.safetensors
---

# 📚 References

1. Alotaibi, F., et al. (2024). *Explainable artificial intelligence in web phishing classification on secure IoT with cloud-based cyber-physical systems*. Cluster Computing.

2. Alhogail, A., & Alsabih, A. (2023). *Explainable AI for IoT devices and robotic communication phishing detection: A machine learning approach using LIME and SHAP*. Applied Sciences.

3. Basit, A., et al. (2023). *An intelligent phishing email detection system using ensemble methods and explainable AI*. Future Generation Computer Systems.

4. Korkmaz, M., et al. (2023). *Mitigating cyber threats: Machine learning and explainable AI for phishing detection*. Computers and Security.

5. Salloum, S., et al. (2024). *Smart and transparent defense: A hybrid explainable AI framework for phishing resilience*. IEEE Access.

6. Sanh, V., Debut, L., Chaumond, J., & Wolf, T. (2019). *DistilBERT, a distilled version of BERT: smaller, faster, cheaper and lighter*. arXiv preprint arXiv:1910.01108.

---
