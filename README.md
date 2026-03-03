🛡️ PhishGuard
Explainable Phishing Email Detection using Hybrid AI
PhishGuard is a hybrid phishing detection system combining:
Rule-based static analysis
Cloud LLM semantic analysis

Unlike traditional spam filters, PhishGuard provides:
🚨 Urgency detection
🌐 Suspicious URL extraction
📊 Risk score (0–100)
🧠 Human-readable reasoning

🛠 Tech Stack
Python
Streamlit (UI Layer)
OpenAI-compatible API (OpenAI / Groq)
Regex (URL extraction)
python-dotenv (secure API key management)

🏗 System Architecture
User Input (Streamlit UI)
↓
Rule-Based Pre-analysis
URL extraction

Keyword detection
↓
LLM Semantic Analysis
Context understanding

Risk scoring
↓
Structured JSON Output
↓
Explainable UI Display

🚀 Why This Project Is Different
Hybrid architecture (rule + LLM)
Explainable AI output
Risk scoring instead of binary classification
Modular LLM provider support
SOC-ready JSON output


📊 Example Output
📥 Input Email
Subject: Urgent! Your bank account will be suspended

Dear User,
Your account has been compromised. Click the link below to verify immediately:
http://secure-bank-login-verification.com
📤 Output

Classification: Phishing
Risk Score: 92/100

Indicators:
Urgent tone detected (“immediately”, “suspended”)
Suspicious domain
Generic greeting (“Dear User”)
External login link

Explanation:
The email uses urgency tactics and contains a suspicious login URL that does not match the official bank domain. The language structure and sender mismatch strongly indicate phishing intent.