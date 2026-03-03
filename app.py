"""Streamlit UI for phishing email detection."""

import streamlit as st
from dotenv import load_dotenv

from utils import analyze_text
from llm_engine import analyze_email, is_provider_available

st.set_page_config(page_title="PhishGuard", page_icon="🛡️")
st.title("🛡️ PhishGuard")
st.caption("Phishing email detection using URL/keyword checks + cloud LLM")

load_dotenv()

with st.sidebar:
    st.subheader("LLM Settings")
    provider = st.selectbox("Provider", options=["groq", "openai"], index=0)
    if provider == "groq":
        st.caption("Uses `GROQ_API_KEY` and Groq OpenAI-compatible endpoint.")
        model_default = "llama-3.1-8b-instant"
    else:
        st.caption("Uses `OPENAI_API_KEY` and OpenAI endpoint.")
        model_default = "gpt-4o-mini"

    model = st.text_input("Model", value=model_default)
    timeout_seconds = st.slider("Timeout (seconds)", min_value=5, max_value=120, value=30, step=5)
    max_retries = st.slider("Max retries", min_value=0, max_value=5, value=2, step=1)

email_input = st.text_area(
    "Paste email content",
    placeholder="Subject: Urgent! Your account will be suspended\n\nDear User,\nYour account has been compromised. Click here to verify: http://fake-bank.com/login",
    height=200,
)

if st.button("Analyze", type="primary"):
    if not email_input.strip():
        st.warning("Please paste an email to analyze.")
    else:
        # Step 1: URL and keyword detection
        with st.spinner("Running URL & keyword detection..."):
            text_analysis = analyze_text(email_input)

        st.subheader("📋 Pre-analysis")
        col1, col2 = st.columns(2)
        with col1:
            st.metric("URLs found", text_analysis["url_count"])
        with col2:
            st.metric("Suspicious keywords", text_analysis["keyword_count"])

        if text_analysis["urls"]:
            st.write("**URLs:**")
            for url in text_analysis["urls"]:
                st.code(url, language=None)
        if text_analysis["suspicious_keywords"]:
            st.write("**Keywords:** ", ", ".join(text_analysis["suspicious_keywords"]))

        # Step 2: LLM analysis
        if not is_provider_available(provider):
            st.error(
                "Cloud LLM not configured. Set `GROQ_API_KEY` (for Groq) or `OPENAI_API_KEY` (for OpenAI) "
                "and ensure your API account has access to the selected model."
            )
        else:
            with st.spinner("Running LLM analysis..."):
                llm_result = analyze_email(
                    email_input,
                    url_count=text_analysis["url_count"],
                    keyword_list=text_analysis["suspicious_keywords"],
                    provider=provider,
                    model=(model.strip() or None),
                    timeout_seconds=float(timeout_seconds),
                    max_retries=int(max_retries),
                )

            st.subheader("🧠 LLM Analysis")
            st.metric("Classification", llm_result["classification"])
            st.progress(llm_result["risk_score"] / 100)
            st.write(f"**Risk score:** {llm_result['risk_score']}/100")
            st.write("**Reasoning:**", llm_result["reasoning"])
