import sys
import os

# Add path like verify_setup.py
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.append(current_dir)

try:
    from app.core.config import settings
    if settings.LLM_PROVIDER == "groq":
        print(f"GROQ_KEY_LEN: {len(settings.GROQ_API_KEY)}")
    elif settings.LLM_PROVIDER == "ollama":
        print("Using Ollama (local LLM)")
    print(f"LLM_PROVIDER: {settings.LLM_PROVIDER}")
    print(f"MODEL_NAME: {settings.MODEL_NAME}")
    print("Environment loaded successfully.")
except Exception as e:
    print(f"Error loading settings: {e}")
