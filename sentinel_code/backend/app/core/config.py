import os
from dotenv import load_dotenv

# Load environment variables from .env file
# Load environment variables from .env file
# Calculate the path to the .env file in the project root
# config.py is in sentinel_code/backend/app/core/
# Load environment variables from .env file
# Calculate the path to the .env file in the project root
# config.py is in sentinel_code/backend/app/core/
# Project root is 5 levels up from this file (including filename)
# .../Sentinel/sentinel_code/backend/app/core/config.py
base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))
env_path = os.path.join(base_dir, ".env")
load_dotenv(env_path)

class Settings:
    GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY", "")
    GROQ_API_KEY: str = os.getenv("GROQ_API_KEY", "")
    
    # Provider selection: 'gemini', 'groq', or 'ollama'
    LLM_PROVIDER: str = os.getenv("LLM_PROVIDER", "ollama")

    @property
    def MODEL_NAME(self) -> str:
        if self.LLM_PROVIDER == "groq":
            return "llama-3.3-70b-versatile"
        elif self.LLM_PROVIDER == "ollama":
            return "gemma3:4b"
        #llama3.1:8b
        return "gemini-2.0-flash"
    
    def validate(self):
        if self.LLM_PROVIDER == "gemini" and not self.GEMINI_API_KEY:
            raise ValueError("GEMINI_API_KEY is not set in environment variables or .env file.")
        if self.LLM_PROVIDER == "groq" and not self.GROQ_API_KEY:
            raise ValueError("GROQ_API_KEY is not set in environment variables or .env file.")
        if self.LLM_PROVIDER == "ollama":
            # Ollama runs locally, no API key needed
            pass

settings = Settings()
