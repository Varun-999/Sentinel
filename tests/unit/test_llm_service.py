import os
import pytest
from sentinel_code.backend.app.services.llm import LLMService

def test_initial_token_count(monkeypatch):
    # Ensure required env var for Groq is present
    monkeypatch.setenv("GROQ_API_KEY", "dummy_key")
    # Force provider to groq (default) and re‑load settings validation
    service = LLMService()
    assert service.total_tokens_used == 0
