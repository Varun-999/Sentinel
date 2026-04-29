import os
import pytest
from sentinel_code.backend.app.services.llm import LLMService

def test_initial_token_count(monkeypatch):
    # Set provider to ollama (no API key needed)
    monkeypatch.setenv("LLM_PROVIDER", "ollama")
    service = LLMService()
    assert service.total_tokens_used == 0
