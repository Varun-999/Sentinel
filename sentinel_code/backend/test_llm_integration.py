#!/usr/bin/env python3
"""
Test script to verify Ollama model integration is working correctly.
"""

import sys
import os

# Add the backend directory to the path
current_dir = os.path.dirname(os.path.abspath(__file__))
backend_dir = os.path.join(current_dir, 'backend')
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

try:
    from app.services.llm import llm_service
    from app.core.config import settings

    print("=== LLM Service Test ===")
    print(f"Provider: {settings.LLM_PROVIDER}")
    print(f"Model: {settings.MODEL_NAME}")
    print()

    # Test prompt
    test_prompt = "Hello! Please respond with a short greeting and confirm you're working."

    print("Sending test prompt to LLM...")
    print(f"Prompt: {test_prompt}")
    print()

    try:
        response = llm_service.generate_text(test_prompt)
        print("✅ Success! Response received:")
        print(f"Response: {response}")
        print()
        print(f"Total tokens used so far: {llm_service.total_tokens_used}")

    except Exception as e:
        print(f"❌ Error calling LLM: {e}")
        print("Make sure:")
        print("1. Ollama is running (ollama serve)")
        print("2. The model is pulled (ollama pull gemma3:4b)")
        print("3. LLM_PROVIDER is set to 'ollama' in .env")

except ImportError as e:
    print(f"❌ Import error: {e}")
    print("Make sure you're running this from the sentinel_code/backend directory")
    print("or that the Python path includes the backend directory.")