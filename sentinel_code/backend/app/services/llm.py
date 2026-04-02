from app.core.config import settings

import time

class LLMService:
    def __init__(self):
        settings.validate()
        self.provider = settings.LLM_PROVIDER
        self.model_name = settings.MODEL_NAME
        self.total_tokens_used = 0
        
        if self.provider == "gemini":
            from google import genai
            self.client = genai.Client(api_key=settings.GEMINI_API_KEY)
        elif self.provider == "groq":
            from groq import Groq
            self.client = Groq(api_key=settings.GROQ_API_KEY)

    def generate_text(self, prompt: str, max_retries: int = 4) -> str:
        """
        Generates text using the configured LLM and tracks tokens.
        Retries on rate-limit errors with exponential backoff.
        Raises an exception to the caller on unrecoverable failures 
        (rather than silently returning an error string that could corrupt files).
        """
        last_error = None
        for attempt in range(max_retries):
            try:
                if self.provider == "gemini":
                    response = self.client.models.generate_content(
                        model=self.model_name,
                        contents=prompt
                    )
                    if not response.text:
                        raise ValueError("Empty response from LLM")
                        
                    if hasattr(response, 'usage_metadata') and response.usage_metadata:
                        self.total_tokens_used += getattr(response.usage_metadata, 'total_token_count', len(prompt)//4)
                    else:
                        self.total_tokens_used += len(prompt) // 4
                        
                    return response.text
                    
                elif self.provider == "groq":
                    chat_completion = self.client.chat.completions.create(
                        messages=[{"role": "user", "content": prompt}],
                        model=self.model_name,
                        max_tokens=4096,
                        timeout=30.0
                    )
                    if hasattr(chat_completion, 'usage') and chat_completion.usage:
                        self.total_tokens_used += getattr(chat_completion.usage, 'total_tokens', len(prompt)//4)
                    return chat_completion.choices[0].message.content
                    
            except Exception as e:
                last_error = e
                err_str = str(e).lower()
                is_rate_limit = any(kw in err_str for kw in [
                    "429", "resource_exhausted", "rate_limit", "quota",
                    "too many requests", "rateLimitExceeded"
                ])
                
                if is_rate_limit and attempt < max_retries - 1:
                    wait = 15 * (2 ** attempt)  # 15s, 30s, 60s...
                    print(f"[LLM] Rate limit hit (attempt {attempt+1}/{max_retries}). Retrying in {wait}s...")
                    time.sleep(wait)
                    continue
                else:
                    # Non-rate-limit error or exhausted retries — raise so callers don't write garbage
                    print(f"[LLM] Unrecoverable error after {attempt+1} attempts: {e}")
                    raise RuntimeError(f"LLM call failed: {e}") from e
        
        raise RuntimeError(f"LLM call failed after {max_retries} retries: {last_error}")

llm_service = LLMService()
