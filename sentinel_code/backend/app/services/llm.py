from app.core.config import settings

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

    def generate_text(self, prompt: str) -> str:
        """
        Generates text using the configured LLM and tracks tokens.
        """
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
                    timeout=30.0  # 30 second timeout
                )
                if hasattr(chat_completion, 'usage') and chat_completion.usage:
                    self.total_tokens_used += getattr(chat_completion.usage, 'total_tokens', len(prompt)//4)
                return chat_completion.choices[0].message.content
                
        except Exception as e:
            print(f"LLM service error: {e}")
            return f"LLM_ERROR: {str(e)}"

llm_service = LLMService()
