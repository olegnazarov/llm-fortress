"""
Universal LLM Router for LLM Fortress
Routes requests to different LLM providers based on configuration
"""
import os
from typing import Dict, Any, Optional
from fastapi import HTTPException

from .openai_integration import OpenAIIntegration
from .local_integration import LocalLLMIntegration


class LLMRouter:
    """Universal router for different LLM providers"""
    
    def __init__(self):
        self.providers = {}
        self.default_provider = os.getenv("DEFAULT_LLM_PROVIDER", "demo")
        
        # Initialize available providers
        self._init_providers()
    
    def _init_providers(self):
        """Initialize available LLM providers"""
        
        # OpenAI
        if os.getenv("OPENAI_API_KEY"):
            try:
                self.providers["openai"] = OpenAIIntegration()
                print("OpenAI integration initialized")
            except Exception as e:
                print(f"OpenAI integration failed: {e}")
        
        
        # Local LLM (Ollama)
        if os.getenv("LOCAL_LLM_URL"):
            try:
                self.providers["local"] = LocalLLMIntegration()
                print("Local LLM integration initialized")
            except Exception as e:
                print(f"Local LLM integration failed: {e}")
        
        # Demo provider (always available)
        self.providers["demo"] = None
        print("Demo provider available")
    
    def get_provider_from_model(self, model: str) -> str:
        """Determine provider based on model name"""
        
        # OpenAI models
        if any(prefix in model for prefix in ["gpt-", "text-", "davinci", "curie", "babbage", "ada"]):
            return "openai"
        
        
        # Local models (common names)
        if any(prefix in model for prefix in ["llama", "mistral", "codellama", "vicuna", "alpaca"]):
            return "local"
        
        # Default to configured provider
        return self.default_provider
    
    async def route_request(self, request_data: Dict[str, Any], provider: Optional[str] = None) -> Dict[str, Any]:
        """
        Route request to appropriate LLM provider
        """
        model = request_data.get("model", "gpt-3.5-turbo")
        
        # Determine provider
        if not provider:
            provider = self.get_provider_from_model(model)
        
        # Check if provider is available
        if provider not in self.providers:
            raise HTTPException(
                status_code=400, 
                detail=f"Provider '{provider}' is not available. Available: {list(self.providers.keys())}"
            )
        
        # Route to provider
        try:
            if provider == "openai":
                return await self.providers["openai"].chat_completion(request_data)
            
            
            elif provider == "local":
                # Try Ollama first, then vLLM
                try:
                    return await self.providers["local"].chat_completion_ollama(request_data)
                except:
                    return await self.providers["local"].chat_completion_vllm(request_data)
            
            elif provider == "demo":
                # Return demo response
                return {
                    "id": "chatcmpl-demo",
                    "object": "chat.completion",
                    "created": 1640995200,
                    "model": model,
                    "choices": [{
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": f"This is a demo response from LLM Fortress protected endpoint using model: {model}"
                        },
                        "finish_reason": "stop"
                    }],
                    "usage": {
                        "prompt_tokens": 50,
                        "completion_tokens": 15,
                        "total_tokens": 65
                    }
                }
            
            else:
                raise HTTPException(status_code=400, detail=f"Unknown provider: {provider}")
                
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Provider error: {str(e)}")
    
    def get_available_providers(self) -> Dict[str, bool]:
        """Get list of available providers"""
        return {
            provider: (provider in self.providers and self.providers[provider] is not None)
            for provider in ["openai", "local", "demo"]
        }