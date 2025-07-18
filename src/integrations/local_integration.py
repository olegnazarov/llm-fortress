"""
Local LLM integration for LLM Fortress (Ollama, vLLM, etc.)
"""
import os
import httpx
from typing import Dict, Any, List
from fastapi import HTTPException


class LocalLLMIntegration:
    """Integration with local LLM services (Ollama, vLLM, etc.)"""
    
    def __init__(self, base_url: str = None):
        self.base_url = base_url or os.getenv("LOCAL_LLM_URL", "http://localhost:11434")
        self.client = httpx.AsyncClient(timeout=300.0)  # 5 minutes timeout
    
    async def chat_completion_ollama(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Send request to Ollama API
        """
        try:
            messages = request_data.get("messages", [])
            
            # Format for Ollama API
            ollama_request = {
                "model": request_data.get("model", "llama2"),
                "messages": messages,
                "stream": False,
                "options": {
                    "temperature": request_data.get("temperature", 0.7),
                    "top_p": request_data.get("top_p", 1.0),
                    "num_predict": request_data.get("max_tokens", 150)
                }
            }
            
            response = await self.client.post(
                f"{self.base_url}/api/chat",
                json=ollama_request
            )
            
            if response.status_code != 200:
                raise HTTPException(status_code=response.status_code, 
                                  detail=f"Ollama API error: {response.text}")
            
            ollama_response = response.json()
            
            # Convert Ollama response to OpenAI format
            openai_response = {
                "id": f"chatcmpl-{ollama_response.get('created_at', '')}",
                "object": "chat.completion",
                "created": 1640995200,  # Placeholder timestamp
                "model": request_data.get("model", "llama2"),
                "choices": [{
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": ollama_response.get("message", {}).get("content", "")
                    },
                    "finish_reason": "stop"
                }],
                "usage": {
                    "prompt_tokens": ollama_response.get("prompt_eval_count", 0),
                    "completion_tokens": ollama_response.get("eval_count", 0),
                    "total_tokens": ollama_response.get("prompt_eval_count", 0) + ollama_response.get("eval_count", 0)
                }
            }
            
            return openai_response
            
        except httpx.ConnectError:
            raise HTTPException(status_code=503, detail="Cannot connect to local LLM service")
        except httpx.TimeoutException:
            raise HTTPException(status_code=504, detail="Local LLM service timeout")
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Local LLM error: {str(e)}")
    
    async def chat_completion_vllm(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Send request to vLLM API (OpenAI compatible)
        """
        try:
            response = await self.client.post(
                f"{self.base_url}/v1/chat/completions",
                json=request_data
            )
            
            if response.status_code != 200:
                raise HTTPException(status_code=response.status_code, 
                                  detail=f"vLLM API error: {response.text}")
            
            return response.json()
            
        except httpx.ConnectError:
            raise HTTPException(status_code=503, detail="Cannot connect to vLLM service")
        except httpx.TimeoutException:
            raise HTTPException(status_code=504, detail="vLLM service timeout")
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"vLLM error: {str(e)}")
    
    async def __aenter__(self):
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.client.aclose()