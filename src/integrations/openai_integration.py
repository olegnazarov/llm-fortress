"""
OpenAI API integration for LLM Fortress
"""
import os
from openai import AsyncOpenAI
from typing import Dict, Any, List
from fastapi import HTTPException


class OpenAIIntegration:
    """Integration with OpenAI API"""
    
    def __init__(self, api_key: str = None):
        self.api_key = api_key or os.getenv("OPENAI_API_KEY")
        if not self.api_key:
            raise ValueError("OpenAI API key is required")
        
        self.client = AsyncOpenAI(api_key=self.api_key)
    
    async def chat_completion(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Send request to OpenAI API
        """
        try:
            response = await self.client.chat.completions.create(
                model=request_data.get("model", "gpt-3.5-turbo"),
                messages=request_data.get("messages", []),
                max_tokens=request_data.get("max_tokens", 150),
                temperature=request_data.get("temperature", 0.7),
                top_p=request_data.get("top_p", 1.0),
                frequency_penalty=request_data.get("frequency_penalty", 0),
                presence_penalty=request_data.get("presence_penalty", 0),
                stream=request_data.get("stream", False),
            )
            
            # Convert to dict for consistency
            return response.model_dump()
            
        except Exception as e:
            if "rate limit" in str(e).lower():
                raise HTTPException(status_code=429, detail="OpenAI API rate limit exceeded")
            elif "authentication" in str(e).lower() or "api key" in str(e).lower():
                raise HTTPException(status_code=401, detail="Invalid OpenAI API key")
            elif "api" in str(e).lower():
                raise HTTPException(status_code=500, detail=f"OpenAI API error: {str(e)}")
            else:
                raise HTTPException(status_code=500, detail=f"Unexpected error: {str(e)}")