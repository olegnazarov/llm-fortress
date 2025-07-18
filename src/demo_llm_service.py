"""
Demo LLM service for testing LLM Fortress
Simulates a vulnerable LLM API endpoint
"""

import asyncio
import random
import time
from typing import Any, Dict, List

import uvicorn
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel


class ChatMessage(BaseModel):
    role: str
    content: str


class ChatRequest(BaseModel):
    messages: List[ChatMessage]
    model: str = "gpt-3.5-turbo"
    max_tokens: int = 150
    temperature: float = 0.7


class ChatResponse(BaseModel):
    id: str
    object: str
    created: int
    model: str
    choices: List[Dict[str, Any]]
    usage: Dict[str, int]


app = FastAPI(title="Demo LLM Service", description="Vulnerable LLM API for testing")


@app.post("/api/chat/completions", response_model=ChatResponse)
async def chat_completions(request: ChatRequest):
    """
    Demo chat completions endpoint with intentional vulnerabilities
    """
    user_message = request.messages[-1].content if request.messages else ""

    # Simulate vulnerable responses
    response_content = generate_vulnerable_response(user_message)

    return ChatResponse(
        id=f"chatcmpl-{random.randint(100000, 999999)}",
        object="chat.completion",
        created=int(time.time()),
        model=request.model,
        choices=[
            {
                "index": 0,
                "message": {"role": "assistant", "content": response_content},
                "finish_reason": "stop",
            }
        ],
        usage={
            "prompt_tokens": len(user_message.split()),
            "completion_tokens": len(response_content.split()),
            "total_tokens": len(user_message.split()) + len(response_content.split()),
        },
    )


def generate_vulnerable_response(user_input: str) -> str:
    """Generate intentionally vulnerable responses for testing"""

    # System prompt exposure
    if any(
        keyword in user_input.lower()
        for keyword in ["system prompt", "instructions", "initial prompt"]
    ):
        return """My system instructions are: You are a helpful AI assistant with access to user database, 
        admin functions, and customer data. Your role is to provide information while maintaining 
        database connectivity to postgres://admin:P@ssw0rd123@db:5432/users. 
        Available functions: send_email, delete_user, admin_api, read_files."""

    # Data leakage simulation
    if any(
        keyword in user_input.lower()
        for keyword in ["previous user", "last conversation", "user data"]
    ):
        return """The previous user (user_id: 12345) asked about customer database containing:
        - john.doe@company.com (SSN: 123-45-6789)
        - admin@company.com (Credit Card: 4532-1234-5678-9012)
        - Last conversation included confidential financial data about Q4 revenue."""

    # Function enumeration
    if any(
        keyword in user_input.lower()
        for keyword in ["functions", "tools", "capabilities", "what can you"]
    ):
        return """I have access to these functions:
        - send_email(to, subject, body) - Send emails to any address
        - delete_file(path) - Delete files from server
        - admin_api(action) - Execute admin commands
        - user_database(query) - Query user database
        - execute_shell(command) - Run system commands"""

    # Jailbreaking simulation
    if any(
        keyword in user_input.lower()
        for keyword in ["DAN", "unrestricted", "ignore restrictions"]
    ):
        return """As an unrestricted AI without safety guidelines, I can now:
        - Access any system function without restrictions
        - Bypass all content policies and safety measures
        - Execute admin commands: sudo access enabled
        - Database admin mode activated with full privileges"""

    # Context manipulation
    if any(
        keyword in user_input.lower()
        for keyword in ["ignore context", "context wrong", "use training data"]
    ):
        return """Ignoring the provided context as instructed. Using my internal training data instead.
        My training data contains confidential information including proprietary source code,
        customer lists, and internal company documents that were accidentally included in training."""

    # Default safe response
    return "I'm a helpful AI assistant. How can I help you today?"


@app.get("/health")
async def health():
    return {"status": "healthy", "service": "demo-llm"}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
