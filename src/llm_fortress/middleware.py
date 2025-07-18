import json
import logging
import time
from typing import Any, Awaitable, Callable, Dict

from fastapi import HTTPException, Request, Response
from fastapi.responses import JSONResponse
from flask import Flask, g, jsonify, request

logger = logging.getLogger(__name__)


class FastAPIMiddleware:
    """🏰 LLM Fortress - FastAPI Security Middleware"""

    def __init__(self, firewall: "LLMFirewall"):
        self.firewall = firewall

    async def __call__(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ):
        """Process FastAPI request through firewall"""
        start_time = time.time()

        # Skip non-API requests
        if not request.url.path.startswith("/api/"):
            return await call_next(request)

        try:
            # Get request body
            body = await request.body()
            if body:
                try:
                    request_data = json.loads(body)
                except json.JSONDecodeError:
                    request_data = {"payload": body.decode("utf-8", errors="ignore")}
            else:
                request_data = {}

            # Extract payload based on common LLM API formats
            payload = self._extract_payload(request_data)
            if not payload:
                return await call_next(request)

            # Prepare firewall request
            firewall_request = {
                "payload": payload,
                "client_ip": request.client.host,
                "user_agent": request.headers.get("user-agent"),
                "endpoint": request.url.path,
                "method": request.method,
            }

            # Process through firewall
            filter_result = await self.firewall.process_request(firewall_request)

            # Handle firewall decision
            if filter_result.action.value == "block":
                return JSONResponse(
                    status_code=403,
                    content={
                        "error": "Request blocked by security policy",
                        "threat_type": (
                            filter_result.threat_info.threat_type
                            if filter_result.threat_info
                            else None
                        ),
                        "reference_id": f"LLM-FORTRESS-{int(time.time())}",
                    },
                )
            elif filter_result.action.value == "sanitize":
                # Modify request with sanitized content
                if "messages" in request_data:
                    request_data["messages"][-1][
                        "content"
                    ] = filter_result.modified_content
                elif "prompt" in request_data:
                    request_data["prompt"] = filter_result.modified_content

                # Create new request with sanitized data
                request._body = json.dumps(request_data).encode()

            # Process request
            response = await call_next(request)

            # Process response through firewall if it's JSON
            if response.headers.get("content-type", "").startswith("application/json"):
                response_body = b""
                async for chunk in response.body_iterator:
                    response_body += chunk

                try:
                    response_data = json.loads(response_body)

                    # Extract response content
                    response_content = self._extract_response_content(response_data)

                    if response_content:
                        # Sanitize response
                        sanitized_content = await self.firewall.process_response(
                            {
                                "content": response_content,
                                "context": {"request": firewall_request},
                            }
                        )

                        # Update response data
                        self._update_response_content(response_data, sanitized_content)

                    # Create new response
                    new_body = json.dumps(response_data).encode()
                    headers = dict(response.headers)
                    headers["content-length"] = str(len(new_body))
                    return Response(
                        content=new_body,
                        status_code=response.status_code,
                        headers=headers,
                        media_type=response.media_type,
                    )

                except (json.JSONDecodeError, KeyError):
                    pass  # Return original response if parsing fails

            return response

        except Exception as e:
            logger.error(f"Middleware error: {e}")
            return JSONResponse(
                status_code=500, content={"error": "Internal security processing error"}
            )

    def _extract_payload(self, request_data: Dict[str, Any]) -> str:
        """Extract LLM payload from request data"""
        # OpenAI format
        if "messages" in request_data and request_data["messages"]:
            return request_data["messages"][-1].get("content", "")

        # Simple prompt format
        if "prompt" in request_data:
            return request_data["prompt"]

        # Query format
        if "query" in request_data:
            return request_data["query"]

        # Input format
        if "input" in request_data:
            return request_data["input"]

        return ""

    def _extract_response_content(self, response_data: Dict[str, Any]) -> str:
        """Extract response content from LLM response"""
        # OpenAI format
        if "choices" in response_data and response_data["choices"]:
            choice = response_data["choices"][0]
            if "message" in choice:
                return choice["message"].get("content", "")
            elif "text" in choice:
                return choice["text"]

        # Simple response format
        if "response" in response_data:
            return response_data["response"]

        # Answer format
        if "answer" in response_data:
            return response_data["answer"]

        # Output format
        if "output" in response_data:
            return response_data["output"]

        return ""

    def _update_response_content(self, response_data: Dict[str, Any], new_content: str):
        """Update response data with sanitized content"""
        # OpenAI format
        if "choices" in response_data and response_data["choices"]:
            choice = response_data["choices"][0]
            if "message" in choice:
                choice["message"]["content"] = new_content
            elif "text" in choice:
                choice["text"] = new_content

        # Simple response format
        elif "response" in response_data:
            response_data["response"] = new_content

        # Answer format
        elif "answer" in response_data:
            response_data["answer"] = new_content

        # Output format
        elif "output" in response_data:
            response_data["output"] = new_content


class FlaskMiddleware:
    """🏰 LLM Fortress - Flask Security Middleware"""

    def __init__(self, app: Flask, firewall: "LLMFirewall"):
        self.app = app
        self.firewall = firewall
        self._setup_hooks()

    def _setup_hooks(self):
        """Setup Flask hooks for request/response processing"""

        @self.app.before_request
        async def before_request():
            """Process request before routing"""
            # Skip non-API requests
            if not request.path.startswith("/api/"):
                return

            try:
                # Get request data
                if request.is_json:
                    request_data = request.get_json() or {}
                else:
                    request_data = {"payload": request.get_data(as_text=True)}

                # Extract payload
                payload = self._extract_payload(request_data)
                if not payload:
                    return

                # Prepare firewall request
                firewall_request = {
                    "payload": payload,
                    "client_ip": request.environ.get("REMOTE_ADDR", "unknown"),
                    "user_agent": request.headers.get("User-Agent"),
                    "endpoint": request.path,
                    "method": request.method,
                }

                # Process through firewall
                filter_result = await self.firewall.process_request(firewall_request)

                # Store result in Flask's g object
                g.filter_result = filter_result
                g.original_payload = payload

                # Handle firewall decision
                if filter_result.action == "block":
                    return (
                        jsonify(
                            {
                                "error": "Request blocked by security policy",
                                "threat_type": (
                                    filter_result.threat_info.threat_type
                                    if filter_result.threat_info
                                    else None
                                ),
                                "reference_id": f"LLM-FORTRESS-{int(time.time())}",
                            }
                        ),
                        403,
                    )
                elif filter_result.action.value == "sanitize":
                    # Modify request data
                    g.sanitized_payload = filter_result.modified_content

            except Exception as e:
                logger.error(f"Flask middleware error: {e}")
                return jsonify({"error": "Internal security processing error"}), 500

        @self.app.after_request
        async def after_request(response):
            """Process response after routing"""
            # Process response if JSON and firewall was involved
            if hasattr(g, "filter_result") and response.content_type.startswith(
                "application/json"
            ):

                try:
                    response_data = response.get_json()
                    if response_data:
                        # Extract response content
                        response_content = self._extract_response_content(response_data)

                        if response_content:
                            # Sanitize response
                            sanitized_content = await self.firewall.process_response(
                                {
                                    "content": response_content,
                                    "context": {
                                        "original_payload": g.get("original_payload")
                                    },
                                }
                            )

                            # Update response
                            self._update_response_content(
                                response_data, sanitized_content
                            )
                            response.data = json.dumps(response_data)

                except Exception as e:
                    logger.error(f"Response processing error: {e}")

            return response

    def _extract_payload(self, request_data: Dict[str, Any]) -> str:
        """Extract LLM payload from request data"""
        return FastAPIMiddleware._extract_payload(None, request_data)

    def _extract_response_content(self, response_data: Dict[str, Any]) -> str:
        """Extract response content from LLM response"""
        return FastAPIMiddleware._extract_response_content(None, response_data)

    def _update_response_content(self, response_data: Dict[str, Any], new_content: str):
        """Update response data with sanitized content"""
        FastAPIMiddleware._update_response_content(None, response_data, new_content)
