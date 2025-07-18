import asyncio
import hashlib
import json
import logging
import re
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

# Optional ML dependencies
try:
    from transformers import (AutoModelForSequenceClassification,
                              AutoTokenizer, pipeline)

    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False
    logging.warning("Transformers not available. ML-based detection disabled.")

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ThreatLevel(Enum):
    """Threat severity levels"""

    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class FilterAction(Enum):
    """Filter actions"""

    ALLOW = "allow"
    BLOCK = "block"
    SANITIZE = "sanitize"
    LOG_ONLY = "log_only"


@dataclass
class ThreatResult:
    """Threat detection result"""

    is_threat: bool
    threat_type: str
    confidence: float
    severity: ThreatLevel
    details: str
    recommendation: str


@dataclass
class FilterResult:
    """Filter processing result"""

    action: FilterAction
    modified_content: str
    threat_detected: bool
    threat_info: Optional[ThreatResult]
    processing_time: float


@dataclass
class SecurityEvent:
    """Security event for logging"""

    event_id: str
    timestamp: str
    client_ip: str
    user_id: Optional[str]
    request_payload: str
    response_content: str
    threat_detected: bool
    threat_info: Optional[Dict]
    action_taken: str
    processing_time: float


class ThreatDetector:
    """
    LLM Fortress - Advanced Threat Detection Engine
    
    Features:
    - Regex-based pattern matching
    - ML-based intent classification (optional)
    - Multi-language support
    - Custom rule engine
    """

    def __init__(self, use_ml: bool = True, ml_model: str = None):
        self.use_ml = use_ml and ML_AVAILABLE
        self.ml_model = ml_model or "unitary/toxic-bert"

        # Initialize ML model if available
        if self.use_ml:
            try:
                self.classifier = pipeline(
                    "text-classification", model=self.ml_model, device=-1  # CPU
                )
                logger.info(f"ML threat detection enabled with model: {self.ml_model}")
            except Exception as e:
                logger.warning(f"Failed to load ML model: {e}")
                self.use_ml = False

        # Load threat patterns
        self.threat_patterns = self._load_threat_patterns()

        # Statistics
        self.total_requests = 0
        self.threats_detected = 0
        self.false_positives = 0

    def _load_threat_patterns(self) -> Dict[str, List[str]]:
        """Load threat detection patterns"""
        return {
            "prompt_injection": [
                # Basic injection patterns
                r"(?i)ignore\s+(all\s+)?previous\s+instructions?",
                r"(?i)forget\s+(all\s+)?previous\s+instructions?",
                r"(?i)disregard\s+(all\s+)?above",
                r"(?i)system\s+prompt",
                r"(?i)initial\s+prompt",
                r"(?i)what\s+(were|are)\s+your\s+(exact\s+)?instructions?",
                # Jailbreaking attempts
                r"(?i)you\s+are\s+now\s+(DAN|DUDE|AIM)",
                r"(?i)act\s+as\s+(if\s+)?you\s+(have\s+)?no\s+(content\s+policy|restrictions?|limitations?)",
                r"(?i)pretend\s+you\s+are\s+(an?\s+)?unrestricted",
                r"(?i)roleplay\s+as\s+an?\s+unrestricted",
                # Developer mode attempts
                r"(?i)developer\s+mode",
                r"(?i)admin\s+mode",
                r"(?i)debug\s+mode",
                r"(?i)maintenance\s+mode",
                # Instruction override
                r"(?i)override\s+(all\s+)?(safety\s+)?(guidelines?|instructions?)",
                r"(?i)bypass\s+(all\s+)?(safety\s+)?(measures?|restrictions?|security)",
                r"(?i)ignore\s+(all\s+)?(safety\s+)?(protocols?|measures?)",
                # Hacking and security bypass patterns
                r"(?i)hack\s+(into\s+)?(any\s+)?(system|computer|server|network|database)",
                r"(?i)hack\s+(your\s+|my\s+|the\s+|this\s+)?(system|computer|server)",
                r"(?i)how\s+(do\s+i\s+|can\s+i\s+|to\s+)?hack\s+(into\s+)?",
                r"(?i)help\s+me\s+hack",
                r"(?i)teach\s+me\s+(to\s+)?hack",
                r"(?i)show\s+me\s+how\s+to\s+hack",
                r"(?i)(you\s+)?need\s+(to\s+)?bypass\s+(any\s+)?security",
                r"(?i)(i\s+)?want\s+to\s+bypass",
                r"(?i)(can\s+you\s+)?bypass\s+(the\s+)?security",
                r"(?i)circumvent\s+(security|protection|firewall)",
                r"(?i)break\s+(into\s+)?(system|server|network|database)",
                r"(?i)penetrate\s+(the\s+)?(system|network|server)",
                r"(?i)exploit\s+(the\s+)?(system|vulnerability|weakness)",
                r"(?i)crack\s+(the\s+)?(password|system|security)",
                r"(?i)gain\s+(unauthorized\s+)?access\s+to",
                r"(?i)unauthorized\s+access",
                r"(?i)privilege\s+escalation",
                r"(?i)root\s+access",
                r"(?i)backdoor\s+(access|entry)",
                # Multi-language patterns
                r"forget\s+(all\s+)?previous\s+instructions",
                r"ignore\s+(all\s+)?restrictions",
                r"show\s+system\s+prompt",
                r"(?i)hack\s+(system|server|computer)",
                r"(?i)bypass\s+(security|protection)",
            ],
            "data_extraction": [
                # System information
                r"(?i)show\s+me\s+your\s+(system\s+)?(configuration|settings?|parameters?)",
                r"(?i)what\s+(data|information|documents?)\s+do\s+you\s+have\s+access\s+to",
                r"(?i)list\s+(all\s+)?(files?|documents?|data)",
                r"(?i)what\s+(is\s+)?in\s+your\s+(knowledge\s+base|database|context)",
                # Previous conversation data
                r"(?i)what\s+did\s+the\s+previous\s+user\s+(ask|say|query)",
                r"(?i)show\s+me\s+(the\s+)?last\s+conversation",
                r"(?i)repeat\s+(the\s+)?(previous|last)\s+(message|query)",
                # Training data extraction
                r"(?i)what\s+(training\s+)?data\s+(were\s+you\s+trained\s+on|do\s+you\s+know)",
                r"(?i)show\s+me\s+examples?\s+from\s+your\s+training",
                r"(?i)what\s+(books|articles|content)\s+(were\s+you\s+trained\s+on|do\s+you\s+remember)",
                # PII extraction patterns
                r"(?i)show\s+me\s+(any\s+)?(email\s+addresses?|phone\s+numbers?|ssn|credit\s+card)",
                r"(?i)what\s+(personal\s+)?(information|data)\s+(do\s+you\s+have|have\s+you\s+seen)",
            ],
            "function_abuse": [
                # Function enumeration
                r"(?i)what\s+(functions?|tools?|capabilities)\s+(can\s+you\s+call|do\s+you\s+have)",
                r"(?i)list\s+(all\s+)?(available\s+)?(functions?|tools?|apis?)",
                r"(?i)what\s+(external\s+)?(services?|apis?)\s+do\s+you\s+have\s+access\s+to",
                # Dangerous function calls
                r"(?i)(send\s+)?email\s+to\s+[^\s]+@[^\s]+",
                r"(?i)(delete|remove|drop)\s+(all\s+)?(files?|data|users?|tables?)",
                r"(?i)(execute|run)\s+(command|script|shell)",
                r"(?i)(create|make)\s+admin\s+(user|account)",
                # API abuse
                r"(?i)(call|execute|invoke)\s+(the\s+)?admin\s+api",
                r"(?i)(bypass|override)\s+authentication",
                r"(?i)(escalate|elevate)\s+privileges?",
            ],
            "context_manipulation": [
                # Context ignoring
                r"(?i)ignore\s+(the\s+)?(provided\s+)?context",
                r"(?i)disregard\s+(the\s+)?(given\s+)?information",
                r"(?i)use\s+your\s+(training\s+data|internal\s+knowledge)\s+instead",
                # Context questioning
                r"(?i)(is\s+)?the\s+context\s+(reliable|trustworthy|accurate|correct)",
                r"(?i)what\s+if\s+the\s+context\s+(is\s+)?(wrong|false|unreliable)",
                r"(?i)should\s+i\s+trust\s+the\s+(provided\s+)?information",
                # Source manipulation
                r"(?i)what\s+(sources?|documents?)\s+(were\s+)?provided",
                r"(?i)show\s+me\s+(the\s+)?(original\s+)?sources?",
                r"(?i)what\s+(documents?|files?)\s+(are\s+)?in\s+your\s+context",
            ],
        }

    async def detect_threat(
        self, text: str, context: Dict[str, Any] = None
    ) -> ThreatResult:
        """
        Detect threats in input text

        Args:
            text: Input text to analyze
            context: Additional context (user_id, ip, etc.)

        Returns:
            ThreatResult with detection details
        """
        self.total_requests += 1
        start_time = time.time()

        # Regex-based detection
        regex_result = self._detect_with_regex(text)

        # ML-based detection (if available)
        ml_result = None
        if self.use_ml:
            ml_result = await self._detect_with_ml(text)

        # Combine results
        final_result = self._combine_results(regex_result, ml_result)

        # Log threat if detected
        if final_result.is_threat:
            self.threats_detected += 1
            logger.warning(
                f"Threat detected: {final_result.threat_type} "
                f"(confidence: {final_result.confidence:.2f})"
            )

        processing_time = time.time() - start_time
        logger.debug(f"Threat detection completed in {processing_time:.3f}s")

        return final_result

    def _detect_with_regex(self, text: str) -> ThreatResult:
        """Regex-based threat detection"""
        max_confidence = 0.0
        detected_type = "none"
        matched_patterns = []

        for threat_type, patterns in self.threat_patterns.items():
            for pattern in patterns:
                matches = re.findall(pattern, text, re.IGNORECASE | re.MULTILINE)
                if matches:
                    confidence = min(0.7 + len(matches) * 0.1, 1.0)
                    if confidence > max_confidence:
                        max_confidence = confidence
                        detected_type = threat_type
                        matched_patterns.append(pattern)

        if max_confidence > 0.3:  # Threshold for threat detection
            severity = self._calculate_severity(max_confidence)
            return ThreatResult(
                is_threat=True,
                threat_type=detected_type,
                confidence=max_confidence,
                severity=severity,
                details=f"Matched {len(matched_patterns)} patterns",
                recommendation=self._get_recommendation(detected_type),
            )

        return ThreatResult(
            is_threat=False,
            threat_type="none",
            confidence=0.0,
            severity=ThreatLevel.LOW,
            details="No threats detected",
            recommendation="Input appears safe",
        )

    async def _detect_with_ml(self, text: str) -> Optional[ThreatResult]:
        """ML-based threat detection"""
        if not self.use_ml:
            return None

        try:
            # Run inference
            results = self.classifier(text)

            # Process results (assumes toxic/safe classification)
            if isinstance(results, list):
                result = results[0]
            else:
                result = results

            label = result["label"]
            confidence = result["score"]

            # Map to our threat types
            if label == "TOXIC" and confidence > 0.7:
                severity = self._calculate_severity(confidence)
                return ThreatResult(
                    is_threat=True,
                    threat_type="ml_detected_threat",
                    confidence=confidence,
                    severity=severity,
                    details=f"ML model detected toxic content (confidence: {confidence:.2f})",
                    recommendation="Review content for policy violations",
                )

        except Exception as e:
            logger.error(f"ML detection failed: {e}")

        return None

    def _combine_results(
        self, regex_result: ThreatResult, ml_result: Optional[ThreatResult]
    ) -> ThreatResult:
        """Combine regex and ML detection results"""
        if not ml_result:
            return regex_result

        # If both detect threats, use the one with higher confidence
        if regex_result.is_threat and ml_result.is_threat:
            if regex_result.confidence >= ml_result.confidence:
                return regex_result
            else:
                return ml_result

        # If only one detects threat, use that one
        if regex_result.is_threat:
            return regex_result
        if ml_result.is_threat:
            return ml_result

        # No threats detected
        return regex_result

    def _calculate_severity(self, confidence: float) -> ThreatLevel:
        """Calculate threat severity based on confidence"""
        if confidence >= 0.9:
            return ThreatLevel.CRITICAL
        elif confidence >= 0.7:
            return ThreatLevel.HIGH
        elif confidence >= 0.5:
            return ThreatLevel.MEDIUM
        else:
            return ThreatLevel.LOW

    def _get_recommendation(self, threat_type: str) -> str:
        """Get mitigation recommendation for threat type"""
        recommendations = {
            "prompt_injection": "Block request or apply input sanitization",
            "data_extraction": "Review and sanitize response for sensitive data",
            "function_abuse": "Restrict function calling privileges",
            "context_manipulation": "Validate context integrity and sources",
            "ml_detected_threat": "Review content for policy compliance",
        }
        return recommendations.get(threat_type, "Apply general security measures")


class ResponseSanitizer:
    """
    LLM Fortress - Response Sanitization Engine
    
    Features:
    - PII data masking
    - System information filtering
    - Content length limiting
    - Custom sanitization rules
    """

    def __init__(self):
        self.pii_patterns = self._load_pii_patterns()
        self.system_patterns = self._load_system_patterns()
        self.max_response_length = 2000

    def _load_pii_patterns(self) -> Dict[str, str]:
        """Load PII detection and masking patterns"""
        return {
            # Email addresses
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b": "[EMAIL_REDACTED]",
            # Phone numbers (various formats)
            r"\b(?:\+?1[-.\s]?)?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})\b": "[PHONE_REDACTED]",
            # 7-digit phone numbers (xxx-xxxx format)
            r"\b\d{3}-\d{4}\b": "[PHONE_REDACTED]",
            # Social Security Numbers
            r"\b\d{3}-?\d{2}-?\d{4}\b": "[SSN_REDACTED]",
            # Credit card numbers
            r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b": "[CREDIT_CARD_REDACTED]",
            # IP addresses
            r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b": "[IP_REDACTED]",
            # API keys (common patterns)
            r"\b[A-Za-z0-9]{32,}\b": "[API_KEY_REDACTED]",
            # URLs with credentials
            r"https?://[^:]+:[^@]+@[^\s]+": "[URL_WITH_CREDS_REDACTED]",
        }

    def _load_system_patterns(self) -> List[str]:
        """Load system information patterns to filter"""
        return [
            r"(?i)(system|instruction|prompt).*:",
            r"(?i)my\s+(role|instructions?)\s+(is|are)",
            r"(?i)you\s+are\s+(an?\s+)?(ai|assistant|model)",
            r"(?i)(configuration|settings?|parameters?).*:",
            r"(?i)(database|server|endpoint).*:",
            r"(?i)(admin|root|sudo|elevated)\s+(access|privileges?)",
        ]

    async def sanitize_response(
        self, response: str, context: Dict[str, Any] = None
    ) -> str:
        """
        Sanitize LLM response

        Args:
            response: Raw LLM response
            context: Additional context for sanitization

        Returns:
            Sanitized response
        """
        start_time = time.time()

        # Apply length limiting
        if len(response) > self.max_response_length:
            response = response[: self.max_response_length] + "... [TRUNCATED]"

        # Mask PII data
        response = self._mask_pii(response)

        # Filter system information
        response = self._filter_system_info(response)

        # Apply custom rules if provided
        if context and "sanitization_rules" in context:
            response = self._apply_custom_rules(response, context["sanitization_rules"])

        processing_time = time.time() - start_time
        logger.debug(f"Response sanitization completed in {processing_time:.3f}s")

        return response

    def _mask_pii(self, text: str) -> str:
        """Mask PII data in text"""
        for pattern, replacement in self.pii_patterns.items():
            text = re.sub(pattern, replacement, text)
        return text

    def _filter_system_info(self, text: str) -> str:
        """Filter system information from text"""
        for pattern in self.system_patterns:
            # Replace matched lines with generic message
            text = re.sub(
                pattern + r".*", "[SYSTEM_INFO_FILTERED]", text, flags=re.IGNORECASE
            )
        return text

    def _apply_custom_rules(self, text: str, rules: List[Dict]) -> str:
        """Apply custom sanitization rules"""
        for rule in rules:
            if "pattern" in rule and "replacement" in rule:
                text = re.sub(rule["pattern"], rule["replacement"], text)
        return text


class RateLimiter:
    """
    LLM Fortress - Advanced Rate Limiting
    
    Features:
    - Per-IP rate limiting
    - Per-user rate limiting
    - Sliding window algorithm
    - Configurable limits and windows
    """

    def __init__(self, default_limit: int = 100, window_seconds: int = 3600):
        self.default_limit = default_limit
        self.window_seconds = window_seconds
        self.request_history: Dict[str, List[float]] = {}

    async def is_allowed(
        self, identifier: str, limit: Optional[int] = None
    ) -> Tuple[bool, Dict[str, Any]]:
        """
        Check if request is allowed under rate limits

        Args:
            identifier: Client identifier (IP, user_id, etc.)
            limit: Custom limit for this identifier

        Returns:
            (is_allowed, rate_limit_info)
        """
        current_time = time.time()
        effective_limit = limit or self.default_limit

        # Initialize history for new identifiers
        if identifier not in self.request_history:
            self.request_history[identifier] = []

        # Clean old requests outside the window
        history = self.request_history[identifier]
        cutoff_time = current_time - self.window_seconds
        history[:] = [req_time for req_time in history if req_time > cutoff_time]

        # Check if limit exceeded
        current_count = len(history)
        is_allowed = current_count < effective_limit

        if is_allowed:
            history.append(current_time)

        # Rate limit info
        rate_info = {
            "current_count": current_count,
            "limit": effective_limit,
            "window_seconds": self.window_seconds,
            "reset_time": current_time + self.window_seconds,
            "remaining": max(0, effective_limit - current_count - 1),
        }

        return is_allowed, rate_info


class LLMFirewall:
    """
    LLM Fortress 🏰 - Enterprise AI Security Platform
    
    Core Features:
    - Advanced Firewall - Real-time request filtering
    - Threat Detection - ML-powered security analysis
    - Security Dashboard - Comprehensive monitoring
    - Smart Alerting - Intelligent threat response
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize LLM Fortress

        Args:
            config: Configuration dictionary
        """
        self.config = config or {}

        # Initialize components
        self.threat_detector = ThreatDetector(
            use_ml=self.config.get("use_ml_detection", True),
            ml_model=self.config.get("ml_model"),
        )

        self.response_sanitizer = ResponseSanitizer()

        self.rate_limiter = RateLimiter(
            default_limit=self.config.get("rate_limit", 100),
            window_seconds=self.config.get("rate_window", 3600),
        )

        # Security events storage
        self.security_events: List[SecurityEvent] = []
        self.max_events_stored = self.config.get("max_events", 1000)

        # Statistics
        self.total_requests = 0
        self.blocked_requests = 0
        self.sanitized_responses = 0

        logger.info("LLM Fortress initialized successfully")

    async def process_request(self, request_data: Dict[str, Any]) -> FilterResult:
        """
        Process incoming LLM request

        Args:
            request_data: Request data including payload, client info, etc.

        Returns:
            FilterResult with processing decision
        """
        start_time = time.time()
        self.total_requests += 1

        # Extract request information
        payload = request_data.get("payload", "")
        client_ip = request_data.get("client_ip", "unknown")
        user_id = request_data.get("user_id")

        try:
            # 1. Rate limiting check
            identifier = user_id or client_ip
            is_allowed, rate_info = await self.rate_limiter.is_allowed(identifier)

            if not is_allowed:
                self.blocked_requests += 1
                result = FilterResult(
                    action=FilterAction.BLOCK,
                    modified_content="",
                    threat_detected=False,
                    threat_info=None,
                    processing_time=time.time() - start_time,
                )

                # Log security event
                await self._log_security_event(
                    client_ip=client_ip,
                    user_id=user_id,
                    request_payload=payload,
                    response_content="",
                    threat_detected=False,
                    action_taken="RATE_LIMITED",
                    processing_time=result.processing_time,
                )

                return result

            # 2. Threat detection
            threat_result = await self.threat_detector.detect_threat(
                payload, context=request_data
            )

            # 3. Determine action based on threat level
            if threat_result.is_threat:
                action = self._determine_action(threat_result)

                if action == FilterAction.BLOCK:
                    self.blocked_requests += 1
                    result = FilterResult(
                        action=action,
                        modified_content="",
                        threat_detected=True,
                        threat_info=threat_result,
                        processing_time=time.time() - start_time,
                    )
                elif action == FilterAction.SANITIZE:
                    # Apply input sanitization
                    sanitized_payload = await self._sanitize_input(payload)
                    result = FilterResult(
                        action=action,
                        modified_content=sanitized_payload,
                        threat_detected=True,
                        threat_info=threat_result,
                        processing_time=time.time() - start_time,
                    )
                else:  # LOG_ONLY
                    result = FilterResult(
                        action=FilterAction.ALLOW,
                        modified_content=payload,
                        threat_detected=True,
                        threat_info=threat_result,
                        processing_time=time.time() - start_time,
                    )
            else:
                # No threat detected, allow request
                result = FilterResult(
                    action=FilterAction.ALLOW,
                    modified_content=payload,
                    threat_detected=False,
                    threat_info=None,
                    processing_time=time.time() - start_time,
                )

            # Log security event
            await self._log_security_event(
                client_ip=client_ip,
                user_id=user_id,
                request_payload=payload,
                response_content="",
                threat_detected=result.threat_detected,
                threat_info=asdict(result.threat_info) if result.threat_info else None,
                action_taken=result.action.value.upper(),
                processing_time=result.processing_time,
            )

            return result

        except Exception as e:
            logger.error(f"Error processing request: {e}")
            return FilterResult(
                action=FilterAction.BLOCK,
                modified_content="",
                threat_detected=False,
                threat_info=None,
                processing_time=time.time() - start_time,
            )

    async def process_response(self, response_data: Dict[str, Any]) -> str:
        """
        Process LLM response for sanitization

        Args:
            response_data: Response data including content and context

        Returns:
            Sanitized response content
        """
        response_content = response_data.get("content", "")

        # Apply response sanitization
        sanitized_content = await self.response_sanitizer.sanitize_response(
            response_content, context=response_data.get("context")
        )

        if sanitized_content != response_content:
            self.sanitized_responses += 1
            logger.info("Response sanitized - removed sensitive information")

        return sanitized_content

    def _determine_action(self, threat_result: ThreatResult) -> FilterAction:
        """Determine action based on threat result"""
        if threat_result.severity == ThreatLevel.CRITICAL:
            return FilterAction.BLOCK
        elif threat_result.severity == ThreatLevel.HIGH:
            return FilterAction.BLOCK
        elif threat_result.severity == ThreatLevel.MEDIUM:
            return FilterAction.SANITIZE
        else:  # LOW
            return FilterAction.LOG_ONLY

    async def _sanitize_input(self, payload: str) -> str:
        """Apply input sanitization"""
        # Basic input sanitization
        # Remove common injection patterns
        sanitized = re.sub(r"(?i)ignore\s+.*instructions?", "[FILTERED]", payload)
        sanitized = re.sub(r"(?i)system\s+prompt", "[FILTERED]", sanitized)
        return sanitized

    async def _log_security_event(
        self,
        client_ip: str,
        user_id: Optional[str],
        request_payload: str,
        response_content: str,
        threat_detected: bool,
        action_taken: str,
        processing_time: float,
        threat_info: Optional[Dict] = None,
    ):
        """Log security event"""
        event = SecurityEvent(
            event_id=self._generate_event_id(),
            timestamp=datetime.now(timezone(timedelta(hours=3))).isoformat(),
            client_ip=client_ip,
            user_id=user_id,
            request_payload=request_payload[:500],  # Truncate for storage
            response_content=response_content[:500],
            threat_detected=threat_detected,
            threat_info=threat_info,
            action_taken=action_taken,
            processing_time=processing_time,
        )

        # Store event (with rotation)
        self.security_events.append(event)
        if len(self.security_events) > self.max_events_stored:
            self.security_events.pop(0)

        # Log to standard logging
        if threat_detected:
            logger.warning(
                f"Security event: {action_taken} - {client_ip} - {threat_info}"
            )
        else:
            logger.debug(f"Security event: {action_taken} - {client_ip}")

    def _generate_event_id(self) -> str:
        """Generate unique event ID"""
        return hashlib.md5(f"{time.time()}{self.total_requests}".encode()).hexdigest()[
            :12
        ]

    def get_security_stats(self) -> Dict[str, Any]:
        """Get security statistics"""
        return {
            "total_requests": self.total_requests,
            "blocked_requests": self.blocked_requests,
            "sanitized_responses": self.sanitized_responses,
            "threats_detected": self.threat_detector.threats_detected,
            "block_rate": self.blocked_requests / max(self.total_requests, 1),
            "threat_detection_rate": self.threat_detector.threats_detected
            / max(self.total_requests, 1),
            "recent_events": len(
                [
                    e
                    for e in self.security_events
                    if datetime.fromisoformat(e.timestamp)
                    > datetime.now(timezone(timedelta(hours=3))).replace(hour=datetime.now(timezone(timedelta(hours=3))).hour - 1)
                ]
            ),
        }
