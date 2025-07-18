# ================================
# LLM Fortress - Enterprise AI Security Platform
# Complete Python Solution with FastAPI, Docker, and Web Dashboard
# Author: Oleg Nazarov
# GitHub: https://github.com/olegnazarov/llm-fortress
# ================================

# ================================
# File: src/llm_fortress/__init__.py
# ================================

"""
LLM Fortress - Enterprise AI Security Platform

This module provides comprehensive security for Large Language Model applications
through advanced threat detection, real-time filtering, and monitoring capabilities.

Author: Oleg Nazarov
"""

__version__ = "1.0.0"
__author__ = "Oleg Nazarov"
__email__ = "oleg@olegnazarov.com"

from .dashboard import SecurityDashboard
from .firewall import LLMFirewall, ResponseSanitizer, ThreatDetector
from .middleware import FastAPIMiddleware, FlaskMiddleware
from .monitoring import SecurityMonitor

__all__ = [
    "LLMFirewall",
    "ThreatDetector",
    "ResponseSanitizer",
    "FastAPIMiddleware",
    "FlaskMiddleware",
    "SecurityDashboard",
    "SecurityMonitor",
]
