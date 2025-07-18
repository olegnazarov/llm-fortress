import asyncio
import json
import logging
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

logger = logging.getLogger(__name__)


class SecurityDashboard:
    """
    LLM Fortress 🏰 - Security Dashboard
    
    Features:
    - Real-time threat monitoring
    - Security metrics and statistics
    - Event logs and search
    - Configuration management
    """

    def __init__(self, firewall: "LLMFirewall"):
        self.firewall = firewall

    def get_dashboard_data(self) -> Dict[str, Any]:
        """Get comprehensive dashboard data"""
        # Basic statistics
        stats = self.firewall.get_security_stats()

        # Recent events
        recent_events = self._get_recent_events(hours=24)

        # Threat trends
        threat_trends = self._calculate_threat_trends()

        # Top threats
        top_threats = self._get_top_threats()

        # System health
        health_status = self._get_system_health()

        return {
            "timestamp": datetime.now(timezone(timedelta(hours=3))).isoformat(),
            "statistics": stats,
            "recent_events": recent_events,
            "threat_trends": threat_trends,
            "top_threats": top_threats,
            "system_health": health_status,
        }

    def _get_recent_events(self, hours: int = 24) -> List[Dict[str, Any]]:
        """Get recent security events"""
        cutoff_time = datetime.now(timezone(timedelta(hours=3))) - timedelta(hours=hours)

        recent_events = []
        for event in self.firewall.security_events:
            event_time = datetime.fromisoformat(event.timestamp)
            if event_time > cutoff_time:
                # Convert to dict and sanitize sensitive data
                event_dict = asdict(event)
                event_dict["request_payload"] = (
                    event_dict["request_payload"][:100] + "..."
                )
                event_dict["response_content"] = (
                    event_dict["response_content"][:100] + "..."
                )
                recent_events.append(event_dict)

        return sorted(recent_events, key=lambda x: x["timestamp"], reverse=True)

    def _calculate_threat_trends(self) -> Dict[str, List[Dict[str, Any]]]:
        """Calculate threat trends over time"""
        # Group events by hour for the last 24 hours
        hourly_data = {}
        cutoff_time = datetime.now(timezone(timedelta(hours=3))) - timedelta(hours=24)

        for event in self.firewall.security_events:
            event_time = datetime.fromisoformat(event.timestamp)
            if event_time > cutoff_time:
                hour_key = event_time.strftime("%Y-%m-%d %H:00")

                if hour_key not in hourly_data:
                    hourly_data[hour_key] = {
                        "total_requests": 0,
                        "threats_detected": 0,
                        "blocked_requests": 0,
                    }

                hourly_data[hour_key]["total_requests"] += 1
                if event.threat_detected:
                    hourly_data[hour_key]["threats_detected"] += 1
                if event.action_taken == "BLOCKED":
                    hourly_data[hour_key]["blocked_requests"] += 1

        # Convert to list format
        trends = []
        for hour, data in sorted(hourly_data.items()):
            trends.append({"hour": hour, **data})

        return {"hourly_trends": trends}

    def _get_top_threats(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get top threat types"""
        threat_counts = {}

        for event in self.firewall.security_events:
            if event.threat_detected and event.threat_info:
                threat_type = event.threat_info.get("threat_type", "unknown")
                if threat_type not in threat_counts:
                    threat_counts[threat_type] = {
                        "type": threat_type,
                        "count": 0,
                        "latest_timestamp": event.timestamp,
                    }
                threat_counts[threat_type]["count"] += 1
                threat_counts[threat_type]["latest_timestamp"] = max(
                    threat_counts[threat_type]["latest_timestamp"], event.timestamp
                )

        # Sort by count and return top threats
        top_threats = sorted(
            threat_counts.values(), key=lambda x: x["count"], reverse=True
        )[:limit]

        return top_threats

    def _get_system_health(self) -> Dict[str, Any]:
        """Get system health metrics"""
        return {
            "firewall_status": "active",
            "ml_detection_available": self.firewall.threat_detector.use_ml,
            "events_stored": len(self.firewall.security_events),
            "uptime_hours": 24,  # Placeholder - implement actual uptime tracking
            "memory_usage": "normal",  # Placeholder - implement actual monitoring
            "processing_latency_avg": 0.05,  # Placeholder
        }

    def search_events(
        self, filters: Dict[str, Any], limit: int = 100
    ) -> List[Dict[str, Any]]:
        """Search security events with filters"""
        results = []

        for event in self.firewall.security_events:
            # Apply filters
            if "start_date" in filters:
                start_date = datetime.fromisoformat(filters["start_date"])
                if datetime.fromisoformat(event.timestamp) < start_date:
                    continue

            if "end_date" in filters:
                end_date = datetime.fromisoformat(filters["end_date"])
                if datetime.fromisoformat(event.timestamp) > end_date:
                    continue

            if "threat_type" in filters:
                if (
                    not event.threat_info
                    or event.threat_info.get("threat_type") != filters["threat_type"]
                ):
                    continue

            if "client_ip" in filters:
                if event.client_ip != filters["client_ip"]:
                    continue

            if "action_taken" in filters:
                if event.action_taken != filters["action_taken"]:
                    continue

            # Add to results
            event_dict = asdict(event)
            results.append(event_dict)

            if len(results) >= limit:
                break

        return sorted(results, key=lambda x: x["timestamp"], reverse=True)
