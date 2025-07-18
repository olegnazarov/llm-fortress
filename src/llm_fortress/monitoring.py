import asyncio
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List

logger = logging.getLogger(__name__)


@dataclass
class AlertRule:
    """Alert rule configuration"""

    name: str
    condition: str  # Python expression
    threshold: float
    window_minutes: int
    enabled: bool = True
    last_triggered: datetime = None


class SecurityMonitor:
    """
    🏰 LLM Fortress - Security Monitoring & Alerting
    
    Features:
    - Real-time threat monitoring
    - Configurable alert rules
    - Email/webhook notifications
    - Performance monitoring
    """

    def __init__(self, firewall: "LLMFirewall"):
        self.firewall = firewall
        self.alert_rules: List[AlertRule] = []
        self.alert_callbacks: List[Callable] = []
        self.monitoring_active = False

        # Load default alert rules
        self._load_default_rules()

    def _load_default_rules(self):
        """Load default monitoring rules"""
        default_rules = [
            AlertRule(
                name="High Threat Rate",
                condition="threat_rate > 0.1",
                threshold=0.1,
                window_minutes=10,
            ),
            AlertRule(
                name="Multiple Blocked Requests",
                condition="blocked_requests > 10",
                threshold=10,
                window_minutes=5,
            ),
            AlertRule(
                name="Critical Threat Detected",
                condition="critical_threats > 0",
                threshold=0,
                window_minutes=1,
            ),
            AlertRule(
                name="High Error Rate",
                condition="error_rate > 0.05",
                threshold=0.05,
                window_minutes=15,
            ),
        ]

        self.alert_rules.extend(default_rules)

    async def start_monitoring(self, interval_seconds: int = 60):
        """Start continuous monitoring"""
        self.monitoring_active = True
        logger.info("Security monitoring started")

        while self.monitoring_active:
            try:
                await self._check_alert_rules()
                await asyncio.sleep(interval_seconds)
            except Exception as e:
                logger.error(f"Monitoring error: {e}")
                await asyncio.sleep(interval_seconds)

    def stop_monitoring(self):
        """Stop monitoring"""
        self.monitoring_active = False
        logger.info("Security monitoring stopped")

    async def _check_alert_rules(self):
        """Check all alert rules"""
        current_metrics = self._calculate_current_metrics()

        for rule in self.alert_rules:
            if not rule.enabled:
                continue

            # Check if rule was recently triggered
            if rule.last_triggered and datetime.now(timezone.utc) - rule.last_triggered < timedelta(
                minutes=rule.window_minutes
            ):
                continue

            # Evaluate rule condition
            if self._evaluate_rule_condition(rule, current_metrics):
                await self._trigger_alert(rule, current_metrics)
                rule.last_triggered = datetime.now(timezone.utc)

    def _calculate_current_metrics(self) -> Dict[str, float]:
        """Calculate current security metrics"""
        # Get events from the last hour
        cutoff_time = datetime.now(timezone.utc) - timedelta(hours=1)
        recent_events = [
            event
            for event in self.firewall.security_events
            if datetime.fromisoformat(event.timestamp).replace(tzinfo=timezone.utc) > cutoff_time
        ]

        total_events = len(recent_events)
        threat_events = len([e for e in recent_events if e.threat_detected])
        blocked_events = len([e for e in recent_events if e.action_taken == "BLOCKED"])
        critical_threats = len(
            [
                e
                for e in recent_events
                if e.threat_info and e.threat_info.get("severity") == "CRITICAL"
            ]
        )

        return {
            "total_requests": total_events,
            "threat_requests": threat_events,
            "blocked_requests": blocked_events,
            "critical_threats": critical_threats,
            "threat_rate": threat_events / max(total_events, 1),
            "block_rate": blocked_events / max(total_events, 1),
            "error_rate": 0.0,  # Placeholder - implement actual error tracking
        }

    def _evaluate_rule_condition(
        self, rule: AlertRule, metrics: Dict[str, float]
    ) -> bool:
        """Evaluate if rule condition is met"""
        try:
            # Create safe evaluation context
            context = {**metrics, "threshold": rule.threshold}

            # Evaluate condition
            return eval(rule.condition, {"__builtins__": {}}, context)
        except Exception as e:
            logger.error(f"Error evaluating rule {rule.name}: {e}")
            return False

    async def _trigger_alert(self, rule: AlertRule, metrics: Dict[str, float]):
        """Trigger alert for rule"""
        alert_data = {
            "rule_name": rule.name,
            "condition": rule.condition,
            "threshold": rule.threshold,
            "current_metrics": metrics,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "severity": self._determine_alert_severity(rule, metrics),
        }

        logger.warning(f"SECURITY ALERT: {rule.name} - {alert_data}")

        # Call registered alert callbacks
        for callback in self.alert_callbacks:
            try:
                await callback(alert_data)
            except Exception as e:
                logger.error(f"Alert callback error: {e}")

    def _determine_alert_severity(
        self, rule: AlertRule, metrics: Dict[str, float]
    ) -> str:
        """Determine alert severity"""
        if "critical" in rule.name.lower():
            return "CRITICAL"
        elif metrics.get("threat_rate", 0) > 0.2:
            return "HIGH"
        elif metrics.get("blocked_requests", 0) > 20:
            return "HIGH"
        else:
            return "MEDIUM"

    def add_alert_callback(self, callback: Callable[[Dict[str, Any]], None]):
        """Add alert notification callback"""
        self.alert_callbacks.append(callback)

    def add_custom_rule(self, rule: AlertRule):
        """Add custom alert rule"""
        self.alert_rules.append(rule)

    def get_monitoring_status(self) -> Dict[str, Any]:
        """Get monitoring status"""
        return {
            "active": self.monitoring_active,
            "rules_count": len(self.alert_rules),
            "enabled_rules": len([r for r in self.alert_rules if r.enabled]),
            "callbacks_registered": len(self.alert_callbacks),
            "last_check": datetime.now(timezone.utc).isoformat(),
        }
