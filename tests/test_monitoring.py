"""
Tests for monitoring and alerting functionality
"""

import asyncio
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, Mock

import pytest

from llm_fortress.firewall import LLMFirewall, SecurityEvent
from llm_fortress.monitoring import AlertRule, SecurityMonitor


class TestSecurityMonitor:
    """Test security monitoring functionality"""

    @pytest.fixture
    def firewall(self):
        return LLMFirewall({"use_ml_detection": False})

    @pytest.fixture
    def monitor(self, firewall):
        return SecurityMonitor(firewall)

    def test_default_rules_loaded(self, monitor):
        """Test that default alert rules are loaded"""
        assert len(monitor.alert_rules) > 0
        rule_names = [rule.name for rule in monitor.alert_rules]
        assert "High Threat Rate" in rule_names
        assert "Critical Threat Detected" in rule_names

    def test_add_custom_rule(self, monitor):
        """Test adding custom alert rule"""
        initial_count = len(monitor.alert_rules)

        custom_rule = AlertRule(
            name="Test Rule",
            condition="blocked_requests > 5",
            threshold=5,
            window_minutes=5,
        )

        monitor.add_custom_rule(custom_rule)
        assert len(monitor.alert_rules) == initial_count + 1
        assert custom_rule in monitor.alert_rules

    def test_calculate_metrics(self, monitor, firewall):
        """Test metrics calculation"""
        # Add some test events
        test_events = [
            SecurityEvent(
                event_id="test1",
                timestamp=(datetime.now() - timedelta(minutes=5)).isoformat(),
                client_ip="192.168.1.1",
                user_id="user1",
                request_payload="test",
                response_content="response",
                threat_detected=True,
                threat_info={"threat_type": "prompt_injection", "severity": "HIGH"},
                action_taken="BLOCKED",
                processing_time=0.1,
            ),
            SecurityEvent(
                event_id="test2",
                timestamp=(datetime.now() - timedelta(minutes=3)).isoformat(),
                client_ip="192.168.1.2",
                user_id="user2",
                request_payload="safe request",
                response_content="safe response",
                threat_detected=False,
                threat_info=None,
                action_taken="ALLOWED",
                processing_time=0.05,
            ),
        ]

        firewall.security_events.extend(test_events)

        metrics = monitor._calculate_current_metrics()

        assert metrics["total_requests"] == 2
        assert metrics["threat_requests"] == 1
        assert metrics["blocked_requests"] == 1
        assert metrics["threat_rate"] == 0.5

    def test_rule_evaluation(self, monitor):
        """Test alert rule evaluation"""
        rule = AlertRule(
            name="Test Rule",
            condition="threat_rate > 0.3",
            threshold=0.3,
            window_minutes=10,
        )

        # Test condition that should trigger
        metrics = {"threat_rate": 0.5, "blocked_requests": 2}
        assert monitor._evaluate_rule_condition(rule, metrics) == True

        # Test condition that should not trigger
        metrics = {"threat_rate": 0.1, "blocked_requests": 1}
        assert monitor._evaluate_rule_condition(rule, metrics) == False

    @pytest.mark.asyncio
    async def test_alert_callback(self, monitor):
        """Test alert callback functionality"""
        callback_called = False
        alert_data_received = None

        async def test_callback(alert_data):
            nonlocal callback_called, alert_data_received
            callback_called = True
            alert_data_received = alert_data

        monitor.add_alert_callback(test_callback)

        # Simulate alert trigger
        rule = AlertRule(
            name="Test Alert",
            condition="threat_rate > 0.8",
            threshold=0.8,
            window_minutes=5,
        )

        metrics = {"threat_rate": 0.9, "blocked_requests": 10}
        await monitor._trigger_alert(rule, metrics)

        assert callback_called == True
        assert alert_data_received is not None
        assert alert_data_received["rule_name"] == "Test Alert"

    def test_monitoring_status(self, monitor):
        """Test monitoring status reporting"""
        status = monitor.get_monitoring_status()

        assert "active" in status
        assert "rules_count" in status
        assert "enabled_rules" in status
        assert isinstance(status["active"], bool)
        assert isinstance(status["rules_count"], int)
