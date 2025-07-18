import asyncio
import json
import time
from typing import Any, Dict, List, Optional

from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, Response
from pydantic import BaseModel

from .dashboard import SecurityDashboard
from .firewall import LLMFirewall, ThreatLevel
from .middleware import FastAPIMiddleware
from .monitoring import SecurityMonitor

# Simple OpenAI integration
import os
import httpx
try:
    from openai import AsyncOpenAI
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False

class SimpleOpenAIIntegration:
    def __init__(self):
        self.api_key = os.getenv("OPENAI_API_KEY")
        if self.api_key and OPENAI_AVAILABLE:
            self.client = AsyncOpenAI(api_key=self.api_key)
            self.available = True
        else:
            self.available = False
    
    async def chat_completion(self, request_data):
        if not self.available:
            return None
        
        try:
            response = await self.client.chat.completions.create(
                model=request_data.get("model", "gpt-3.5-turbo"),
                messages=request_data.get("messages", []),
                max_tokens=request_data.get("max_tokens", 150),
                temperature=request_data.get("temperature", 0.7),
            )
            return response.model_dump()
        except Exception as e:
            print(f"OpenAI error: {e}")
            return None


class SimpleOllamaIntegration:
    def __init__(self):
        # For Docker container use host.docker.internal
        default_url = "http://host.docker.internal:11434"
        self.base_url = os.getenv("OLLAMA_URL", default_url)
        self.available = self._check_availability()
    
    def _check_availability(self):
        try:
            import httpx
            response = httpx.get(f"{self.base_url}/api/tags", timeout=2)
            return response.status_code == 200
        except:
            return False
    
    async def chat_completion(self, request_data):
        if not self.available:
            return None
        
        try:
            # Convert OpenAI format to Ollama format
            messages = request_data.get("messages", [])
            
            # Create prompt from messages
            prompt = ""
            for msg in messages:
                if msg["role"] == "user":
                    prompt += f"User: {msg['content']}\n"
                elif msg["role"] == "assistant":
                    prompt += f"Assistant: {msg['content']}\n"
                elif msg["role"] == "system":
                    prompt += f"System: {msg['content']}\n"
            
            prompt += "Assistant:"
            
            # Request to Ollama
            async with httpx.AsyncClient() as client:
                ollama_request = {
                    "model": request_data.get("model", "llama3.2:latest"),
                    "prompt": prompt,
                    "stream": False,
                    "options": {
                        "temperature": request_data.get("temperature", 0.7),
                        "num_predict": request_data.get("max_tokens", 150)
                    }
                }
                
                response = await client.post(
                    f"{self.base_url}/api/generate",
                    json=ollama_request,
                    timeout=30
                )
                
                if response.status_code != 200:
                    print(f"Ollama error: {response.status_code}")
                    return None
                
                ollama_response = response.json()
                
                # Convert response to OpenAI format
                return {
                    "id": f"ollama-{int(time.time())}",
                    "object": "chat.completion",
                    "created": int(time.time()),
                    "model": request_data.get("model", "llama3.2:latest"),
                    "choices": [{
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": ollama_response.get("response", "")
                        },
                        "finish_reason": "stop" if ollama_response.get("done", False) else "length"
                    }],
                    "usage": {
                        "prompt_tokens": ollama_response.get("prompt_eval_count", 0),
                        "completion_tokens": ollama_response.get("eval_count", 0),
                        "total_tokens": ollama_response.get("prompt_eval_count", 0) + ollama_response.get("eval_count", 0)
                    }
                }
                
        except Exception as e:
            print(f"Ollama error: {e}")
            return None


# Pydantic models for API
class LLMRequest(BaseModel):
    messages: List[Dict[str, str]]
    model: str = "gpt-3.5-turbo"
    max_tokens: int = 150
    temperature: float = 0.7


class SecurityConfig(BaseModel):
    use_ml_detection: bool = True
    rate_limit: int = 100
    rate_window: int = 3600
    ml_model: Optional[str] = None


class AlertRuleConfig(BaseModel):
    name: str
    condition: str
    threshold: float
    window_minutes: int
    enabled: bool = True


# Create FastAPI app
def create_app(config: Dict[str, Any] = None) -> FastAPI:
    """Create FastAPI application with LLM Fortress integration"""

    app = FastAPI(
        title="LLM Fortress API",
        description="Enterprise AI Security Platform - Advanced Firewall, Threat Detection, Security Dashboard & Smart Alerting",
        version="1.0.0",
    )

    # CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Initialize firewall
    firewall = LLMFirewall(config or {})

    # Initialize dashboard and monitoring
    dashboard = SecurityDashboard(firewall)
    monitor = SecurityMonitor(firewall)
    
    # Initialize OpenAI integration
    openai_integration = SimpleOpenAIIntegration()
    
    # Initialize Ollama integration
    ollama_integration = SimpleOllamaIntegration()

    # Add firewall middleware
    middleware = FastAPIMiddleware(firewall)
    app.middleware("http")(middleware)

    @app.on_event("startup")
    async def startup_event():
        """Start monitoring on startup"""
        asyncio.create_task(monitor.start_monitoring())

    @app.on_event("shutdown")
    async def shutdown_event():
        """Stop monitoring on shutdown"""
        monitor.stop_monitoring()

    # API Routes
    @app.get("/")
    async def root():
        """Root endpoint"""
        return {"message": "LLM Fortress API", "version": "1.0.0"}

    @app.post("/api/v1/chat/completions")
    async def chat_completions(request: LLMRequest):
        """
        Protected LLM chat completions endpoint
        Routes to different LLM providers based on model or configuration
        """
        # Convert to dict for processing
        request_data = {
            "messages": [{"role": msg["role"], "content": msg["content"]} for msg in request.messages],
            "model": request.model,
            "max_tokens": request.max_tokens,
            "temperature": request.temperature
        }
        
        # Route to appropriate LLM provider
        # First try OpenAI for GPT models
        if request.model.startswith("gpt-") and openai_integration.available:
            openai_response = await openai_integration.chat_completion(request_data)
            if openai_response:
                return openai_response
        
        # Try Ollama for local models (check if model doesn't start with gpt-)
        if not request.model.startswith("gpt-") and ollama_integration.available:
            ollama_response = await ollama_integration.chat_completion(request_data)
            if ollama_response:
                return ollama_response
        
        # Fallback to demo response
        return {
            "id": "chatcmpl-demo",
            "object": "chat.completion",
            "created": 1640995200,
            "model": request.model,
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": f"This is a demo response from LLM Fortress for model: {request.model}"
                },
                "finish_reason": "stop"
            }],
            "usage": {"prompt_tokens": 50, "completion_tokens": 12, "total_tokens": 62}
        }

    @app.get("/api/v1/dashboard")
    async def get_dashboard():
        """Get security dashboard data"""
        return dashboard.get_dashboard_data()

    @app.get("/api/v1/stats")
    async def get_stats():
        """Get security statistics"""
        return firewall.get_security_stats()

    @app.get("/api/v1/events")
    async def get_events(
        limit: int = 100,
        threat_type: Optional[str] = None,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
    ):
        """Get security events with optional filters"""
        filters = {}
        if threat_type:
            filters["threat_type"] = threat_type
        if start_date:
            filters["start_date"] = start_date
        if end_date:
            filters["end_date"] = end_date

        return dashboard.search_events(filters, limit)

    @app.get("/api/v1/health")
    async def health_check():
        """Health check endpoint"""
        return {
            "status": "healthy",
            "firewall": "active",
            "monitoring": monitor.get_monitoring_status(),
            "stats": firewall.get_security_stats(),
        }

    @app.post("/api/v1/config")
    async def update_config(config: SecurityConfig):
        """Update security configuration"""
        # Update firewall configuration
        firewall.config.update(config.dict())

        # Reinitialize components if needed
        if "use_ml_detection" in config.dict():
            firewall.threat_detector.use_ml = config.use_ml_detection

        return {"message": "Configuration updated successfully"}

    @app.get("/api/v1/config")
    async def get_config():
        """Get current security configuration"""
        return firewall.config

    @app.get("/api/v1/providers")
    async def get_providers():
        """Get available LLM providers"""
        # Get available Ollama models
        ollama_models = []
        if ollama_integration.available:
            try:
                async with httpx.AsyncClient() as client:
                    response = await client.get(f"{ollama_integration.base_url}/api/tags", timeout=5)
                    if response.status_code == 200:
                        data = response.json()
                        ollama_models = [model["name"] for model in data.get("models", [])]
            except:
                pass
        
        return {
            "available_providers": {
                "openai": openai_integration.available,
                "ollama": ollama_integration.available,
                "demo": True
            },
            "default_provider": "openai" if openai_integration.available else "ollama" if ollama_integration.available else "demo",
            "openai_models": ["gpt-3.5-turbo", "gpt-4", "gpt-4-turbo-preview"] if openai_integration.available else [],
            "ollama_models": ollama_models,
            "openai_api_key_configured": bool(openai_integration.api_key),
            "ollama_url": ollama_integration.base_url if ollama_integration.available else None,
            "note": "Demo mode available for testing purposes"
        }

    @app.post("/api/v1/alerts/rules")
    async def add_alert_rule(rule: AlertRuleConfig):
        """Add custom alert rule"""
        from .monitoring import AlertRule

        alert_rule = AlertRule(
            name=rule.name,
            condition=rule.condition,
            threshold=rule.threshold,
            window_minutes=rule.window_minutes,
            enabled=rule.enabled,
        )

        monitor.add_custom_rule(alert_rule)
        return {"message": "Alert rule added successfully"}

    @app.get("/api/v1/alerts/rules")
    async def get_alert_rules():
        """Get all alert rules"""
        return [
            {
                "name": rule.name,
                "condition": rule.condition,
                "threshold": rule.threshold,
                "window_minutes": rule.window_minutes,
                "enabled": rule.enabled,
                "last_triggered": (
                    rule.last_triggered.isoformat() if rule.last_triggered else None
                ),
            }
            for rule in monitor.alert_rules
        ]

    @app.get("/dashboard", response_class=HTMLResponse)
    async def dashboard_ui():
        """Security dashboard web interface"""
        return get_dashboard_html()

    @app.get("/api/v1/metrics")
    async def metrics():
        """Prometheus metrics endpoint"""
        stats = firewall.get_security_stats()
        
        # Generate Prometheus metrics format
        metrics_text = f"""# HELP llm_fortress_total_requests Total number of requests processed
# TYPE llm_fortress_total_requests counter
llm_fortress_total_requests {stats['total_requests']}

# HELP llm_fortress_threats_detected Total number of threats detected
# TYPE llm_fortress_threats_detected counter
llm_fortress_threats_detected {stats['threats_detected']}

# HELP llm_fortress_blocked_requests Total number of blocked requests
# TYPE llm_fortress_blocked_requests counter
llm_fortress_blocked_requests {stats['blocked_requests']}

# HELP llm_fortress_threat_detection_rate Current threat detection rate
# TYPE llm_fortress_threat_detection_rate gauge
llm_fortress_threat_detection_rate {stats['threat_detection_rate']}

# HELP llm_fortress_block_rate Current block rate
# TYPE llm_fortress_block_rate gauge
llm_fortress_block_rate {stats['block_rate']}

# HELP llm_fortress_sanitized_responses Total number of sanitized responses
# TYPE llm_fortress_sanitized_responses counter
llm_fortress_sanitized_responses {stats['sanitized_responses']}

# HELP llm_fortress_recent_events Recent events in the last hour
# TYPE llm_fortress_recent_events gauge
llm_fortress_recent_events {stats['recent_events']}
"""
        
        return Response(
            content=metrics_text,
            media_type="text/plain",
            headers={"Content-Type": "text/plain; version=0.0.4; charset=utf-8"}
        )

    return app


def get_dashboard_html() -> str:
    """Generate dashboard HTML"""
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>LLM Fortress Dashboard v1</title>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/3.9.1/chart.min.js"></script>
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f8f9fa; }
            .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
            .header { background: linear-gradient(135deg, #1a365d, #2a4365); color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; position: relative; }
            .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 20px; }
            .stat-card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); text-align: center; }
            .stat-number { font-size: 2em; font-weight: bold; color: #2b6cb0; }
            .stat-label { color: #4a5568; margin-top: 5px; }
            .chart-container { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 20px; height: 400px; position: relative; }
            .events-table { background: white; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); overflow: hidden; }
            .events-table table { width: 100%; border-collapse: collapse; }
            .events-table th, .events-table td { padding: 12px; text-align: left; border-bottom: 1px solid #e2e8f0; }
            .events-table th { background: #f7fafc; font-weight: 600; }
            .severity-badge { padding: 4px 8px; border-radius: 12px; font-size: 0.8em; font-weight: bold; }
            .severity-critical { background: #fed7d7; color: #c53030; }
            .severity-high { background: #feebc8; color: #c05621; }
            .severity-medium { background: #fefcbf; color: #b7791f; }
            .severity-low { background: #c6f6d5; color: #276749; }
            .refresh-btn { background: rgba(255, 255, 255, 0.2); color: white; border: 1px solid rgba(255, 255, 255, 0.3); padding: 8px 16px; border-radius: 6px; cursor: pointer; font-size: 14px; position: absolute; top: 20px; right: 20px; transition: all 0.3s; }
            .refresh-btn:hover { background: rgba(255, 255, 255, 0.3); border-color: rgba(255, 255, 255, 0.5); }
            .pagination { display: flex; justify-content: center; align-items: center; gap: 5px; margin-top: 20px; }
            .pagination-btn { background: #f7fafc; border: 1px solid #e2e8f0; padding: 8px 12px; border-radius: 4px; cursor: pointer; font-size: 14px; transition: all 0.2s; }
            .pagination-btn:hover { background: #edf2f7; }
            .pagination-btn.active { background: #4299e1; color: white; border-color: #4299e1; }
            .pagination-btn.disabled { background: #f7fafc; color: #a0aec0; cursor: not-allowed; }
            .pagination-btn.disabled:hover { background: #f7fafc; }
            .footer { margin-top: 40px; padding: 20px; text-align: center; border-top: 1px solid #e2e8f0; background: #f8f9fa; }
            .footer a { color: #4299e1; text-decoration: none; font-weight: 500; }
            .footer a:hover { text-decoration: underline; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🏰 LLM Fortress Security Dashboard</h1>
                <p>Enterprise AI Security Platform</p>
                <button class="refresh-btn" onclick="refreshDashboard()">🔄 Refresh</button>
            </div>
            
            <div class="stats-grid" id="statsGrid">
                <!-- Stats will be loaded here -->
            </div>
            
            <div class="chart-container">
                <canvas id="threatChart"></canvas>
            </div>
            
            <div class="events-table">
                <h3 style="padding: 20px;">Recent Security Events</h3>
                <table>
                    <thead>
                        <tr>
                            <th>Timestamp</th>
                            <th>Client IP</th>
                            <th>Threat Type</th>
                            <th>Severity</th>
                            <th>Action</th>
                            <th>Payload</th>
                        </tr>
                    </thead>
                    <tbody id="eventsTable">
                        <!-- Events will be loaded here -->
                    </tbody>
                </table>
                <div id="eventsPagination"></div>
            </div>
            
            <div class="footer">
                <p>🏰 LLM Fortress - Enterprise AI Security Platform<br>
                Advanced Firewall • Threat Detection • Security Dashboard • Smart Alerting<br>
                <a href="https://github.com/olegnazarov/llm-fortress" target="_blank">View on GitHub</a></p>
            </div>
        </div>
        
        <script>
            let threatChart;
            
            async function fetchDashboardData() {
                try {
                    const response = await fetch('/api/v1/dashboard');
                    return await response.json();
                } catch (error) {
                    console.error('Error fetching dashboard data:', error);
                    return null;
                }
            }
            
            function updateStats(data) {
                const statsGrid = document.getElementById('statsGrid');
                const stats = data.statistics;
                
                statsGrid.innerHTML = `
                    <div class="stat-card">
                        <div class="stat-number">${stats.total_requests}</div>
                        <div class="stat-label">Total Requests</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">${stats.threats_detected}</div>
                        <div class="stat-label">Threats Detected</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">${stats.blocked_requests}</div>
                        <div class="stat-label">Blocked Requests</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">${(stats.threat_detection_rate * 100).toFixed(1)}%</div>
                        <div class="stat-label">Threat Rate</div>
                    </div>
                `;
            }
            
            function updateChart(data) {
                const ctx = document.getElementById('threatChart').getContext('2d');
                const trends = data.threat_trends.hourly_trends || [];
                
                if (threatChart) {
                    threatChart.destroy();
                }
                
                // Generate 24-hour labels with Moscow timezone
                const generateHourlyLabels = () => {
                    const labels = [];
                    const now = new Date();
                    
                    // Generate last 24 hours in Moscow time
                    for (let i = 23; i >= 0; i--) {
                        const hourDate = new Date(now.getTime() - (i * 60 * 60 * 1000));
                        // Moscow time is UTC+3, so use local time directly
                        const hour = hourDate.getHours();
                        labels.push(hour.toString().padStart(2, '0') + ':00');
                    }
                    return labels;
                };
                
                // Create data arrays with 24 hours of data
                const createHourlyData = (trends, field) => {
                    const data = new Array(24).fill(0);
                    const now = new Date();
                    
                    trends.forEach(trend => {
                        const trendDate = new Date(trend.hour);
                        const hoursDiff = Math.floor((now - trendDate) / (1000 * 60 * 60));
                        if (hoursDiff >= 0 && hoursDiff < 24) {
                            data[23 - hoursDiff] = trend[field];
                        }
                    });
                    return data;
                };
                
                const labels = generateHourlyLabels();
                const threatData = createHourlyData(trends, 'threats_detected');
                const requestData = createHourlyData(trends, 'total_requests');
                
                threatChart = new Chart(ctx, {
                    type: 'line',
                    data: {
                        labels: labels,
                        datasets: [{
                            label: 'Threats Detected',
                            data: threatData,
                            borderColor: '#e53e3e',
                            backgroundColor: 'rgba(229, 62, 62, 0.1)',
                            borderWidth: 3,
                            fill: true,
                            tension: 0.4,
                            pointBackgroundColor: '#e53e3e',
                            pointBorderColor: '#fff',
                            pointBorderWidth: 2,
                            pointRadius: 4,
                            pointHoverRadius: 6
                        }, {
                            label: 'Total Requests',
                            data: requestData,
                            borderColor: '#4299e1',
                            backgroundColor: 'rgba(66, 153, 225, 0.1)',
                            borderWidth: 3,
                            fill: true,
                            tension: 0.4,
                            pointBackgroundColor: '#4299e1',
                            pointBorderColor: '#fff',
                            pointBorderWidth: 2,
                            pointRadius: 4,
                            pointHoverRadius: 6
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {
                            title: {
                                display: true,
                                text: 'Security Trends (Last 24 Hours)',
                                font: {
                                    size: 16,
                                    weight: 'bold'
                                },
                                padding: 20
                            },
                            legend: {
                                display: true,
                                position: 'top',
                                labels: {
                                    usePointStyle: true,
                                    padding: 20,
                                    font: {
                                        size: 14
                                    }
                                }
                            },
                            tooltip: {
                                mode: 'index',
                                intersect: false,
                                backgroundColor: 'rgba(0, 0, 0, 0.8)',
                                titleColor: '#fff',
                                bodyColor: '#fff',
                                borderColor: '#4299e1',
                                borderWidth: 1,
                                callbacks: {
                                    title: function(tooltipItems) {
                                        return tooltipItems[0].label;
                                    },
                                    label: function(context) {
                                        const label = context.dataset.label || '';
                                        return label + ': ' + context.parsed.y;
                                    }
                                }
                            }
                        },
                        scales: {
                            x: {
                                display: true,
                                title: {
                                    display: true,
                                    text: 'Time',
                                    font: {
                                        size: 14,
                                        weight: 'bold'
                                    }
                                },
                                grid: {
                                    display: true,
                                    color: 'rgba(0, 0, 0, 0.1)'
                                },
                                ticks: {
                                    maxTicksLimit: 12,
                                    font: {
                                        size: 12
                                    }
                                }
                            },
                            y: {
                                display: true,
                                beginAtZero: true,
                                title: {
                                    display: true,
                                    text: 'Count',
                                    font: {
                                        size: 14,
                                        weight: 'bold'
                                    }
                                },
                                grid: {
                                    display: true,
                                    color: 'rgba(0, 0, 0, 0.1)'
                                },
                                ticks: {
                                    stepSize: 1,
                                    font: {
                                        size: 12
                                    }
                                }
                            }
                        },
                        interaction: {
                            mode: 'nearest',
                            axis: 'x',
                            intersect: false
                        }
                    }
                });
            }
            
            // Pagination variables
            let currentPage = 0;
            const eventsPerPage = 10;
            
            function updateEvents(data) {
                const eventsTable = document.getElementById('eventsTable');
                const events = data.recent_events || [];
                
                if (!eventsTable) {
                    console.error('Events table element not found!');
                    return;
                }
                
                if (events.length === 0) {
                    eventsTable.innerHTML = '<tr><td colspan="6" style="text-align: center; padding: 20px; color: #666;">No events found</td></tr>';
                    return;
                }
                
                // Map severity numbers to strings
                const severityMap = {
                    1: 'low',
                    2: 'medium', 
                    3: 'high',
                    4: 'critical'
                };
                
                const tableHTML = events.slice(currentPage * eventsPerPage, (currentPage + 1) * eventsPerPage).map(event => {
                    const severityNum = event.threat_info ? event.threat_info.severity : 0;
                    const severityStr = severityMap[severityNum] || 'none';
                    const threatType = event.threat_info ? event.threat_info.threat_type : 'N/A';
                    
                    // Format timestamp (already in Moscow time)
                    const eventDate = new Date(event.timestamp);
                    const timeString = eventDate.toLocaleString('ru-RU', {
                        year: 'numeric',
                        month: '2-digit',
                        day: '2-digit',
                        hour: '2-digit',
                        minute: '2-digit',
                        second: '2-digit'
                    });
                    
                    return `
                        <tr>
                            <td>${timeString}</td>
                            <td>${event.client_ip}</td>
                            <td>${threatType}</td>
                            <td><span class="severity-badge severity-${severityStr}">${severityStr.toUpperCase()}</span></td>
                            <td>${event.action_taken}</td>
                            <td title="${event.request_payload}">${event.request_payload.substring(0, 50)}...</td>
                        </tr>
                    `;
                }).join('');
                
                eventsTable.innerHTML = tableHTML;
                updatePagination(events.length);
            }
            
            function updatePagination(totalEvents) {
                const paginationDiv = document.getElementById('eventsPagination');
                if (!paginationDiv) return;
                
                const totalPages = Math.ceil(totalEvents / eventsPerPage);
                
                if (totalPages <= 1) {
                    paginationDiv.innerHTML = '';
                    return;
                }
                
                let paginationHTML = '<div class="pagination">';
                
                // Previous button
                if (currentPage > 0) {
                    paginationHTML += `<button onclick="changePage(${currentPage - 1})" class="pagination-btn">« Previous</button>`;
                } else {
                    paginationHTML += `<button class="pagination-btn disabled">« Previous</button>`;
                }
                
                // Page numbers
                for (let i = 0; i < totalPages; i++) {
                    if (i === currentPage) {
                        paginationHTML += `<button class="pagination-btn active">${i + 1}</button>`;
                    } else {
                        paginationHTML += `<button onclick="changePage(${i})" class="pagination-btn">${i + 1}</button>`;
                    }
                }
                
                // Next button
                if (currentPage < totalPages - 1) {
                    paginationHTML += `<button onclick="changePage(${currentPage + 1})" class="pagination-btn">Next »</button>`;
                } else {
                    paginationHTML += `<button class="pagination-btn disabled">Next »</button>`;
                }
                
                paginationHTML += '</div>';
                paginationDiv.innerHTML = paginationHTML;
            }
            
            function changePage(newPage) {
                currentPage = newPage;
                refreshDashboard();
            }
            
            async function refreshDashboard() {
                const data = await fetchDashboardData();
                if (data) {
                    updateStats(data);
                    updateChart(data);
                    updateEvents(data);
                } else {
                    console.error('No data received from dashboard API');
                }
            }
            
            // Initial load
            document.addEventListener('DOMContentLoaded', function() {
                refreshDashboard();
            });
            
            // Auto-refresh every 30 seconds
            setInterval(refreshDashboard, 30000);
        </script>
    </body>
    </html>
    """
