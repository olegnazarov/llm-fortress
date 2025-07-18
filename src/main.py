"""
LLM Fortress main application entry point
"""

import asyncio
import json
import os
from pathlib import Path

import uvicorn

from llm_fortress.api import create_app


def load_config() -> dict:
    """Load configuration from file"""
    config_path = os.getenv("LLM_FORTRESS_CONFIG_PATH", "config/development.json")

    if not os.path.exists(config_path):
        print(f"Config file not found: {config_path}, using defaults")
        return {}

    try:
        with open(config_path, "r") as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading config: {e}, using defaults")
        return {}


def main():
    """Main application entry point"""
    config = load_config()
    app = create_app(config)

    # Configure uvicorn
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "8000"))
    debug = os.getenv("DEBUG", "false").lower() == "true"

    uvicorn.run(
        app,
        host=host,
        port=port,
        reload=debug,
        access_log=True,
        log_level=config.get("log_level", "info").lower(),
    )


if __name__ == "__main__":
    main()
