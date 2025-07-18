.PHONY: help install dev test clean docker-build docker-run docs

help:
	@echo "🛡️  LLM Fortress - Enterprise AI Security Platform"
	@echo "================================================="
	@echo "Available commands:"
	@echo "  make install     - Install production dependencies"
	@echo "  make dev         - Install development dependencies"
	@echo "  make test        - Run test suite"
	@echo "  make lint        - Run code linting"
	@echo "  make format      - Format code with black"
	@echo "  make clean       - Clean temporary files"
	@echo "  make docker-build - Build Docker image"
	@echo "  make docker-run  - Run with Docker"
	@echo "  make docker-dev  - Run development environment with Docker Compose"
	@echo "  make docs        - Build documentation"
	@echo "  make demo        - Run demo with test LLM service"

install:
	@echo "📦 Installing production dependencies..."
	pip install -r requirements.txt

dev:
	@echo "🔧 Installing development dependencies..."
	pip install -r requirements.txt
	pip install -r requirements-dev.txt

test:
	@echo "🧪 Running test suite..."
	pytest tests/ -v --cov=src/llm_fortress --cov-report=html --cov-report=term

lint:
	@echo "🔍 Running code linting..."
	flake8 src/ tests/
	mypy src/
	bandit -r src/

format:
	@echo "✨ Formatting code..."
	black src/ tests/
	isort src/ tests/

clean:
	@echo "🧹 Cleaning temporary files..."
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	rm -rf .pytest_cache/
	rm -rf htmlcov/
	rm -rf dist/
	rm -rf build/
	rm -rf *.egg-info/

docker-build:
	@echo "🐳 Building Docker image..."
	docker build -t llm-fortress:latest .

docker-run:
	@echo "🐳 Running with Docker..."
	docker run -p 8000:8000 --env-file .env llm-fortress:latest

docker-dev:
	@echo "🐳 Starting development environment..."
	docker-compose up -d
	@echo "Dashboard: http://localhost:8000/dashboard"
	@echo "API: http://localhost:8000/api/v1/"

docs:
	@echo "📚 Building documentation..."
	mkdocs build

demo:
	@echo "🎭 Starting demo environment..."
	docker-compose up llm-fortress demo-llm
	@echo "LLM Fortress: http://localhost:8000"
	@echo "Demo LLM: http://localhost:8001"

security-scan:
	@echo "🔒 Running security scan..."
	safety check
	bandit -r src/

release-check:
	@echo "✅ Running pre-release checks..."
	make test
	make lint
	make security-scan
	@echo "🚀 Ready for release!"