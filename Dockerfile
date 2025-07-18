FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app

# LLM Fortress environment variables
ENV USE_ML_DETECTION=true
ENV LLM_FORTRESS_CONFIG_PATH=/app/config/production.json
ENV HOST=0.0.0.0
ENV PORT=8000

# Set work directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY src/ ./src/
COPY config/ ./config/
COPY README.md .

# Create necessary directories
RUN mkdir -p logs reports

# Create non-root user
RUN useradd --create-home --shell /bin/bash llmfortress
RUN chown -R llmfortress:llmfortress /app
USER llmfortress

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/api/v1/health || exit 1

# Expose port
EXPOSE 8000

# Default command
CMD ["uvicorn", "src.llm_fortress.api:create_app", "--host", "0.0.0.0", "--port", "8000", "--factory"]

# Labels
LABEL maintainer="Oleg Nazarov <oleg@olegnazarov.com>"
LABEL description="LLM Fortress - Enterprise AI Security Platform"
LABEL version="1.0.0"