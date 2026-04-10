FROM python:3.11-slim
WORKDIR /app
COPY . .
RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir \
    fastapi \
    uvicorn \
    python-jose[cryptography] \
    bcrypt==4.1.3 \
    python-multipart \
    httpx \
    requests \
    psutil
RUN mkdir -p /tmp/c2_layers
RUN python3 -c "import database; database.init_db()"
ENV GROQ_API_KEY=""
ENV GROQ_MODEL=llama-3.3-70b-versatile
ENV SECRET_KEY=""
ENV AGENT_SECRET=""
ENV ENABLE_SIMULATED_LOGS=true
ENV CORS_ORIGINS="http://localhost:8000,http://127.0.0.1:8000,http://172.20.0.2:8000,http://172.20.0.1:8000"
ENV VICTIM_NAME=websecsim-victim-c2
ENV PYTHONUNBUFFERED=1
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1
    CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--log-level", "info"]
