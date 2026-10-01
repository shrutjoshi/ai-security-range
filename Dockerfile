# Breach & Brief service image
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app

COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install . \
    && useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin app

# Run unprivileged. 0.0.0.0 is required inside a container; publish the port
# deliberately (e.g. -p 127.0.0.1:8000:8000) and put a proxy in front if exposed.
USER 10001
EXPOSE 8000
ENV HOST=0.0.0.0 PORT=8000 AISR_DISABLE_DOCS=1
HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=2).status != 200)"
CMD ["python", "-m", "ai_security_range"]
