# Breach & Brief service image
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app

COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir .

EXPOSE 8000
ENV HOST=0.0.0.0 PORT=8000
CMD ["python", "-m", "ai_security_range"]
