FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY pyproject.toml ./
COPY gateway ./gateway

RUN pip install --no-cache-dir .

EXPOSE 8080

CMD ["python", "-m", "gateway.main"]
