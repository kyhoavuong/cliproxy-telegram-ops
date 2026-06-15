FROM python:3.12-alpine

WORKDIR /app
COPY src/ /app/src/

ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app/src
CMD ["python", "-m", "telegram_alerts"]
