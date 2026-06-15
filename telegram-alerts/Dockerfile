FROM python:3.14-alpine

WORKDIR /app
COPY src/ /app/src/

ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app/src
CMD ["python", "-m", "telegram_alerts"]
