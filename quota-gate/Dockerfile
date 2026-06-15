FROM python:3.14-alpine

RUN pip install --no-cache-dir aiohttp

WORKDIR /app
COPY quota_gate.py /app/quota_gate.py

EXPOSE 8081
CMD ["python", "/app/quota_gate.py"]
