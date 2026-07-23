FROM docker:27-cli AS docker-cli
FROM python:3.12-slim
COPY --from=docker-cli /usr/local/bin/docker /usr/local/bin/docker
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN mkdir -p /data /managed-users
EXPOSE 8085
HEALTHCHECK --interval=30s --timeout=3s --retries=3 CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8085/health', timeout=2)"
CMD ["gunicorn", "--bind", "0.0.0.0:8085", "--workers", "2", "--threads", "4", "--timeout", "20", "app:app"]
