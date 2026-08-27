FROM hashicorp/terraform:1.15.8 AS terraform

FROM python:3.12.11-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

COPY --from=terraform /bin/terraform /usr/local/bin/terraform

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN python -m pip install --no-cache-dir . \
    && useradd --system --uid 10001 --create-home elcapitan \
    && mkdir -p /data \
    && chown -R elcapitan:elcapitan /data

USER 10001
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=3).read()"]

CMD ["elcapitan", "serve-demo", "--host", "0.0.0.0", "--port", "8080", "--workdir", "/data", "--prepare"]
