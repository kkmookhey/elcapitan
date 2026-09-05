FROM golang:1.27.1-alpine@sha256:cf6fca6641884b8433441b2b0652976f975e1d0fdd26d177eaaf8596087f3125 AS terraform

WORKDIR /src
ADD --checksum=sha256:091ca86edd29d325d5400c80c110cb51847a092c37c16d101607fc3321ae183b \
    https://github.com/hashicorp/terraform/archive/58e916f6706597d9d87898f9ecedf811b68c6f29.tar.gz \
    /tmp/terraform.tar.gz
RUN tar -xzf /tmp/terraform.tar.gz --strip-components=1 -C /src \
    && CGO_ENABLED=0 GOTOOLCHAIN=local go build -trimpath \
      -ldflags="-s -w -X github.com/hashicorp/terraform/version.dev=no" \
      -o /bin/terraform .

FROM python:3.12-slim-bookworm@sha256:0f5b26b9518d002b6173fd61daad821fa340635ebfec5bba471013f9ca114579

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

COPY --from=terraform /bin/terraform /usr/local/bin/terraform

WORKDIR /app
COPY pyproject.toml README.md requirements-runtime.txt ./
COPY src ./src
RUN python -m pip install --no-cache-dir --require-hashes -r requirements-runtime.txt \
    && python -m pip install --no-cache-dir --no-deps . \
    && useradd --system --uid 10001 --create-home elcapitan \
    && mkdir -p /data \
    && chown -R elcapitan:elcapitan /data

USER 10001
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=3).read()"]

CMD ["elcapitan", "serve-demo", "--host", "0.0.0.0", "--port", "8080", "--workdir", "/data", "--prepare"]
