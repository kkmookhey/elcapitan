# El Capitan runtime image — Hermes base plus the tooling the probe's
# evidence collection depends on (terraform, trivy, prowler, the cloud CLIs).
#
# Base identity is pinned by digest (measured in docs/spike-findings.md §1);
# the base image already runs as root and s6-overlay drops privileges to the
# `hermes` user (uid 10000) itself at container start, so this Dockerfile
# never issues a USER directive — docs/spike-findings.md §5 shows
# `docker run --user 1000 ...` is rejected outright (exit 1) by a guard in
# the image's own entrypoint.
FROM nousresearch/hermes-agent@sha256:16788311e2fa3035456bdc1bafb8ec2b1777db64ebf020af9bb7eb73c3712c9e

ARG TARGETARCH

# git and curl already ship with the base image (Debian GNU/Linux 13
# "trixie" — confirmed by `which git curl` inside the base image), so
# reinstalling or version-pinning them is pure churn. jq, unzip, and pipx are
# genuinely missing and are installed unpinned: trixie is a rolling suite
# whose exact package revisions rotate as the mirror updates, and pinning an
# apt version here would fail the build the first time that happens, for
# tools that do not affect what the probe measures. The tools whose findings
# the probe actually depends on — terraform, trivy, prowler — are pinned
# hard below, each by an explicit version baked into its download URL or
# pip/pipx spec.
RUN apt-get update \
 && apt-get install -y --no-install-recommends jq unzip pipx ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Terraform 1.15.8 (pinned — resolved from the hashicorp/terraform GitHub
# releases API on 2026-08-09, the plan's "1.9.8" guess is not current),
# architecture-selected at build time so the same Dockerfile builds
# correctly on the amd64 and arm64 variants of the base image (`docker
# manifest inspect` confirms both exist).
RUN case "${TARGETARCH}" in \
      amd64) TF_ARCH=amd64 ;; \
      arm64) TF_ARCH=arm64 ;; \
      *) echo "unsupported TARGETARCH=${TARGETARCH}"; exit 1 ;; \
    esac \
 && curl -fsSL -o /tmp/terraform.zip \
      "https://releases.hashicorp.com/terraform/1.15.8/terraform_1.15.8_linux_${TF_ARCH}.zip" \
 && unzip -q -d /usr/local/bin /tmp/terraform.zip \
 && rm /tmp/terraform.zip \
 && terraform version

# Trivy 0.73.0 (pinned — resolved from the aquasecurity/trivy GitHub
# releases API on 2026-08-09, the plan's "0.56.2" guess is not current),
# architecture-selected the same way.
RUN case "${TARGETARCH}" in \
      amd64) TRIVY_ARCH=64bit ;; \
      arm64) TRIVY_ARCH=ARM64 ;; \
      *) echo "unsupported TARGETARCH=${TARGETARCH}"; exit 1 ;; \
    esac \
 && curl -fsSL -o /tmp/trivy.deb \
      "https://github.com/aquasecurity/trivy/releases/download/v0.73.0/trivy_0.73.0_Linux-${TRIVY_ARCH}.deb" \
 && dpkg -i /tmp/trivy.deb \
 && rm /tmp/trivy.deb \
 && trivy --version

# AWS CLI v2, 2.36.19 (pinned — resolved from the aws/aws-cli GitHub tags on
# 2026-08-09), via the officially supported versioned installer URL. The
# "awscli" package on PyPI is CLI v1, which AWS has deprecated — the
# versioned zip installer is the real pin for v2.
RUN case "${TARGETARCH}" in \
      amd64) AWS_ARCH=x86_64 ;; \
      arm64) AWS_ARCH=aarch64 ;; \
      *) echo "unsupported TARGETARCH=${TARGETARCH}"; exit 1 ;; \
    esac \
 && curl -fsSL -o /tmp/awscliv2.zip \
      "https://awscli.amazonaws.com/awscli-exe-linux-${AWS_ARCH}-2.36.19.zip" \
 && unzip -q /tmp/awscliv2.zip -d /tmp \
 && /tmp/aws/install \
 && rm -rf /tmp/awscliv2.zip /tmp/aws \
 && aws --version

# Prowler 5.37.1 and Azure CLI 2.89.0, installed via pipx into their own
# isolated virtualenvs rather than `pip install`ed into the system python3
# — the base image's system python3 is the interpreter Hermes itself runs
# on, and these two packages carry large, easily-conflicting dependency
# trees. PIPX_BIN_DIR is pinned to /usr/local/bin (already on PATH for every
# user) so the shims are reachable after s6-overlay drops to the uid-10000
# `hermes` user at runtime.
#
# Prowler is NOT pinned to the newest PyPI release (5.38.0, resolved from
# PyPI's JSON API on 2026-08-09). 5.38.0 pins cryptography==50.0.0 directly
# while also depending on alibabacloud-tea-openapi==0.4.5, which requires a
# cryptography version older than 49.0.0 — an unresolvable conflict in
# prowler's own declared dependency graph (measured: pip's resolver rejects
# it outright, verified by installing 5.38.0 in this base image). 5.37.1
# pins cryptography==48.0.1, satisfies that same alibabacloud-tea-openapi
# constraint, and installs clean — confirmed by actually running
# `pipx install prowler==5.37.1` against this exact base image before
# pinning it here.
ENV PIPX_HOME=/opt/pipx PIPX_BIN_DIR=/usr/local/bin
RUN pipx install prowler==5.37.1 \
 && pipx install azure-cli==2.89.0 \
 && chmod -R a+rX /opt/pipx \
 && prowler --version \
 && az version

WORKDIR /work
