# Ephemeral self-hosted GitHub Actions runner for ironmesh (Linux / x86_64).
#
# Goal: behave as close as possible to a GitHub-hosted `ubuntu-latest` runner so
# the same jobs run unchanged. GitHub-hosted ubuntu-latest is currently Ubuntu
# 24.04, so we base on that. Most toolchains (Rust, Node, pnpm, Java, ...) are
# installed per-job by the workflow's own setup actions, so this image only
# needs the base OS packages that those actions and the runner agent expect.
#
# Deliberately NOT included: the Docker socket / docker-in-docker. None of the
# current Linux jobs need it, and leaving it out is a big security win on a
# public repo. Add it later only if a job truly requires container builds.

FROM ubuntu:24.04

ARG RUNNER_VERSION=2.330.0
ARG TARGETARCH=x64

ENV DEBIAN_FRONTEND=noninteractive \
    RUNNER_MANUALLY_TRAP_SIG=1 \
    ACTIONS_RUNNER_PRINT_LOG_TO_STDOUT=1

# Base packages that ubuntu-latest ships and that setup-actions/steps rely on.
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl wget git jq unzip zip tar gzip xz-utils \
        sudo gnupg lsb-release software-properties-common \
        build-essential pkg-config \
        openssh-client locales tzdata \
        libicu74 libssl3 zlib1g \
        python3 python3-pip python3-venv \
    && rm -rf /var/lib/apt/lists/* \
    && locale-gen en_US.UTF-8

ENV LANG=en_US.UTF-8 LC_ALL=en_US.UTF-8

# Dedicated unprivileged user with passwordless sudo, exactly like the
# `runner` user on GitHub-hosted images.
RUN useradd -m -s /bin/bash runner \
    && echo "runner ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/runner \
    && chmod 0440 /etc/sudoers.d/runner

# Install the official Actions runner agent.
RUN mkdir -p /opt/actions-runner \
    && cd /opt/actions-runner \
    && curl -fsSL -o runner.tar.gz \
        "https://github.com/actions/runner/releases/download/v${RUNNER_VERSION}/actions-runner-linux-${TARGETARCH}-${RUNNER_VERSION}.tar.gz" \
    && tar xzf runner.tar.gz \
    && rm runner.tar.gz \
    && ./bin/installdependencies.sh \
    && chown -R runner:runner /opt/actions-runner

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

USER runner
WORKDIR /opt/actions-runner

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
