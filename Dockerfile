FROM python:3.12-slim

LABEL org.opencontainers.image.source="https://github.com/aumos-ai/agentshield"
LABEL org.opencontainers.image.description="agentshield: Multi-layer agent defense framework"
LABEL org.opencontainers.image.licenses="Apache-2.0"
LABEL org.opencontainers.image.vendor="AumOS"

WORKDIR /app

# Install package
COPY pyproject.toml README.md LICENSE ./
COPY src/ ./src/
RUN pip install --no-cache-dir . && rm -rf /root/.cache

# Create non-root user
RUN useradd -m -s /bin/bash aumos
USER aumos

ENV PYTHONUNBUFFERED=1

ENTRYPOINT ["agentshield"]
CMD ["--help"]
