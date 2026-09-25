FROM node:24-bookworm

# Install system dependencies and Python
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    git \
    unzip \
    ca-certificates \
    gnupg \
    python3 \
    python3-pip \
    socat \
    && rm -rf /var/lib/apt/lists/*

# Install Claude Code
RUN npm install -g @anthropic-ai/claude-code

# Install Gemini CLI 
RUN npm install -g @google/gemini-cli 2>/dev/null || true

# Install Codex
RUN npm i -g @openai/codex

# Install uv (provides uvx command for chroma-mcp)
RUN pip install --no-cache-dir --break-system-packages uv

# Install Python dependencies
RUN pip install --no-cache-dir --break-system-packages \
    chromadb \
    pandas \
    beautifulsoup4 \
    python-dotenv \
    requests \
    click
# Remap built-in 'node' user to match host UID/GID
ARG APP_UID=1000
ARG APP_GID=1000
RUN if [ "$APP_UID" != "1000" ] || [ "$APP_GID" != "1000" ]; then \
    groupmod -g $APP_GID node && \
    usermod -u $APP_UID -g $APP_GID node && \
    chown -R node:node /home/node; \
    fi

# Create directories and set ownership
RUN mkdir -p /app /opt && \
    chown -R node:node /app /opt

# Environment variables for tool paths
ENV QLCODER_ROOT=/app
ENV PYTHONPATH=/app
ENV HOME=/home/node
# Put codeql on PATH (binary is volume-mounted at /opt/codeql)
ENV PATH="/home/node/.local/bin:/opt/codeql:${PATH}"

WORKDIR /app

# Switch to non-root user
USER node

CMD ["/bin/bash"]
