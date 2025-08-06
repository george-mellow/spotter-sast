# Multi-stage build for Spotter-SAST
# Stage 1: Build environment with all tools
FROM node:18-bullseye AS builder

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-dev \
    build-essential \
    git \
    curl \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Create symlink for python (some tools expect 'python' command)
RUN ln -s /usr/bin/python3 /usr/bin/python

# Copy package files
COPY package*.json ./
COPY requirements.txt ./

# Install Node.js dependencies
RUN npm ci --only=production

# Install Python dependencies and SAST tools
RUN pip3 install --no-cache-dir -r requirements.txt

# Install additional SAST tools globally
RUN npm install -g eslint @eslint/js

# Verify tool installations
RUN semgrep --version && \
    bandit --version && \
    eslint --version && \
    njsscan --version

# Stage 2: Production image
FROM node:18-bullseye-slim AS production

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-venv \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create symlink for python
RUN ln -s /usr/bin/python3 /usr/bin/python

# Create non-root user
RUN groupadd -r spotter && useradd -r -g spotter -m -d /home/spotter spotter

# Set working directory
WORKDIR /app

# Copy Python packages from builder
COPY --from=builder /usr/local/lib/python3.9/site-packages /usr/local/lib/python3.9/site-packages
COPY --from=builder /usr/local/bin/semgrep /usr/local/bin/semgrep
COPY --from=builder /usr/local/bin/bandit /usr/local/bin/bandit
COPY --from=builder /usr/local/bin/njsscan /usr/local/bin/njsscan

# Copy Node.js dependencies from builder
COPY --from=builder /app/node_modules ./node_modules

# Copy ESLint global installation
COPY --from=builder /usr/local/lib/node_modules/eslint /usr/local/lib/node_modules/eslint
COPY --from=builder /usr/local/lib/node_modules/@eslint /usr/local/lib/node_modules/@eslint
RUN ln -s /usr/local/lib/node_modules/eslint/bin/eslint.js /usr/local/bin/eslint

# Copy application files with new structure
COPY --chown=spotter:spotter src/ ./src/
COPY --chown=spotter:spotter config/ ./config/
COPY --chown=spotter:spotter infra/scripts/ ./infra/scripts/
COPY --chown=spotter:spotter package*.json ./
COPY --chown=spotter:spotter requirements.txt ./
COPY --chown=spotter:spotter .env* ./
COPY --chown=spotter:spotter .complianceignore ./

# Create necessary directories with proper permissions
RUN mkdir -p /app/data/logs /app/data/compliance-baselines /app/data/compliance-evidence \
             /app/data/incident-reports /app/data/quarantine /app/reports /app/tmp && \
    chown -R spotter:spotter /app

# Create volume mount points
RUN mkdir -p /scan-target && chown spotter:spotter /scan-target

# Verify all tools are accessible
USER spotter
RUN semgrep --version && \
    bandit --version && \
    eslint --version && \
    njsscan --version && \
    node --version && \
    python --version

# Create default environment file if not provided
RUN if [ ! -f .env ]; then \
    echo "JWT_SECRET=docker-default-secret-change-in-production" > .env && \
    echo "ENABLE_RBAC=false" >> .env && \
    echo "LOG_LEVEL=info" >> .env && \
    echo "AUDIT_LOGGING=true" >> .env; \
    fi

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
  CMD node -e "console.error('Health check: Spotter-SAST is running')" || exit 1

# Environment variables with defaults
ENV NODE_ENV=production
ENV JWT_SECRET=docker-default-secret-change-in-production
ENV ENABLE_RBAC=false
ENV LOG_LEVEL=info
ENV AUDIT_LOGGING=true

# Expose port for potential future HTTP endpoints
EXPOSE 3000

# Volume for external code scanning and data persistence
VOLUME ["/scan-target", "/app/data/logs", "/app/reports", "/app/data"]

# Default command - updated path
CMD ["node", "src/server.js"]