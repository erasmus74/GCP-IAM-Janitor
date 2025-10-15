# GCP IAM Janitor - Multi-stage Docker Build
# Supports all app versions: simple, enhanced, consolidation, advanced

# Use Python base image and install uv
FROM python:3.13-slim

# Install uv using official method
COPY --from=ghcr.io/astral-sh/uv:0.9.3 /uv /uvx /bin/

# Install runtime dependencies only
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for security
RUN useradd --create-home --shell /bin/bash appuser

# Install the project into `/app`
WORKDIR /app

# Enable bytecode compilation
ENV UV_COMPILE_BYTECODE=1

# Copy from the cache instead of linking since it's a mounted volume
ENV UV_LINK_MODE=copy

# Install the project's dependencies using the lockfile and settings
RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=bind,source=uv.lock,target=uv.lock \
    --mount=type=bind,source=pyproject.toml,target=pyproject.toml \
    uv sync --locked --no-install-project

# Then, add the rest of the project source code and install it
# Installing separately from its dependencies allows optimal layer caching
COPY . /app
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked

# Place executables in the environment at the front of the path
ENV PATH="/app/.venv/bin:$PATH"

# Create necessary directories and set permissions
RUN mkdir -p /app/logs && chown -R appuser:appuser /app

# Reset the entrypoint, don't invoke `uv`
ENTRYPOINT []

# Switch to non-root user
USER appuser

# Expose Streamlit port
EXPOSE 8501

# Environment variables
ENV PYTHONUNBUFFERED=1 \
    STREAMLIT_SERVER_PORT=8501 \
    STREAMLIT_SERVER_ADDRESS=0.0.0.0 \
    STREAMLIT_SERVER_HEADLESS=true \
    STREAMLIT_BROWSER_GATHER_USAGE_STATS=false

# App version argument (simple, enhanced, consolidation, advanced)
ARG APP_VERSION=advanced
ENV APP_VERSION=$APP_VERSION

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:8501/_stcore/health || exit 1

# Create entrypoint script
RUN echo '#!/bin/bash\n\
set -e\n\
\n\
# Validate APP_VERSION\n\
case "$APP_VERSION" in\n\
    simple|enhanced|consolidation|advanced)\n\
        echo "🔐 Starting GCP IAM Janitor - $APP_VERSION version..."\n\
        ;;\n\
    *)\n\
        echo "❌ Invalid APP_VERSION: $APP_VERSION. Must be: simple, enhanced, consolidation, or advanced"\n\
        exit 1\n\
        ;;\n\
esac\n\
\n\
# Determine app file based on version\n\
case "$APP_VERSION" in\n\
    simple)\n\
        APP_FILE="app_simple.py"\n\
        ;;\n\
    enhanced)\n\
        APP_FILE="app_enhanced.py"\n\
        ;;\n\
    consolidation)\n\
        APP_FILE="app_consolidation.py"\n\
        ;;\n\
    advanced)\n\
        APP_FILE="app_advanced.py"\n\
        ;;\n\
esac\n\
\n\
# Verify app file exists\n\
if [[ ! -f "$APP_FILE" ]]; then\n\
    echo "❌ Error: $APP_FILE not found in /app directory"\n\
    ls -la /app/app_*.py || echo "No app_*.py files found"\n\
    exit 1\n\
fi\n\
\n\
# Check for Google Cloud credentials (optional warning)\n\
if [[ -z "$GOOGLE_APPLICATION_CREDENTIALS" ]]; then\n\
    echo "⚠️  Warning: GOOGLE_APPLICATION_CREDENTIALS not set. Ensure ADC is configured."\n\
fi\n\
\n\
echo "🚀 Starting Streamlit with $APP_FILE..."\n\
echo "📱 Application will be available at: http://localhost:8501"\n\
\n\
# Start the application\n\
exec streamlit run "$APP_FILE" \\\n\
    --server.port="$STREAMLIT_SERVER_PORT" \\\n\
    --server.address="$STREAMLIT_SERVER_ADDRESS" \\\n\
    --server.headless="$STREAMLIT_SERVER_HEADLESS" \\\n\
    --browser.gatherUsageStats="$STREAMLIT_BROWSER_GATHER_USAGE_STATS"\n\
' > /app/entrypoint.sh && chmod +x /app/entrypoint.sh

# Use the entrypoint script
ENTRYPOINT ["/app/entrypoint.sh"]