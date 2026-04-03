FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim

WORKDIR /app

# Copy agent implementation
COPY agent.py .

# Install isolated dependencies directly into system scope
RUN uv pip install --system google-adk[a2a] pyjwt python-dotenv uvicorn

# Allow Cloud Run to dynamically bind dynamic serving PORT assigns
EXPOSE 8080
CMD uvicorn agent:a2a_app --host 0.0.0.0 --port ${PORT:-8080}
