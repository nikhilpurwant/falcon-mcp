# 🕵️‍♂️ Diagnostic Claims Inspector Agent

This agent acts as a secure toolless diagnostic inspector designed to dump redacted visibilities of incoming authentication headers during Workspace tools routing traffic clearance validates.

## ⚙️ Features

- **Multi-Token Inspection:** segregation visibility scanning distinct Authorization (Human Access Tokens) vs. X-Serverless-Authorization (Infrastructure Clearance Service Accounts) headers.
- **Dynamic Live verification swapping:** Detects proprietary Google Opaque Access signatures (`ya29.`) spawning asynchronous Live exchanges proving human user tenancy profile occupying `sub` occupancy keys.
- **Secret Redaction:** Safeguards production security automatically masking raw Bearer credentials leakage logs prints.

## 🚀 Running Locally

Ensure workspace top-level installation mounted dependencies:

```bash
uv run pip install -r requirements.txt
uv run uvicorn agent:a2a_app --port 8001
```

You can also test it locally using the `test_a2a_client.py` script.

```bash
uv run python test_a2a_client.py
```

## ☁️ Deployment (Cloud Run)

A supportive `Dockerfile` is provided for containerized packaging and deployment.
