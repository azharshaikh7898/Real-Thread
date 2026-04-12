# Real-Time Threat Monitoring & Analysis Platform

A production-ready cybersecurity monitoring stack for ingesting logs, detecting threats in real time, broadcasting live alerts, and visualizing incidents in a modern dashboard.

## What it does

- Ingests system and application logs through a secure FastAPI API.
- Detects brute force, suspicious activity, and anomaly signals with rule-based logic plus Isolation Forest scoring.
- Stores logs, threats, alerts, and users in MongoDB.
- Streams live updates to the dashboard over WebSockets.
- Protects endpoints with JWT authentication, role-based access, and rate limiting.
- Ships with Docker Compose, NGINX reverse proxy, and a GitHub Actions pipeline.

## Quick Start

1. Copy the environment file:

   ```bash
   cp .env.example .env
   ```

2. Start the full stack:

   ```bash
   docker compose up --build
   ```

3. Open the dashboard:

   ```text
   http://localhost
   ```

## Demo Credentials

- Admin: `admin / ChangeMe123!`
- Analyst: `analyst / ChangeMe123!`

## Main Endpoints

- `POST /auth/login`
- `POST /logs`
- `GET /alerts`
- `GET /threats`
- `GET /health`
- `GET /ws/live`

## Architecture

See [docs/architecture.md](docs/architecture.md).

## Deployment

See [docs/deployment.md](docs/deployment.md).

## Sample Logs

See [docs/sample-logs.md](docs/sample-logs.md).
