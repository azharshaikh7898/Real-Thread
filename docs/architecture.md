# Architecture

## High-Level Flow

```text
Logs / API Clients
        |
        v
FastAPI Ingest API  ---> Auth / Rate Limit / Validation
        |
        v
Detection Engine
  - rule-based alerts
  - Isolation Forest anomaly scoring
        |
        v
MongoDB Storage
  - logs
  - threats
  - alerts
  - users
        |
        +----> WebSocket Broadcasts ----> React Dashboard
        |
        +----> Webhook / Email Notifier
```

## Data Flow

1. Logs arrive at `POST /logs`.
2. Input is validated and authorized.
3. The detector evaluates rules and ML anomaly score.
4. Logs, threats, and alerts are persisted in MongoDB.
5. New incidents are broadcast over WebSockets.
6. The frontend updates charts and live threat feeds in near real time.

## Security Controls

- JWT authentication on all sensitive endpoints.
- Role-based access for admin and analyst users.
- Request rate limiting on login and ingest routes.
- Structured validation with Pydantic schemas.
- CORS locked to known dashboard origins.
