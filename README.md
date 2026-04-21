# Real-Time Threat Monitoring & Analysis Platform

Full-stack threat monitoring app with:
- FastAPI backend
- MongoDB storage
- React dashboard
- Docker Compose orchestration

The current backend API stores threat records and returns them for dashboard visualization.

## Dashboard Screenshots

![Real-Time Threat Monitoring Dashboard](docs/dashboard-screenshot.png)

Main dashboard view with threat timeline, severity distribution, and live threat feed.

![Live Threat Feed](docs/threat-feed-screenshot.png)

Detailed live threat feed showing threats by IP address with severity badges.

## Project Structure

```text
backend/        FastAPI app and API endpoints
frontend/       React dashboard UI
docker/         Backend and frontend Dockerfiles
nginx/          Reverse proxy config
docker-compose.yml
```

## What Works Right Now

- `POST /threat` saves threats in MongoDB.
- `GET /threats` returns all stored threats.
- Frontend dashboard fetches `/threats` and renders records, charts, and feed.
- CORS is enabled for local development.
- `POST /logs` ingests normalized events with schema and enrichment fields.
- `POST /onboarding/validate` and `POST /onboarding/register` validate and register source onboarding samples.
- Detection engine includes MITRE-mapped rules for brute force, spray, payload abuse, suspicious PowerShell, persistence, lateral movement, exfiltration indicators, anomaly, and privileged probing.
- `GET /metrics/ingestion-health` provides ingestion quality by source (parse success, field completeness, timestamp skew).
- `POST /cases`, `PATCH /cases/{id}`, and `GET /cases/{id}/timeline` support analyst case management and investigation timelines.
- `GET /tuning/summary` and `POST /tuning` support suppression, whitelist, and threshold tuning workflows.
- `GET /reports/final` returns a generated audit-ready threat monitoring report artifact.

## SOC Documentation Pack

- Gap matrix: [docs/gap-matrix.md](docs/gap-matrix.md)
- Detection catalog: [docs/detection-catalog.md](docs/detection-catalog.md)
- Triage and investigation playbook: [docs/triage-investigation-playbook.md](docs/triage-investigation-playbook.md)
- Report template: [docs/threat-monitoring-report-template.md](docs/threat-monitoring-report-template.md)

## Prerequisites

- Docker Engine
- Docker Compose v1 (`docker-compose`) or v2 (`docker compose`)

## Run Locally (Recommended)

Run commands from repository root:

```bash
cd "/home/azhar/Real-Time Threat Monitoring & Analysis Platform"
docker-compose down
docker-compose up -d --build
```

## Service URLs

- Backend API: `http://localhost:8001`
- Frontend (via NGINX): `http://localhost:18080`
- MongoDB host port: `localhost:27019`

## Real-Time Mode (No Sample Threats)

By default, the backend seeds demo users and demo log events on first startup.
To run with real incoming events only, disable demo log seeding.

Set environment variables before starting backend:

```bash
SEED_DEFAULT_USERS=true
SEED_DEMO_LOGS=false
```

If you use Docker Compose, add these to the backend service environment and restart.

Once enabled, the live feed is populated only by events you send to `POST /logs`.

## APIs To Integrate For Live Threat Feed

Use this flow for real-time, non-sample threat updates:

1. `POST /auth/login` to get a JWT.
2. `POST /logs` from your log shipper/SIEM/agent.
3. `WS /ws/live?token=<JWT>` from frontend to receive threat/alert/log events instantly.

### Example: Get JWT

```bash
curl -X POST http://localhost:8001/auth/login \
   -H "Content-Type: application/json" \
   -d '{"username":"admin","password":"ChangeMe123!"}'
```

### Example: Push One Real Event

```bash
curl -X POST http://localhost:8001/logs \
   -H "Content-Type: application/json" \
   -H "Authorization: Bearer <JWT_TOKEN>" \
   -d '{
      "source": "linux",
      "host": "prod-web-01",
      "event_type": "auth_failure",
      "message": "Failed SSH login for root from 10.0.0.20",
      "severity": "medium",
      "src_ip": "10.0.0.20",
      "username": "root",
      "status": "failed"
   }'
```

### Example: Receive Live Events Over WebSocket

Use browser frontend (already integrated) or a WebSocket client:

```bash
wscat -c "ws://localhost:8001/ws/live?token=<JWT_TOKEN>"
```

When a log triggers detection, backend broadcasts events with:
- `event_type: threat`
- `event_type: alert`
- `event_type: log`

This is what drives the Live Threat Feed in the dashboard.

## Linux Auth Log Connector (Real Host Telemetry)

For immediate real-time data, use the included Linux auth log shipper:

- Script: `backend/scripts/linux_auth_shipper.py`
- Input: `/var/log/auth.log`, `/var/log/nginx/access.log`, or `/var/log/syslog`
- Output: normalized events to `POST /logs`

### Run the connector

```bash
cd backend
source .venv/bin/activate
export RTMAP_API_BASE=http://localhost:8001
export RTMAP_USERNAME=admin
export RTMAP_PASSWORD='ChangeMe123!'
export RTMAP_LOG_FILE=/var/log/auth.log
export RTMAP_SOURCE_MODE=auth
python scripts/linux_auth_shipper.py
```

Notes:
- Use `sudo` if needed to read `/var/log/auth.log`.
- Keep the frontend open at `/dashboard`; new auth failures/suspicious events appear in Live Threat Feed in real time.
- To replay historical lines once, run with `--read-from-start`.

### Example sources

Auth logs:

```bash
RTMAP_LOG_FILE=/var/log/auth.log RTMAP_SOURCE_MODE=auth python scripts/linux_auth_shipper.py
```

Nginx access logs:

```bash
RTMAP_LOG_FILE=/var/log/nginx/access.log RTMAP_SOURCE_MODE=nginx python scripts/linux_auth_shipper.py
```

Generic syslog:

```bash
RTMAP_LOG_FILE=/var/log/syslog RTMAP_SOURCE_MODE=syslog python scripts/linux_auth_shipper.py
```

### Auto-start with systemd

If you want the collector to start automatically at boot, install the included unit file:

```bash
ln -sfn "$PWD" /home/azhar/rtmap
sudo cp deploy/systemd/rtmap-live-collector.service /etc/systemd/system/rtmap-live-collector.service
sudo systemctl daemon-reload
sudo systemctl enable --now rtmap-live-collector
sudo systemctl status rtmap-live-collector
```

If you switch between auth, nginx, or syslog, update `RTMAP_LOG_FILE` and `RTMAP_SOURCE_MODE` in `.env` before reloading the service:

```bash
sudo systemctl restart rtmap-live-collector
```

## VirusTotal + AlienVault OTX Threat Intel

The backend now supports external threat intelligence enrichment for source IPs.

Set these in your root `.env` (used by Docker Compose backend):

```bash
ENABLE_EXTERNAL_ENRICHMENT=true
ENRICHMENT_TIMEOUT_SECONDS=6
VIRUSTOTAL_API_KEY=<your_virustotal_key>
ALIENVAULT_OTX_API_KEY=<your_otx_key>
```

After setting keys, restart backend:

```bash
docker-compose -p rtmap up -d --build backend
```

Frontend usage:
- In **Live threat feed** and **Threats** sections, click **Threat intel**.
- The dashboard fetches and shows risk score/summary from VirusTotal and AlienVault OTX.

New APIs:
- `GET /threats/intel/ip/{ip}`
- `GET /threats/{threat_id}/intel`
- `POST /threats/{threat_id}/enrich`

## Live Deployment

- Frontend: `https://real-threaddd.onrender.com/dashboard`
- Backend Docs: `https://real-threadd.onrender.com/docs`

The frontend is built with `VITE_API_BASE_URL=http://localhost:8001` by default so the browser can reach the backend directly during local development.

## API Usage

### Create Threat

```bash
curl -X POST http://localhost:8001/threat \
   -H "Content-Type: application/json" \
   -d '{"ip":"8.8.8.8","threat_type":"Malware","severity":"high"}'
```

Response:

```json
{"message":"Threat stored successfully"}
```

### List Threats

```bash
curl http://localhost:8001/threats
```

Sample response:

```json
[
   {
      "ip": "8.8.8.8",
      "threat_type": "Malware",
      "severity": "high",
      "timestamp": "2026-04-13T10:23:12.123456"
   }
]
```

## Frontend Data Flow

Dashboard fetches threat data from:

`http://localhost:8001/threats`

Each record expects:
- `ip`
- `threat_type`
- `severity`
- `timestamp` (optional, dashboard safely handles missing values)

## Troubleshooting

### 1. Compose file not found

Error:
`Can't find a suitable configuration file in this directory`

Fix:

```bash
cd "/home/azhar/Real-Time Threat Monitoring & Analysis Platform"
```

### 2. Port already allocated (Mongo 27019)

Error:
`Bind for 0.0.0.0:27019 failed: port is already allocated`

Fix:

```bash
docker ps --format "table {{.Names}}\t{{.Ports}}"
docker rm -f <container_using_27019>
docker-compose up -d --build
```

### 3. docker-compose v1 `ContainerConfig` error

If you see KeyError `ContainerConfig`, clear stale project containers and restart:

```bash
docker rm -f $(docker ps -aq --filter "name=real-timethreatmonitoringanalysisplatform") 2>/dev/null || true
docker network rm real-timethreatmonitoringanalysisplatform_default 2>/dev/null || true
docker-compose -p rtmap up -d --build
```

## Development Notes

- Backend app entrypoint: [backend/app/main.py](backend/app/main.py)
- Dashboard component: [frontend/src/components/Dashboard.jsx](frontend/src/components/Dashboard.jsx)
- Compose config: [docker-compose.yml](docker-compose.yml)
