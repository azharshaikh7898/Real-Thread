# Sample Logs

## SSH brute force

```json
{
  "timestamp": "2026-04-12T10:00:00Z",
  "source": "system",
  "host": "srv-01",
  "event_type": "auth",
  "message": "Failed password for invalid user root from 10.0.0.20 port 54321 ssh2",
  "severity": "warning",
  "src_ip": "10.0.0.20",
  "username": "root"
}
```

After 5 failed attempts from the same source IP within the sliding window, the platform raises a `brute_force` threat and a high-severity alert.

## HTTP attack pattern

```json
{
  "timestamp": "2026-04-12T10:01:00Z",
  "source": "web",
  "host": "app-01",
  "event_type": "http",
  "message": "GET /admin HTTP/1.1 403 Forbidden",
  "severity": "warning",
  "src_ip": "203.0.113.44",
  "status_code": 403,
  "user_agent": "sqlmap/1.7"
}
```

Multiple 401/403 responses from the same IP create an `access_abuse` threat, while unusual payloads may also trigger anomaly detection.

## Curl ingestion example

```bash
curl -X POST http://localhost/logs \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer <token>' \
  -d '{"host":"srv-01","source":"system","event_type":"auth","message":"Failed password for invalid user root from 10.0.0.20 port 54321 ssh2","severity":"warning","src_ip":"10.0.0.20","username":"root"}'
```
