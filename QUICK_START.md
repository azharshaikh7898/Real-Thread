# Quick Start Guide - Real-Time Threat Monitoring & Analysis Platform

## ✅ What's Running Now

- **Backend API**: http://localhost:8001 (FastAPI with async threat detection)
- **Frontend UI**: http://localhost:4173 (React + Vite)  
- **Collector Service**: Active systemd unit monitoring logs in real-time
- **Database**: Local JSON state store at `./backend/data/app_state.json`

---

## 🚀 To View Live Threats

### 1. Open the Dashboard
```bash
# Open in browser:
http://localhost:4173
```

### 2. Login
- Username: `admin`
- Password: `ChangeMe123!`

### 3. Look for the WebSocket Indicator
In the top bar, you'll see a **green "● Live connected"** badge when the frontend is connected to the backend's real-time stream.

---

## 📊 To Simulate Live Threats

### Option A: Run the Demo Script (Easiest)
```bash
./demo-live-threats.sh
```
This emits 10 test auth events and shows you threats being detected in real-time.

### Option B: Manually Emit Events
```bash
# SSH failed login attempts (detected as threats)
sudo logger -p authpriv.notice "Failed password for invalid user testuser from 198.51.100.1 port 22 ssh2"
sudo logger -p authpriv.notice "Failed password for invalid user admin from 198.51.100.2 port 22 ssh2"

# Check live dashboard - new threats should appear within 1-2 seconds
```

### Option C: View API Directly
```bash
# Get auth token
token=$(curl -sS -X POST http://localhost:8001/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"ChangeMe123!"}' | python3 -c 'import sys, json; print(json.load(sys.stdin)["access_token"])')

# See metrics
curl -H "Authorization: Bearer $token" http://localhost:8001/metrics/summary

# List threats
curl -H "Authorization: Bearer $token" http://localhost:8001/threats?limit=10
```

---

## 🔧 System Components

### 1. **Log Collector Service** (systemd)
```bash
# Check status
sudo systemctl status rtmap-live-collector

# View logs
sudo journalctl -u rtmap-live-collector -n 20

# Restart if needed
sudo systemctl restart rtmap-live-collector
```
- Monitors `/var/log/auth.log` every 0.5 seconds
- Detects SSH failures, invalid users, brute force attempts
- Sends events to backend API for processing

### 2. **Backend API** (FastAPI)
- **Threat Detection**: IsolationForest ML model for anomalies
- **Threat Intel**: Real-time enrichment via VirusTotal + AlienVault OTX
- **WebSocket Broadcast**: Sends threat events to all connected clients
- **APIs**: `/logs`, `/threats`, `/alerts`, `/health`, `/metrics`, `/ws/live`

### 3. **Frontend Dashboard** (React)
- **Real-Time Display**: Updates automatically as threats arrive
- **Threat Intel Panel**: Click "Threat intel" button on any threat to see VirusTotal/OTX data
- **Live Feed**: Latest threats with severity and timing
- **Case Workbench**: Incident investigation and tracking

---

## 📈 What Happens When You Log In

```
1. Frontend authenticates with backend
   ↓
2. Frontend downloads list of existing threats and alerts
   ↓
3. Frontend opens WebSocket connection to /ws/live
   ↓
4. Collector service emits a log event (e.g., failed SSH login)
   ↓
5. Backend receives log → detects threat → broadcasts via WebSocket
   ↓
6. Frontend receives threat event → updates dashboard in real-time
   ↓
7. You see new threat appear in Live threat feed instantly
```

---

## 🔑 API Credentials

- **Default Admin**: `admin` / `ChangeMe123!`
- **VirusTotal API Key**: Configured in `.env` ✓
- **AlienVault OTX Key**: Configured in `.env` ✓

---

## 📝 Troubleshooting

### Dashboard not loading?
```bash
# Check backend health
curl http://localhost:8001/health
# Should return: {"status": "operational", ...}
```

### Not seeing "Live connected"?
```bash
# Check WebSocket endpoint
curl -i http://localhost:8001/ws/live?token=<your-token>
# Should upgrade to WebSocket (HTTP 101)
```

### No threats appearing?
```bash
# Check collector is running
sudo systemctl is-active rtmap-live-collector

# Check it can read logs
sudo tail -1 /var/log/auth.log

# Manually trigger an event
sudo logger -p authpriv.notice "Test message from logger"

# Watch metrics increment
curl -H "Authorization: Bearer $token" http://localhost:8001/metrics/summary
```

### Need to reset?
```bash
# Stop all services
docker-compose -p rtmap down

# Clean up old data
rm -f backend/data/app_state.json

# Restart
docker-compose -p rtmap up -d
sudo systemctl start rtmap-live-collector
```

---

## 🎯 Key Features Enabled

✅ **Real-Time Log Ingestion** - Collector monitors auth.log continuously  
✅ **Anomaly Detection** - ML model (IsolationForest) identifies behavioral outliers  
✅ **Threat Enrichment** - Automatic lookup of IPs via VirusTotal + AlienVault OTX  
✅ **Live WebSocket Broadcast** - Threats appear on dashboard instantly  
✅ **Incident Response** - Create cases, add evidence, track playbooks  
✅ **Multi-Source Logging** - Auth, NginX, generic syslog support  
✅ **Auto-Start Service** - Collector runs on reboot via systemd  

---

## 📞 Support

For issues or questions, check systemd logs:
```bash
sudo journalctl -u rtmap-live-collector -f
```

Or backend API logs:
```bash
docker logs rtmap_backend_1 -f
```
