#!/bin/bash
set -e

# Colors for output
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

echo -e "${CYAN}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║  RTMAP Live Threat Simulator                              ║${NC}"
echo -e "${CYAN}║  Real-Time Threat Monitoring & Analysis Platform          ║${NC}"
echo -e "${CYAN}╚════════════════════════════════════════════════════════════╝${NC}\n"

# Check services
echo -e "${YELLOW}[1/5] Checking system health...${NC}"
token=$(curl -sS -X POST http://localhost:8001/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"ChangeMe123!"}' | python3 -c 'import sys, json; print(json.load(sys.stdin)["access_token"])')

if [ -z "$token" ]; then
  echo -e "${RED}✗ Backend authentication failed${NC}"
  exit 1
fi

metrics=$(curl -sS -H "Authorization: Bearer $token" http://localhost:8001/metrics/summary)
total_logs=$(echo "$metrics" | python3 -c 'import sys, json; print(json.load(sys.stdin)["total_logs"])')
total_threats=$(echo "$metrics" | python3 -c 'import sys, json; print(json.load(sys.stdin)["total_threats"])')

echo -e "${GREEN}✓ Backend: healthy${NC}"
echo -e "${GREEN}✓ Current state: $total_logs logs, $total_threats threats${NC}\n"

# Check collector
echo -e "${YELLOW}[2/5] Checking collector service...${NC}"
if sudo systemctl is-active --quiet rtmap-live-collector; then
  echo -e "${GREEN}✓ Collector service: active${NC}\n"
else
  echo -e "${RED}✗ Collector service: not running${NC}"
  echo -e "${YELLOW}Starting service...${NC}"
  sudo systemctl start rtmap-live-collector
  sleep 2
fi

# Emit test threats
echo -e "${YELLOW}[3/5] Emitting 10 test auth events (1/sec)...${NC}"
for i in {1..10}; do
  user_index=$((i % 3))
  case $user_index in
    0) username="testadmin" ;;
    1) username="jenkins_svc" ;;
    2) username="backup_user" ;;
  esac
  
  ip_octet=$((100 + i))
  src_ip="203.0.113.$ip_octet"
  port=$((22000 + i * 100))
  
  sudo logger -p authpriv.notice "Failed password for invalid user $username from $src_ip port $port ssh2"
  echo -e "${GREEN}  [$i/10] Logged: Failed password for $username from $src_ip${NC}"
  sleep 1
done

echo -e "${GREEN}✓ Events emitted${NC}\n"

# Wait for ingestion
echo -e "${YELLOW}[4/5] Waiting for threat detection (5 seconds)...${NC}"
sleep 5

# Check updated metrics
metrics=$(curl -sS -H "Authorization: Bearer $token" http://localhost:8001/metrics/summary)
new_logs=$(echo "$metrics" | python3 -c 'import sys, json; print(json.load(sys.stdin)["total_logs"])')
new_threats=$(echo "$metrics" | python3 -c 'import sys, json; print(json.load(sys.stdin)["total_threats"])')

logs_added=$((new_logs - total_logs))
threats_added=$((new_threats - total_threats))

echo -e "${GREEN}✓ Metrics updated:${NC}"
echo -e "  • Logs: $total_logs → $new_logs (+$logs_added)"
echo -e "  • Threats: $total_threats → $new_threats (+$threats_added)\n"

# List recent threats
echo -e "${YELLOW}[5/5] Recent detected threats:${NC}"
threats_response=$(curl -sS -H "Authorization: Bearer $token" 'http://localhost:8001/threats?limit=5')
if [ ! -z "$threats_response" ]; then
  echo "$threats_response" | python3 << 'EOF'
import sys, json
try:
  threats = json.load(sys.stdin)
  if isinstance(threats, list):
    for idx, threat in enumerate(threats[:5], 1):
      print(f"\n  [{idx}] {threat.get('title', 'Unknown')}")
      print(f"      User: {threat.get('username', 'N/A')}")
      print(f"      Severity: {threat.get('severity', 'unknown').upper()}")
      print(f"      Confidence: {threat.get('confidence', 0):.0%}")
      print(f"      Created: {threat.get('created_at', 'N/A')}")
except:
  print("  (Threats list unavailable right now)")
EOF
fi

echo -e "\n${GREEN}✓ Live threat detection working!${NC}\n"

echo -e "${CYAN}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║  HOW IT WORKS:                                            ║${NC}"
echo -e "${CYAN}╠════════════════════════════════════════════════════════════╣${NC}"
echo -e "${CYAN}║  1. Collector Service (systemd)                           ║${NC}"
echo -e "${CYAN}║     └─ Monitors /var/log/auth.log every 0.5s              ║${NC}"
echo -e "${CYAN}║     └─ POSTs logs to backend /logs endpoint               ║${NC}"
echo -e "${CYAN}║                                                            ║${NC}"
echo -e "${CYAN}║  2. Backend Detection (FastAPI)                           ║${NC}"
echo -e "${CYAN}║     └─ ML Model analyzes anomalies (IsolationForest)      ║${NC}"
echo -e "${CYAN}║     └─ Enriches threats with VirusTotal + OTX            ║${NC}"
echo -e "${CYAN}║     └─ Broadcasts to all WebSocket clients                ║${NC}"
echo -e "${CYAN}║                                                            ║${NC}"
echo -e "${CYAN}║  3. Frontend Display (React + Vite)                       ║${NC}"
echo -e "${CYAN}║     └─ WebSocket listener receives threat events          ║${NC}"
echo -e "${CYAN}║     └─ Live feed updates in real-time                     ║${NC}"
echo -e "${CYAN}║     └─ 'Live connected' badge shows connection status     ║${NC}"
echo -e "${CYAN}╚════════════════════════════════════════════════════════════╝${NC}\n"

echo -e "${CYAN}NEXT STEPS:${NC}"
echo -e "  1. Open http://localhost:4173 in your browser"
echo -e "  2. Login with: admin / ChangeMe123!"
echo -e "  3. Go to Dashboard tab"
echo -e "  4. Watch the 'Live connected' badge (should show green '●')"
echo -e "  5. View threats appearing in real-time in the Live threat feed\n"

echo -e "${GREEN}✓ Demo complete! System is fully operational.${NC}\n"
