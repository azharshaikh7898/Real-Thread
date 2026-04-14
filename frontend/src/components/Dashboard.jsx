import WarningAmberIcon from '@mui/icons-material/WarningAmber';
import ShieldIcon from '@mui/icons-material/Shield';
import FeedIcon from '@mui/icons-material/Feed';
import AccessAlarmIcon from '@mui/icons-material/AccessAlarm';
import GppGoodIcon from '@mui/icons-material/GppGood';
import {
  Box,
  Chip,
  Divider,
  Grid,
  LinearProgress,
  Paper,
  Stack,
  Typography,
} from '@mui/material';
import {
  Area,
  AreaChart,
  Cell,
  Legend,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';

const severityPalette = {
  low: '#60a5fa',
  medium: '#f59e0b',
  high: '#fb7185',
  critical: '#ef4444',
  info: '#38bdf8',
};

function severityColor(severity) {
  return severityPalette[severity] || severityPalette.info;
}

function groupByHour(threats) {
  const counts = new Map();
  threats.forEach((threat) => {
    const rawTs = threat.timestamp || threat.created_at;
    const parsed = new Date(rawTs);
    if (!rawTs || Number.isNaN(parsed.getTime())) {
      return;
    }
    const hour = parsed.toISOString().slice(0, 13) + ':00';
    counts.set(hour, (counts.get(hour) || 0) + 1);
  });
  return Array.from(counts.entries()).map(([hour, value]) => ({ hour, value }));
}

function severityDistribution(threats) {
  const buckets = { low: 0, medium: 0, high: 0, critical: 0 };
  threats.forEach((threat) => {
    buckets[threat.severity] = (buckets[threat.severity] || 0) + 1;
  });
  return Object.entries(buckets)
    .filter(([, value]) => value > 0)
    .map(([name, value]) => ({ name, value, color: severityColor(name) }));
}

function StatCard({ label, value, icon, accent, helper }) {
  return (
    <Paper className="stat-card">
      <Stack direction="row" justifyContent="space-between" alignItems="flex-start" spacing={2}>
        <Box>
          <Typography variant="overline" color="text.secondary">{label}</Typography>
          <Typography variant="h4" sx={{ mt: 0.5, fontWeight: 800 }}>{value}</Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5 }}>{helper}</Typography>
        </Box>
        <Box className="stat-icon" sx={{ bgcolor: accent }}>
          {icon}
        </Box>
      </Stack>
    </Paper>
  );
}

function SeverityChip({ severity }) {
  return (
    <Chip
      label={severity}
      size="small"
      sx={{
        textTransform: 'uppercase',
        letterSpacing: '0.08em',
        fontWeight: 700,
        bgcolor: `${severityColor(severity)}22`,
        color: severityColor(severity),
        border: `1px solid ${severityColor(severity)}44`,
      }}
    />
  );
}

export default function Dashboard({ summary, threats, alerts, health, liveEvents, role, onLogout }) {
  const displayThreats = threats;
  const lineData = groupByHour(displayThreats);
  const pieData = severityDistribution(displayThreats);
  const latestAlerts = alerts.slice(0, 5);
  const latestThreats = displayThreats.slice(0, 8);

  return (
    <Box className="dashboard-shell">
      <Paper className="topbar" elevation={8}>
        <Box>
          <Typography variant="h4" sx={{ fontWeight: 800, lineHeight: 1.1 }}>
            Real-Time Threat Monitoring
          </Typography>
          <Typography variant="body2" color="text.secondary">
            Live security telemetry, detection, and incident response in one place.
          </Typography>
        </Box>
        <Stack direction="row" spacing={1.5} alignItems="center" flexWrap="wrap">
          <Chip icon={<ShieldIcon />} label={role} color="primary" />
          <Chip icon={<GppGoodIcon />} label={health?.status || 'unknown'} color={health?.status === 'operational' ? 'success' : 'warning'} />
          <Chip icon={<AccessAlarmIcon />} label={`${summary?.open_alerts || 0} open alerts`} color="warning" />
          <Chip label="Sign out" variant="outlined" onClick={onLogout} clickable />
        </Stack>
      </Paper>

      <Grid container spacing={2.5} sx={{ mt: 0 }}>
        <Grid item xs={12} md={3}><StatCard label="Total logs" value={summary?.total_logs ?? 0} icon={<FeedIcon />} accent="linear-gradient(135deg, #2563eb, #60a5fa)" helper="Ingested and normalized events" /></Grid>
        <Grid item xs={12} md={3}><StatCard label="Detected threats" value={summary?.total_threats ?? 0} icon={<WarningAmberIcon />} accent="linear-gradient(135deg, #f97316, #fb7185)" helper="Rule-based plus anomaly signals" /></Grid>
        <Grid item xs={12} md={3}><StatCard label="Open alerts" value={summary?.open_alerts ?? 0} icon={<AccessAlarmIcon />} accent="linear-gradient(135deg, #a855f7, #ec4899)" helper="Unacknowledged incidents" /></Grid>
        <Grid item xs={12} md={3}><StatCard label="High severity" value={summary?.high_severity_threats ?? 0} icon={<ShieldIcon />} accent="linear-gradient(135deg, #ef4444, #f97316)" helper="High and critical threats" /></Grid>

        <Grid item xs={12} lg={8}>
          <Paper className="panel panel-large">
            <Box className="panel-header">
              <Typography variant="h6" sx={{ fontWeight: 800 }}>Threats over time</Typography>
              <Chip size="small" label={`${displayThreats.length} recent threats`} />
            </Box>
            <Box className="chart-wrap">
              <ResponsiveContainer width="100%" height={280}>
                <AreaChart data={lineData}>
                  <defs>
                    <linearGradient id="threatGradient" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#60a5fa" stopOpacity={0.45} />
                      <stop offset="95%" stopColor="#60a5fa" stopOpacity={0.02} />
                    </linearGradient>
                  </defs>
                  <XAxis dataKey="hour" stroke="#6b7f98" tick={{ fontSize: 12 }} />
                  <YAxis stroke="#6b7f98" tick={{ fontSize: 12 }} allowDecimals={false} />
                  <Tooltip contentStyle={{ background: '#0b1424', border: '1px solid #20314d', borderRadius: 12 }} />
                  <Area type="monotone" dataKey="value" stroke="#60a5fa" fill="url(#threatGradient)" strokeWidth={3} />
                </AreaChart>
              </ResponsiveContainer>
            </Box>
          </Paper>
        </Grid>

        <Grid item xs={12} lg={4}>
          <Paper className="panel panel-large">
            <Box className="panel-header">
              <Typography variant="h6" sx={{ fontWeight: 800 }}>Severity distribution</Typography>
              <Chip size="small" label="Live snapshot" />
            </Box>
            <Box className="chart-wrap chart-wrap-small">
              <ResponsiveContainer width="100%" height={280}>
                <PieChart>
                  <Pie data={pieData} dataKey="value" nameKey="name" innerRadius={65} outerRadius={100} paddingAngle={4}>
                    {pieData.map((entry) => (
                      <Cell key={entry.name} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip contentStyle={{ background: '#0b1424', border: '1px solid #20314d', borderRadius: 12 }} />
                  <Legend />
                </PieChart>
              </ResponsiveContainer>
            </Box>
          </Paper>
        </Grid>

        <Grid item xs={12} lg={5}>
          <Paper className="panel">
            <Box className="panel-header">
              <Typography variant="h6" sx={{ fontWeight: 800 }}>Live threat feed</Typography>
              <Chip size="small" label={`${liveEvents.length} events`} />
            </Box>
            <Stack spacing={1.5} className="feed-list">
              {latestThreats.length ? latestThreats.map((threat) => (
                <Box key={threat.id || `${threat.ip}-${threat.threat_type}-${threat.severity}`} className="feed-item">
                  <Box className="feed-item-main">
                    <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>{threat.title || threat.threat_type || 'Threat'}</Typography>
                    <Typography variant="body2" color="text.secondary">{threat.description || `IP: ${threat.ip || threat.source_ip || 'n/a'}`}</Typography>
                  </Box>
                  <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap">
                    <SeverityChip severity={threat.severity || 'info'} />
                    <Typography variant="caption" color="text.secondary">{threat.ip || threat.source_ip || 'n/a'}</Typography>
                  </Stack>
                </Box>
              )) : <Typography color="text.secondary">No threats detected yet.</Typography>}
            </Stack>
          </Paper>
        </Grid>

        <Grid item xs={12}>
          <Paper className="panel">
            <Box className="panel-header">
              <Typography variant="h6" sx={{ fontWeight: 800 }}>Threats</Typography>
              <Chip size="small" label={`${displayThreats.length} records`} />
            </Box>
            <Stack spacing={1.25}>
              {displayThreats.map((t, index) => (
                <Box key={`${t.ip || 'na'}-${t.threat_type || 'na'}-${index}`} className="alert-row">
                  <Typography variant="body2">IP: {t.ip || t.source_ip || 'n/a'}</Typography>
                  <Typography variant="body2">Type: {t.threat_type || t.title || 'n/a'}</Typography>
                  <Typography variant="body2">Severity: {t.severity || 'info'}</Typography>
                  <Typography variant="body2">
                    Time: {!t.timestamp || Number.isNaN(new Date(t.timestamp).getTime())
                      ? 'N/A'
                      : new Date(t.timestamp).toLocaleString()}
                  </Typography>
                </Box>
              ))}
              {!displayThreats.length ? <Typography color="text.secondary">No threats detected yet.</Typography> : null}
            </Stack>
          </Paper>
        </Grid>

        <Grid item xs={12} lg={7}>
          <Paper className="panel">
            <Box className="panel-header">
              <Typography variant="h6" sx={{ fontWeight: 800 }}>Alert queue</Typography>
              <Chip size="small" label={`${latestAlerts.length} alerts shown`} />
            </Box>
            <Stack spacing={1.25}>
              {latestAlerts.length ? latestAlerts.map((alert) => (
                <Box key={alert.id} className="alert-row">
                  <Box>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>{alert.title}</Typography>
                    <Typography variant="body2" color="text.secondary">{alert.message}</Typography>
                  </Box>
                  <Stack spacing={1} alignItems="flex-end">
                    <SeverityChip severity={alert.severity} />
                    <Typography variant="caption" color="text.secondary">{alert.delivery_status}</Typography>
                  </Stack>
                </Box>
              )) : <Typography color="text.secondary">No alerts yet.</Typography>}
            </Stack>
          </Paper>
        </Grid>

        <Grid item xs={12}>
          <Paper className="panel">
            <Box className="panel-header">
              <Typography variant="h6" sx={{ fontWeight: 800 }}>System status</Typography>
              <Chip size="small" label={health?.timestamp || 'live'} />
            </Box>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 1.5 }}>
              The backend, detection engine, and data store are reporting healthy when the bar is full.
            </Typography>
            <LinearProgress
              variant="determinate"
              value={health?.status === 'operational' ? 100 : 55}
              sx={{ height: 10, borderRadius: 999, bgcolor: 'rgba(255,255,255,0.08)' }}
            />
          </Paper>
        </Grid>
      </Grid>

      <Divider sx={{ my: 3, borderColor: 'rgba(255,255,255,0.08)' }} />
      <Typography variant="caption" color="text.secondary">
        Live connections: {health?.websocket_connections || 0} | Dashboard refreshes automatically through WebSockets.
      </Typography>
    </Box>
  );
}
