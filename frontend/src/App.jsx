import { useEffect, useState } from 'react';
import { Alert, Box, CircularProgress, Snackbar } from '@mui/material';
import { Navigate, Route, Routes, useLocation, useNavigate } from 'react-router-dom';

import Dashboard from './components/Dashboard';
import LoginView from './components/LoginView';
import { buildWebSocketUrl, fetchAlerts, fetchHealth, fetchSummary, fetchThreats, login } from './api/client';

const TOKEN_KEY = 'threat-monitoring-token';

export default function App() {
  const navigate = useNavigate();
  const location = useLocation();
  const [token, setToken] = useState(() => localStorage.getItem(TOKEN_KEY) || '');
  const [role, setRole] = useState('');
  const [summary, setSummary] = useState(null);
  const [threats, setThreats] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [health, setHealth] = useState(null);
  const [liveEvents, setLiveEvents] = useState([]);
  const [loading, setLoading] = useState(Boolean(token));
  const [authLoading, setAuthLoading] = useState(false);
  const [error, setError] = useState('');
  const [snack, setSnack] = useState('');

  useEffect(() => {
    if (!token) {
      setLoading(false);
      return;
    }

    let cancelled = false;
    let socket;

    async function loadDashboard() {
      try {
        const [summaryData, threatsData, alertsData, healthData] = await Promise.all([
          fetchSummary(token),
          fetchThreats(token),
          fetchAlerts(token),
          fetchHealth(),
        ]);
        if (cancelled) {
          return;
        }
        setSummary(summaryData);
        setThreats(threatsData);
        setAlerts(alertsData);
        setHealth(healthData);
        setLoading(false);
      } catch (requestError) {
        if (!cancelled) {
          setError(requestError.message);
          setLoading(false);
          handleLogout();
        }
      }
    }

    function connectStream() {
      try {
        socket = new WebSocket(buildWebSocketUrl(token));
        socket.onmessage = (event) => {
          const payload = JSON.parse(event.data);
          setLiveEvents((current) => [payload, ...current].slice(0, 40));
          if (payload.event_type === 'threat') {
            setThreats((current) => [payload.payload, ...current].slice(0, 50));
            setSummary((current) => current ? { ...current, total_threats: current.total_threats + 1 } : current);
            setSnack(`Threat detected: ${payload.payload.title}`);
          }
          if (payload.event_type === 'alert') {
            setAlerts((current) => [payload.payload, ...current].slice(0, 50));
          }
          if (payload.event_type === 'log') {
            setSummary((current) => current ? { ...current, total_logs: current.total_logs + 1 } : current);
          }
        };
        socket.onclose = () => {
          if (!cancelled) {
            setSnack('Live stream disconnected');
          }
        };
      } catch (streamError) {
        if (!cancelled) {
          setSnack(streamError.message);
        }
      }
    }

    loadDashboard().then(connectStream);

    return () => {
      cancelled = true;
      if (socket) {
        socket.close();
      }
    };
  }, [token]);

  useEffect(() => {
    if (token && location.pathname === '/') {
      navigate('/dashboard', { replace: true });
    }
  }, [token, location.pathname, navigate]);

  async function handleLogin(username, password) {
    setAuthLoading(true);
    setError('');
    try {
      const result = await login(username, password);
      localStorage.setItem(TOKEN_KEY, result.access_token);
      setToken(result.access_token);
      setRole(result.role);
      setLiveEvents([]);
      navigate('/dashboard', { replace: true });
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setAuthLoading(false);
    }
  }

  function handleLogout() {
    localStorage.removeItem(TOKEN_KEY);
    setToken('');
    setRole('');
    setSummary(null);
    setThreats([]);
    setAlerts([]);
    setHealth(null);
    setLiveEvents([]);
    navigate('/', { replace: true });
  }

  const dashboardElement = loading ? (
    <Box className="loading-state">
      <CircularProgress />
      <Alert severity="info" sx={{ mt: 3 }}>Loading live threat workspace...</Alert>
    </Box>
  ) : (
    <>
      <Dashboard
        summary={summary}
        threats={threats}
        alerts={alerts}
        health={health}
        liveEvents={liveEvents}
        role={role || 'authenticated'}
        onLogout={handleLogout}
      />
      <Snackbar
        open={Boolean(snack)}
        autoHideDuration={3500}
        onClose={() => setSnack('')}
        message={snack}
      />
    </>
  );

  return (
    <Routes>
      <Route path="/" element={<LoginView onLogin={handleLogin} error={error} loading={authLoading} />} />
      <Route path="/dashboard" element={dashboardElement} />
      <Route path="*" element={<Navigate to={token ? '/dashboard' : '/'} replace />} />
    </Routes>
  );
}
