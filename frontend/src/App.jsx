import { useEffect, useState } from 'react';
import { Alert, Box, CircularProgress, Snackbar } from '@mui/material';
import { Navigate, Route, Routes, useLocation, useNavigate } from 'react-router-dom';

import Dashboard from './components/Dashboard';
import LoginView from './components/LoginView';
import {
  buildWebSocketUrl,
  createCase,
  fetchAlerts,
  fetchCaseTimeline,
  fetchCases,
  fetchFinalReport,
  fetchIngestionHealth,
  fetchHealth,
  fetchSummary,
  fetchTuningSummary,
  fetchThreats,
  login,
  updateCase,
} from './api/client';

const TOKEN_KEY = 'threat-monitoring-token';

export default function App() {
  const navigate = useNavigate();
  const location = useLocation();
  const [token, setToken] = useState(() => localStorage.getItem(TOKEN_KEY) || '');
  const [role, setRole] = useState('');
  const [summary, setSummary] = useState(null);
  const [threats, setThreats] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [cases, setCases] = useState([]);
  const [selectedCaseId, setSelectedCaseId] = useState('');
  const [caseTimeline, setCaseTimeline] = useState([]);
  const [ingestionHealth, setIngestionHealth] = useState(null);
  const [tuningSummary, setTuningSummary] = useState(null);
  const [finalReport, setFinalReport] = useState(null);
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
        const [summaryData, threatsData, alertsData, healthData, casesData, ingestionHealthData, tuningSummaryData, reportData] = await Promise.all([
          fetchSummary(token),
          fetchThreats(token),
          fetchAlerts(token),
          fetchHealth(),
          fetchCases(token),
          fetchIngestionHealth(token),
          fetchTuningSummary(token),
          fetchFinalReport(token),
        ]);
        if (cancelled) {
          return;
        }
        setSummary(summaryData);
        setThreats(threatsData);
        setAlerts(alertsData);
        setHealth(healthData);
        setCases(casesData);
        setIngestionHealth(ingestionHealthData);
        setTuningSummary(tuningSummaryData);
        setFinalReport(reportData);
        if (!selectedCaseId && casesData.length > 0) {
          setSelectedCaseId(casesData[0].id);
        }
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
    if (!token || !selectedCaseId) {
      setCaseTimeline([]);
      return;
    }

    let cancelled = false;

    async function loadTimeline() {
      try {
        const timelineData = await fetchCaseTimeline(token, selectedCaseId);
        if (!cancelled) {
          setCaseTimeline(timelineData);
        }
      } catch (requestError) {
        if (!cancelled) {
          setSnack(requestError.message);
          setCaseTimeline([]);
        }
      }
    }

    loadTimeline();

    return () => {
      cancelled = true;
    };
  }, [token, selectedCaseId]);

  useEffect(() => {
    if (!selectedCaseId && cases.length > 0) {
      setSelectedCaseId(cases[0].id);
    }
  }, [cases, selectedCaseId]);

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
    setCases([]);
    setSelectedCaseId('');
    setCaseTimeline([]);
    setIngestionHealth(null);
    setTuningSummary(null);
    setFinalReport(null);
    setHealth(null);
    setLiveEvents([]);
    navigate('/', { replace: true });
  }

  async function handleCreateCaseFromAlert(alertId) {
    if (!token) {
      return;
    }

    try {
      const newCase = await createCase(token, { alert_id: alertId });
      const casesData = await fetchCases(token);
      setCases(casesData);
      setSelectedCaseId(newCase.id);
      setSnack(`Case opened: ${newCase.title}`);
    } catch (requestError) {
      setSnack(requestError.message);
    }
  }

  async function handleUpdateCase(caseId, updates) {
    if (!token) {
      return;
    }

    try {
      const updatedCase = await updateCase(token, caseId, updates);
      const casesData = await fetchCases(token);
      setCases(casesData);
      setSelectedCaseId(updatedCase.id);
      setSnack(`Case updated: ${updatedCase.title}`);
    } catch (requestError) {
      setSnack(requestError.message);
    }
  }

  const selectedCase = cases.find((item) => item.id === selectedCaseId) || null;

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
        cases={cases}
        caseTimeline={caseTimeline}
        selectedCase={selectedCase}
        ingestionHealth={ingestionHealth}
        tuningSummary={tuningSummary}
        finalReport={finalReport}
        health={health}
        liveEvents={liveEvents}
        role={role || 'authenticated'}
        onLogout={handleLogout}
        onSelectCase={setSelectedCaseId}
        onCreateCaseFromAlert={handleCreateCaseFromAlert}
        onUpdateCase={handleUpdateCase}
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
      <Route path="/dashboard" element={token ? dashboardElement : <Navigate to="/" replace />} />
      <Route path="*" element={<Navigate to={token ? '/dashboard' : '/'} replace />} />
    </Routes>
  );
}
