import SecurityIcon from '@mui/icons-material/Security';
import TerminalIcon from '@mui/icons-material/Terminal';
import { Alert, Box, Button, Paper, TextField, Typography } from '@mui/material';
import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';

export default function LoginView({ onLogin, error, loading }) {
  const navigate = useNavigate();
  const [username, setUsername] = useState('admin');
  const [password, setPassword] = useState('ChangeMe123!');

  useEffect(() => {
    navigate('/dashboard', { replace: true });
  }, [navigate]);

  const submit = (event) => {
    event.preventDefault();
    navigate('/dashboard', { replace: true });
  };

  return (
    <Box className="login-shell">
      <Box className="login-hero">
        <div className="hero-badge">SOC-grade observability</div>
        <Typography variant="h2" className="hero-title">
          Real-Time Threat Monitoring & Analysis Platform
        </Typography>
        <Typography variant="body1" className="hero-copy">
          Track failed logins, suspicious traffic, and anomalies in one live command center.
        </Typography>
        <Box className="hero-points">
          <div><SecurityIcon fontSize="small" /> JWT auth and role control</div>
          <div><TerminalIcon fontSize="small" /> Live log ingestion and detection</div>
        </Box>
      </Box>

      <Paper elevation={18} className="login-card">
        <Typography variant="h5" sx={{ fontWeight: 700, mb: 1 }}>
          Sign in
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
          Use the seeded demo credentials or connect your own identity provider.
        </Typography>

        <Box component="form" onSubmit={submit} className="login-form">
          <TextField label="Username" value={username} onChange={(event) => setUsername(event.target.value)} fullWidth autoComplete="username" />
          <TextField label="Password" type="password" value={password} onChange={(event) => setPassword(event.target.value)} fullWidth autoComplete="current-password" />
          {error ? <Alert severity="error">{error}</Alert> : null}
          <Button type="submit" variant="contained" size="large" disabled={loading} sx={{ py: 1.5, fontSize: 16 }}>
            {loading ? 'Connecting...' : 'Enter dashboard'}
          </Button>
        </Box>

        <Box className="demo-credentials">
          <Typography variant="caption" color="text.secondary">Demo credentials</Typography>
          <Typography variant="body2">admin / ChangeMe123!</Typography>
          <Typography variant="body2">analyst / ChangeMe123!</Typography>
        </Box>
      </Paper>
    </Box>
  );
}
