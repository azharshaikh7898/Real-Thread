const API_BASE = import.meta.env.VITE_API_BASE_URL || '';

function buildUrl(path) {
  return `${API_BASE}${path}`;
}

export async function login(username, password) {
  const response = await fetch(buildUrl('/auth/login'), {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ username, password }),
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({}));
    throw new Error(error.detail || 'Login failed');
  }

  return response.json();
}

async function apiGet(path, token) {
  const response = await fetch(buildUrl(path), {
    headers: {
      Authorization: `Bearer ${token}`,
    },
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({}));
    throw new Error(error.detail || 'Request failed');
  }

  return response.json();
}

export async function fetchSummary(token) {
  return apiGet('/metrics/summary', token);
}

export async function fetchThreats(token) {
  return apiGet('/threats?limit=50', token);
}

export async function fetchAlerts(token) {
  return apiGet('/alerts?limit=50', token);
}

export async function fetchHealth() {
  const response = await fetch(buildUrl('/health'));
  if (!response.ok) {
    throw new Error('Health check failed');
  }
  return response.json();
}

export function buildWebSocketUrl(token) {
  const base = API_BASE.startsWith('http') ? API_BASE.replace(/^http/, 'ws') : window.location.origin.replace(/^http/, 'ws');
  return `${base}/ws/live?token=${encodeURIComponent(token)}`;
}
