import AssignmentIcon from '@mui/icons-material/Assignment';
import TimelineIcon from '@mui/icons-material/Timeline';
import {
  Box,
  Button,
  Chip,
  Grid,
  MenuItem,
  Paper,
  Stack,
  TextField,
  Typography,
} from '@mui/material';
import { useEffect, useState } from 'react';

const statusPalette = {
  open: '#60a5fa',
  investigating: '#f59e0b',
  closed: '#36d399',
};

const dispositionPalette = {
  open: '#94a3b8',
  true_positive: '#ef4444',
  false_positive: '#38bdf8',
  benign_positive: '#a855f7',
  closed: '#36d399',
};

function statusColor(value) {
  return statusPalette[value] || '#94a3b8';
}

function dispositionColor(value) {
  return dispositionPalette[value] || '#94a3b8';
}

function formatTimestamp(value) {
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    return 'N/A';
  }
  return parsed.toLocaleString();
}

export default function CaseWorkbench({ cases, selectedCase, caseTimeline, onSelectCase, onUpdateCase }) {
  const [draft, setDraft] = useState({
    owner: '',
    notes: '',
    disposition: 'open',
    status: 'open',
  });

  useEffect(() => {
    if (!selectedCase) {
      setDraft({ owner: '', notes: '', disposition: 'open', status: 'open' });
      return;
    }

    setDraft({
      owner: selectedCase.owner || '',
      notes: selectedCase.notes || '',
      disposition: selectedCase.disposition || 'open',
      status: selectedCase.status || 'open',
    });
  }, [selectedCase]);

  const updateField = (field, value) => {
    setDraft((current) => ({ ...current, [field]: value }));
  };

  const saveCase = (nextStatus) => {
    if (!selectedCase) {
      return;
    }

    onUpdateCase(selectedCase.id, {
      owner: draft.owner,
      notes: draft.notes,
      disposition: draft.disposition,
      status: nextStatus || draft.status,
    });
  };

  return (
    <Grid container spacing={2.5}>
      <Grid item xs={12} md={4}>
        <Paper className="panel panel-case-list">
          <Box className="panel-header">
            <Typography variant="h6" sx={{ fontWeight: 800 }}>Cases</Typography>
            <Chip size="small" label={`${cases.length} tracked`} icon={<AssignmentIcon />} />
          </Box>
          <Stack spacing={1.25} className="case-list">
            {cases.length ? cases.map((caseItem) => (
              <Box
                key={caseItem.id}
                className={`case-item ${selectedCase?.id === caseItem.id ? 'case-item-selected' : ''}`}
                onClick={() => onSelectCase(caseItem.id)}
                role="button"
                tabIndex={0}
              >
                <Box>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>{caseItem.title}</Typography>
                  <Typography variant="body2" color="text.secondary" sx={{ mt: 0.4 }}>
                    {caseItem.description}
                  </Typography>
                </Box>
                <Stack direction="row" spacing={1} sx={{ mt: 1 }} flexWrap="wrap">
                  <Chip
                    size="small"
                    label={caseItem.status}
                    sx={{
                      textTransform: 'uppercase',
                      bgcolor: `${statusColor(caseItem.status)}22`,
                      color: statusColor(caseItem.status),
                      border: `1px solid ${statusColor(caseItem.status)}44`,
                    }}
                  />
                  <Chip
                    size="small"
                    label={caseItem.disposition}
                    sx={{
                      textTransform: 'uppercase',
                      bgcolor: `${dispositionColor(caseItem.disposition)}22`,
                      color: dispositionColor(caseItem.disposition),
                      border: `1px solid ${dispositionColor(caseItem.disposition)}44`,
                    }}
                  />
                </Stack>
                <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mt: 1 }}>
                  Updated {formatTimestamp(caseItem.updated_at)}
                </Typography>
              </Box>
            )) : <Typography color="text.secondary">No cases yet. Open one from an alert.</Typography>}
          </Stack>
        </Paper>
      </Grid>

      <Grid item xs={12} md={8}>
        <Paper className="panel panel-case-detail">
          <Box className="panel-header">
            <Typography variant="h6" sx={{ fontWeight: 800 }}>Investigation timeline</Typography>
            <Chip size="small" label={selectedCase ? `${caseTimeline.length} events` : 'No case selected'} icon={<TimelineIcon />} />
          </Box>

          {selectedCase ? (
            <Box>
              <Stack direction="row" spacing={1} flexWrap="wrap" sx={{ mb: 2 }}>
                <Chip label={selectedCase.status} sx={{ bgcolor: `${statusColor(selectedCase.status)}22`, color: statusColor(selectedCase.status) }} />
                <Chip label={selectedCase.disposition} sx={{ bgcolor: `${dispositionColor(selectedCase.disposition)}22`, color: dispositionColor(selectedCase.disposition) }} />
                {selectedCase.severity ? <Chip label={selectedCase.severity} /> : null}
                {selectedCase.rule_id ? <Chip label={selectedCase.rule_id} variant="outlined" /> : null}
              </Stack>

              <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>{selectedCase.title}</Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5, mb: 2 }}>
                {selectedCase.description}
              </Typography>

              <Grid container spacing={2} sx={{ mb: 2 }}>
                <Grid item xs={12} md={4}>
                  <TextField
                    label="Owner"
                    value={draft.owner}
                    onChange={(event) => updateField('owner', event.target.value)}
                    fullWidth
                    size="small"
                  />
                </Grid>
                <Grid item xs={12} md={4}>
                  <TextField
                    select
                    label="Disposition"
                    value={draft.disposition}
                    onChange={(event) => updateField('disposition', event.target.value)}
                    fullWidth
                    size="small"
                  >
                    <MenuItem value="open">Open</MenuItem>
                    <MenuItem value="true_positive">True Positive</MenuItem>
                    <MenuItem value="false_positive">False Positive</MenuItem>
                    <MenuItem value="benign_positive">Benign Positive</MenuItem>
                    <MenuItem value="closed">Closed</MenuItem>
                  </TextField>
                </Grid>
                <Grid item xs={12} md={4}>
                  <TextField
                    select
                    label="Status"
                    value={draft.status}
                    onChange={(event) => updateField('status', event.target.value)}
                    fullWidth
                    size="small"
                  >
                    <MenuItem value="open">Open</MenuItem>
                    <MenuItem value="investigating">Investigating</MenuItem>
                    <MenuItem value="closed">Closed</MenuItem>
                  </TextField>
                </Grid>
                <Grid item xs={12}>
                  <TextField
                    label="Investigation notes"
                    value={draft.notes}
                    onChange={(event) => updateField('notes', event.target.value)}
                    fullWidth
                    multiline
                    minRows={4}
                  />
                </Grid>
              </Grid>

              <Stack direction="row" spacing={1.5} flexWrap="wrap" sx={{ mb: 2 }}>
                <Button variant="contained" onClick={() => saveCase()}>
                  Save case
                </Button>
                <Button variant="outlined" onClick={() => saveCase('investigating')}>
                  Mark investigating
                </Button>
                <Button variant="outlined" onClick={() => saveCase('closed')}>
                  Close case
                </Button>
              </Stack>

              <Typography variant="subtitle2" sx={{ mb: 1, fontWeight: 700 }}>Observed entities</Typography>
              <Stack direction="row" spacing={1} flexWrap="wrap" sx={{ mb: 2 }}>
                {selectedCase.impacted_entities?.length ? selectedCase.impacted_entities.map((entity, index) => (
                  <Chip key={`${entity.type}-${index}`} label={`${entity.type}: ${entity.value}`} variant="outlined" />
                )) : <Typography variant="body2" color="text.secondary">No entities captured yet.</Typography>}
              </Stack>

              <Typography variant="subtitle2" sx={{ mb: 1, fontWeight: 700 }}>Timeline</Typography>
              <Stack spacing={1.25} className="timeline-list">
                {caseTimeline.length ? caseTimeline.map((event) => (
                  <Box key={`${event.record_id || event.summary}-${event.timestamp}`} className="timeline-item">
                    <Box>
                      <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>{event.summary}</Typography>
                      <Typography variant="body2" color="text.secondary">
                        {event.event_type} | {event.source} | {formatTimestamp(event.timestamp)}
                      </Typography>
                    </Box>
                    <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap">
                      <Chip size="small" label={event.severity || 'info'} />
                      {event.entity ? <Chip size="small" label={event.entity} variant="outlined" /> : null}
                    </Stack>
                  </Box>
                )) : <Typography color="text.secondary">No timeline events matched the current case window.</Typography>}
              </Stack>
            </Box>
          ) : (
            <Box className="case-empty-state">
              <Typography variant="h6" sx={{ fontWeight: 700 }}>Select a case to investigate</Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
                Open a case from the alert queue to build a timeline, capture notes, and set disposition.
              </Typography>
            </Box>
          )}
        </Paper>
      </Grid>
    </Grid>
  );
}
