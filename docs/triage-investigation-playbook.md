# Triage and Investigation Playbook

## 1. Alert Intake

- Confirm alert metadata: rule_id, severity, confidence, source_ip, username, created_at.
- Check whether related alerts from same entity exist in the last 24h.
- Assign initial priority based on severity and impacted asset criticality.

## 2. Entity Pivoting

- Pivot by user: review recent authentication and privilege events.
- Pivot by host: review process/network activity around alert time window.
- Pivot by source/destination IP: inspect denied access, payload, and transfer patterns.

## 3. Timeline Reconstruction

- Build timeline from 15 minutes before alert to 30 minutes after.
- Include correlated logs, generated threats, and alert acknowledgments.
- Mark key transitions: initial signal, escalation, containment actions.

## 4. Scope Determination

- Determine blast radius: single host, multiple hosts, or account-centric spread.
- Identify impacted users, services, and data paths.
- Record affected critical assets first.

## 5. Disposition

- True Positive: confirmed malicious behavior.
- False Positive: detection fired on benign behavior requiring tuning.
- Benign Positive: expected sanctioned activity that still resembles threat behavior.

## 6. Containment and Recovery

- Credential-related: lock/reset affected test accounts.
- Network-related: simulate block on malicious source/destination.
- Endpoint-related: simulate endpoint quarantine and gather volatile evidence.

## 7. Evidence and Case Notes

- Save raw event references and screenshots.
- Capture detection rule version and threshold parameters at trigger time.
- Document root cause and lessons learned for tuning backlog.
