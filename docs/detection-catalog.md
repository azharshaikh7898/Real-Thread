# Detection Catalog (MITRE-Mapped)

Version: 1.0

This catalog maps implemented detections to ATT&CK-aligned context and response guidance.

| Rule ID | Detection Name | Logic Summary | Severity | MITRE Tactic | MITRE Technique | Response Guidance |
|---|---|---|---|---|---|---|
| AUTH-001 | Brute Force Attempt | >= 5 failed logins from same source IP in 10 minutes (critical at >= 10). | High/Critical | Credential Access | T1110 | Block source, reset impacted credentials, review post-failure successes. |
| AUTH-002 | Password Spraying | >= 8 failed logins from same source IP across >= 3 users in 10 minutes. | High | Credential Access | T1110.003 | Lock targeted accounts and validate if any success occurred. |
| WEB-001 | Repeated Unauthorized Access | >= 4 denied HTTP responses (401/403) from same source in 5 minutes. | Medium | Reconnaissance | T1595 | Inspect requested paths and user-agent patterns, apply filtering controls. |
| WEB-002 | Suspicious Payload Abuse | Injection/traversal signatures in request content (SQLi, XSS, path traversal). | High | Initial Access | T1190 | Block source, inspect application logs, validate no exploitation chain. |
| EXEC-001 | Suspicious PowerShell Execution | Encoded or obfuscated PowerShell command patterns. | High | Execution | T1059.001 | Isolate endpoint, capture process lineage and command history. |
| PERS-001 | Persistence Attempt | Scheduled tasks/run key/service persistence keywords observed. | High | Persistence | T1053 | Audit startup persistence points and remove unauthorized entries. |
| LAT-001 | Lateral Movement Indicator | Remote movement indicators (PsExec/WMIC/SMB/RDP patterns). | Medium | Lateral Movement | T1021 | Validate session legitimacy and inspect neighboring hosts. |
| EXFIL-001 | Possible Data Exfiltration | Large outbound transfer to rare destination in previous 24h window. | High | Exfiltration | T1048 | Investigate transfer context and enforce containment if unauthorized. |
| UEBA-001 | Behavioral Anomaly | IsolationForest flags event as outlier from baseline profile. | Medium | Defense Evasion | T1070 | Correlate with auth/process/network events before disposition. |
| PRIV-001 | Privileged Account Probing | Denied access against privileged account from source IP. | High | Privilege Escalation | T1078 | Validate account activity and enforce additional auth controls. |

## Validation Notes

- Unit tests validate key detectors in backend/tests/test_detector.py.
- Alert records include severity, delivery status, and acknowledgment state.
- Threat records include MITRE tactic/technique and response guidance fields.
