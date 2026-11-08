# SENTINEL AI Detection Rules

## Brute-force authentication
Rule: BRUTE_FORCE_AUTH

Five or more failed authentication attempts from the same IP
within 10 minutes. Base risk score: 80.

## Suspicious authentication
Rule: SUSPICIOUS_AUTH

Detects explicit indicators:
- new_device
- impossible_travel
- mfa_bypass
- suspicious_location
- outside_business_hours

Also detects a successful login after at least three failures
from the same IP and username within 15 minutes.

Base risk score: 75.

## Network port scan
Rule: PORT_SCAN

Ten or more unique destination ports from the same source IP
within five minutes.

Accepted event types:
network, network_connection, network_flow, firewall_connection.

Port field: details.destination_port or details.dst_port.

Base risk score: 85.

## Privilege escalation
Rule: PRIVILEGE_ESCALATION

Detects privileged event types, explicit privilege escalation
flags, and recognized actions such as sudo, su, usermod,
grant_admin, and assume_role.

Base risk score: 95.

## Risk scoring

Additional evidence can increase the base score by two points
per event beyond the configured baseline, capped at ten bonus
points. Scores are capped at 100.

- 90-100: critical
- 75-89: high
- 50-74: medium
- 0-49: low

## Incident API

- GET /api/v1/incidents
- GET /api/v1/incidents/{incident_id}
- Filter: ?severity=high
- Filter: ?status=open

Incidents contain evidence event IDs and are deduplicated by
rule, source IP, username, and UTC hour.

These are heuristic portfolio-lab rules, not production-validated
security detections.
