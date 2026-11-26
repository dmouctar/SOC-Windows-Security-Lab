# Windows Brute-Force Detection Validation

## 1. Objective

Validate a Splunk detection rule designed to identify potential brute-force authentication activity using Windows Security Event ID 4625.

## 2. Detection Logic

The detection identifies five or more failed authentication attempts originating from the same source IP address within a 10-minute window.

## 3. Detection Results

### Initial Detection

The initial search identified activity from localhost (`127.0.0.1`).

Two daily periods contained threshold-matching activity:
- October 14, 2025: 12 attempts
- November 22, 2025: 5 attempts

### Remote IP Validation

A second search excluded:
- 127.0.0.1
- ::1

Results:
- 3 raw events returned before aggregation.
- 0 events met the five-attempt detection threshold.
- No remote source IP met the configured threshold.

## 4. Security Analysis

The initial detection identified repeated authentication failures originating from the local system.

The remote IP validation did not identify a qualifying brute-force pattern.

These results do not establish that an attack occurred. Additional investigation would be necessary to determine the cause of the authentication failures.

## 5. Conclusion

The Splunk detection successfully applies the configured threshold and distinguishes localhost activity from remote authentication attempts.

Future improvements include:
- Correlating failed and successful authentication events.
- Monitoring repeated attempts across multiple accounts.
- Investigating suspicious source IP addresses.
- Improving alert severity and detection context.

**Platform:** Splunk Enterprise  
**Log Source:** Windows Security Event Logs  
**Event ID:** 4625  
**Detection Threshold:** 5 failures within 10 minutes
