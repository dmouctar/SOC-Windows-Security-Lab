# Enterprise Security Operations Dashboard

## 1. Overview

The Enterprise Security Operations Dashboard is a centralized security monitoring dashboard built using Splunk Enterprise.

It provides visibility into Windows endpoint activity, authentication events, PowerShell execution, process creation, DNS queries, network connections, and file activity.

The dashboard combines Windows Event Logs and Sysmon telemetry to support security monitoring, threat hunting, and investigation of potentially suspicious activity.

## 2. Dashboard Objectives

The primary objectives are to:

1. Monitor endpoint activity across Windows systems.
2. Track PowerShell execution and suspicious command activity.
3. Monitor successful and failed Windows authentication attempts.
4. Identify unusual process creation activity.
5. Observe DNS queries and outbound network connections.
6. Monitor file creation events.
7. Investigate potentially suspicious executable and LOLBin activity.

## 3. Data Sources

The dashboard uses the following telemetry sources:

| Data Source | Purpose |
|---|---|
| Windows Security Logs | Authentication and account activity |
| Windows System Logs | Operating system and service events |
| Sysmon | Process creation, network connections, DNS queries, and file activity |
| Splunk Enterprise | Centralized log collection, searching, analysis, and visualization |

## 4. Dashboard Panels and Metrics

The dashboard includes the following monitoring panels.

### 4.1 Security Overview

The top section provides an overview of endpoint activity during the selected time range.

The following metrics were observed in the dashboard screenshot:

| Panel | Observed Value |
|---|---:|
| Total Sysmon Events | 6,622 |
| PowerShell Executions | 497 |
| Failed Logons | 0 |
| Successful Logons | 164 |
| Network Connections | 18 |
| File Creations | 2,074 |

**Note:** These values represent one dashboard snapshot using the Last 24 Hours time selection on November 18, 2026. They are not permanent baseline values.

### 4.2 Process Creation Timeline

Displays process creation activity over time.

This panel helps identify unusual increases in process execution and provides a starting point for investigating suspicious programs or execution patterns.

### 4.3 PowerShell Activity

Tracks PowerShell execution activity over time.

This panel supports investigations involving:

- Unusual PowerShell execution patterns.
- Potentially encoded commands.
- Suspicious command-line arguments.
- Unexpected PowerShell activity.

### 4.4 DNS Queries

Displays DNS requests captured through Sysmon telemetry.

This panel helps investigate domain resolution activity and identify potentially unusual DNS communication patterns.

### 4.5 Network Connections

Displays outbound network connections observed through Sysmon Event ID 3.

This panel provides visibility into endpoint network activity and can help identify unexpected communication.

### 4.6 Top Executables

Provides visibility into executable activity observed across monitored endpoints.

This panel can help identify frequently executed programs and investigate unusual executable behavior.

### 4.7 LOLBins Activity

Provides visibility into activity involving legitimate Windows utilities that can potentially be abused by attackers.

Examples of utilities worth investigating include:

- certutil.exe
- reg.exe
- rundll32.exe
- mshta.exe
- wmic.exe

The presence of these utilities does not automatically indicate malicious activity. Context and command-line arguments are important during investigation.

## 5. Authentication Monitoring

Windows Security Event Logs are used to investigate authentication activity.

Important event IDs include:

| Event ID | Description |
|---|---|
| 4624 | Successful logon |
| 4625 | Failed logon |
| 4634 | Account logged off |
| 4672 | Special privileges assigned to a new logon |
| 4627 | Group membership information |

These events provide useful context for identifying authentication failures, account activity, and potentially suspicious access attempts.

## 6. Investigation Examples

During development and validation of the lab, Windows Security events were examined using Splunk SPL searches.

Examples included:

- Investigating failed authentication attempts involving the Manager01 account.
- Extracting target account names and source IP addresses from Event ID 4625.
- Identifying repeated authentication failures from individual source addresses.
- Examining successful logon and logoff activity.
- Comparing Splunk search results with Windows Event Viewer.

One investigation identified failed logon activity involving the Manager01 account and the source address `::1` (IPv6 loopback).

Another investigation identified failed authentication attempts involving the Djibrilla account from `192.168.2.100`.

These results demonstrate how Windows Security logs can be used to investigate authentication activity.

## 7. Dashboard Implementation

The dashboard was developed in Splunk Enterprise using SPL searches and visualizations.

The implementation includes:

1. Windows and Sysmon event collection.
2. SPL-based event analysis.
3. Time-based event aggregation.
4. Dashboard panels and statistical visualizations.
5. Time-range filtering for interactive monitoring.

## 8. Security Analysis Considerations

Dashboard metrics should be interpreted within their selected time ranges and the context of the monitored environment.

A zero failed-logon count does not necessarily mean that no failed authentication attempts have ever occurred.

Likewise, legitimate administrative activity, software execution, and Windows background processes may generate events that resemble suspicious behavior.

Further investigation should consider:

- Account names and privileges.
- Source IP addresses.
- Event timestamps.
- Process names and command-line arguments.
- Parent-child process relationships.
- Network destinations.
- Related Windows Security and Sysmon events.

## 9. Skills Demonstrated

- Splunk Enterprise administration and dashboard development.
- Search Processing Language (SPL).
- Windows Security Event Log analysis.
- Sysmon telemetry analysis.
- Authentication monitoring.
- Process and PowerShell monitoring.
- DNS and network activity monitoring.
- Security investigation and threat hunting.
- Detection engineering and event correlation.

## 10. Project Status

The Enterprise Security Operations Dashboard has been implemented in the lab.

The dashboard provides centralized visibility into Windows security events and Sysmon telemetry. Additional detection rules, investigation reports, and dashboard improvements will be documented as the project progresses.
