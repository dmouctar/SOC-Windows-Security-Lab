# SOC Windows Security Lab – Architecture Documentation

## 1. Purpose

This document describes the architecture of the Windows Security Monitoring and Threat Detection Lab. It explains the lab components, their responsibilities, security telemetry, logging workflow, and how Splunk Enterprise is used to monitor and investigate Windows security events.

The primary objective is to simulate a Security Operations Center (SOC) environment in which endpoint activity is collected, analyzed, correlated, and investigated using SIEM technology.

## 2. Lab Components and Verification Status

| Component | Purpose | Status |
|---|---|---|
| Splunk Enterprise | Centralized log search, analysis, and visualization | Implemented and tested |
| Sysmon | Endpoint telemetry and process monitoring | Events demonstrated in Splunk |
| Windows Server 2019 | Windows server and security event source | Implemented and monitored |
| Active Directory | Centralized identity and account management | Configuration details to verify |
| Group Policy | Centralized Windows security configuration | Configuration details to verify |
| DNS and DHCP | Network name resolution and IP assignment | Configuration details to verify |
| pfSense | Network routing and firewall management | Configuration details to verify |
| Windows endpoints | Sources of endpoint and authentication events | Event analysis demonstrated |

*Note: Status describes the evidence currently documented in the project. Additional configuration and integration details will be documented as they are verified.*

## 3. Architecture Overview

The lab uses Windows Server 2019, Windows Security Event Logs, Sysmon, and Splunk Enterprise to provide visibility into endpoint and authentication activity.

The architecture consists of three primary layers:

### A. Endpoint and Event Generation Layer

Windows systems generate security and operational events.

The monitored telemetry includes:

- Windows authentication events
- Successful and failed logons
- Process creation activity
- Network connection activity
- File creation activity
- PowerShell execution

### B. Log Collection and SIEM Layer

Splunk Enterprise serves as the centralized SIEM platform.

It is used to:
- Search collected Windows security events.
- Analyze Sysmon telemetry.
- Extract and normalize event fields.
- Correlate authentication activity.
- Develop custom SPL detection searches.

The exact log-forwarding configuration and collection mechanism remain subject to verification.

### C. Detection and Investigation Layer

Custom SPL searches and dashboards provide visibility into security activity.

The investigation workflow includes:
- Identifying suspicious authentication patterns.
- Reviewing source IP addresses.
- Identifying targeted accounts.
- Investigating process execution.
- Correlating failed and successful authentication events.
- Documenting investigation findings.

## 4. Logging and Monitoring Flow

The documented monitoring workflow is:

```text
Windows Server 2019
        |
        v
Windows Security Event Logs
        |
        +------------------+
        |                  |
        v                  v
   Event ID 4624      Event ID 4625
   Successful         Failed
   Authentication    Authentication
        |                  |
        +--------+---------+
                 |
                 v
          Splunk Enterprise
                 |
                 v
          SPL Searches
                 |
        +--------+---------+
        |                  |
        v                  v
   Detection Logic    Event Correlation
        |                  |
        +--------+---------+
                 |
                 v
          SOC Dashboards
                 |
                 v
       Security Investigations
```

Sysmon provides additional endpoint telemetry, including process creation, network connections, and file creation events.

**Important:** This diagram represents the logical monitoring workflow. The specific forwarding agent, configuration, and network path should be documented separately after verification.

## 5. Windows Security Event Monitoring

The lab uses Windows Security Event IDs to investigate authentication behavior.

| Event ID | Description | Security Relevance |
|---|---|---|
| 4624 | Successful account logon | Identifies successful authentication |
| 4625 | Failed account logon | Helps identify repeated failed authentication attempts |

### Authentication Monitoring

The lab includes searches for:

- Failed authentication attempts.
- Successful account logons.
- Targeted account analysis.
- Source IP investigation.
- Failed-to-successful authentication correlation.

The authentication correlation investigation identifies successful logons occurring shortly after failed attempts for the same account and source IP.

This provides useful investigative context but does not independently establish that an account was compromised.

## 6. Sysmon Event Monitoring

Sysmon provides additional endpoint visibility.

The following event types are included in the documented monitoring scope:

| Sysmon Event ID | Description | Investigation Purpose |
|---|---|---|
| 1 | Process Creation | Investigate executable and process activity |
| 3 | Network Connection | Examine endpoint network connections |
| 11 | File Creation | Monitor file creation activity |

These events support investigations into suspicious process execution, network behavior, and file activity.

## 7. Splunk Detection Engineering

Custom SPL searches were developed to analyze Windows security events and endpoint telemetry.

### Current Detection and Investigation Areas

| Detection / Investigation | Purpose |
|---|---|
| Windows Brute-Force Detection | Identifies repeated failed authentication attempts |
| Failed Logon Analysis | Examines Event ID 4625 |
| Successful Logon Analysis | Examines Event ID 4624 |
| Authentication Correlation | Correlates failed and successful logons |
| Encoded PowerShell Investigation | Examines potentially suspicious encoded commands |
| Registry Utility Investigation | Investigates registry-related activity |
| Process Creation Analysis | Examines process execution and parent-child relationships |

### Example: Failed Authentication Detection

The following SPL search identifies repeated failed authentication attempts within a ten-minute time window.

```spl
index=* host="MOUCTAR-SERV19"
source="WinEventLog:Security" EventCode=4625
| rex field=_raw "Source Network Address:\s+(?<Source_IP>[^\r\n]+)"
| rex field=_raw "(?s)Account For Which Logon Failed:.*?Account Name:\s+(?<Failed_Account>[^\r\n]+)"
| eval Failed_Account=lower(trim(Failed_Account))
| bin _time span=10m
| stats count as Failed_Attempts by _time Source_IP Failed_Account
| where Failed_Attempts>=5
| sort -Failed_Attempts
```

**Detection logic:**

- Event ID 4625 identifies failed logon events.
- Source IP identifies the originating network address when available.
- Failed account identifies the account being targeted.
- Events are grouped into ten-minute intervals.
- Five or more failures in a time window meet the configured detection threshold.

The threshold is an investigation trigger, not proof of malicious activity.

## 8. Splunk Dashboard Architecture

The Enterprise Security Operations Dashboard provides a centralized view of endpoint and authentication activity.

### Dashboard Monitoring Panels

- Total Sysmon Events
- PowerShell Executions
- Failed Logons
- Successful Logons
- Network Connections
- File Creations
- Process Creation Timeline
- PowerShell Activity
- DNS Queries
- Privileged Account Activity
- Failed Logons Over Time
- Failed Logons by Account
- Potential Brute-Force Activity

Dashboard panels depend on the selected time range and available telemetry. Some panels may return no results when matching events are unavailable.

Dashboard documentation and screenshots are maintained under:

`/splunk/dashboards/`

## 9. Network and Infrastructure Security

The broader lab environment includes the following infrastructure components:

### Windows Server 2019
Provides the Windows server environment and generates security and operational events.

### Active Directory
Provides centralized identity and account management capabilities.

### Group Policy
Supports centralized Windows security and configuration management.

### DNS and DHCP
Provide network name resolution and IP address assignment.

### pfSense
Provides network routing and firewall functionality.

Detailed network topology, IP addressing, firewall rules, domain configuration, and log-forwarding paths will be added after configuration review.

## 10. Security Considerations

The following considerations apply to the monitoring environment:

- Authentication failures should be investigated in context.
- Successful authentication following repeated failures may warrant additional investigation.
- Localhost and loopback addresses should be distinguished from external source addresses.
- System accounts and service accounts should be considered when analyzing authentication events.
- Repeated logon activity does not automatically indicate a brute-force attack.
- Detection thresholds should be adjusted based on normal system behavior.
- Dashboard results should be validated against underlying events.

## 11. Future Architecture Improvements

Planned improvements include:

- Expanding Active Directory security monitoring.
- Expanding Sysmon detection coverage.
- Improving alert severity and investigation workflows.

## 12. Conclusion

This lab demonstrates the implementation of a Windows security monitoring environment using Splunk Enterprise, Windows Security Event Logs, and Sysmon.

It provides hands-on experience with SIEM operations, SPL development, authentication monitoring, endpoint telemetry analysis, detection engineering, and security investigations.

The project is designed to evolve as additional monitoring capabilities, infrastructure integrations, and detection techniques are implemented.

---

**Project:** SOC Windows Security Monitoring & Threat Detection Lab
**Author:** Djibrilla Mouctar
**Technologies:** Splunk Enterprise | Windows Server 2019 | Sysmon | Windows Security Event Logs | SPL | pfSense | Active Directory
