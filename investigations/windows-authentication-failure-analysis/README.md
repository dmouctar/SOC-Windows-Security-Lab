# Windows Authentication Monitoring & Threat Investigation

## 1. Project Overview

This investigation documents the implementation of Windows authentication monitoring and threat detection using Splunk Enterprise.

The objective is to identify failed authentication attempts, analyze targeted accounts, investigate source IP addresses, and develop detection logic for potential brute-force activity.

## 2. Lab Environment

| Component | Configuration |
|---|---|
| SIEM | Splunk Enterprise |
| Operating System | Windows Server 2019 |
| Endpoint Monitoring | Sysmon |
| Log Sources | Windows Security Events |
| Monitored Host | MOUCTAR-SERV19 |
| Search Language | Splunk SPL |

## 3. Windows Security Auditing

Windows logon auditing was initially disabled.

The following command was used to inspect the configuration:

```powershell
auditpol /get /subcategory:"Logon"
```

Logon auditing was enabled for successful and failed authentication attempts:

```powershell
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
```

The configuration was verified:

```powershell
auditpol /get /subcategory:"Logon"
```

**Result:** Success and Failure auditing enabled.

## 4. Windows Authentication Event Analysis

The investigation focused on these Windows Security Event IDs:

| Event ID | Description |
|---|---|
| 4624 | Successful account logon |
| 4625 | Failed account logon |
| 4672 | Special privileges assigned to a new logon |

### Failed Logon Investigation — Event ID 4625

The investigation identified 71 historical failed logon events.

SPL query:

```spl
index=* host="MOUCTAR-SERV19"
source="WinEventLog:Security" EventCode=4625
| table _time host source EventCode Message
| sort -_time
```

### 4.1 Failed Logons by Account

Account names were extracted from the Windows event messages and normalized to lowercase.

```spl
index=* host="MOUCTAR-SERV19"
source="WinEventLog:Security" EventCode=4625
| rex field=_raw "(?s)Account For Which Logon Failed:.*?Account Name:\s+(?<Failed_Account>[^\r\n]+)"
| eval Failed_Account=lower(trim(Failed_Account))
| stats count by Failed_Account
| sort -count
```

**Observed results:**

| Targeted Account | Failed Attempts |
|---|---:|
| manager01 | 55 |
| administrator | 10 |
| administrators | 2 |
| djibrilla | 2 |
| morty | 2 |
| **Total** | **71** |

Manager01 represented approximately 77.5% of the observed failed authentication events.

### 4.2 Failed Logons by Source IP

The next investigation identified the source addresses associated with failed authentication attempts.

```spl
index=* host="MOUCTAR-SERV19"
source="WinEventLog:Security" EventCode=4625
| rex field=_raw "Source Network Address:\s+(?<Source_IP>[^\r\n]+)"
| stats count by Source_IP
| sort -count
```

Observed addresses included:

- `127.0.0.1` — localhost.
- `192.168.2.100` — private network address.

Further investigation is required to identify the device associated with the private network address.

## 5. Potential Brute-Force Detection

A threshold-based detection was developed to identify repeated failed authentication attempts.

**Detection criteria:**
- Five or more failed authentication attempts.
- Same source IP.
- Within a 10-minute window.
- Identify the targeted accounts.

SPL detection:

```spl
index=* host="MOUCTAR-SERV19"
source="WinEventLog:Security" EventCode=4625
| rex field=_raw "Source Network Address:\s+(?<Source_IP>[^\r\n]+)"
| rex field=_raw "(?s)Account For Which Logon Failed:.*?Account Name:\s+(?<Failed_Account>[^\r\n]+)"
| eval Failed_Account=trim(Failed_Account)
| bin _time span=10m
| stats count as Failed_Attempts values(Failed_Account) as Targeted_Accounts by _time Source_IP
| where Failed_Attempts>=5
| sort -Failed_Attempts
```

**Observed results:**

Three time windows met the detection threshold:

| Failed Attempts | Targeted Account |
|---:|---|
| 7 | Manager01 |
| 5 | Manager01 |
| 5 | administrator |

All three qualifying windows showed `127.0.0.1` as the source IP.

**Investigation note:** These results represent potential brute-force indicators, not confirmed attacks. Additional investigation is needed to determine whether local services or processes generated these authentication requests.

## 6. Authentication Process Investigation

Additional Windows event fields were extracted to investigate the authentication process.

The investigation included:
- Failed account
- Source IP address
- Logon type
- Caller process
- Event timestamp

```spl
index=* host="MOUCTAR-SERV19"
source="WinEventLog:Security" EventCode=4625
| rex field=_raw "Caller Process Name:\s+(?<Caller_Process>[^\r\n]+)"
| rex field=_raw "Logon Type:\s+(?<Logon_Type>\d+)"
| rex field=_raw "Source Network Address:\s+(?<Source_IP>[^\r\n]+)"
| rex field=_raw "(?s)Account For Which Logon Failed:.*?Account Name:\s+(?<Failed_Account>[^\r\n]+)"
| table _time Failed_Account Source_IP Logon_Type Caller_Process
| sort -_time
```

### Windows Logon Types

| Logon Type | Description |
|---|---|
| 2 | Interactive |
| 3 | Network |
| 7 | Unlock |

**Observed findings:**

- `127.0.0.1` appeared in local authentication attempts.
- `192.168.2.100` appeared in network authentication attempts.
- `svchost.exe` appeared as a caller process in some events.
- Some events did not contain caller process information.

The presence of svchost.exe does not independently indicate malicious activity.

## 7. Splunk Enterprise SOC Dashboard

The existing SOC dashboard was expanded with additional monitoring panels.

Dashboard components include:

| Dashboard Panel | Purpose |
|---|---|
| Total Sysmon Events | Monitor endpoint telemetry |
| PowerShell Executions | Monitor PowerShell activity |
| Failed Logons | Monitor failed authentication |
| Successful Logons | Monitor successful authentication |
| Network Connections | Monitor network activity |
| File Creations | Monitor file creation |
| Process Creation Timeline | Monitor process execution |
| PowerShell Activity | Visualize PowerShell execution trends |
| DNS Queries | Monitor DNS requests |
| Top Executables | Identify frequently executed programs |
| LOLBins Activity | Monitor potential living-off-the-land activity |
| Privileged Account Activity | Monitor privileged account activity |
| Potential Brute-Force Activity | Identify repeated failed authentication attempts |

### Selected Observed Metrics

| Metric | Observed Value |
|---|---:|
| Total Sysmon Events | 4,384 |
| PowerShell Executions | 568 |
| Network Connections | 10 |
| File Creations | 489 |

These are historical dashboard observations and depend on the selected time range.

## 8. Technical Skills Demonstrated

- Windows Security Auditing
- Windows Event Log Analysis
- Splunk Enterprise Administration
- Splunk Search Processing Language (SPL)
- Regular Expression Field Extraction
- Authentication Monitoring
- Failed Logon Investigation
- Source IP Analysis
- Time-Based Event Correlation
- Brute-Force Detection Logic
- SOC Dashboard Development
- Security Event Investigation

## 9. Future Improvements

Planned investigation activities:

1. Identify the device associated with `192.168.2.100`.
2. Investigate local authentication attempts associated with `svchost.exe`.
3. Correlate successful and failed logon events.
4. Improve brute-force detection and alerting.
5. Investigate Remote Desktop authentication activity.
6. Expand correlation between Windows Security Events and Sysmon telemetry.
7. Develop additional threat-hunting searches.

## 10. Conclusion

This investigation demonstrates how Windows Security Event Logs can be collected, analyzed, and monitored through Splunk Enterprise.

The lab successfully implemented Windows logon auditing, extracted authentication information, identified frequently targeted accounts, investigated source addresses, and developed a time-based detection for potential brute-force activity.

The work establishes a foundation for more advanced SOC monitoring, threat hunting, and security detection engineering.

**Project:** SOC & Windows Security Monitoring Lab  
**SIEM:** Splunk Enterprise  
**Focus:** Windows Security Monitoring, Authentication Analysis, Threat Hunting, and Detection Engineering
