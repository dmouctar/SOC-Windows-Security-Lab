# Windows Successful Logon Investigation

## 1. Investigation Overview

This investigation examines successful Windows authentication events using Security Event ID 4624 and Splunk Enterprise.

The objective is to identify authenticated accounts, understand Windows logon types, examine source IP addresses, and establish normal authentication patterns within the Windows infrastructure lab.

## 2. Data Sources

- Windows Security Event Logs
- Splunk Enterprise
- Windows Event Viewer
- Host: MOUCTAR-SERV19

## 3. Relevant Windows Event IDs

| Event ID | Description |
|---|---|
| 4624 | Successful logon |
| 4625 | Failed logon |
| 4634 | Account logged off |
| 4672 | Special privileges assigned to a new logon |

Event ID 4624 is the primary event examined in this investigation.

## 4. SPL Investigation

The following SPL search extracts account names, domains, logon types, and source IP addresses.

```spl
index=* host="MOUCTAR-SERV19" source="WinEventLog:Security" EventCode=4624
| rex field=Message "New Logon:\s+Security ID:\s+[^\r\n]+\s+Account Name:\s+(?<TargetAccount>[^\r\n]+)\s+Account Domain:\s+(?<TargetDomain>[^\r\n]+)"
| rex field=Message "Logon Type:\s+(?<LogonType>\d+)"
| rex field=Message "Source Network Address:\s+(?<SourceIP>[^\r\n]+)"
| stats count by TargetAccount TargetDomain LogonType SourceIP
| sort -count
```

## 5. Investigation Results

The search returned 31,232 successful authentication events and 49 distinct combinations of extracted account, domain, logon type, and source IP fields.

Selected observations:

| Account | Domain | Logon Type | Source IP | Count |
|---|---|---:|---|---:|
| MOUCTAR-SERV19$ | MOUCTAR.PRI | 3 | ::1 | 11,010 |
| MOUCTAR-SERV19$ | MOUCTAR.PRI | 3 | fe80::258e:3ab3:6454:a1dd | 7,959 |
| SYSTEM | NT AUTHORITY | 5 | - | 5,989 |
| MOUCTAR-SERV19$ | MOUCTAR.PRI | 3 | 192.168.2.102 | 1,929 |
| MOUCTAR-SERV19$ | MOUCTAR.PRI | 3 | - | 1,868 |
| WIN11$ | MOUCTAR.PRI | 3 | 192.168.2.100 | 435 |

These observations represent selected rows from the Splunk results.

## 6. Logon Type Analysis

| Logon Type | Description |
|---|---|
| 2 | Interactive |
| 3 | Network |
| 5 | Service |
| 7 | Unlock |
| 10 | Remote Interactive |

The observed results include network logons (Type 3) and service logons (Type 5).

## 7. Security Analysis

Several observations are relevant to understanding authentication behavior:

1. The MOUCTAR-SERV19$ computer account generated a high volume of network logons.
2. The SYSTEM account generated service logon events.
3. Local IPv6 loopback traffic appeared in the authentication records.
4. Multiple IPv4 and IPv6 addresses appeared in the extracted results.
5. Authentication events provide a baseline for identifying unusual account and source-address combinations.

High authentication volume does not independently indicate malicious activity. The events must be evaluated against expected Windows and Active Directory behavior.

## 8. Recommended Investigation Steps

1. Map source IP addresses to their corresponding lab devices.
2. Identify unexpected account authentication patterns.
3. Review successful logons following repeated failed logon attempts.
4. Investigate privileged account authentication.
5. Correlate logon events with process creation and network activity.
6. Review logon types associated with remote access.

## 9. Conclusion

This investigation demonstrates how Splunk Enterprise can extract and analyze successful Windows authentication events.

By examining account names, domains, logon types, and source addresses, the lab establishes a foundation for authentication monitoring and threat hunting.

The results will support future correlation between successful logons, failed logons, and account logoff events.
