# Windows Failed Logon Investigation

## 1. Investigation Overview

This investigation analyzes failed Windows authentication attempts using Windows Security Event ID 4625 and Splunk Enterprise.

The objective is to identify failed authentication activity, examine affected accounts, identify source addresses, and understand possible authentication-related security issues.

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

Event ID 4625 is the primary event examined in this investigation.

## 4. SPL Investigation

The following SPL search identifies failed logon events and extracts account names and source IP addresses.

```spl
index=* host="MOUCTAR-SERV19" EventCode=4625
| rex field=Message "Account For Which Logon Failed:\s*(?:.|\n)*?Account Name:\s*(?<TargetAccount>[^\r\n]+)"
| rex field=Message "Source Network Address:\s*(?<SourceIP>[^\r\n]+)"
| stats count by TargetAccount SourceIP
| sort -count
```

This search groups failed authentication events by target account and source IP address.

## 5. Investigation Results

The following results were observed in the Splunk aggregation.

| Target Account | Source IP | Event Count |
|---|---|---:|
| Manager01 | ::1 | 31 |
| Manager01 | 127.0.0.1 | 23 |
| administrator | 127.0.0.1 | 8 |
| Djibrilla | 192.168.2.100 | 2 |
| Morty | 127.0.0.1 | 2 |
| administrators | 127.0.0.1 | 2 |
| Administrator | 127.0.0.1 | 1 |
| Manager01 | - | 1 |

The results show multiple failed authentication events involving different accounts and source addresses.

The loopback addresses ::1 and 127.0.0.1 indicate local-host communication rather than an external network source.

## 6. Individual Event Analysis

### 6.1 Djibrilla Account

One observed Event ID 4625 contained the following information:

- Target Account: Djibrilla
- Account Domain: WIN11
- Logon Type: 3
- Source Network Address: 192.168.2.100
- Failure Reason: Unknown user name or bad password.
- Status: 0xC000006D
- Sub Status: 0xC0000064

This event indicates that Windows rejected the authentication attempt because the supplied account name was not recognized or the authentication information was invalid.

Logon Type 3 represents a network logon.

### 6.2 Manager01 Account

Another observed Event ID 4625 contained:

- Target Account: Manager01
- Account Name in Subject: Administrator
- Logon Type: 2
- Source Network Address: ::1
- Failure Reason: The user has not been granted the requested logon type at this machine.

Logon Type 2 represents an interactive logon.

This event indicates that the requested logon was rejected because the account did not have the required logon permission.

## 7. Security Analysis

The investigation demonstrates how failed authentication events can help identify account-related issues and potentially suspicious activity.

Important observations include:

1. Multiple failed authentication events involved the Manager01 account.
2. Several events originated from loopback addresses.
3. Failed authentication activity involving Djibrilla originated from 192.168.2.100.
4. Different failure reasons were observed.
5. Logon types provide additional context about the authentication method.

Repeated failed logons can be associated with incorrect passwords, account configuration problems, automated services, or potential brute-force activity.

Additional investigation is necessary before classifying these events as malicious.

## 8. Recommended Investigation Steps

For future investigations:

1. Compare failed logons with successful logons.
2. Examine the source IP address and originating workstation.
3. Identify whether the affected account is privileged.
4. Review account lockout events.
5. Investigate repeated failures over short time periods.
6. Correlate authentication activity with other Windows Security events.
7. Determine whether the activity is expected administrative or application behavior.

## 9. Conclusion

This investigation demonstrates the use of Splunk Enterprise to analyze Windows failed authentication events.

By extracting target account names, source IP addresses, failure reasons, and logon types, the lab provides a practical method for investigating Windows authentication activity.

The results also demonstrate how centralized logging and SPL searches can support security monitoring, threat hunting, and incident investigation.
