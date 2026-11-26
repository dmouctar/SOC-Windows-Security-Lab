# Windows Authentication Correlation Investigation

## 1. Investigation Overview

This investigation correlates successful and failed Windows authentication events using Splunk Enterprise.

The objective is to identify successful logons that occur within 15 minutes of previous failed authentication attempts involving the same account and source IP address.

This investigation uses Windows Security Event IDs 4624 and 4625.

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

## 4. Detection Methodology

The investigation uses the following process:

1. Collect successful and failed authentication events.
2. Extract account names and source IP addresses.
3. Normalize account names to lowercase.
4. Sort authentication events chronologically.
5. Use Splunk `streamstats` with a 15-minute time window.
6. Identify successful logons preceded by failed attempts.
7. Display matching events for further investigation.

## 5. SPL Detection Logic

```spl
index=* host="MOUCTAR-SERV19" source="WinEventLog:Security"
(EventCode=4624 OR EventCode=4625)

| rex field=Message "(?s)New Logon:.*?Account Name:\s*(?<SuccessAccount>[^\r\n]+)"

| rex field=Message "(?s)Account For Which Logon Failed:.*?Account Name:\s*(?<FailedAccount>[^\r\n]+)"

| rex field=Message "(?s)Source Network Address:\s*(?<SourceIP>[^\r\n]+)"

| rex field=Message "Logon Type:\s*(?<LogonType>\d+)"

| eval Account=if(EventCode=4625,FailedAccount,SuccessAccount)

| eval Account=lower(trim(Account))
| eval SourceIP=trim(SourceIP)

| eval Result=if(EventCode=4625,"Failed","Successful")

| sort 0 _time

| streamstats time_window=15m
    count(eval(Result="Failed")) as Failed_In_Previous_15m
    by Account SourceIP

| where Result="Successful" AND Failed_In_Previous_15m>0

| table _time Account SourceIP LogonType Failed_In_Previous_15m EventCode Result

| sort -_time
```

## 6. Investigation Results

The Splunk search successfully returned 10 matching authentication events.

Observed results included:

| Account | Source IP | Failed attempts in window |
|---|---|---:|
| administrator | 127.0.0.1 | 1 |
| administrator | 127.0.0.1 | 5 |
| morty | 127.0.0.1 | 2 |

Additional matching events were returned for these accounts.

### Key Observations

- Successful authentication events were identified following failed attempts.
- The observed source IP address was 127.0.0.1.
- Logon Type 2 represented interactive authentication.
- Logon Type 7 represented workstation unlock activity.
- Account capitalization was normalized to improve correlation.

## 7. Security Analysis

Repeated failed authentication attempts followed by successful authentication can indicate potentially suspicious authentication behavior.

However, the results from this investigation do not independently establish malicious activity.

The observed loopback address indicates locally originated authentication activity rather than evidence of a remote attack.

Further investigation should examine:

- Authentication frequency and timing.
- Account ownership and expected behavior.
- Windows logon types.
- Related Event IDs 4672 and 4634.
- Associated process and service activity.
- Whether authentication failures were caused by outdated credentials or legitimate user activity.

## 8. False Positive Considerations

Potential false positives include:

- Users entering incorrect passwords.
- Applications attempting authentication with outdated credentials.
- Windows services performing local authentication.
- Workstation unlock attempts.
- Automated background processes.

## 9. Conclusion

This investigation demonstrates how Splunk Enterprise can correlate Windows authentication events across a 15-minute time window.

The search successfully identified 10 matching events involving failed authentication attempts followed by successful logons.

The investigation demonstrates practical experience with SPL, Windows Security Event IDs, event extraction, time-based correlation, and authentication threat hunting.

**Status:** Implemented and tested in the SOC lab.

**Environment:** Authorized Windows and Splunk home lab.
