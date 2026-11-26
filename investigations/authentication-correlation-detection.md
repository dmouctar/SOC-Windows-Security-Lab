
# Windows Authentication Correlation Detection

## 1. Objective

Develop a Splunk detection that correlates failed Windows authentication attempts (Event ID 4625) with subsequent successful logins (Event ID 4624).

The objective is to identify accounts that experience a failed login followed by a successful authentication within a 10-minute window.

## 2. Detection Logic

The detection performs the following operations:

1. Collects Windows Security Event IDs 4624 and 4625.
2. Extracts account names and source IP addresses.
3. Normalizes account names.
4. Classifies events as Successful or Failed.
5. Groups events by account and source IP.
6. Compares each successful login with the preceding authentication event.
7. Identifies successful logins occurring within 600 seconds of a failure.

## 3. SPL Query

```spl
index=* host="MOUCTAR-SERV19"
source="WinEventLog:Security" (EventCode=4624 OR EventCode=4625)

| rex field=_raw "(?s)New Logon:.*?Account Name:\s+(?<Success_Account>[^\r\n]+)"
| rex field=_raw "(?s)Account For Which Logon Failed:.*?Account Name:\s+(?<Failed_Account>[^\r\n]+)"
| rex field=_raw "Source Network Address:\s+(?<Source_IP>[^\r\n]+)"

| eval Account=lower(trim(coalesce(Success_Account,Failed_Account)))
| eval Result=if(EventCode=4625,"Failed","Successful")
| eval Source_IP=trim(Source_IP)

| where Account!="" AND Source_IP!="" AND Source_IP!="-"

| sort 0 Account Source_IP _time

| streamstats current=f last(Result) as Previous_Result last(_time) as Previous_Time by Account Source_IP

| eval Seconds_After_Failure=_time-Previous_Time

| where Result="Successful"
    AND Previous_Result="Failed"
    AND Seconds_After_Failure>=0
    AND Seconds_After_Failure<=600

| eval Seconds_After_Failure=round(Seconds_After_Failure,2)

| table _time Account Source_IP Previous_Result Result Seconds_After_Failure
| sort -_time
```

## 4. Investigation Results

The query returned seven matching authentication sequences.

| Metric | Result |
|---|---:|
| Correlated sequences | 7 |
| Shortest interval | 5.50 seconds |
| Longest interval | 28.87 seconds |
| Observed source IP | 127.0.0.1 |
| Accounts observed | administrator, morty |

## 5. Security Analysis

The results demonstrate that Splunk can correlate failed and successful authentication events using account identity, source IP, and event timestamps.

All seven observed sequences originated from 127.0.0.1, the IPv4 loopback address.

This indicates locally sourced activity in the recorded events. The results alone do not establish malicious activity or an external brute-force attack.

Further investigation is required to determine the processes and activities responsible for these authentication sequences.

## 6. Limitations

- Only the immediately preceding authentication event is compared.
- Multiple failures followed by a success may require additional correlation logic.
- Local loopback events can complicate source attribution.
- Missing source IP fields are excluded.
- Event extraction depends on the Windows Security event message format.

## 7. Conclusion

This investigation demonstrates authentication event correlation using Splunk SPL.

The detection provides a foundation for identifying suspicious authentication sequences and developing more advanced Windows security monitoring capabilities.
