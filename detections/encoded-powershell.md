# Encoded PowerShell Detection

## Objective

Identify PowerShell process-creation events whose command lines contain common encoded-command arguments. Attackers may use encoded commands to make scripts harder to read during an initial review.

## Data Source

- Platform: Windows
- Telemetry: Sysmon Operational log
- Event ID: Sysmon Event ID 1 — Process Create
- Splunk source: `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`

## SPL Query

```spl
index=* earliest=-24h source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| where match(lower(Image), "powershell\.exe$")
| eval encoded_flag=if(match(lower(CommandLine), "-enc|-encodedcommand"), "Yes", "No")
| stats count by host, encoded_flag
```

## How It Works

1. Searches Sysmon process-creation events from the preceding 24 hours.
2. Filters for PowerShell executable paths.
3. Checks command lines for `-enc` or `-encodedcommand`.
4. Groups results by host and whether the command line matched the expression.

## Validation Evidence

The captured Splunk search returned 354 PowerShell process-creation events:

| Host | Not flagged | Flagged |
|---|---:|---:|
| `win11` | 342 | 0 |
| `MOUCTAR-SERV19` | 12 | 0 |
| **Total** | **354** | **0** |

These counts describe the captured search window.

## Limitations

- This is an initial matching test, not a production-ready alert.
- The expression may miss alternative encodings or command-line formats.
- Encoded PowerShell can be used for legitimate administration as well as malicious activity.
- A match would require investigation; it would not prove compromise.

## Investigation Procedure

If a match appears:

1. Review the complete command line.
2. Identify the host, user, timestamp, and parent process.
3. Inspect related Sysmon process and network events.
4. Correlate with Windows Security logs and other available telemetry.
5. Determine whether the activity is expected, suspicious, or inconclusive.

## Current Status

**Search execution:** Verified.

**Observed encoded-command matches:** Zero in the captured window.

**Detection effectiveness:** Not yet validated against known test cases.

**Confirmed malicious activity:** None established by this search.

## Detection Logic Test

### Test Method

A synthetic Splunk event was generated using `makeresults`. The event contained a sample PowerShell executable path and a command line with the `-EncodedCommand` argument.

### Test SPL

```spl
| makeresults
| eval Image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
| eval CommandLine="powershell.exe -EncodedCommand VwByAGkAdABlAC0ASABvAHMAdAAgACcAdABlAHMAdAAnAA=="
| eval encoded_flag=if(match(lower(CommandLine), "-enc|-encodedcommand"), "Yes", "No")
| table Image CommandLine encoded_flag
```

### Observed Result

- Synthetic events generated: 1
- Events flagged by the expression: 1
- Observed `encoded_flag`: `Yes`

### Conclusion

The matching expression detected the encoded-command argument in this synthetic test case.

This validates one test case only. Broader testing is still needed to assess alternative argument formats, false positives, and detection coverage.

No PowerShell payload was executed during this test.
