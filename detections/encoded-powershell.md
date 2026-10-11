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
