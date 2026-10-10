# CMD Child Process Analysis

## Objective

Analyze processes launched by `cmd.exe` using Sysmon process-creation telemetry. This search establishes a baseline for command-interpreter activity and helps identify process relationships for further investigation.

## SPL Query

```spl
index=* earliest=-24h source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| where match(lower(ParentImage), "\\\\cmd\.exe$")
| stats count by host, Image, ParentImage
| sort - count
```

## Observed Results

The captured Splunk search returned 35 matching events grouped into 11 host, child-process, and parent-process combinations.

Observed child processes included Splunk Universal Forwarder components, `splunk.exe`, `PING.EXE`, `findstr.exe`, `reg.exe`, and `cmd.exe`.

## Interpretation

- Splunk-related executables may represent routine monitoring-agent activity.
- `PING.EXE` may represent connectivity troubleshooting.
- `findstr.exe` may be used for text filtering or administrative scripts.
- `reg.exe` can be used for legitimate registry administration or registry-related attacker activity.

The process name alone is insufficient to determine whether an event is malicious.

## Investigation Steps

1. Identify the specific event and timestamp.
2. Inspect the complete command line.
3. Review the user and host context.
4. Examine the parent and child process relationship.
5. Correlate with nearby Sysmon and Windows Security events.
6. Document whether the activity is expected, suspicious, or inconclusive.

## Validation Status

**Search execution:** Verified by screenshot.

**Observed event count:** 35.

**Confirmed malicious activity:** None established.

**Next step:** Inspect individual command lines and determine whether any process relationship warrants a detection rule.
