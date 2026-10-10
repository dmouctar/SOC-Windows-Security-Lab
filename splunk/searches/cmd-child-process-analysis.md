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

**Observed event count:** 35.

**Confirmed malicious activity:** None established.

**Next step:** Inspect individual command lines and determine whether any process relationship warrants a detection rule.

## Individual Event Investigation

### Evidence Reviewed

A Splunk search returned 35 Sysmon process-creation events where `cmd.exe` was the parent process.

The visible records included events from `win11` and `MOUCTAR-SERV19`, running under `NT AUTHORITY\SYSTEM`.

### Observed Command Lines

Examples from the captured events included:

- `ping -n 2 127.0.0.1`
- `FindStr /L \Google\GoogleUpdater`
- Splunk Universal Forwarder internal checks
- Splunk `bttool` server-list operations

### Initial Assessment

The loopback ping is consistent with a local connectivity test. The Google Updater-related command is consistent with software-update activity. The Splunk-related commands appear consistent with monitoring-agent operations.

These interpretations are preliminary. The full process chain, executable signatures, and surrounding events would be needed for stronger confirmation.

### Investigation Method

1. Identify the timestamp, host, and user.
2. Inspect the parent and child process paths.
3. Review the complete command line.
4. Determine whether the activity matches expected software or administration behavior.
5. Correlate with nearby events and other telemetry.
6. Record the conclusion and any remaining uncertainty.

### Conclusion

The captured records demonstrate how Sysmon process-creation telemetry supports investigation of command-line activity. No confirmed malicious behavior was established from the reviewed sample.

### Status

**Search execution:** Verified.

**Individual command lines:** Inspected in the visible sample.

**Incident classification:** Inconclusive at the overall case level; the visible examples appear consistent with routine activity.

**Detection rule:** Not yet implemented.

## Command-Line Telemetry Validation

### SPL Query

```spl
index=* earliest=-24h source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| eval command_line_present=if(isnotnull(CommandLine) AND len(CommandLine)>0,"Yes","No")
| stats count by host, command_line_present
```

### Observed Results

The captured search returned 1,890 events.

| Host | Command line present | Command line missing |
|---|---:|---:|
| MOUCTAR-SERV19 | 358 | 0 |
| win11 | 1,532 | 0 |
| **Total** | **1,890** | **0** |

### Interpretation

Every event returned by this search had a nonempty `CommandLine` field.

This supports using command-line fields for further investigation and detection development in the current dataset. It does not establish that command-line logging will always be complete or that the captured commands are malicious.

### Validation Status

**Command-line field coverage:** Verified for the captured search results.

**Detection accuracy:** Not yet evaluated.
