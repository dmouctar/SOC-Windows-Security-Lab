# Registry Utility Investigation — Sysmon

## Objective

Investigate registry utility execution recorded by Sysmon process-creation telemetry and establish whether the observed command warrants further security review.

## Data Source

- Platform: Windows Server
- Host: `MOUCTAR-SERV19`
- Source: `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`
- Event type: Sysmon Event ID 1 — Process Create

## SPL Query

```spl
index=* earliest=-24h source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| where match(lower(Image), "\\\\reg\.exe$")
| table _time host User ParentImage Image CommandLine
| sort - _time
```

## Observed Evidence

The captured search returned one matching event.

- Parent process: `C:\Windows\System32\cmd.exe`
- Executable: `C:\Windows\System32\reg.exe`
- User: `NT AUTHORITY\SYSTEM`
- Command: Query the `SoftwareInventoryLogging` registry key for the `collectionstate` value using the 64-bit registry view.

## Initial Assessment

The command reads a registry value rather than explicitly modifying it. Its target is consistent with a software inventory or management function.

The initiating application and the reason for the query have not been confirmed. The event is therefore documented as observed activity, not a confirmed security incident.

## Investigation Steps

1. Review the complete command line and timestamp.
2. Identify the parent process and any related process-creation events.
3. Determine which scheduled task, service, or management component initiated the command, if possible.
4. Correlate with nearby Sysmon and Windows logs.
5. Record the final classification and supporting evidence.

## Validation Status

**Matching events observed:** 1.

**Malicious activity confirmed:** No.

**Detection effectiveness:** Not yet evaluated against known suspicious and benign test cases.
