# Process Creation Analysis — SPL Search

## Objective

Analyze process-creation events across monitored Windows systems using Splunk Enterprise. The results help establish which processes are running and which parent processes launched them.

## SPL Query

```spl
index=* earliest=-24h
| search EventCode=1 OR EventID=1
| stats count by host, Image, ParentImage
| sort - count
```

## Command-by-Command Explanation

### 1. Select the search scope

```spl
index=* earliest=-24h
```

Searches all indexes accessible to the user for the preceding 24 hours.

Using `index=*` is useful for initial discovery, but a known index should be specified in production searches to improve efficiency.

### 2. Filter candidate events

```spl
| search EventCode=1 OR EventID=1
```

Keeps events where either field matches the value 1. Sysmon Event ID 1 represents Process Create.

The field names and event source must be validated before treating every matching record as a confirmed Sysmon event.

### 3. Aggregate by host and process relationship

```spl
| stats count by host, Image, ParentImage
```

Groups the matching events by host, process image, and parent process image. The `count` column shows the number of events in each group.

- `host`: The reporting host.
- `Image`: The executable associated with the event.
- `ParentImage`: The executable that launched the process.
- `count`: Number of matching events in each group.

### 4. Sort the results

```spl
| sort - count
```

Sorts the groups by count in descending order, placing the most frequently observed combinations first.

## Observed Results

In the captured Splunk session:

- The search reported 1,129 matching events.
- The Statistics tab displayed 311 result rows.
- Results included hosts labeled `win11` and `MOUCTAR-SERV19`.
- Process and parent-process paths were populated in the displayed results.
- Examples included `svchost.exe`, `cmd.exe`, and Splunk Universal Forwarder executables.

These counts describe the captured search session and are not permanent baselines.

## Security Investigation Value

Process-creation telemetry helps analysts investigate:

- Unexpected command interpreters such as `cmd.exe` or PowerShell.
- Unusual parent-child process relationships.
- Suspicious execution paths.
- Potential misuse of administrative tools.
- Unexpected activity on servers or workstations.

High event counts alone do not prove malicious behavior. Legitimate Windows services, software updates, and monitoring agents can generate substantial process activity.

## Validation Status

**Search execution:** Verified by screenshot.

**Event source and sourcetype:** Pending verification.

**Detection accuracy:** Not yet validated.

This is an initial process-creation analysis search, not a confirmed malicious-activity alert.

## Next Steps

1. Verify the source and sourcetype of matching events.
2. Inspect a representative event's raw details.
3. Confirm the event is Sysmon Event ID 1.
4. Develop a focused detection hypothesis and test it against benign and suspicious activity.
