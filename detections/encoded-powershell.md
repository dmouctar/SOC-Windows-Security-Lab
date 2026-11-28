# Encoded PowerShell Detection and Investigation

## 1. Overview

This document covers the development, implementation, and validation of an SPL-based detection designed to identify potentially suspicious PowerShell execution involving encoded-command arguments.

PowerShell is a legitimate Windows administration tool. However, attackers may abuse it to execute commands, download files, run scripts, and perform malicious activities.

Encoding command-line arguments can make scripts harder to read during an initial investigation.

The objective of this detection is to identify PowerShell process-creation events containing common encoded-command arguments and provide a starting point for further security investigation.

## 2. Lab Environment and Data Sources

| Component | Configuration |
|---|---|
| SIEM | Splunk Enterprise |
| Operating System | Windows |
| Endpoint Telemetry | Sysmon |
| Event ID | Sysmon Event ID 1 |
| Event Description | Process Creation |
| Splunk Source | `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` |
| Detection Host | `MOUCTAR-SERV19` and `win11` |

Sysmon Event ID 1 records process creation activity, including executable paths, command-line arguments, and process relationships when configured and collected.

## 3. Detection Objective

The detection focuses on identifying:

- PowerShell process execution.
- Encoded-command arguments.
- Potentially suspicious command-line activity.
- PowerShell execution across monitored Windows endpoints.

The detection currently examines two command-line indicators:

- `-enc`
- `-encodedcommand`

These indicators are used to identify potentially encoded PowerShell execution.

A matching command line does not automatically indicate malicious activity.

## 4. SPL Detection Query

The following search was implemented in Splunk Enterprise:

```spl
index=* earliest=-24h source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| where match(lower(Image), "powershell\\.exe$")
| eval encoded_flag=if(match(lower(CommandLine), "-enc|-encodedcommand"), "Yes", "No")
| stats count by host, encoded_flag
```

### 4.1 SPL Breakdown

| SPL Command | Purpose |
|---|---|
| `index=*` | Searches available indexes |
| `earliest=-24h` | Restricts the search to the preceding 24 hours |
| `source=...` | Selects Sysmon Operational events |
| `EventCode=1` | Filters for process creation |
| `where match()` | Filters for PowerShell executable paths |
| `eval` | Creates an encoded-command classification field |
| `stats count` | Counts events by host and classification |

### 4.2 Detection Logic

The search performs the following operations:

1. Retrieves Sysmon process-creation events.
2. Filters events associated with `powershell.exe`.
3. Examines the command line for encoded-command indicators.
4. Assigns either `Yes` or `No` to the `encoded_flag` field.
5. Groups results by hostname and detection classification.

## 5. Initial Detection Results

The initial Splunk search returned 354 PowerShell process-creation events.

### 5.1 Observed Results

| Host | Not Flagged | Flagged | Total |
|---|---:|---:|---:|
| `win11` | 342 | 0 | 342 |
| `MOUCTAR-SERV19` | 12 | 0 | 12 |
| **Total** | **354** | **0** | **354** |

### 5.2 Analysis

The search identified 354 PowerShell process-creation events across two monitored Windows systems.

No command lines matched the encoded-command indicators during the captured search window.

This establishes an initial observation of PowerShell activity within the lab.

However, zero matches do not establish that encoded PowerShell activity is impossible or that the environment is free from malicious activity.

## 6. Detection Logic Validation

To verify that the detection expression works as intended, synthetic Splunk events were generated using `makeresults`.

These tests allowed the detection logic to be evaluated without executing an actual PowerShell payload.

### 6.1 Encoded Command Test

**Objective:** Verify that the detection identifies a command line containing `-EncodedCommand`.

Test SPL:

```spl
| makeresults
| eval Image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
| eval CommandLine="powershell.exe -EncodedCommand VwByAGkAdABlAC0ASABvAHMAdAAgACcAdABlAHMAdAAnAA=="
| eval encoded_flag=if(match(lower(CommandLine), "-enc|-encodedcommand"), "Yes", "No")
| table Image CommandLine encoded_flag
```

**Observed results:**

| Test Attribute | Result |
|---|---|
| Synthetic events generated | 1 |
| Encoded-command argument | Present |
| Observed classification | Yes |
| Expected classification | Yes |
| Outcome | Pass |

The detection expression successfully identified the encoded-command argument in this test.

### 6.2 Normal PowerShell Command Test

**Objective:** Verify that an ordinary PowerShell command is not incorrectly classified as encoded.

Test command line:

```text
powershell.exe -ExecutionPolicy Restricted -Command Write-Host test
```

Test SPL:

```spl
