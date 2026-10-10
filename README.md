# SOC and Windows Security Monitoring Lab

#Project Overview

This project documents my hands-on Security Operations Center (SOC) and Windows infrastructure lab. The goal is to develop practical skills in security monitoring, log analysis, detection engineering, threat hunting, and incident response.

The lab combines Windows enterprise infrastructure with centralized security monitoring using Splunk Enterprise.

#Lab Components

The environment includes the following technologies, which will be documented and validated as the project progresses:
 1. Splunk Enterprise: Security event search and analysis.
 2. Sysmon: Detailed Windows endpoint telemetry.
 3. Windows Server 2019: Windows infrastructure and Active Directory.
 4. Active Directory and Group Policy: Domain identity and policy management.
 5. Windows Event Logs: Operating system and security auditing.
 6. DNS and DHCP: Name resolution and network address management.
 7. pfSense: Network routing and firewall controls.

#Learning Objectives
  1. Understand how endpoint and Windows security logs are generated and collected.
  2. Analyze Windows Security and Sysmon events.
  3. Develop Splunk SPL searches for security investigations.
  4. Build and validate security monitoring dashboards.
  5. Investigate authentication, process execution, and network activity.
  6. Detect suspicious behavior and understand potential false positives.
  7. Practice threat hunting and incident response in an authorized lab.

#Planned Detection Use Cases

The following are planned use cases, not claims that every detection is already implemented or validated.
  1. Failed and successful logons
  2. Process creation and PowerShell activity
  3. DNS queries and network connections
  4. Encoded PowerShell and suspicious command execution
  5. LOLBins and Certutil activity
  6. Scheduled task creation
  7. Registry persistence
  8. Windows service installation
  9. LSASS process access
  10. Suspicious parent-child process relationships
  11. Remote Desktop Protocol (RDP) activity

Each completed use case will include its SPL search, explanation, relevant event IDs, investigation steps, false-positive considerations, and validation evidence where available.

#Repository Structure

  1. docs/ — Architecture and setup documentation
  2. splunk/ — SPL searches and dashboard exports
  3. sysmon/ — Sysmon configuration and event documentation
  4. windows/ — Windows logging, auditing, and hardening
  5. pfsense/ — Sanitized firewall and network documentation
  6. detections/ — Detection logic and investigation guides
  7. investigations/ — Sanitized threat-hunting reports
  8. incident-response/ — Incident response procedures
  9. screenshots/ — Sanitized lab evidence

These sections will be populated as the project is documented.

#Security Considerations

This repository will contain sanitized documentation and authorized lab examples. Credentials, passwords, tokens, private keys, sensitive network configurations, and unredacted logs will not be published.

#Project Status

In progress. This repository will evolve as I document the lab, verify log collection, develop detections, test use cases, and record investigation results.

#Skills Developed

Splunk · SPL · Windows Security Monitoring · Sysmon · Active Directory · Group Policy · Detection Engineering · Threat Hunting · Incident Response
