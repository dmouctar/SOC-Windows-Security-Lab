# SOC Lab Architecture

## Purpose

This document will describe the architecture of my Windows security monitoring lab and how its components communicate.

## Components to Document

| Component | Purpose | Verification status |
|---|---|---|
| Splunk Enterprise | Centralized log search and analysis | To document |
| Sysmon | Endpoint telemetry | To document |
| Windows Server 2019 | Server and domain infrastructure | To document |
| Active Directory | Centralized identity management | To document |
| Group Policy | Centralized Windows configuration | To document |
| DNS and DHCP | Network services | To document |
| pfSense | Network routing and firewalling | To document |
| Windows endpoints | Sources of endpoint and security events | To document |

## Logging Flow

The intended documentation will trace events from their generation on Windows systems through collection and forwarding into Splunk.

The exact forwarding configuration, Splunk roles, indexes, hostnames, and data sources will be recorded after they are verified in the lab.

## Architecture Diagram

To be added after the actual VM and network configuration has been reviewed.

## Security Notes

Sensitive IP addresses, credentials, private keys, and other confidential configuration details will be excluded from the public documentation.
