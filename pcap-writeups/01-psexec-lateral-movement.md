# Threat Investigation Report: PsExec Service Execution & Lateral Movement

**File:** `automation-scripts/psexec_attack.pcap`  
**Severity:** CRITICAL  
**Category:** Lateral Movement / Service Execution  
**MITRE ATT&CK:** [T1569.002 - System Services: Service Execution](https://attack.mitre.org/techniques/T1569/002/), [T1021.002 - Remote Services: SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002/)

---

## Executive Summary

During a routine network threat hunt, automated detection rules flagged suspicious Server Message Block (SMB) and Service Control Manager (SCM) RPC traffic originating from `10.0.0.50` targeted at `10.0.0.5`. Packet analysis confirmed remote service creation and execution behavior characteristic of Sysinternals PsExec.

---

## Technical Analysis

### 1. SMB Administrative Share Connection
The attacker initiated an SMB2 Session Setup followed by a Tree Connect request to the `IPC$` (Inter-Process Communication) administrative share.

* **Source IP:** `10.0.0.50`
* **Destination IP:** `10.0.0.5`
* **Target Share:** `\\10.0.0.5\IPC$`

### 2. Service Control Manager (svcctl) Pipe Access
Following share authentication, a named pipe request was opened to `svcctl` (Service Control Manager Remote Protocol).

```text
SMB2 Protocol:
└── Tree Connect: \\10.0.0.5\IPC$
    └── Create Request File: \svcctl
