# Wireshark Display Filter Cheat Sheet: SMB & NTLM Threat Hunting

A targeted collection of Wireshark display filters designed for identifying Active Directory anomalies, administrative share access, and NTLM authentication hazards during packet analysis.

---

## 1. SMB Administrative Shares & Lateral Movement

| Objective | Wireshark Display Filter |
| :--- | :--- |
| **Admin Share Connections** | `smb2.tree == "IPC$" || smb2.tree == "C$" || smb2.tree == "ADMIN$"` |
| **PsExec & Service Execution** | `smb2.filename contains "PSEXESVC" || smb2.filename contains "svcctl"` |
| **File Write Actions over SMB** | `smb2.cmd == 6 && smb2.create.disposition == 1` |

---

## 2. NTLM Authentication & Downgrade Attacks

| Objective | Wireshark Display Filter |
| :--- | :--- |
| **All NTLMSSP Traffic** | `ntlmssp` |
| **NTLM Negotiate Flags** | `ntlmssp.messagetype == 0x00000001` |
| **NTLM Challenge / Response** | `ntlmssp.messagetype == 0x00000003` |
| **Filter Out Kerberos Traffic** | `smb2 && !kerberos` |

---

## 3. Threat Hunting Combo Filter

Isolate lateral movement and legacy authentication attempts in a single view:

```text
(smb2.tree contains "$" || smb2.filename contains "svcctl") && ntlmssp
