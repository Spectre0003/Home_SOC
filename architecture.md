# Home SOC — Architecture

## 1. Project Overview

This project is a self-hosted Security Operations Center (SOC) lab built using VMware virtualization.

The purpose of the lab is to simulate a small enterprise-style security monitoring environment where security activity can be generated, collected, detected, investigated, and documented.

The core workflow is:

```text
Endpoints → Telemetry → Collection → SIEM → Detection → Investigation → Response
```

---

## 2. Virtualization

Virtualization platform:

- VMware Workstation

The lab currently consists of three virtual machines:

| Machine | Role | Operating System |
|---|---|---|
| Kali | Analyst / Attacker | Kali Linux |
| Ubuntu | Monitored Linux Endpoint | Ubuntu Server 24.04.4 LTS |
| Windows | Monitored Windows Endpoint | Windows 11 Pro 25H2 |

---

## 3. Network Architecture

The lab uses two VMware virtual networks.

### VMnet8 — NAT

Purpose:

- Internet connectivity for the virtual machines
- Software updates
- Package installation

Network:

```text
192.168.67.0/24
```

Gateway:

```text
192.168.67.2
```

### VMnet1 — SOC-LAB

Purpose:

- Isolated communication between SOC machines
- Attack simulation
- Monitoring and investigation traffic

Network:

```text
192.168.8.0/24
```

VMnet1 is configured as a Host-only network.

The SOC-LAB network does not use a default gateway on the endpoint interfaces.

The Home SOC uses an isolated VMware network for communication between the
analyst machine and monitored endpoints.

### SOC-LAB Network

- Network: `192.168.8.0/24`
- VMware Network: `VMnet1`
- Network purpose: Internal SOC communication and attack simulation

| System | Role | IP Address |
|---|---|---|
| Kali Linux | SOC Analyst / Attack Simulation | `192.168.8.128` |
| Ubuntu | Linux Endpoint | `192.168.8.129` |
| Windows 11 | Windows Endpoint | `192.168.8.130` |

### Ubuntu Network Configuration

Ubuntu has two network interfaces:

| Interface | Network | IP | Purpose |
|---|---|---|---|
| `ens33` | `192.168.67.0/24` | `192.168.67.129` | NAT / Internet |
| `ens34` | `192.168.8.0/24` | `192.168.8.129` | SOC-LAB |

The default route uses the NAT interface:

```text
default via 192.168.67.2 dev ens33
```

---

## 4. Current IP Address Allocation

| Machine | Interface | Network | IP Address | Purpose |
|---|---|---|---|---|
| Kali | eth0 | VMnet8 | 192.168.67.128 | Internet |
| Kali | eth1 | VMnet1 | 192.168.8.128 | SOC-LAB |
| Ubuntu | ens33 | VMnet8 | 192.168.67.129 | Internet |
| Ubuntu | ens34 | VMnet1 | 192.168.8.129 | SOC-LAB |
| Windows | Ethernet0 | VMnet8 | 192.168.67.130 | Internet |
| Windows | Ethernet1 | VMnet1 | 192.168.8.130 | SOC-LAB |

> IP addresses are currently assigned through VMware DHCP and may change if the virtual machines are recreated or their DHCP leases change.

---

## 5. Network Topology

```text
                         HOST MACHINE
                              │
                           VMware
                              │
                 ┌────────────┴────────────┐
                 │                         │
              VMnet8                    VMnet1
               NAT                    SOC-LAB LAN
        192.168.67.0/24             192.168.8.0/24
                 │                         │
        ┌────────┼────────┐       ┌────────┼────────┐
        │        │        │       │        │        │
      Kali    Ubuntu   Windows   Kali    Ubuntu   Windows
      .67.128 .67.129  .67.130  .8.128   .8.129   .8.130
        │        │        │       │        │        │
        └────────┴────────┘       └────────┴────────┘
             Internet                 SOC-LAB
```

---

## 6. Virtual Machine Resources

### Kali

Role:

- SOC analyst workstation
- Attack simulation workstation
- Security tools

Current allocation:

- RAM: 4 GB
- CPU: 2 cores

### Ubuntu

Role:

- Monitored Linux endpoint
- SSH server
- Linux telemetry source

Current allocation:

- RAM: 4 GB
- CPU: 2 cores
- Disk: 40 GB

### Windows

Role:

- Monitored Windows endpoint
- Windows telemetry source
- Sysmon endpoint

Current allocation:

- RAM: 4 GB
- CPU: 2 cores
- Disk: 64 GB
- Virtual TPM: Present
- Firmware: UEFI
- Secure Boot: Enabled

---

## 7. Connectivity Verification

The following connectivity has been verified.

### Internet

- Kali → Internet: Verified
- Ubuntu → Internet: Verified
- Windows → Internet: Verified

### SOC-LAB

- Kali → Ubuntu: Verified
- Kali → Windows: Verified
- Windows → Ubuntu: Verified

### SSH

Kali successfully connected to Ubuntu through the isolated SOC-LAB network:

```text
Kali
192.168.8.128
    │
    │ SSH / TCP 22
    ▼
Ubuntu
192.168.8.129
```

SSH connectivity was successfully established using:

```bash
ssh socadmin@192.168.8.129
```

---

## 8. Current Project State

### Completed

- [x] VMware environment configured
- [x] VMnet8 NAT network verified
- [x] VMnet1 SOC-LAB network created
- [x] Kali configured
- [x] Ubuntu Server installed
- [x] Ubuntu SSH server configured
- [x] Kali → Ubuntu SSH connectivity verified
- [x] Windows 11 Pro installed
- [x] Windows networking configured
- [x] Windows hostname configured
- [x] Windows → Ubuntu connectivity verified
- [x] Clean Windows baseline snapshot created


---

## 9. Design Philosophy

The lab is being built incrementally rather than by installing a complete SOC stack immediately.

Each component will be introduced only after understanding:

1. What telemetry it generates
2. Why the telemetry is useful
3. How the telemetry is collected
4. How it can be detected
5. How an analyst can investigate it

The goal is to understand the complete security workflow rather than simply deploying a SIEM.

---

## 10. Planned SOC Architecture

The final architecture is expected to follow this general model:

```text
                    ATTACK / USER ACTIVITY
                             │
              ┌──────────────┴──────────────┐
              │                             │
           Windows                        Linux
           Endpoint                      Endpoint
              │                             │
       Event Logs / Sysmon          journald / auth logs
              │                             │
              └──────────────┬──────────────┘
                             │
                      Log Collection
                             │
                             ▼
                         SIEM / Storage
                             │
                             ▼
                         Detection
                             │
                             ▼
                           Alert
                             │
                             ▼
                       Investigation
                             │
                             ▼
                          Response
                             │
                             ▼
                       Documentation
```

---

## 11. Future Components

The following components are planned for later phases of the project:

### Windows Telemetry

- Windows Security Event Logs
- Windows System and Application Logs
- PowerShell logging
- Sysmon

### Linux Telemetry

- systemd journal
- Authentication logs
- SSH activity
- Linux audit telemetry

### Security Monitoring

- Centralized log collection
- SIEM
- Detection rules
- Alert triage
- IOC analysis
- Threat hunting

### Investigation

- Event correlation
- Incident timelines
- Process analysis
- Authentication analysis
- Network activity analysis
- MITRE ATT&CK mapping

### Response

- Containment
- Evidence collection
- Account/session investigation
- Remediation
- Incident documentation

---

## 12. Project Objective

The objective of the Home SOC is not simply to install and configure security tools.

The project aims to demonstrate the complete SOC workflow:

```text
Generate Activity
       ↓
Collect Telemetry
       ↓
Detect Activity
       ↓
Generate Alert
       ↓
Triage Alert
       ↓
Investigate
       ↓
Determine Cause and Impact
       ↓
Respond
       ↓
Document the Incident
```

The final lab should demonstrate how raw endpoint activity can be transformed into actionable security information.