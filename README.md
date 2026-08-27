# Home SOC Lab

A personal cybersecurity lab designed to simulate a small Security Operations Center (SOC) environment using multiple virtual machines.

The project is being built incrementally to understand how security monitoring, logging, network traffic, authentication events, and incident investigation work in a controlled environment.

---

## Objectives

The main goals of this project are to:

- Build a functional home SOC environment from scratch.
- Understand how endpoints generate security telemetry.
- Collect and analyze Windows and Linux logs.
- Monitor network traffic between systems.
- Generate controlled security events.
- Investigate authentication and network activity.
- Develop practical SOC analysis and incident-response skills.
- Eventually automate portions of the monitoring and analysis process.

---

## Lab Architecture

The current environment consists of three virtual machines:

| System | Role | IP Address |
|---|---|---|
| Kali Linux | Security testing / analyst workstation | `192.168.8.128` |
| Ubuntu | SOC server / monitoring infrastructure | `192.168.8.129` |
| Windows 11 | Monitored endpoint | `192.168.8.130` |

The systems communicate through a dedicated VMware virtual network.

### Network Layout

```text
                    Home SOC Lab Network
                         192.168.8.0/24

       ┌────────────────────┐
       │     Kali Linux     │
       │  Analyst / Testing │
       │   192.168.8.128    │
       └─────────┬──────────┘
                 │
                 │
       ┌─────────┴──────────┐
       │    SOC Network     │
       │   192.168.8.0/24  │
       └─────────┬──────────┘
                 │
        ┌────────┴─────────┐
        │                  │
┌───────▼────────┐ ┌───────▼──────────┐
│     Ubuntu     │ │    Windows 11    │
│   SOC Server   │ │ Monitored Endpoint│
│ 192.168.8.129  │ │  192.168.8.130   │
└────────────────┘ └──────────────────┘
```

The Windows and Ubuntu systems also have separate network connectivity for Internet access:

- Ubuntu:
  - SOC interface: `192.168.8.129`
  - Internet-facing interface: `192.168.67.129`

- Windows:
  - SOC interface: `192.168.8.130`
  - Internet-facing interface: `192.168.67.130`

This separation allows the SOC network to remain distinct from the normal Internet-facing network.

For the detailed architecture and network configuration, see:

- [`architecture.md`](architecture.md)

---

## Current Environment

### Kali Linux

Kali Linux acts as the security testing and analyst machine.

It is used to:

- Test network connectivity.
- Interact with the monitored endpoint.
- Generate controlled authentication activity.
- Test SMB connectivity.
- Perform security testing against the lab systems.

### Ubuntu

Ubuntu acts as the SOC infrastructure/server machine.

It is currently configured with:

- Ubuntu Server
- SSH
- A dedicated SOC network interface
- Connectivity to Kali
- Connectivity to the Windows endpoint

Ubuntu is currently operating as a CLI-based server rather than a graphical desktop environment.

### Windows 11

Windows 11 acts as the monitored endpoint.

It is used to generate endpoint telemetry such as:

- Successful logons
- Failed logons
- Network authentication
- SMB activity
- Windows Security Event Logs

The Windows machine is configured with the local account:

```text
socadmin
```

The account is a member of the local `Administrators` group for lab purposes.

---

# Completed Setup

## 1. Virtual Machines

The initial virtual lab environment has been created using VMware.

Current systems:

- Kali Linux
- Ubuntu
- Windows 11

---

## 2. Ubuntu Configuration

Ubuntu was installed as a server-oriented system without a graphical desktop environment.

The SOC network interface was configured successfully:

```text
Interface: ens34
IPv4:      192.168.8.129/24
```

SSH was also configured and tested.

From Kali, SSH connectivity to Ubuntu was successfully established:

```bash
ssh socadmin@192.168.8.129
```

This confirmed that Kali can remotely access the Ubuntu SOC server.

---

## 3. Windows 11 Configuration

Windows 11 was installed as the monitored endpoint.

The machine was configured with two network interfaces.

SOC interface:

```text
IPv4 Address:    192.168.8.130
Subnet Mask:     255.255.255.0
```

Internet-facing interface:

```text
IPv4 Address:    192.168.67.130
Subnet Mask:     255.255.255.0
Default Gateway: 192.168.67.2
```

The SOC interface was configured as a Private network.

---

## 4. Network Connectivity

Connectivity between the systems has been tested successfully.

### Kali → Ubuntu

```text
192.168.8.128 → 192.168.8.129
```

Successful.

### Windows → Ubuntu

```text
192.168.8.130 → 192.168.8.129
```

Successful.

### Windows → Internet

Connectivity was verified using:

```powershell
ping 8.8.8.8
```

Successful.

### Kali → Windows

Connectivity was initially affected by Windows being powered off and Windows Firewall configuration.

After troubleshooting, SMB connectivity was successfully established.

---

# SMB Testing

SMB (Server Message Block) is being used as one of the first practical protocols for generating network authentication events.

Windows was configured to allow SMB traffic through the appropriate Windows Firewall rule.

The SMB service was verified using:

```powershell
Get-Service LanmanServer
```

The service was running.

From Kali, TCP port 445 was tested:

```bash
nc -nvz 192.168.8.130 445
```

Result:

```text
192.168.8.130 445 (microsoft-ds) open
```

This confirmed that SMB was reachable from Kali.

---

## SMB Authentication

Kali successfully authenticated to the Windows endpoint using the `socadmin` account:

```bash
smbclient //192.168.8.130/C$ -U 'WORKGROUP\socadmin' -m SMB3
```

The authentication allowed access to the Windows administrative share.

The available shares included:

```text
ADMIN$
C$
IPC$
```

The SMB session was subsequently used to list the contents of the Windows `C$` administrative share.

This confirmed that:

```text
Kali
  │
  │ SMB
  │ TCP/445
  ▼
Windows 11
```

is functioning correctly.

---

# Windows Security Event Monitoring

The first Windows security events have now been generated and investigated.

Windows Event Viewer was used to inspect the Security log.

## Event ID 4624 — Successful Logon

A successful network authentication generated:

```text
Event ID:   4624
Logon Type: 3
```

Logon Type `3` represents a network logon.

The event identified the source system as Kali:

```text
Source IP: 192.168.8.128
```

and the target Windows system as:

```text
192.168.8.130
```

The account involved was:

```text
socadmin
```

This demonstrates that SMB authentication activity can be observed through Windows Security Event Logs.

---

## Event ID 4625 — Failed Logon

A deliberately unsuccessful authentication attempt generated:

```text
Event ID:   4625
Logon Type: 3
```

The event contained:

```text
Account Name: socadmin
Account Domain: WORKGROUP
Source Network Address: 192.168.8.128
```

The failure reason was:

```text
Unknown user name or bad password.
```

This demonstrates the difference between:

```text
4624 → Successful authentication
4625 → Failed authentication
```

while both can have:

```text
Logon Type 3 → Network authentication
```

These events provide the first examples of security telemetry that the SOC will eventually collect and analyze automatically.

---

# Troubleshooting

Several issues were encountered while building the environment.

### Ubuntu installation

The Ubuntu installer initially failed to unmount `/cdrom`.

**Cause:**

The installation ISO was still attached to VMware's virtual CD/DVD device.

**Resolution:**

The ISO was disconnected and the VM continued booting from the virtual disk.

---

### Kali → Windows connectivity

Kali initially reported:

```text
No route to host
```

when attempting to reach Windows.

**Cause:**

The Windows VM was not powered on.

**Resolution:**

Windows was started and connectivity was retested.

---

### Windows SMB connectivity

TCP port 445 was initially unreachable from Kali.

Windows was checked using:

```powershell
Get-Service LanmanServer
```

The SMB server service was running.

The Windows network profile and firewall configuration were then investigated.

After correcting the firewall configuration, TCP/445 became reachable:

```text
192.168.8.130 445 (microsoft-ds) open
```

SMB authentication was subsequently successful.

Detailed troubleshooting notes are maintained in:

- [`troubleshooting_log.md`](troubleshooting_log.md)

---

# Current Project Status

### Completed

- [x] Create VMware lab environment
- [x] Install Kali Linux
- [x] Install Ubuntu
- [x] Install Windows 11
- [x] Configure SOC network
- [x] Configure Ubuntu SSH
- [x] Establish Kali → Ubuntu connectivity
- [x] Establish Windows → Ubuntu connectivity
- [x] Verify Windows Internet connectivity
- [x] Configure Windows local `socadmin` account
- [x] Configure Windows network profile
- [x] Configure Windows SMB service
- [x] Configure SMB firewall access
- [x] Verify TCP/445 connectivity
- [x] Successfully authenticate to Windows over SMB
- [x] Generate Windows Event ID 4624
- [x] Generate Windows Event ID 4625
- [x] Investigate Windows Logon Type 3
- [x] Identify Kali as the source of network authentication events


---

# Documentation

The project documentation is currently organized as:

```text
HomeSOC/
│
├── README.md
├── architecture.md
└── troubleshooting_log.md
```

### README.md

Contains:

- Project overview
- Objectives
- Current architecture
- Lab status
- Major milestones
- Security observations

### architecture.md

Contains the detailed:

- VM architecture
- Network interfaces
- IP addressing
- Network design
- System roles

### troubleshooting_log.md

Contains problems encountered during construction of the lab and their resolutions.

---

# Future Development

The lab will gradually evolve from a collection of virtual machines into a functional SOC environment.

The planned progression is:

```text
Virtual Lab
     │
     ▼
Network Connectivity
     │
     ▼
Endpoint Configuration
     │
     ▼
Log Generation
     │
     ▼
Centralized Log Collection
     │
     ▼
Log Analysis
     │
     ▼
Detection Rules
     │
     ▼
Alerting
     │
     ▼
Incident Investigation
     │
     ▼
Automation
```

The long-term objective is to create a realistic but controlled environment in which security events can be intentionally generated, detected, investigated, and documented.

---