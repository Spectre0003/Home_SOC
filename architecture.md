# Home SOC — Architecture

## 1. Project Overview

This project is a self-hosted Security Operations Center (SOC) lab built using VMware virtualization.

The purpose of the lab is to simulate a small enterprise-style security monitoring environment where security activity can be generated, collected, detected, investigated, and documented.

The core workflow is:

Endpoints → Telemetry → Collection → SIEM → Detection → Investigation → Response

---

## 2. Virtualization

Virtualization platform:

- VMware Workstation

The lab currently consists of three virtual machines:

| Machine   | Role                          | Operating System              |
|           |                               |                               |
| Kali      | Analyst / Attacker            | Kali Linux                    |
| Ubuntu    | Monitored Linux Endpoint      | Ubuntu Server 24.04.4 LTS     |
| Windows   | Monitored Windows Endpoint    | Windows 11 Pro 25H2           |

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