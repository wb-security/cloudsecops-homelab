# CloudSecOps Homelab

### Warren Bowen | Tier II NOC/SOC Engineer | CloudSecOps Pathway

---

## Overview

This repository documents my personal CloudSecOps homelab — a hands-on environment built to develop and demonstrate cloud security engineering skills that complement my production SOC experience.

The lab is designed around four interconnected focus areas that mirror real enterprise security architecture: an on-premises Active Directory foundation, a Microsoft Azure cloud layer, a detection engineering layer for building and tuning detection logic, and a purple team exercise track for adversary simulation and hunt development.

This is a living project. Documentation is added as each phase is built and validated.

---

## Lab Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    AZURE CLOUD LAYER                    │
│  Microsoft Sentinel │ Defender for Cloud │ Entra ID     │
│  Log Analytics Workspace │ Security Center              │
└──────────────────────────┬──────────────────────────────┘
                           │ Hybrid connectivity
┌──────────────────────────▼──────────────────────────────┐
│                 ON-PREMISES ENVIRONMENT                  │
│                                                         │
│  ┌─────────────────┐      ┌─────────────────────────┐  │
│  │  Windows Server │      │   Windows 10 Endpoint   │  │
│  │  Domain Control │      │   Domain-joined client  │  │
│  │  Active Director│      │   Simulated user target │  │
│  └─────────────────┘      └─────────────────────────┘  │
│                                                         │
│  ┌─────────────────────────────────────────────────┐   │
│  │              Kali Linux Attack Box              │   │
│  │     Adversary simulation / purple team ops      │   │
│  └─────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────┘
```

---

## Focus Areas

### 1. Active Directory Attack and Defense
Building foundational knowledge of AD security by both attacking and defending the same environment. Coverage includes common AD attack paths (Kerberoasting, AS-REP Roasting, Pass-the-Hash, DCSync), detection logic for each technique, and hardening countermeasures validated against real attack tooling.

### 2. Azure Cloud Security
Deploying and configuring Microsoft's native cloud security stack: Microsoft Sentinel as the cloud SIEM, Defender for Cloud for posture management and workload protection, and Entra ID for identity security. Connecting on-premises AD to Azure via hybrid identity to mirror real enterprise environments.

### 3. Detection Engineering
Writing, testing, and tuning detection rules against known attack techniques. Focus on reducing false positive rates, improving signal quality, and building detections that survive adversary evasion attempts. All detections documented with the attack technique they target, the log source they rely on, and known evasion paths.

### 4. Threat Hunting and Purple Team Exercises
Structured purple team exercises using Kali Linux as the adversary platform against the Windows environment. Each exercise documents the attack path, the log artifacts generated, whether existing detections fired, and what new detections or log sources were identified as gaps.

---

## Repository Structure

```
cloudsecops-homelab/
├── README.md
├── infrastructure/
│   ├── network-diagram.md
│   ├── active-directory-setup.md
│   ├── azure-environment-setup.md
│   └── sentinel-workspace-config.md
├── active-directory/
│   ├── README.md
│   ├── attack-techniques/
│   │   ├── kerberoasting.md
│   │   ├── as-rep-roasting.md
│   │   ├── pass-the-hash.md
│   │   └── dcsync.md
│   └── defenses/
│       ├── tiered-admin-model.md
│       └── ad-hardening-checklist.md
├── azure-security/
│   ├── README.md
│   ├── sentinel-setup.md
│   ├── defender-for-cloud-config.md
│   ├── entra-id-hardening.md
│   └── conditional-access-policies.md
├── detection-engineering/
│   ├── README.md
│   ├── detection-template.md
│   └── detections/
│       ├── kerberoasting-detection.md
│       ├── impossible-travel-detection.md
│       └── inbox-forwarding-rule-detection.md
└── purple-team/
    ├── README.md
    ├── exercise-template.md
    └── exercises/
        └── (exercises added as completed)
```

---

## Build Roadmap

### Phase 1 — On-Premises Foundation *(in progress)*
- [ ] Windows Server — Domain Controller setup and AD configuration
- [ ] Windows 10 endpoint — domain join and baseline configuration
- [ ] Kali Linux — attack tooling setup
- [ ] Basic AD attack and defense documentation

### Phase 2 — Azure Integration
- [ ] Azure tenant setup and Log Analytics Workspace
- [ ] Microsoft Sentinel deployment and on-prem log forwarding
- [ ] Defender for Cloud enablement
- [ ] Entra ID hybrid identity configuration

### Phase 3 — Detection Engineering
- [ ] Detection rule templates and documentation standard
- [ ] Initial detection set targeting Phase 1 AD attack techniques
- [ ] False positive tuning and evasion testing

### Phase 4 — Purple Team Exercises
- [ ] Structured exercise format and documentation template
- [ ] First full exercise: Kerberoasting end-to-end
- [ ] Detection gap analysis and remediation

---

## Tools and Platforms

| Category | Tool |
|---|---|
| Cloud SIEM | Microsoft Sentinel |
| Cloud Security Posture | Microsoft Defender for Cloud |
| Identity | Microsoft Entra ID (Azure AD) |
| On-Prem Directory | Active Directory Domain Services |
| Adversary Simulation | Kali Linux, Impacket, Mimikatz, BloodHound |
| AD Enumeration | BloodHound, SharpHound, PowerView |
| Detection Development | KQL (Kusto Query Language) |
| Virtualization | *(to be documented)* |

---

## Related

- [Security Operations Portfolio](https://github.com/wb-security/security-operations-portfolio) — Production SOC methodology, case studies, and documentation standards from my Tier II NOC/SOC engineering work
