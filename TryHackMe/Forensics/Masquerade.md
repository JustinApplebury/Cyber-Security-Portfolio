# Cyber Exercise Writeup: Masquerade | https://tryhackme.com/room/masquerade

## BLUF

**Bottom Line Up Front:**  
<Provide a 2–4 sentence executive summary of what happened, why it mattered, and the final outcome.>

Example:

> The exercise demonstrated how exposed credentials and weak service configuration can enable initial access, lateral movement, and privilege escalation. Enumeration identified an externally accessible web service, which led to credential discovery and unauthorized system access. The attack path highlights the need for stronger access controls, credential hygiene, and continuous monitoring aligned with DoD cyber defense priorities.

---

## Executive Summary

**Exercise Name:** <Challenge Name>  
**Platform / Environment:** <TryHackMe / Hack The Box / CyberDefenders / DoD Lab / Internal Exercise>  
**Exercise Type:** <CTF / Blue Team / Red Team / Purple Team / SOC Investigation / Malware Analysis / Forensics>  
**Primary Domain:** <Network Defense / Web Exploitation / Endpoint Analysis / Threat Hunting / Incident Response / Forensics>  
**Difficulty:** <Easy / Medium / Hard>  
**Date Completed:** <YYYY-MM-DD>  
**Author:** Justin Applebury  
**Classification / Handling:** <Unclassified / CUI / Internal Use / Training Only>  

### Mission Relevance

Explain how this exercise relates to federal, military, or intelligence community cyber operations.

Example:

> This exercise reinforces skills relevant to defensive cyberspace operations, including service enumeration, threat detection, vulnerability validation, incident response triage, and adversary behavior analysis.

---

# 1. Scope and Objectives

## Scope

**Target System / Network:** `<IP / hostname / lab range>`  
**Rules of Engagement:** `<Authorized actions, prohibited actions, time limits, constraints>`  
**Assumptions:** `<Known starting conditions>`  
**Limitations:** `<Tooling, access, or environment limitations>`  

## Objectives

- Identify exposed services and potential attack surface
- Determine likely vulnerabilities or misconfigurations
- Gain authorized access within exercise boundaries
- Analyze adversary-relevant techniques
- Document evidence, commands, and artifacts
- Identify detection and mitigation opportunities
- Map activity to relevant frameworks

---

# 2. Environment Details

| Field | Details |
|---|---|
| Target IP / Hostname | `<target>` |
| Attacker / Analyst System | `<Kali / Ubuntu / Windows / REMnux / Security Onion>` |
| Operating System Identified | `<Linux / Windows / Unknown>` |
| Network Segment | `<Lab VPN / Local Range / Cloud Range>` |
| Tools Used | `<Nmap, Burp, Wireshark, Splunk, Velociraptor, etc.>` |
| Access Level at Start | `<Unauthenticated / User / Analyst / Admin>` |
| Final Access Level | `<User / Root / Administrator / Domain Admin / N/A>` |

---

# 3. BLUF Technical Findings

| Finding | Severity | Operational Impact | Evidence |
|---|---:|---|---|
| `<Finding 1>` | `<Low/Med/High/Critical>` | `<Mission or system impact>` | `<Command/output/log/source>` |
| `<Finding 2>` | `<Low/Med/High/Critical>` | `<Mission or system impact>` | `<Command/output/log/source>` |
| `<Finding 3>` | `<Low/Med/High/Critical>` | `<Mission or system impact>` | `<Command/output/log/source>` |

---

# 4. Methodology

## Approach

Describe the process used during the exercise.

Example:

> The assessment followed a structured methodology: reconnaissance, enumeration, vulnerability identification, exploitation validation, post-exploitation analysis, privilege escalation, documentation, and defensive mapping.

## Phases

1. Reconnaissance
2. Enumeration
3. Vulnerability identification
4. Exploitation or investigation
5. Post-exploitation or evidence review
6. Privilege escalation or impact analysis
7. Defensive recommendations
8. Reporting

---

# 5. Reconnaissance and Enumeration

## Network Discovery

Command:

```bash
<command here>
