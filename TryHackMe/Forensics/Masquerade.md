# Cyber Exercise Writeup: Masquerade | https://tryhackme.com/room/masquerade

## BLUF

**Bottom Line Up Front:**  
<Provide a 2–4 sentence executive summary of what happened, why it mattered, and the final outcome.>

Example:

> The exercise demonstrated how exposed credentials and weak service configuration can enable initial access, lateral movement, and privilege escalation. Enumeration identified an externally accessible web service, which led to credential discovery and unauthorized system access. The attack path highlights the need for stronger access controls, credential hygiene, and continuous monitoring aligned with DoD cyber defense priorities.

---

## Executive Summary

**Exercise Name:** Masquerade
**Platform / Environment:** TryHackMe
**Exercise Type:** Malware Analysis / Forensics
**Primary Domain:** Network DefenseEndpoint Analysis / Threat Hunting / Incident Response / Forensics
**Difficulty:** Medium
**Date Completed:** <YYYY-MM-DD>  
**Author:** Justin Applebury  
**Classification / Handling:** Unclassified / Training Only

### Mission Relevance

Explain how this exercise relates to federal, military, or intelligence community cyber operations.

Example:

> This exercise reinforces skills relevant to defensive cyberspace operations, including service enumeration, threat detection, vulnerability validation, incident response triage, and adversary behavior analysis.

---

# 1. Scope and Objectives

## Scope

**Target System / Network:** Event Log, Packet Capture <pcapng>
**Rules of Engagement:** Malware analysis in an isolated environment
**Assumptions:** Jim from Finance ran a script "apply critical security updates" from a phishing email. Unusual network traffic were observed. 
**Limitations:** Analyze Event Log and Packet Capture and analyze malicious code in packets, but do not run any code outside the isolated environment.

## Objectives

- Investigate what happened
- Determine the impact
- Identify how the attacker established control over the system
- What external domain was contacted during script execution?
- What encryption algorithm was used by the script?
- What key was used to decrypt the second-stage payload?
- What was the timestamp of the server response containing the payload?
- What is the SHA-256 hash of the extracted and decrypted payload?
- What remote URL did the client use to communicate with the victim machine?
- Which encryption key and algorithm does the client use?
- After determining the client's encryption, decrypt the commands the attacker executed on the victim and submit the flag.

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
