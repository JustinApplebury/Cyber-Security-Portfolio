# Cyber Exercise Writeup: <Challenge / Exercise Name>

## BLUF

**Bottom Line Up Front:**  
<Provide a 2–4 sentence executive summary of what happened, why it mattered, and the final outcome.>

Example:

> The exercise demonstrated how exposed credentials and weak service configuration can enable initial access, lateral movement, and privilege escalation. Enumeration identified an externally accessible web service, which led to credential discovery and unauthorized system access. The attack path highlights the need for stronger access controls, credential hygiene, and continuous monitoring aligned with DoD cyber defense priorities.

---

## Executive Summary

**Exercise Name:** Invite-Only 
**Platform / Environment:** TryHackMe  
**Exercise Type:** Forensics 
**Primary Domain:** Forensics
**Difficulty:** Easy
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

**Target System / Network:** `Flagged IP: 101[.]99[.]76[.]120 / Flagged SHA256 hash: 5d0509f68a9b7c415a726be75a078180e3f02e59866f193b0a99eee8e39c874f`  
**Rules of Engagement:** `<Authorized actions, prohibited actions, time limits, constraints>`  
**Assumptions:** `One of the L1 analysts flagged two suspicious findings early in the morning and escalated them. Your task is to analyse these findings further and distil the information into usable threat intelligence.`  
**Limitations:** `We recently purchased a new threat intelligence search application called TryDetectThis2.0. You can use this application to gather information on the indicators above.`  

## Objectives

- Identify exposed services and potential attack surface
- Determine likely vulnerabilities or misconfigurations
- Gain authorized access within exercise boundaries
- Analyze adversary-relevant techniques
- Document evidence, commands, and artifacts
- Identify detection and mitigation opportunities
- Map activity to relevant frameworks
- What is the name of the file identified with the flagged SHA256 hash?
- What is the file type associated with the flagged SHA256 hash?
- What are the execution parents of the flagged hash? List the names chronologically, using a comma as a separator. Note down the hashes for later use.
- What is the name of the file being dropped? Note down the hash value for later use.
- Research the second hash in question 3 and list the four malicious dropped files in the order they appear (from up to down), separated by commas.
- Analyse the files related to the flagged IP. What is the malware family that links these files?
- What is the title of the original report where these flagged indicators are mentioned? Use Google to find the report.
- Which tool did the attackers use to steal cookies from the Google Chrome browser?
- Which phishing technique did the attackers use? Use the report to answer the question.
- What is the name of the platform that was used to redirect a user to malicious servers?

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

Launching TryDetectThis2.0 gives us a TryHackMe version of VirusTotal.  
First I run a search for the given Hash:  


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
