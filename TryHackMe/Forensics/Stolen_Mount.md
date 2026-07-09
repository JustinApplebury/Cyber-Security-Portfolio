# Cyber Exercise Writeup: [TryHackMe | Stolen Mount](https://tryhackme.com/room/hfb1stolenmount)

> **Authorized Training Environment:** This writeup documents activity conducted within an authorized cyber training or lab environment. No real-world systems, networks, or data were targeted.

---

## BLUF

<!--
Write this section last.

Recommended structure:
1. What was the exercise and what was the overall outcome?
2. What was the primary attack path, investigation path, or technical cause?
3. What level of impact or access was demonstrated?
4. What is the most important defensive takeaway?

Aim for 3–5 sentences. Avoid command details, flag values, and step-by-step narration.
-->

> `<Challenge Name>` demonstrated how `<primary vulnerability, misconfiguration, malicious behavior, or investigative problem>` could lead to `<operational or security impact>`. Analysis identified `<initial finding or entry point>`, which enabled or revealed `<key progression in the attack or investigation>`. The exercise concluded with `<final access level, investigation result, recovered evidence, or objective achieved>`. From a defensive perspective, the activity highlights the importance of `<primary security control, detection opportunity, or mitigation>`.

### Example BLUF

> The exercise demonstrated how an exposed network service and weak privilege boundaries could enable progression from unauthenticated enumeration to privileged system access. Reconnaissance identified a misconfigured service that exposed information necessary to establish an initial foothold, while post-exploitation analysis revealed an insecure privileged process that enabled escalation. The exercise concluded with full administrative control of the target system. From a defensive perspective, the attack path highlights the importance of secure service configuration, least-privilege enforcement, credential protection, and monitoring for abnormal process execution.

---

## Executive Summary

| Field                       | Details                                                                                                              |
| --------------------------- | -------------------------------------------------------------------------------------------------------------------- |
| **Exercise Name**           | `Stolen Mount`                                                                                                   |
| **Platform / Environment**  | `TryHackMe`                                          |
| **Exercise Type**           | `Forensics`                      |
| **Primary Domain**          | `Network Security / Threat Hunting / Incident Response / Digital Forensics` |
| **Difficulty**              | `Easy`                                                                                             |
| **Assessment Outcome**      | `Completed`                                                         |
| **Date Completed**          | `2026-07-06`                                                                                                       |
| **Author**                  | `Justin Applebury`                                                                                                     |
| **Handling / Distribution** | `Public Training Content`                                                                                            |

### Mission Relevance

<!--
Explain why the technical skills practiced in this exercise matter outside the lab.

Focus on:
- defensive cyberspace operations
- intelligence support
- incident response
- threat detection
- adversary behavior analysis
- network or endpoint defense

Keep this to one short paragraph.
-->

> This exercise reinforced skills relevant to `Network Security / Threat Hunting / Incident Response / Digital Forensics `, including `packet/protocol analysis, decoding, hash cracking, NFSv4 analysis`. The activity also provided practical experience analyzing adversary behavior, validating security weaknesses, preserving technical evidence, and translating technical observations into actionable defensive findings.

---

## 1. Scope and Objectives

### Scope

| Field                       | Details                                                                               |
| --------------------------- | ------------------------------------------------------------------------------------- |
| **Target System / Dataset** | `challenge.pcapng`          |
| **Starting Access**         | `Provided Evidence`              |
| **Authorized Actions**      | `log analysis`                   |
| **Constraints**             | `Only access to .pcapng file`       |
| **Success Criteria**        | `flag recovery` |

### Objectives

* An intruder has infiltrated our network and targeted the NFS server where the backup files are stored.
* A classified secret was accessed and stolen.
* The only trace left behind is a packet capture (PCAP) file recorded during the incident.
* Your mission, should you accept it, is to discover the contents of the stolen data.

---

## 2. Environment Details

| Field                        | Details                                                                             |
| ---------------------------- | ----------------------------------------------------------------------------------- |
| **Target / Evidence Source** | `challenge.pcapng`                               |
| **Analyst System**           | `Kali Linux`                         |
| **Target Operating System**  | `Linux`                                                 |
| **Network Environment**      | `Offline Analysis`                          |
| **Primary Tools Used**       | `Wireshark`             |
| **Access Level at Start**    | `Analyst`                                |
| **Final Access / Outcome**   | `Evidence Recovered / Incident Reconstructed` |

---

## 3. Key Findings

<!--
Keep this section brief. These are the most important conclusions, not every technical observation.

Use severity only when it adds value. Do not assign Critical severity merely because a CTF resulted in root access.
-->

| ID   | Finding                | Severity                                  | Security / Operational Impact | Evidence                          |
| ---- | ---------------------- | ----------------------------------------- | ----------------------------- | --------------------------------- |
| F-01 | `<Primary finding>`    | `<Info / Low / Medium / High / Critical>` | `<Why it mattered>`           | `<Section or artifact reference>` |
| F-02 | `<Secondary finding>`  | `<Info / Low / Medium / High / Critical>` | `<Why it mattered>`           | `<Section or artifact reference>` |
| F-03 | `<Additional finding>` | `<Info / Low / Medium / High / Critical>` | `<Why it mattered>`           | `<Section or artifact reference>` |

### Attack or Investigation Path

<!--
Summarize the full progression in a single line.
-->

```text
<Reconnaissance / Evidence Source>
Initially looking at the pcap we see a TCP connection between two IPs and no other traffic, so any other traffic was conveniently filtered off the pcap

        ↓
<Initial Finding>
        ↓
<Access, Pivot, or Investigative Breakthrough>
        ↓
<Privilege Escalation, Root Cause, or Attribution>
        ↓
<Final Objective>
```

---

## 4. Methodology

### Approach

> The exercise followed a structured analytical process consisting of reconnaissance or evidence review, enumeration, vulnerability or anomaly identification, exploitation or investigative validation, post-access or evidence analysis, impact assessment, defensive mapping, and reporting.

### Exercise Phases

1. Reconnaissance or evidence acquisition
2. Enumeration and data review
3. Vulnerability or anomaly identification
4. Exploitation, validation, or investigation
5. Post-access analysis or evidence correlation
6. Privilege escalation, root-cause analysis, or impact determination
7. Detection and mitigation analysis
8. Reporting and lessons learned

---

## 5. Reconnaissance and Initial Analysis

### Objective

<!--
What were you trying to determine during this phase?
-->

> `<Describe the purpose of the reconnaissance or initial evidence review.>`

### Network Discovery / Evidence Review

**Command or Query:**

```bash
<command here>
```

**Relevant Output:**

```text
<Trim output to the lines that actually matter>
```

**Analysis:**

> `<Explain what the output means and why it influenced the next action.>`

### Key Observation

> **Observation:** `<What did you find?>`
> **Significance:** `<Why did it matter?>`
> **Next Action:** `<What did this finding lead you to investigate?>`

---

## 6. Enumeration and Technical Analysis

### `<Service, Host, Artifact, or Evidence Source>`

#### Objective

> `<Explain what you were attempting to confirm or understand.>`

#### Evidence

```bash
<command, query, filter, or analysis step>
```

```text
<relevant output>
```

#### Analysis

> `<Explain the technical significance of the evidence. Do not simply restate the output.>`

#### Assessment

> The evidence indicated `<conclusion>`. This was significant because `<security or investigative relevance>`, leading to `<next action>`.

---

## 7. Initial Access, Investigation Pivot, or Primary Discovery

<!--
Choose the heading that best matches the exercise.

Examples:
- Initial Access
- Investigation Pivot
- Malware Identification
- Incident Reconstruction
- Exploitation Validation
-->

### Finding

> `<Describe the vulnerability, investigative breakthrough, or key discovery.>`

### Evidence

```bash
<command or query>
```

```text
<relevant result>
```

### Technical Analysis

> `<Explain why the technique worked or why the evidence was significant. Describe the underlying weakness, protocol behavior, attacker action, or forensic relationship.>`

### Result

| Field                         | Outcome                                                     |
| ----------------------------- | ----------------------------------------------------------- |
| **Access / Discovery**        | `<Result>`                                                  |
| **Affected Component**        | `<Service, host, account, process, or artifact>`            |
| **Security Boundary Crossed** | `<None / Network / User / Privilege / Trust / Application>` |
| **Evidence Preserved**        | `<Screenshot, log entry, packet, hash, file, etc.>`         |

---

## 8. Post-Exploitation, Root Cause, or Impact Analysis

<!--
Rename this section based on the type of exercise.
-->

### Situation

> `<Describe the system state, evidence state, or access level at this point in the exercise.>`

### Analysis Performed

```bash
<command or query>
```

### Relevant Evidence

```text
<output or artifact>
```

### Technical Assessment

> `<Explain how the evidence revealed the next stage of the attack, the root cause of the incident, or the actual system impact.>`

### Final Outcome

> `<Clearly state what was achieved or determined.>`

---

## 9. Findings Analysis

### F-01: `<Finding Title>`

**Severity:** `<Informational / Low / Medium / High / Critical>`

#### Description

> `<Explain the weakness, malicious behavior, or investigative finding.>`

#### Evidence

```text
<Relevant command output, log entry, packet field, or artifact>
```

#### Technical Impact

> `<Explain what the finding enabled or could enable.>`

#### Root Cause

> `<Explain the configuration, design, process, or control failure that made the finding possible.>`

#### Recommendation

> `<Provide a specific and actionable remediation.>`

#### Detection Opportunity

> `<Explain what telemetry could reveal this activity: process execution, authentication logs, network traffic, file events, EDR telemetry, SIEM correlation, etc.>`

---

## 10. Adversary Behavior and Framework Mapping

### MITRE ATT&CK Mapping

<!--
Map only techniques that were actually demonstrated. Avoid adding techniques solely because they seem related.
-->

| Phase                    | Technique          | Technique ID | Evidence              |
| ------------------------ | ------------------ | ------------ | --------------------- |
| `<Initial Access>`       | `<Technique Name>` | `<T####>`    | `<Observed activity>` |
| `<Execution>`            | `<Technique Name>` | `<T####>`    | `<Observed activity>` |
| `<Persistence>`          | `<Technique Name>` | `<T####>`    | `<Observed activity>` |
| `<Privilege Escalation>` | `<Technique Name>` | `<T####>`    | `<Observed activity>` |
| `<Discovery>`            | `<Technique Name>` | `<T####>`    | `<Observed activity>` |

### Attack Lifecycle Summary

> `<Explain how the observed activity progressed through the attack lifecycle or investigation. Focus on relationships between actions rather than listing framework IDs.>`

---

## 11. Defensive Analysis

### Detection Opportunities

| Activity              | Telemetry Source                                         | Detection Opportunity                       |
| --------------------- | -------------------------------------------------------- | ------------------------------------------- |
| `<Observed behavior>` | `<EDR / Sysmon / Firewall / Zeek / Authentication Logs>` | `<What defenders should detect>`            |
| `<Observed behavior>` | `<Data source>`                                          | `<Detection logic or behavioral indicator>` |

### Indicators and Artifacts

| Type                                           | Value / Description | Significance       |
| ---------------------------------------------- | ------------------- | ------------------ |
| `<IP / Domain / Hash / File / Process / User>` | `<Artifact>`        | `<Why it matters>` |

### Recommended Mitigations

| Priority | Recommendation                          | Expected Benefit      |
| -------- | --------------------------------------- | --------------------- |
| 1        | `<Primary remediation>`                 | `<Risk reduced>`      |
| 2        | `<Secondary remediation>`               | `<Risk reduced>`      |
| 3        | `<Detection or monitoring improvement>` | `<Visibility gained>` |

---

## 12. Lessons Learned

### Technical Lessons

* `<What technical concept became clearer?>`
* `<What tool, protocol, or technique did you improve?>`
* `<What assumption proved incorrect?>`

### Analytical Lessons

* `<What evidence or observation was most important?>`
* `<What decision accelerated or delayed the investigation?>`
* `<How would you approach a similar problem differently?>`

### Professional Relevance

> `<Explain how the exercise improved a skill relevant to a SOC, cyber defense, intelligence, incident response, threat hunting, or security engineering role.>`

---

## 13. Conclusion

> `<Summarize the exercise outcome, the most important technical cause, the demonstrated impact, and the primary defensive lesson. Avoid repeating the BLUF word-for-word.>`

---

## Appendix A: Tools and Commands

| Tool     | Purpose             |
| -------- | ------------------- |
| `<Tool>` | `<How it was used>` |
| `<Tool>` | `<How it was used>` |

---

## Appendix B: References

* `<Official documentation>`
* `<MITRE ATT&CK technique>`
* `<Vendor or protocol documentation>`
* `<Other authoritative reference>`

---

## Appendix C: Exercise Completion

| Objective       | Status     |
| --------------- | ---------- |
| `<Objective 1>` | `Complete` |
| `<Objective 2>` | `Complete` |
| `<Objective 3>` | `Complete` |

---

*This writeup was created for professional development and documents activity performed exclusively within an authorized training environment.*

