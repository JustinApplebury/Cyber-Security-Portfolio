# Cyber Exercise Writeup: TryHackMe Invite-Only
## https://tryhackme.com/room/invite-only

## BLUF

**Bottom Line Up Front:**
This TryHackMe forensics exercise focused on enriching a suspicious IP address and SHA256 hash into actionable threat intelligence. Using the provided TryDetectThis2.0 platform, I correlated malware metadata, file relationships, dropped artifacts, community reporting, and external threat research to identify the malware family, attacker tradecraft, and supporting infrastructure.

The investigation reinforced core defensive cyber skills: indicator enrichment, malware relationship analysis, threat actor research, evidence-based reporting, and translating technical findings into operationally useful intelligence.

---

## Executive Summary

| Field                         | Details                                                     |
| ----------------------------- | ----------------------------------------------------------- |
| **Exercise Name**             | Invite-Only                                                 |
| **Platform / Environment**    | TryHackMe                                                   |
| **Exercise Type**             | Forensics / Threat Intelligence                             |
| **Primary Domain**            | Malware Analysis, Indicator Enrichment, Threat Intelligence |
| **Difficulty**                | Easy                                                        |
| **Date Completed**            | `2026-06-21`                                              |
| **Author**                    | Justin Applebury                                            |
| **Classification / Handling** | Unclassified / Training Only                                |

### Mission Relevance

This exercise is relevant to federal, military, and intelligence community cyber operations because it simulates the early stages of incident triage and threat intelligence development. An analyst is given limited initial indicators and must enrich them into usable intelligence by identifying related files, malware behavior, infrastructure, reporting, and adversary techniques.

The workflow supports defensive cyberspace operations by strengthening skills in:

* Malware and indicator enrichment
* File relationship analysis
* Infrastructure pivoting
* Threat report correlation
* Phishing and credential-theft tradecraft identification
* Evidence-based intelligence reporting

---

# 1. Scope and Objectives

## Scope

| Field                   | Details                                                                                   |
| ----------------------- | ----------------------------------------------------------------------------------------- |
| **Flagged IP Address**  | `101[.]99[.]76[.]120`                                                                     |
| **Flagged SHA256 Hash** | `5d0509f68a9b7c415a726be75a078180e3f02e59866f193b0a99eee8e39c874f`                        |
| **Primary Tool**        | TryDetectThis2.0                                                                          |
| **Analyst Role**        | L2 analyst performing indicator enrichment and threat intelligence analysis               |
| **Scenario Assumption** | An L1 analyst escalated a suspicious IP address and SHA256 hash for further investigation |
| **Limitations**         | Analysis was limited to the TryDetectThis2.0 platform and open-source research            |

## Objectives

The investigation focused on answering the following intelligence requirements:

1. Identify the file associated with the flagged SHA256 hash.
2. Determine the file type associated with the flagged SHA256 hash.
3. Identify the execution parents of the flagged hash in chronological order.
4. Identify the dropped file related to the flagged hash.
5. Pivot from the second execution parent hash to identify four malicious dropped files.
6. Analyze files related to the flagged IP address and determine the associated malware family.
7. Locate the original public report mentioning the flagged indicators.
8. Identify the tool used by the attackers to steal Google Chrome cookies.
9. Identify the phishing technique used by the attackers.
10. Identify the platform used to redirect victims to malicious servers.

---

# 2. Environment Details

| Field                     | Details                                                |
| ------------------------- | ------------------------------------------------------ |
| **Analyst System**        | Browser-based TryHackMe lab environment                |
| **Primary Platform**      | TryDetectThis2.0                                       |
| **External Research**     | Google / Public threat intelligence reporting          |
| **Access Level at Start** | Analyst                                                |
| **Final Access Level**    | N/A — forensics and threat intelligence exercise       |
| **Tools Used**            | TryDetectThis2.0, OSINT research, threat report review |
| **Exercise Type**         | Indicator enrichment and malware relationship analysis |

---

# 3. BLUF Technical Findings

| Finding                                                                                      | Severity | Operational Impact                                                          | Evidence                                |
| -------------------------------------------------------------------------------------------- | -------: | --------------------------------------------------------------------------- | --------------------------------------- |
| The flagged SHA256 hash was associated with a suspicious file submitted to TryDetectThis2.0. |   Medium | Provided initial malware-related indicator for enrichment.                  | Hash search results in TryDetectThis2.0 |
| File relationship analysis identified execution parents and dropped files.                   |     High | Demonstrated malware execution chain and related malicious artifacts.       | Relations tab in TryDetectThis2.0       |
| The flagged IP address was linked to additional malware samples and public reporting.        |     High | Enabled attribution to a malware family and broader campaign context.       | Community tab and external report       |
| Public reporting identified credential theft activity targeting Google Chrome cookies.       |     High | Indicates potential account takeover risk and post-compromise access abuse. | Threat report key takeaways             |
| The attack relied on phishing and redirection infrastructure.                                |     High | Highlights user-targeted delivery and abuse of trusted platforms.           | External threat intelligence report     |

---

# 4. Methodology

## Approach

The assessment followed a structured forensics and threat-intelligence workflow:

1. Search the flagged SHA256 hash.
2. Review file metadata and type information.
3. Pivot into file relationships.
4. Identify execution parents and dropped files.
5. Search related hashes to expand the malware cluster.
6. Analyze the flagged IP address.
7. Review community intelligence for linked malware families and reports.
8. Use open-source research to locate the original reporting.
9. Extract attacker tools, phishing methods, and infrastructure details.
10. Document evidence and map findings to defensive recommendations.

---

# 5. Indicator Enrichment

## 5.1 Flagged SHA256 Hash Analysis

The first step was to search the provided SHA256 hash in TryDetectThis2.0:

```text
5d0509f68a9b7c415a726be75a078180e3f02e59866f193b0a99eee8e39c874f
```

TryDetectThis2.0 functions similarly to VirusTotal within the TryHackMe environment, allowing analysts to review file metadata, detections, relationships, community notes, and linked indicators.

<img width="1237" height="531" alt="TryDetectThis2.0 hash search result" src="https://github.com/user-attachments/assets/782852d5-80c5-46e4-a8f5-4e91e30c473d" />

From the hash search results, I was able to identify:

| Intelligence Requirement                   | Result        |
| ------------------------------------------ | ------------- |
| **File name associated with flagged hash** | `<file name>` |
| **File type associated with flagged hash** | `<file type>` |

This answered the first two investigation questions.

---

## 5.2 Relationship Analysis

After reviewing the main hash results, I selected the **Relations** tab to identify related execution activity.

<img width="629" height="591" alt="Relations tab showing execution parents and dropped file" src="https://github.com/user-attachments/assets/a37b9abf-c969-45ae-8fe7-1acc4111e996" />

The Relations tab revealed execution parent information and a dropped file associated with the flagged hash.

| Intelligence Requirement | Result                 |
| ------------------------ | ---------------------- |
| **Execution parents**    | `<parent1>, <parent2>` |
| **Dropped file name**    | `<dropped file name>`  |
| **Dropped file hash**    | `<dropped file hash>`  |

This answered the third and fourth investigation questions.

---

# 6. Pivoting on Related Hashes

## 6.1 Second Execution Parent Analysis

Next, I pivoted on the hash of the second execution parent identified in the previous step. Searching this hash and reviewing its Relations tab revealed additional dropped files.

<img width="604" height="566" alt="Second execution parent relations showing malicious dropped files" src="https://github.com/user-attachments/assets/d51c862c-2952-42be-9581-6d9fdd3ae111" />

The second execution parent was associated with four malicious dropped files.

| Intelligence Requirement         | Result                               |
| -------------------------------- | ------------------------------------ |
| **Four malicious dropped files** | `<file1>, <file2>, <file3>, <file4>` |

This answered the fifth investigation question.

---

# 7. Flagged IP Address Analysis

## 7.1 IP Address Search

I then searched the flagged IP address in TryDetectThis2.0:

```text
101[.]99[.]76[.]120
```

<img width="1192" height="493" alt="Flagged IP address search result" src="https://github.com/user-attachments/assets/92d412ef-dc60-4736-a76f-3e6643ae0063" />

The IP address results provided additional context, including linked files and community intelligence. Reviewing the **Community** tab helped identify the malware family associated with the files connected to the flagged IP.

| Intelligence Requirement                      | Result             |
| --------------------------------------------- | ------------------ |
| **Malware family linked to flagged IP files** | `<malware family>` |
| **Original report title**                     | `<report title>`   |

This answered the sixth and seventh investigation questions.

---

# 8. External Threat Report Review

## 8.1 Public Reporting Correlation

After identifying the original report from the community intelligence section, I used Google to locate and review the report.

<img width="1108" height="566" alt="External threat report key takeaways" src="https://github.com/user-attachments/assets/1922ce72-c16a-42b3-a069-8c71c7e00ae4" />

The report provided broader campaign context, including attacker tooling, phishing tradecraft, and infrastructure abuse.

From the report’s key takeaways, I identified:

| Intelligence Requirement                                   | Result                 |
| ---------------------------------------------------------- | ---------------------- |
| **Tool used to steal Google Chrome cookies**               | `<cookie theft tool>`  |
| **Phishing technique used**                                | `<phishing technique>` |
| **Platform used to redirect victims to malicious servers** | `<redirect platform>`  |

This answered the final three investigation questions.

---

# 9. Evidence Summary

| Evidence Item                | Source                               | Relevance                                    |
| ---------------------------- | ------------------------------------ | -------------------------------------------- |
| Flagged SHA256 hash          | TryHackMe room prompt                | Initial suspicious file indicator            |
| Flagged IP address           | TryHackMe room prompt                | Initial suspicious infrastructure indicator  |
| File name and type           | TryDetectThis2.0 hash search         | Identified the file associated with the hash |
| Execution parents            | TryDetectThis2.0 Relations tab       | Established execution chain context          |
| Dropped file                 | TryDetectThis2.0 Relations tab       | Identified related malware artifact          |
| Four malicious dropped files | Pivot from second execution parent   | Expanded malware cluster                     |
| Malware family               | TryDetectThis2.0 Community tab       | Linked indicators to known malware activity  |
| Original report              | Public threat intelligence reporting | Provided campaign context                    |
| Cookie theft tool            | Threat report                        | Identified credential theft capability       |
| Phishing technique           | Threat report                        | Identified delivery method                   |
| Redirect platform            | Threat report / attack flow          | Identified infrastructure abuse              |

---

# 10. MITRE ATT&CK Mapping

| Technique                     | Technique ID | Relevance                                                                                   |
| ----------------------------- | ------------ | ------------------------------------------------------------------------------------------- |
| Phishing                      | `T1566`      | The campaign used phishing to lure users into interacting with attacker-controlled content. |
| User Execution                | `T1204`      | Victim interaction was required as part of the attack chain.                                |
| Ingress Tool Transfer         | `T1105`      | Malware or supporting files were delivered to the victim environment.                       |
| Credentials from Web Browsers | `T1555.003`  | Attackers used tooling to steal cookies from Google Chrome.                                 |
| Exfiltration Over Web Service | `T1567`      | Credential or session data may have been transferred using web-based infrastructure.        |
| Web Service Abuse             | `T1102`      | Trusted online platforms were abused for redirection or infrastructure support.             |

---

# 11. Defensive Recommendations

## Detection Opportunities

Defenders should consider monitoring for:

* Suspicious browser cookie access or extraction behavior
* Execution chains involving unusual parent-child process relationships
* Downloads or file writes associated with known malicious hashes
* Connections to suspicious or newly observed infrastructure
* Abuse of trusted platforms for redirection to malicious servers
* User activity consistent with phishing lure interaction

## Mitigation Opportunities

Recommended mitigations include:

* Enforce phishing-resistant multi-factor authentication where possible.
* Monitor and restrict access to browser credential and cookie stores.
* Block known malicious hashes and infrastructure at endpoint and network layers.
* Use DNS and web filtering to limit access to suspicious redirect chains.
* Educate users on phishing techniques that abuse trusted platforms.
* Apply endpoint detection rules for credential theft tooling.
* Correlate threat intelligence indicators with SIEM and EDR telemetry.

---

# 12. Lessons Learned

This exercise reinforced the importance of pivoting from a single indicator into a broader intelligence picture. A hash or IP address alone has limited value, but when enriched through file relationships, dropped artifacts, community notes, and external reporting, it can reveal malware family attribution, attacker tooling, delivery methods, and defensive priorities.

The room also demonstrated how attackers abuse trusted platforms and user-facing services to increase the success rate of phishing operations. From a defensive perspective, this highlights the need for layered detection that combines endpoint telemetry, network indicators, user behavior, and threat intelligence reporting.

---

# 13. Final Answers

| Question                                                              | Answer     |
| --------------------------------------------------------------------- | ---------- |
| What is the name of the file identified with the flagged SHA256 hash? | `<answer>` |
| What is the file type associated with the flagged SHA256 hash?        | `<answer>` |
| What are the execution parents of the flagged hash?                   | `<answer>` |
| What is the name of the file being dropped?                           | `<answer>` |
| What are the four malicious dropped files?                            | `<answer>` |
| What malware family links the files related to the flagged IP?        | `<answer>` |
| What is the title of the original report?                             | `<answer>` |
| Which tool did the attackers use to steal cookies from Google Chrome? | `<answer>` |
| Which phishing technique did the attackers use?                       | `<answer>` |
| What platform redirected users to malicious servers?                  | `<answer>` |

---

# Conclusion

The Invite-Only room provided a practical introduction to threat intelligence enrichment and forensic pivoting. Starting from a single suspicious hash and IP address, the investigation expanded into related malware artifacts, execution relationships, infrastructure analysis, public reporting, and adversary technique identification.

This workflow mirrors real-world defensive cyber operations where analysts must rapidly transform low-context indicators into actionable intelligence for detection, response, and mitigation.
