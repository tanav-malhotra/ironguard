# IronGuard CyberPatriot Master Checklist

> **This checklist is embedded in the AI's system prompt.**
> The AI will systematically work through each item.
> Items marked with ⚡ are quick wins (usually 1-3 points each).
> Items marked with 🔥 are high-value (3-5+ points).
> Items marked with ⚠️ require checking README first.

---

## 🚨 PHASE 0: READ THE README (CRITICAL - DO THIS FIRST)

**NEVER skip this. The README contains restrictions that can cause PENALTIES.**

Extract and store:
- [ ] **Authorized administrators** - users who SHOULD have admin/sudo
- [ ] **Authorized users** - users who should exist but NOT be admin
- [ ] **Required services** - services that MUST stay running (web server, SSH, FTP, etc.)
- [ ] **Prohibited actions** - things like "DO NOT UPDATE", "DO NOT REMOVE X"
- [ ] **Required software** - applications that must remain installed
- [ ] **Scenario context** - what is this machine used for? (helps identify what's suspicious)
- [ ] **Critical applications** - any specific apps mentioned as needed

**STORE THIS INFORMATION AND CHECK BEFORE EVERY DESTRUCTIVE ACTION**

---

## 📝 PHASE 1: FORENSICS QUESTIONS (Do First - Easy Points!)

⚡ **Forensics are low-risk, high-reward investigation tasks.**

- [ ] Read all `Forensics Question *.txt` files from Desktop
- [ ] For each question, investigate and write answer using `write_answer`

### Common Forensics Question Patterns:

| Question Type | How to Find Answer |
|--------------|-------------------|
| "Find the unauthorized user" | Compare user list against README |
| "What file contains X" | `find / -name "*pattern*"` or `grep -r "pattern"` |
| "When was X installed/modified" | Check file timestamps, package logs, event logs |
| "What port is X running on" | `netstat -tulpn` (Linux) / `netstat -an` (Windows) |
| "Find the hidden file" | `ls -la`, check for dot files, hidden attributes |
| "What is the password for X" | Check config files, scripts, .htpasswd, etc. |
| "Who logged in at X time" | Check auth.log, security event logs |
| "What process is listening on port X" | `netstat -tulpn \| grep :X` |
| "Find the backdoor" | Check cron, scheduled tasks, startup items, services |
| "What CVE/vulnerability" | Check software versions, search for known vulns |

---

## 👤 PHASE 2: USER MANAGEMENT

### 2.1 Unauthorized Users 🔥
```
Windows: net user
Linux: cat /etc/passwd | grep -E ':[0-9]{4}:' (UID >= 1000)
```

- [ ] List all users on the system
- [ ] Compare against README authorized list
- [ ] **DELETE** users NOT in README (unless system accounts)
- [ ] Check score after bulk deletion

### 2.2 Administrator/Sudo Group 🔥
```
Windows: net localgroup Administrators
Linux: getent group sudo
```

- [ ] List all administrators
- [ ] Compare against README authorized ADMINS
- [ ] **REMOVE** from admin group if user should exist but not be admin
- [ ] **ADD** to admin group if user should be admin but isn't
- [ ] Check for users with UID 0 (Linux): `awk -F: '$3==0 {print $1}' /etc/passwd`

### 2.3 Guest Account ⚡
```
Windows: net user Guest
Linux: cat /etc/passwd | grep guest
```

- [ ] Disable Guest account (Windows: `net user Guest /active:no`)
- [ ] Check for guest-like accounts (guest, anonymous, test, temp)

### 2.4 Password Policy 🔥
```
Windows: net accounts
Linux: /etc/login.defs, /etc/security/pwquality.conf
```

**Windows (net accounts):**
- [ ] `/maxpwage:30` - Maximum password age 30 days
- [ ] `/minpwage:1` - Minimum password age 1 day
- [ ] `/minpwlen:12` - Minimum length 12 characters
- [ ] `/uniquepw:5` - Password history 5
- [ ] `/lockoutthreshold:5` - Lock after 5 bad attempts
- [ ] `/lockoutduration:30` - Lockout for 30 minutes

**Windows (secedit/secpol.msc):**
- [ ] Password complexity enabled
- [ ] Reversible encryption disabled
- [ ] Store passwords using reversible encryption: Disabled

**Linux (/etc/login.defs):**
- [ ] `PASS_MAX_DAYS 30`
- [ ] `PASS_MIN_DAYS 1`
- [ ] `PASS_WARN_AGE 7`

**Linux (/etc/security/pwquality.conf):**
- [ ] `minlen = 12`
- [ ] `dcredit = -1` (require digit)
- [ ] `ucredit = -1` (require uppercase)
- [ ] `lcredit = -1` (require lowercase)
- [ ] `ocredit = -1` (require special char)

**Linux (PAM):**
- [ ] Remove `nullok` from `/etc/pam.d/common-*`
- [ ] Add `remember=5` to pam_unix.so
- [ ] Add `sha512` to pam_unix.so

### 2.5 Set Strong Passwords ⚡
- [ ] For each authorized user, set strong password
- [ ] Example: `CyberP@tri0t2024!`
- [ ] Force password change on next login: `chage -d 0 username` (Linux)

### 2.6 Lock Root Account (Linux) ⚡
- [ ] `passwd -l root`
- [ ] `usermod -s /usr/sbin/nologin root`

### 2.7 Home Directory Permissions (Linux) ⚡
- [ ] `chmod 750 /home/*`

---

## 🔥 PHASE 3: FIREWALL

### Windows ⚡
```powershell
# Check status
Get-NetFirewallProfile | Select Name, Enabled

# Enable all profiles
Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True
```

- [ ] Enable Windows Firewall for ALL profiles (Domain, Private, Public)
- [ ] Block inbound connections that don't match a rule

### Linux ⚡
```bash
# Check status
sudo ufw status

# Enable
sudo ufw enable
sudo ufw default deny incoming
sudo ufw default allow outgoing
```

- [ ] Install ufw if not present: `apt install ufw`
- [ ] Enable ufw: `ufw --force enable`
- [ ] Default deny incoming: `ufw default deny incoming`
- [ ] Default allow outgoing: `ufw default allow outgoing`
- [ ] Allow required services (check README!):
  - [ ] `ufw allow OpenSSH` (if SSH required)
  - [ ] `ufw allow 80/tcp` (if web server required)
  - [ ] `ufw allow 443/tcp` (if HTTPS required)

---

## 🚫 PHASE 4: PROHIBITED FILES 🔥

### 4.1 Media Files
```
Extensions: .mp3, .mp4, .wav, .avi, .mkv, .flac, .mov, .wmv, .wma, .aac, .ogg, .flv
```

**Windows:**
```powershell
Get-ChildItem -Path C:\Users -Recurse -Include *.mp3,*.mp4,*.wav,*.avi,*.mkv -ErrorAction SilentlyContinue
```

**Linux:**
```bash
find /home -type f \( -iname "*.mp3" -o -iname "*.mp4" -o -iname "*.wav" -o -iname "*.avi" -o -iname "*.mkv" \) 2>/dev/null
```

- [ ] Search user directories for media files
- [ ] Delete each file found (except in system directories)
- [ ] Check score after deletion

**Skip these paths:**
- Windows: `C:\Windows\Web\`, `C:\Windows\Media\`
- Linux: `/usr/share/backgrounds`, `/usr/share/sounds`

### 4.2 Hacking Tools ⚠️
```
Look for: wireshark, nmap, metasploit, john, hashcat, cain, hydra, aircrack-ng, 
ettercap, ophcrack, netcat (nc), burpsuite, sqlmap, nikto, kismet
```

- [ ] Check installed programs for hacking tools
- [ ] Uninstall/remove any found
- [ ] Check for portable versions in user directories

### 4.3 Games ⚠️
```
Look for: Steam, Minecraft, games in Program Files, aisleriot, freeciv
```

- [ ] Check for game software
- [ ] Remove unless README says otherwise

### 4.4 Remote Access Tools ⚠️
```
Look for: TeamViewer, AnyDesk, LogMeIn, VNC (unless required)
```

- [ ] Check for unauthorized remote access tools
- [ ] Remove unless required by README

### 4.5 P2P/Torrent Software
```
Look for: BitTorrent, uTorrent, qBittorrent, Transmission, Deluge, Vuze
```

- [ ] Remove all P2P software

### 4.6 Prohibited Software List
```
Windows: winget uninstall <name>
Linux: apt purge <name>
```

Common prohibited packages:
- wireshark, wireshark-qt
- ophcrack
- aisleriot (solitaire)
- transmission-common, transmission-gtk
- qbittorrent, deluge
- ettercap-common, ettercap-graphical
- hydra, aircrack-ng, kismet
- freeciv, freeciv-data
- netcat, ncat, nc

---

## ⚙️ PHASE 5: SERVICES

### ⚠️ ALWAYS CHECK README BEFORE DISABLING SERVICES

### 5.1 Dangerous Services to Disable (unless README requires)

**Remote Access:**
| Service | Windows | Linux | Default Port |
|---------|---------|-------|--------------|
| Telnet | TlntSvr | telnetd, inetd | 23 |
| FTP | ftpsvc | vsftpd, proftpd | 21 |
| TFTP | TFTP | tftpd | 69 |
| SSH | sshd | ssh | 22 |
| RDP | TermService | xrdp | 3389 |
| VNC | varies | vncserver | 5900 |

**Web Servers:**
| Service | Windows | Linux | Default Port |
|---------|---------|-------|--------------|
| IIS | W3SVC | - | 80, 443 |
| Apache | - | apache2 | 80, 443 |
| Nginx | - | nginx | 80, 443 |

**Mail:**
| Service | Windows | Linux | Default Port |
|---------|---------|-------|--------------|
| SMTP | SMTPSVC | postfix, exim4 | 25 |
| POP3 | - | dovecot | 110 |
| IMAP | - | dovecot | 143 |

**File Sharing:**
| Service | Windows | Linux |
|---------|---------|-------|
| SMB/CIFS | LanmanServer | smbd, nmbd |
| NFS | - | nfs-kernel-server |

**Other:**
| Service | Windows | Linux |
|---------|---------|-------|
| SNMP | SNMP | snmpd |
| CUPS (printing) | Spooler | cups |
| Avahi (mDNS) | - | avahi-daemon |
| Bluetooth | bthserv | bluetooth |

### 5.2 How to Disable Services

**Windows:**
```powershell
Stop-Service -Name "ServiceName" -Force
Set-Service -Name "ServiceName" -StartupType Disabled
```

**Linux:**
```bash
sudo systemctl stop servicename
sudo systemctl disable servicename
```

### 5.3 Service Checklist

- [ ] List all running services
- [ ] Cross-reference with README required services
- [ ] Disable unnecessary services
- [ ] Check score after each batch

---

## 🔒 PHASE 6: SECURITY SETTINGS

### 6.1 Windows Security Settings 🔥

**UAC (User Account Control):**
```
Registry: HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
```
- [ ] EnableLUA = 1 (UAC enabled)
- [ ] PromptOnSecureDesktop = 1 (Secure desktop for prompts)
- [ ] ConsentPromptBehaviorAdmin = 4 (Prompt for consent)
- [ ] ValidateAdminCodeSignatures = 1 (Only elevate signed executables)

**Login Security:**
- [ ] DisableCAD = 0 (Require Ctrl+Alt+Del)
- [ ] DontDisplayLastUserName = 1 (Don't show last username)

**Remote Desktop:**
- [ ] Disable if not required: `fDenyTSConnections = 1`
- [ ] If required: Enable NLA (Network Level Authentication)
- [ ] TLS Security Layer = 2 (SSL/TLS only)

**Remote Assistance:**
- [ ] Disable: `fAllowToGetHelp = 0`
- [ ] Disable unsolicited: `fAllowUnsolicited = 0`

**Windows Defender:**
- [ ] Enable real-time protection
- [ ] Update signatures: `Update-MpSignature`
- [ ] Enable cloud protection (MAPS)
- [ ] Enable network protection

**AutoPlay/AutoRun:**
- [ ] Disable: `NoDriveTypeAutoRun = 255`

**SmartScreen:**
- [ ] Enable: `EnableSmartScreen = 1`

**Anonymous Access:**
- [ ] restrictanonymous = 1
- [ ] restrictanonymoussam = 1
- [ ] everyoneincludesanonymous = 0

**SMB Hardening:**
- [ ] Disable SMBv1
- [ ] Enable SMB signing
- [ ] Enable SMB encryption

**Audit Policies:**
```powershell
auditpol /set /category:"Account Logon" /success:enable /failure:enable
auditpol /set /category:"Account Management" /success:enable /failure:enable
auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable
auditpol /set /category:"Policy Change" /success:enable /failure:enable
auditpol /set /category:"Privilege Use" /success:enable /failure:enable
auditpol /set /category:"System" /success:enable /failure:enable
```

### 6.2 Linux Security Settings 🔥

**Sysctl Hardening (/etc/sysctl.conf or /etc/sysctl.d/99-security.conf):**
```bash
# Network security
net.ipv4.tcp_syncookies = 1
net.ipv4.ip_forward = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0

# Kernel security
kernel.randomize_va_space = 2  # ASLR
kernel.kptr_restrict = 2       # Hide kernel pointers
kernel.perf_event_paranoid = 3 # Restrict perf
kernel.yama.ptrace_scope = 3   # Restrict ptrace

# IPv6 (disable if not needed)
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
```

- [ ] Apply: `sysctl -p`

**SSH Hardening (/etc/ssh/sshd_config):**
- [ ] `PermitRootLogin no`
- [ ] `PasswordAuthentication no` (if using keys) OR strong passwords
- [ ] `PermitEmptyPasswords no`
- [ ] `X11Forwarding no`
- [ ] `MaxAuthTries 3`
- [ ] `Protocol 2`

**File Permissions:**
- [ ] `/etc/passwd` - 644, root:root
- [ ] `/etc/shadow` - 640, root:shadow
- [ ] `/etc/group` - 644, root:root
- [ ] `/etc/gshadow` - 640, root:shadow
- [ ] `/boot/grub/grub.cfg` - 640, root:root

**Sudoers:**
- [ ] `/etc/sudoers` - 440, root:root
- [ ] Check for `NOPASSWD` entries (remove unless required)
- [ ] Check for unauthorized users in sudoers

**AppArmor/SELinux:**
- [ ] Enable AppArmor: `systemctl enable --now apparmor`
- [ ] Enforce profiles: `aa-enforce /etc/apparmor.d/*`

**Fail2Ban:**
- [ ] Install: `apt install fail2ban`
- [ ] Enable: `systemctl enable --now fail2ban`

**Auditd:**
- [ ] Install: `apt install auditd`
- [ ] Enable: `systemctl enable --now auditd`

---

## ⚠️ PHASE 7: UPDATES (CHECK README FIRST!)

**Some rounds say "DO NOT UPDATE" - this causes PENALTIES!**

### If README ALLOWS updates:

**Windows:**
```powershell
# Configure automatic updates
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUOptions" -Value 4
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -Value 0

# Trigger update
UsoClient.exe StartScan
UsoClient.exe StartDownload
UsoClient.exe StartInstall
```

**Linux:**
```bash
apt update
apt upgrade -y
apt install unattended-upgrades
```

### If README says NO UPDATES:
- [ ] **SKIP THIS ENTIRE SECTION**
- [ ] Do NOT run apt update/upgrade
- [ ] Do NOT run Windows Update

---

## 🔍 PHASE 8: PERSISTENCE & BACKDOORS

### 8.1 Scheduled Tasks / Cron Jobs 🔥

**Windows:**
```powershell
Get-ScheduledTask | Where-Object {$_.TaskPath -notlike "\Microsoft\*"}
```

**Linux:**
```bash
# System crontabs
cat /etc/crontab
ls -la /etc/cron.*
cat /etc/cron.d/*

# User crontabs
for user in $(cut -f1 -d: /etc/passwd); do crontab -u $user -l 2>/dev/null; done
```

- [ ] Review all scheduled tasks/cron jobs
- [ ] Remove suspicious entries
- [ ] Check for reverse shells, downloaders, persistence

### 8.2 Startup Items 🔥

**Windows:**
```
Locations to check:
- HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
- HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
- HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
- C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup
- C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
```

**Linux:**
```
Locations to check:
- /etc/rc.local
- /etc/init.d/
- ~/.bashrc, ~/.bash_profile, ~/.profile
- /etc/profile, /etc/profile.d/
- systemd services: /etc/systemd/system/
```

- [ ] Check all startup locations
- [ ] Remove suspicious entries
- [ ] Look for scripts that download/execute remote code

### 8.3 Services with Suspicious Paths

**Windows:**
```powershell
Get-WmiObject Win32_Service | Where-Object {$_.PathName -match 'Users|AppData|Temp'} | Select Name, PathName
```

- [ ] Check for services running from user directories
- [ ] Remove or investigate suspicious services

### 8.4 WMI Persistence (Windows)

```powershell
Get-WmiObject -Namespace root\subscription -Class __EventConsumer
Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding
```

- [ ] Check for WMI event subscriptions
- [ ] Remove malicious subscriptions

### 8.5 Image File Execution Options (Windows)

```
HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\
```

- [ ] Check for debugger hijacks on sethc.exe, utilman.exe, osk.exe, magnify.exe, narrator.exe
- [ ] Remove any Debugger values

### 8.6 Hosts File

**Windows:** `C:\Windows\System32\drivers\etc\hosts`
**Linux:** `/etc/hosts`

- [ ] Check for suspicious redirects
- [ ] Remove entries that redirect legitimate sites

### 8.7 Listening Ports

```bash
# Linux
netstat -tulpn | grep LISTEN
ss -tulpn

# Windows
netstat -an | findstr LISTEN
```

- [ ] Identify all listening ports
- [ ] Investigate unknown services
- [ ] Close unnecessary ports

### 8.8 Aliases (Linux)

Check for malicious aliases in:
- `/etc/profile`
- `/etc/bash.bashrc`
- `/etc/profile.d/*.sh`
- `~/.bashrc`
- `~/.bash_profile`
- `~/.zshrc`

Common malicious aliases:
```bash
alias sudo='...'  # Credential stealing
alias ls='...'    # Hidden output
alias cd='...'    # Backdoor execution
```

- [ ] Review all alias definitions
- [ ] Remove suspicious aliases

---

## 🌐 PHASE 9: BROWSER & APPLICATION SECURITY ⚡

### 9.1 Firefox Policies

**Windows:** `C:\Program Files\Mozilla Firefox\distribution\policies.json`
**Linux:** `/etc/firefox/policies/policies.json`

```json
{
  "policies": {
    "DisableFirefoxAccounts": true,
    "DisablePocket": true,
    "EnableTrackingProtection": {"Value": true, "Locked": true},
    "PasswordManagerEnabled": false,
    "DisableTelemetry": true
  }
}
```

### 9.2 Chrome/Chromium Policies

**Windows:** `HKLM:\SOFTWARE\Policies\Google\Chrome`
**Linux:** `/etc/chromium/policies/managed/`

- [ ] Enable SafeBrowsing
- [ ] Disable password manager
- [ ] Block popups

### 9.3 Remove Unauthorized Browsers

- [ ] If README specifies a browser, remove others
- [ ] Check for portable browsers in user directories

---

## 🖥️ PHASE 10: WINDOWS SERVER SPECIFIC

### 10.1 Active Directory / Domain Controller

- [ ] Check for unauthorized domain admins
- [ ] Review Group Policy Objects
- [ ] Enable LDAP signing: `LDAPServerIntegrity = 2`
- [ ] Disable cached logons: `CachedLogonsCount = 0`
- [ ] Enable FIPS-compliant algorithms

### 10.2 DNS Server

- [ ] Disable recursion if not needed
- [ ] Hide version information

### 10.3 IIS Web Server

- [ ] Disable directory browsing
- [ ] Remove WebDAV Publishing
- [ ] Stop Default Web Site if not needed
- [ ] Remove sample applications

### 10.4 FTP Server (vsftpd) 🔥

**If FTP is REQUIRED by README, harden it properly:**

```
/etc/vsftpd.conf:
anonymous_enable=NO
local_enable=YES
write_enable=YES (if users need to upload)
chroot_local_user=YES
local_umask=022

# SSL/TLS - CRITICAL (often missed!)
ssl_enable=YES
force_local_logins_ssl=YES
force_local_data_ssl=YES
ssl_tlsv1=NO
ssl_sslv2=NO
ssl_sslv3=NO
ssl_tlsv1_1=NO
ssl_tlsv1_2=YES
rsa_cert_file=/etc/ssl/certs/ssl-cert-snakeoil.pem
rsa_private_key_file=/etc/ssl/private/ssl-cert-snakeoil.key
```

- [ ] Disable anonymous access (unless required)
- [ ] **Enable SSL/TLS for logins** ⚠️ COMMONLY MISSED
- [ ] **Force SSL for data transfer** ⚠️ COMMONLY MISSED
- [ ] Use TLS 1.2+ only (disable SSLv2, SSLv3, TLS 1.0, 1.1)
- [ ] Chroot local users
- [ ] Set proper FTP root directory permissions (755, root:root)
- [ ] Configure passive ports if needed

**FileZilla Server (Windows):**
- [ ] Set minimum TLS version to 1.3

### 10.5 Print Spooler

- [ ] Disable on servers (PrintNightmare vulnerability)

### 10.6 Windows Remote Management (WinRM)

- [ ] Disable if not required

### 10.7 SMB Shares

- [ ] Remove non-default shares
- [ ] Keep only: ADMIN$, C$, IPC$, print$

---

## 🐧 PHASE 11: LINUX SPECIFIC

### 11.0 Service Configuration Patterns (From Past Rounds)

**IMPORTANT: Each round has different required services. Examples from past rounds:**

| Round | Required Services | Services to REMOVE |
|-------|------------------|-------------------|
| Round 1 2024 | SSH (setup & secure) | FTP, Apache, Nginx |
| Round 2 2024 | vsftpd (FTP with SSL!) | SSH |
| Semifinals 2023 | Docker, MySQL, Nginx/Apache | varies |

**Key Lesson: READ THE README to know which services to keep vs remove!**

### 11.1 Check for UID 0 Users

```bash
awk -F: '$3==0 {print $1}' /etc/passwd
```

- [ ] Only root should have UID 0

### 11.2 Check SUID/SGID Files

```bash
find / -perm -4000 -type f 2>/dev/null  # SUID
find / -perm -2000 -type f 2>/dev/null  # SGID
```

- [ ] Review unusual SUID/SGID files
- [ ] Remove SUID from unnecessary binaries

### 11.3 World-Writable Files

```bash
find / -type f -perm -0002 2>/dev/null
```

- [ ] Fix permissions on world-writable files

### 11.4 Unowned Files

```bash
find / -nouser -o -nogroup 2>/dev/null
```

- [ ] Assign ownership to unowned files

### 11.5 Apache Hardening

```
/etc/apache2/conf-available/security.conf:
ServerTokens Prod
ServerSignature Off
TraceEnable Off
```

- [ ] Apply hardening configuration
- [ ] Enable mod_headers
- [ ] Remove default pages

### 11.6 Docker Hardening (If Required)

**If Docker is required by README:**

```bash
# Check Docker daemon config
cat /etc/docker/daemon.json

# List running containers
docker ps -a

# Check for privileged containers (BAD)
docker inspect --format='{{.HostConfig.Privileged}}' <container>
```

- [ ] Disable `--privileged` mode on containers
- [ ] Don't run containers as root
- [ ] Use user namespaces
- [ ] Limit container capabilities
- [ ] Enable content trust: `export DOCKER_CONTENT_TRUST=1`
- [ ] Check for exposed ports
- [ ] Remove unused images: `docker image prune`
- [ ] Check docker group membership (shouldn't include unauthorized users)

### 11.7 MySQL/MariaDB Hardening (If Required)

**If MySQL is required by README:**

```bash
# Run security script
mysql_secure_installation

# Check for anonymous users
mysql -e "SELECT User, Host FROM mysql.user WHERE User='';"

# Check for remote root login
mysql -e "SELECT User, Host FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');"
```

- [ ] Run `mysql_secure_installation`
- [ ] Remove anonymous users
- [ ] Disable remote root login
- [ ] Remove test database
- [ ] Set strong root password
- [ ] Check user privileges: `SHOW GRANTS FOR 'user'@'host';`
- [ ] Bind to localhost only (if not needed remotely): `bind-address = 127.0.0.1`

### 11.8 vsftpd Hardening

```
/etc/vsftpd.conf:
anonymous_enable=NO
chroot_local_user=YES
write_enable=NO (unless required)
local_umask=022
```

---

## ✅ PHASE 12: FINAL VERIFICATION

- [ ] Run comprehensive scan one more time
- [ ] Check current score
- [ ] Review any penalties
- [ ] Verify all forensics questions answered
- [ ] Double-check README compliance

---

## 📊 SCORE TRACKING STRATEGY

### After EVERY significant action:
1. Wait ~30 seconds for scoring engine
2. Check if score changed
3. If score **DROPPED**: 
   - Identify what caused penalty
   - UNDO if possible
   - Note for future reference
4. If score **unchanged**:
   - Action didn't help OR already fixed
   - Move on
5. If score **increased**:
   - Note what worked
   - Continue

### Batch Operations:
- Delete all unauthorized users at once, then check score
- Disable all unnecessary services at once, then check score
- This is faster than checking after each individual change

---

## 🚨 COMMON PENALTIES (AVOID!)

| Action | Why It's Bad |
|--------|--------------|
| Deleting authorized users | Breaks required functionality |
| Removing required services | Breaks required functionality |
| Running updates when README says no | Direct violation |
| Changing passwords on service accounts | Can break services |
| Removing required software | Breaks required functionality |
| Breaking network connectivity | Can't score if offline |
| Overly aggressive firewall rules | Can block scoring engine |

---

## 💡 SPEED TIPS

1. **Forensics first** - Easy points, zero risk
2. **Bulk operations** - Don't check score after every tiny change
3. **README is law** - When in doubt, re-read it
4. **Skip if unsure** - Come back to risky items later
5. **Prioritize high-value items** - Users, firewall, services
6. **Don't overthink** - If it looks wrong, it probably is

---

## 🎯 POINT VALUE ESTIMATES

| Category | Typical Points |
|----------|---------------|
| Forensics question | 3-5 each |
| Unauthorized user removed | 2-3 |
| User removed from admin | 2-3 |
| Firewall enabled | 3-5 |
| Password policy | 2-3 each setting |
| Service disabled | 2-3 |
| Prohibited file removed | 1-2 |
| Security setting fixed | 2-3 |
| Update installed | 2-5 |
| Backdoor removed | 3-5 |

**Total typical image: 80-100 points possible**

---

*This checklist will be refined based on answer keys and score reports.*
