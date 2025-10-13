# Changelog

All notable changes to this project will be documented in this file.

## v0.1.0 - Initial MVP
- Unified CyberPatriot hardening tool (Linux and Windows) with async/parallel execution
- Linux: repo sanity, updates, service whitelist/purge, UFW/nftables firewall, SSH hardening (key-only, port override), PAM/login.defs policies, fail2ban, AppArmor, auditd+rsyslog, filesystem perms, cron lockdown, interface blacklists, optional Suricata/DNSCrypt/Docker hardening, software hygiene
- Windows: password policy, disable Guest and blank passwords, firewall rules from config, optional OpenSSH hardening, RDP with NLA + port override, disable Telnet and IPv6, enable audit policies and updates, service whitelist, software hygiene, extra server hardening if Server SKU
- Config-driven `ironguard.toml`; `scan` command for inventory/lynis/malware checks on Linux
- Install scripts for Windows/Linux; release pipeline attaching binaries to tagged releases

### New CLI behavior
- `ironguard run` runs scripts (defaults to script mode; `--dry-run` supported)
- `ironguard` launches the TUI (reserved for AI workflow)
- `ironguard scan` installs needed tools and runs:
  - Linux: inventory + lynis + malware scans (clamav/chkrootkit/rkhunter), `--full` for deeper scans
  - Windows: Microsoft Defender Quick/Full scan (`--full`), signature update, threat history output
  - VirusTotal integration: `--vt-file <path>` (hash lookup), `--vt-url <url>` (submit URL), `--vt-api-key <key>`
