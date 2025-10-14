use anyhow::{Context, Result};
use tokio::{process::Command, fs};
use crate::cli::config::Config;

#[derive(Clone, Debug)]
pub struct EngineOptions {
    pub dry_run: bool,
}

pub mod linux {
    use super::*;

    pub async fn run_baseline(opts: &EngineOptions) -> Result<()> {
		// Backwards-compatible wrapper without config: run core steps
		let p = packages::ensure_packages(opts);
		let s = ssh::harden_sshd(opts);
		let f = firewall::configure_firewall_no_cfg(opts);
		let k = kernel::harden_kernel(opts);
		let i = interfaces::harden_interfaces(opts);
		let pa = pam::configure_pam(opts);
		let ld = login_defs::configure_login_defs(opts);
		let (rp, rs, rf, rk, ri, rpa, rld) = tokio::join!(p, s, f, k, i, pa, ld);
		rp?; rs?; rf?; rk?; ri?; rpa?; rld?;
        Ok(())
    }

    pub async fn run_baseline_with_config(opts: &EngineOptions, cfg: &Config) -> Result<()> {
		let p = packages::ensure_packages(opts);
        let s = ssh::harden_sshd(opts);
        let ssp = ssh::apply_ssh_port(opts, cfg);
        let skey = ssh::enforce_ssh_key_only(opts, cfg);
		let f = firewall::configure_firewall(opts, cfg);
		let k = kernel::harden_kernel(opts);
		let i = interfaces::harden_interfaces(opts);
		let pa = pam::configure_pam(opts);
		let ld = login_defs::configure_login_defs(opts);
		let fb = fail2ban::enable_fail2ban(opts);
		let aa = apparmor::enable_apparmor(opts);
		let apt = apt_settings::configure_apt_unattended(opts);
		let sud = sudoers_login::harden_sudoers_and_login(opts);
		let usr = users::enforce_users_and_passwords(opts, cfg);
		let aud = audit::enable_audit_and_rsyslog(opts);
		let fssec = fs_security::tighten_filesystem_security(opts);
		let nft = nftables::configure_nftables(opts, cfg);
		let ids = ids::configure_suricata(opts);
        let knock = knockd::configure_knockd(opts, cfg);
		let hosts = hosts_hardening::configure_hosts_deny(opts);
        let web = web_hardening::configure_apache_modsecurity(opts, cfg);
        let nginx = web_hardening::configure_nginx_hardening(opts, cfg);
        let fb_tune = fail2ban::tune_fail2ban(opts);
        let session = session_security::configure_screen_timeout(opts);
        let cron = cron_lockdown::configure_cron(opts, cfg);
		let svc = service_whitelist::enforce_service_whitelist(opts, cfg);
		let db = db_hardening::configure_mysql_postgres(opts, cfg);
		let docker = docker_security::configure_docker(opts, cfg);
		let dnssec = dns_security::configure_dnscrypt(opts, cfg);
		let hyg = software_hygiene::purge_unwanted_software(opts, cfg);
		let (rp, rs, rssp, rskey, rf, rk, ri, rpa, rld, rfb, raa, rapt, rsud, rusr, raud, rfs, rnft, rids, rkn, rhs, rweb, rnginx, rfb_tune, rsession, rcron, rsvc, rdb, rdock, rdns, rhyg) = tokio::join!(
			p, s, ssp, skey, f, k, i, pa, ld, fb, aa, apt, sud, usr, aud, fssec, nft, ids, knock, hosts, web, nginx, fb_tune, session, cron, svc, db, docker, dnssec, hyg
		);
		rp?; rs?; rssp?; rskey?; rf?; rk?; ri?; rpa?; rld?; rfb?; raa?; rapt?; rsud?; rusr?; raud?; rfs?; rnft?; rids?; rkn?; rhs?; rweb?; rnginx?; rfb_tune?; rsession?; rcron?; rsvc?; rdb?; rdock?; rdns?; rhyg?;
        Ok(())
    }

    mod packages {
        use super::*;
        pub async fn ensure_packages(opts: &EngineOptions) -> Result<()> {
            if opts.dry_run {
                println!("[linux:packages] dry-run: apt/dnf update && upgrade; remove forbidden");
                return Ok(());
            }
            // Validate/repair repos prior to operations
            if which::which("apt-get").is_ok() {
                // Basic sanity for /etc/apt/sources.list presence; fallback to ubuntu/debian defaults if missing
                if fs::metadata("/etc/apt/sources.list").await.is_err() {
                    // Try to detect ID and VERSION_CODENAME
                    let id = run_cmd_capture("bash", &["-lc",". /etc/os-release 2>/dev/null; echo $ID"]).await.unwrap_or_default().trim().to_string();
                    let code = run_cmd_capture("bash", &["-lc",". /etc/os-release 2>/dev/null; echo $VERSION_CODENAME"]).await.unwrap_or_default().trim().to_string();
                    if id.contains("ubuntu") && !code.is_empty() {
                        let content = format!("deb https://mirrors.kernel.org/ubuntu/ {} main restricted universe multiverse\ndeb https://mirrors.kernel.org/ubuntu/ {}-updates main restricted universe multiverse\ndeb https://security.ubuntu.com/ubuntu/ {}-security main restricted universe multiverse\n", code, code, code);
                        fs::write("/etc/apt/sources.list", content).await.ok();
                    } else if id.contains("debian") && !code.is_empty() {
                        let content = format!("deb http://deb.debian.org/debian/ {} main contrib non-free non-free-firmware\ndeb http://security.debian.org/debian-security {}-security main contrib non-free non-free-firmware\ndeb http://deb.debian.org/debian/ {}-updates main contrib non-free non-free-firmware\n", code, code, code);
                        fs::write("/etc/apt/sources.list", content).await.ok();
                    }
                }
                run_cmd_env(&[("DEBIAN_FRONTEND","noninteractive")], "apt-get", &["-y","-q","update"]).await?;
                run_cmd_env(&[("DEBIAN_FRONTEND","noninteractive")], "apt-get", &["-y","-q","upgrade"]).await?;
                // Ensure terminal editors available
                let _ = run_cmd_env(&[("DEBIAN_FRONTEND","noninteractive")], "apt-get", &["-y","-q","install","neovim","vim"]).await;
                // Best-effort install baseline dependencies used by hardening steps
                let deps = [
                    "ufw","nftables","fail2ban","apparmor","apparmor-utils","auditd","rsyslog",
                    // optional tools if present
                    "dnscrypt-proxy","suricata","clamav","chkrootkit","rkhunter","lynis"
                ];
                let mut args = vec!["-y","-q","install"]; args.extend(deps.iter());
                let _ = run_cmd_env(&[("DEBIAN_FRONTEND","noninteractive")], "apt-get", &args).await;
            } else if which::which("dnf").is_ok() {
                // Optionally tighten repos: prefer enabled official repos, avoid third-party if detected (placeholder)
                let _ = run_cmd("bash", &["-lc","if [ -d /etc/yum.repos.d ]; then echo 'repos present'; fi"]).await;
                run_cmd("dnf", &["-y", "-q", "makecache"]).await.ok();
                run_cmd("dnf", &["-y", "-q", "update"]).await.ok();
                // Ensure terminal editors available
                let _ = run_cmd("dnf", &["-y","install","neovim","vim"]).await;
                // Best-effort dependencies (rpm-based)
                let deps = [
                    "firewalld","nftables","fail2ban","audit","rsyslog","dnscrypt-proxy","suricata","clamav","chkrootkit","rkhunter","lynis"
                ];
                let mut args = vec!["dnf","-y","install"]; args.extend(deps.iter());
                let _ = run_cmd("dnf", &args).await;
            } else {
                println!("[linux:packages] no apt/dnf detected");
            }
            Ok(())
        }
    }

    mod service_whitelist {
        use super::*;
        pub async fn enforce_service_whitelist(opts: &EngineOptions, cfg: &Config) -> Result<()> {
            // Essential desktop apps are exempt; network services are removed unless allowed
            let allowed = cfg.allowed_services.as_ref().map(|v| v.iter().map(|s| s.to_ascii_lowercase()).collect::<Vec<_>>()).unwrap_or_default();
            let is_allowed = |keys: &[&str]| -> bool {
                keys.iter().any(|k| allowed.iter().any(|a| a.contains(&k.to_ascii_lowercase())))
            };

            // Define common services and their package names
            let candidates: &[(&[&str], &[&str])] = &[
                (&["apache","apache2","http","web"], &["apache2","apache2-bin","apache2-data","apache2-utils","httpd","mod_ssl"]),
                (&["nginx"], &["nginx"]),
                (&["lighttpd"], &["lighttpd"]),
                (&["ftp","vsftpd","proftpd","tftp"], &["vsftpd","proftpd","tftpd-hpa","tftp-server"]),
                (&["samba","smb"], &["samba","samba-common","smbclient"]),
                (&["telnet"], &["telnetd","telnet","telnet-server","telnet-client"]),
                (&["rdp","xrdp"], &["xrdp"]),
                (&["vnc","x11vnc","tightvnc"], &["tigervnc","tightvncserver","x11vnc"]),
                (&["snmp"], &["snmpd","net-snmp"]),
                (&["bind","dns"], &["bind9","named"]),
                (&["postfix","smtp"], &["postfix"]),
                (&["dovecot","imap","pop3"], &["dovecot-core","dovecot-imapd","dovecot-pop3d"]),
                (&["mysql","mariadb"], &["mysql-server","mariadb-server"]),
                (&["postgres","postgresql"], &["postgresql"]),
                (&["docker","container"], &["docker","docker.io","docker-ce"]),
                (&["squid","proxy"], &["squid"]),
                (&["openvpn","vpn"], &["openvpn"]),
                (&["snort"], &["snort"]),
                (&["cups","print"], &["cups","cups-daemon","cups-client"]),
                (&["avahi","zeroconf"], &["avahi-daemon","avahi-utils"]),
                (&["bluetooth"], &["bluetooth","bluez"]),
                (&["php"], &["php","libapache2-mod-php"]),
                (&["netcat","nc"], &["netcat","netcat-traditional","ncat"]),
                (&["tcpdump"], &["tcpdump"]),
                (&["wireshark"], &["wireshark"]),
                (&["xinetd","inetd"], &["xinetd","openbsd-inetd","inetutils-inetd"]),
            ];

            // Build keep set: essential tools, user keep_packages, and all packages for allowed services
            let mut keep_packages: std::collections::HashSet<String> = std::collections::HashSet::new();
            let essential_keep = [
                "firefox","chromium","google-chrome-stable","chromium-browser","nautilus","dolphin","thunar","pcmanfm","nemo",
                "network-manager","pulseaudio","pipewire","alsa-utils","lightdm","gdm3","sddm","xorg","openssh-client"
            ];
            for e in essential_keep { keep_packages.insert(e.to_ascii_lowercase()); }
            if let Some(extra) = &cfg.keep_packages { for p in extra { keep_packages.insert(p.to_ascii_lowercase()); } }
            for (keys, pkgs) in candidates.iter() {
                if is_allowed(keys) { for p in *pkgs { keep_packages.insert(p.to_ascii_lowercase()); } }
            }
            // Force remove has highest priority: drop from keep set
            if let Some(force) = &cfg.force_remove { for p in force { keep_packages.remove(&p.to_ascii_lowercase()); } }

            // Mark keep packages to avoid autoremove where supported (and protect criticals)
            let critical_keep = ["systemd","dbus","cron","rsyslog","wpa_supplicant","NetworkManager","nftables","iptables","ufw","firewalld"];
            for c in critical_keep { keep_packages.insert(c.to_ascii_lowercase()); }
            if which::which("apt-mark").is_ok() {
                for p in &keep_packages { let _ = run_cmd("apt-mark", &["manual", p]).await; }
            }

            for (keys, pkgs) in candidates.iter() {
                if is_allowed(keys) { continue; }
                if opts.dry_run { println!("[linux:svc] dry-run: remove disallowed service(s): {:?}", keys); continue; }
                // Stop/disable known unit names loosely based on keys
                if which::which("systemctl").is_ok() {
                    for unit in ["apache2","httpd","nginx","lighttpd","vsftpd","proftpd","smbd","snmpd","named","xrdp","docker"] {
                        let _ = run_cmd("systemctl", &["disable", "--now", unit]).await;
                    }
                }
                if which::which("apt-get").is_ok() {
                    let remove_list: Vec<&str> = pkgs.iter().copied().filter(|p| !keep_packages.contains(&p.to_ascii_lowercase())).collect();
                    if !remove_list.is_empty() {
                        let mut args = vec!["-y","-q","purge"]; args.extend(remove_list.iter().copied());
                        let _ = run_cmd_env(&[("DEBIAN_FRONTEND","noninteractive")], "apt-get", &args).await;
                    }
                    let _ = run_cmd_env(&[("DEBIAN_FRONTEND","noninteractive")], "apt-get", &["-y","-q","autoremove","--purge"]).await;
                } else if which::which("dnf").is_ok() {
                    let remove_list: Vec<&str> = pkgs.iter().copied().filter(|p| !keep_packages.contains(&p.to_ascii_lowercase())).collect();
                    if !remove_list.is_empty() {
                        let mut args = vec!["dnf","-y","remove"]; args.extend(remove_list.iter().copied());
                        let _ = run_cmd("dnf", &args).await;
                    }
                }
            }
            Ok(())
        }
    }

    mod software_hygiene {
        use super::*;
        pub async fn purge_unwanted_software(opts: &EngineOptions, cfg: &Config) -> Result<()> {
            // Hacking tools and games purge
            let hacking_tools: &[&str] = &[
                "john","nmap","vuze","frostwire","kismet","medusa","hydra","truecrack","ophcrack","nikto",
                "cryptcat","nc","netcat","tightvncserver","x11vnc","xinetd","samba","postgresql","vsftpd","apache",
                "apache2","ftp","mysql","php","snmp","pop3","dovecot","bind9","nginx","telnet","rlogind","rshd",
                "rcmd","rexecd","rbootd","rquotad","rstatd","rusersd","rwalld","rexd","fingerd","tftpd","wireshark","burpsuite",
                "telnetd","postfix","proftpd","tftpd-hpa","tftp-server","dovecot-core","dovecot-imapd","dovecot-pop3d"
            ];
            let games: &[&str] = &[
                "gnome-games","iagno","lightsoff","four-in-a-row","gnome-robots","pegsolitaire","gnome-2048","hitori",
                "gnome-klotski","gnome-mines","gnome-mahjongg","gnome-sudoku","quadrapassel","swell-foop","gnome-tetravex",
                "gnome-taquin","aisleriot","gnome-chess","five-or-more","gnome-nibbles","tali","freeciv","wesnoth"
            ];

            if opts.dry_run {
                println!("[linux:hygiene] dry-run: purge hacking tools and games ({} + {})", hacking_tools.len(), games.len());
                return Ok(());
            }
            // Build keep set from essentials and config
            let mut keep_packages: std::collections::HashSet<String> = std::collections::HashSet::new();
            let essential_keep = [
                "firefox","chromium","google-chrome-stable","chromium-browser","nautilus","dolphin","thunar","pcmanfm","nemo","javascript",
                "network-manager","pulseaudio","pipewire","alsa-utils","lightdm","gdm3","sddm","xorg","openssh-client"
            ];
            for e in essential_keep { keep_packages.insert(e.to_ascii_lowercase()); }
            if let Some(extra) = &cfg.keep_packages { for p in extra { keep_packages.insert(p.to_ascii_lowercase()); } }
            // Force remove has highest priority
            let force_list: std::collections::HashSet<String> = cfg.force_remove.clone().unwrap_or_default().into_iter().map(|s| s.to_ascii_lowercase()).collect();

            if which::which("apt-get").is_ok() {
                let ht: Vec<&str> = hacking_tools.iter().copied().filter(|p| !keep_packages.contains(&p.to_ascii_lowercase())).collect();
                // Force-remove entries bypass checks
                let mut ht_final: Vec<&str> = ht.into_iter().collect();
                for f in &force_list { ht_final.push(Box::leak(f.clone().into_boxed_str())); }
                if !ht_final.is_empty() { let mut args = vec!["-y","-q","purge"]; args.extend(ht_final.iter().copied()); let _ = run_cmd_env(&[("DEBIAN_FRONTEND","noninteractive")], "apt-get", &args).await; }
                let gm: Vec<&str> = games.iter().copied().filter(|p| !keep_packages.contains(&p.to_ascii_lowercase())).collect();
                if !gm.is_empty() { let mut args = vec!["-y","-q","purge"]; args.extend(gm.iter().copied()); let _ = run_cmd_env(&[("DEBIAN_FRONTEND","noninteractive")], "apt-get", &args).await; }
                let _ = run_cmd_env(&[("DEBIAN_FRONTEND","noninteractive")], "apt-get", &["-y","-q","autoremove","--purge"]).await;
            } else if which::which("dnf").is_ok() {
                let ht: Vec<&str> = hacking_tools.iter().copied().filter(|p| !keep_packages.contains(&p.to_ascii_lowercase())).collect();
                let mut ht_final: Vec<&str> = ht.into_iter().collect();
                for f in &force_list { ht_final.push(Box::leak(f.clone().into_boxed_str())); }
                if !ht_final.is_empty() { let mut args = vec!["dnf","-y","remove"]; args.extend(ht_final.iter().copied()); let _ = run_cmd("dnf", &args).await; }
                let gm: Vec<&str> = games.iter().copied().filter(|p| !keep_packages.contains(&p.to_ascii_lowercase())).collect();
                if !gm.is_empty() { let mut args = vec!["dnf","-y","remove"]; args.extend(gm.iter().copied()); let _ = run_cmd("dnf", &args).await; }
            }
            Ok(())
        }
    }

    mod db_hardening {
        use super::*;
        pub async fn configure_mysql_postgres(opts: &EngineOptions, cfg: &Config) -> Result<()> {
            let allowed = cfg.allowed_services.as_ref().map(|v| v.iter().map(|s| s.to_ascii_lowercase()).collect::<Vec<_>>()).unwrap_or_default();
            let allow_mysql = allowed.iter().any(|a| a.contains("mysql") || a.contains("mariadb"));
            let allow_pg = allowed.iter().any(|a| a.contains("postgres"));
            if opts.dry_run {
                println!("[linux:db] dry-run: mysql_allowed={} pg_allowed={}", allow_mysql, allow_pg);
                return Ok(());
            }
            if allow_mysql && (which::which("mysql").is_ok() || which::which("mariadbd").is_ok()) {
                let cnf = "[mysqld]\nlocal-infile=0\nskip-show-database\nskip-symbolic-links\nsafe-user-create=1\nsecure-file-priv=/var/lib/mysql-files\nexplicit_defaults_for_timestamp=1\n";
                fs::create_dir_all("/etc/mysql/conf.d").await.ok();
                fs::write("/etc/mysql/conf.d/hardening.cnf", cnf).await.ok();
                if which::which("systemctl").is_ok() { let _ = run_cmd("systemctl", &["restart","mysql"]).await; }
            }
            if allow_pg && which::which("psql").is_ok() {
                // Append basic security settings for each version path
                let _ = run_cmd("bash", &["-lc","for f in /etc/postgresql/*/main/postgresql.conf; do echo 'ssl=on' | tee -a $f >/dev/null; done"]).await;
                if which::which("systemctl").is_ok() { let _ = run_cmd("systemctl", &["restart","postgresql"]).await; }
            }
            Ok(())
        }
    }

    mod docker_security {
        use super::*;
        pub async fn configure_docker(opts: &EngineOptions, cfg: &Config) -> Result<()> {
            let allowed = cfg.allowed_services.as_ref().map(|v| v.iter().map(|s| s.to_ascii_lowercase()).collect::<Vec<_>>()).unwrap_or_default();
            let allow_docker = allowed.iter().any(|a| a.contains("docker") || a.contains("container"));
            if which::which("dockerd").is_err() { return Ok(()); }
            if !allow_docker { return Ok(()); }
            if opts.dry_run { println!("[linux:docker] dry-run: write daemon.json, restart docker"); return Ok(()); }
            fs::create_dir_all("/etc/docker").await.ok();
            let daemon = "{\n  \"userns-remap\": \"default\",\n  \"no-new-privileges\": true,\n  \"live-restore\": true\n}\n";
            fs::write("/etc/docker/daemon.json", daemon).await.ok();
            if which::which("systemctl").is_ok() { let _ = run_cmd("systemctl", &["restart","docker"]).await; }
            Ok(())
        }
    }

    mod dns_security {
        use super::*;
        pub async fn configure_dnscrypt(opts: &EngineOptions, cfg: &Config) -> Result<()> {
            let allowed = cfg.allowed_services.as_ref().map(|v| v.iter().map(|s| s.to_ascii_lowercase()).collect::<Vec<_>>()).unwrap_or_default();
            let allow_dns = allowed.iter().any(|a| a.contains("dnscrypt") || a == "dns");
            if which::which("dnscrypt-proxy").is_err() { return Ok(()); }
            if !allow_dns { return Ok(()); }
            if opts.dry_run { println!("[linux:dns] dry-run: write dnscrypt-proxy config; enable/start"); return Ok(()); }
            let cfg_text = "server_names = ['cloudflare', 'google']\nlisten_addresses = ['127.0.0.1:53']\nmax_clients = 250\nipv4_servers = true\nipv6_servers = false\ndnscrypt_servers = true\ndoh_servers = true\nrequire_dnssec = true\nrequire_nolog = true\nrequire_nofilter = true\n";
            fs::create_dir_all("/etc/dnscrypt-proxy").await.ok();
            fs::write("/etc/dnscrypt-proxy/dnscrypt-proxy.toml", cfg_text).await.ok();
            if which::which("systemctl").is_ok() {
                let _ = run_cmd("systemctl", &["enable","dnscrypt-proxy"]).await;
                let _ = run_cmd("systemctl", &["start","dnscrypt-proxy"]).await;
            }
            Ok(())
        }
    }

    mod ssh {
        use super::*;
        pub async fn harden_sshd(opts: &EngineOptions) -> Result<()> {
            let sshd_config = "/etc/ssh/sshd_config";
            if opts.dry_run {
                println!("[linux:ssh] dry-run: enforce Protocol 2, PermitRootLogin no, PasswordAuthentication no; apply port if configured");
                return Ok(());
            }
            // Minimal safe edit: append overrides if not already present
            if let Ok(content) = fs::read_to_string(sshd_config).await {
                let mut new = content;
                if !new.contains("Protocol 2") { new.push_str("\nProtocol 2\n"); }
                if !new.contains("PermitRootLogin no") { new.push_str("PermitRootLogin no\n"); }
                if !new.contains("PasswordAuthentication no") { new.push_str("PasswordAuthentication no\n"); }
                fs::write(sshd_config, new).await?;
                // Try to reload/restart if systemctl exists
                if which::which("systemctl").is_ok() {
                    let _ = run_cmd("systemctl", &["restart", "ssh"]).await;
                    let _ = run_cmd("systemctl", &["restart", "sshd"]).await;
                }
            }
            Ok(())
        }

        pub async fn apply_ssh_port(opts: &EngineOptions, cfg: &Config) -> Result<()> {
            let desired_port = cfg.service_ports.as_ref().and_then(|m| m.get("ssh").copied());
            if desired_port.is_none() { return Ok(()); }
            let port = desired_port.unwrap();
            let sshd_config = "/etc/ssh/sshd_config";
            if opts.dry_run { println!("[linux:ssh] dry-run: set Port {} and adjust ufw/iptables", port); return Ok(()); }
            if let Ok(c) = fs::read_to_string(sshd_config).await {
                let mut new = String::new();
                let mut saw_port = false;
                for line in c.lines() {
                    if line.trim_start().to_ascii_lowercase().starts_with("port ") {
                        new.push_str(&format!("Port {}\n", port));
                        saw_port = true;
                    } else { new.push_str(line); new.push('\n'); }
                }
                if !saw_port { new.push_str(&format!("\nPort {}\n", port)); }
                fs::write(sshd_config, new).await?;
            }
            if which::which("systemctl").is_ok() { let _ = run_cmd("systemctl", &["restart","ssh"]).await; let _ = run_cmd("systemctl", &["restart","sshd"]).await; }
            Ok(())
        }

        pub async fn enforce_ssh_key_only(opts: &EngineOptions, cfg: &Config) -> Result<()> {
            let key_only = cfg.linux.as_ref().and_then(|l| l.ssh_key_only).unwrap_or(true);
            let sshd_config = "/etc/ssh/sshd_config";
            if opts.dry_run { println!("[linux:ssh] dry-run: ssh_key_only={}", key_only); return Ok(()); }
            if !key_only { return Ok(()); }
            if let Ok(content) = fs::read_to_string(sshd_config).await {
                let mut new = content;
                if !new.contains("PasswordAuthentication no") { new.push_str("PasswordAuthentication no\n"); }
                if !new.contains("PubkeyAuthentication yes") { new.push_str("PubkeyAuthentication yes\n"); }
                fs::write(sshd_config, new).await?;
                if which::which("systemctl").is_ok() { let _ = run_cmd("systemctl", &["restart","ssh"]).await; let _ = run_cmd("systemctl", &["restart","sshd"]).await; }
            }
            Ok(())
        }
    }

    mod firewall {
        use super::*;
        pub async fn configure_firewall_no_cfg(opts: &EngineOptions) -> Result<()> {
            if opts.dry_run {
                println!("[linux:fw] dry-run: enable firewall; allow minimal ports; deny rest");
                return Ok(());
            }
            if which::which("ufw").is_ok() {
                let _ = run_cmd("ufw", &["--force", "enable"]).await;
                // Example: allow SSH
                let _ = run_cmd("ufw", &["allow", "ssh"]).await;
                let _ = run_cmd("ufw", &["default", "deny", "incoming"]).await;
                let _ = run_cmd("ufw", &["default", "allow", "outgoing"]).await;
            } else if which::which("firewall-cmd").is_ok() {
                // firewalld
                let _ = run_cmd("systemctl", &["enable", "--now", "firewalld"]).await;
                let _ = run_cmd("firewall-cmd", &["--permanent", "--add-service=ssh"]).await;
                let _ = run_cmd("firewall-cmd", &["--reload"]).await;
            } else if which::which("iptables").is_ok() {
                // minimal iptables fallback respecting ssh
                let _ = run_cmd("bash", &["-lc","iptables -P INPUT DROP; iptables -P FORWARD DROP; iptables -P OUTPUT ACCEPT; iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT; iptables -A INPUT -i lo -j ACCEPT; iptables -A INPUT -p tcp --dport 22 -j ACCEPT"]).await;
            } else {
                println!("[linux:fw] no firewall tool present");
            }
            Ok(())
        }

        pub async fn configure_firewall(opts: &EngineOptions, cfg: &Config) -> Result<()> {
            if opts.dry_run {
                println!("[linux:fw] dry-run: enable firewall; allow configured ports; deny rest");
                return Ok(());
            }
            // Build allowed ports from firewall config and service_ports
            let mut allowed_tcp: std::collections::HashSet<u16> = std::collections::HashSet::new();
            let mut allowed_udp: std::collections::HashSet<u16> = std::collections::HashSet::new();
            let allowed_services = cfg.allowed_services.clone().unwrap_or_default().into_iter().map(|s| s.to_ascii_lowercase()).collect::<Vec<_>>();
            if let Some(fw) = &cfg.firewall {
                if let Some(ports) = &fw.allowed_ports { for p in ports { allowed_tcp.insert(*p); } }
            }
            if let Some(sp) = &cfg.service_ports {
                // Only apply service ports if service is allowed or firewall already listed the port
                let mut allow_if = |svc: &str, port: u16, proto: &str| {
                    let allowed = allowed_services.iter().any(|a| a.contains(svc));
                    if allowed || cfg.firewall.as_ref().and_then(|f| f.allowed_ports.as_ref()).map_or(false, |v| v.contains(&port)) {
                        match proto {
                            "tcp" => { allowed_tcp.insert(port); },
                            "udp" => { allowed_udp.insert(port); },
                            _ => {}
                        }
                    }
                };
                if let Some(p) = sp.get("ssh") { allow_if("ssh", *p, "tcp"); }
                if let Some(p) = sp.get("http") { allow_if("http", *p, "tcp"); }
                if let Some(p) = sp.get("https") { allow_if("https", *p, "tcp"); }
                if let Some(p) = sp.get("mysql") { allow_if("mysql", *p, "tcp"); }
                if let Some(p) = sp.get("postgres") { allow_if("postgres", *p, "tcp"); allow_if("postgresql", *p, "tcp"); }
                if let Some(p) = sp.get("squid") { allow_if("squid", *p, "tcp"); allow_if("proxy", *p, "tcp"); }
                if let Some(p) = sp.get("openvpn") { allow_if("openvpn", *p, "udp"); }
            }
            let disable_http = cfg.security.as_ref().and_then(|s| s.disable_http).unwrap_or(false);

            if which::which("ufw").is_ok() {
                let _ = run_cmd("ufw", &["--force", "enable"]).await;
                if allowed_tcp.is_empty() { let _ = run_cmd("ufw", &["allow","ssh"]).await; }
                for p in &allowed_tcp { let spec = format!("{}/tcp", p); let _ = run_cmd("ufw", &["allow", &spec]).await; }
                for p in &allowed_udp { let spec = format!("{}/udp", p); let _ = run_cmd("ufw", &["allow", &spec]).await; }
                let _ = run_cmd("ufw", &["default", "deny", "incoming"]).await;
                let _ = run_cmd("ufw", &["default", "allow", "outgoing"]).await;
                // If ssh port changed, explicitly deny old 22
                if let Some(sp) = &cfg.service_ports { if let Some(newp) = sp.get("ssh") { if *newp != 22 { let _ = run_cmd("ufw", &["deny","22/tcp"]).await; } } }
                if let Some(sp) = &cfg.service_ports { if let Some(newp) = sp.get("http") { if *newp != 80 { let _ = run_cmd("ufw", &["deny","80/tcp"]).await; } } }
                if let Some(sp) = &cfg.service_ports { if let Some(newp) = sp.get("https") { if *newp != 443 { let _ = run_cmd("ufw", &["deny","443/tcp"]).await; } } }
                if let Some(sp) = &cfg.service_ports { if let Some(newp) = sp.get("mysql") { if *newp != 3306 { let _ = run_cmd("ufw", &["deny","3306/tcp"]).await; } } }
                if let Some(sp) = &cfg.service_ports { if let Some(newp) = sp.get("postgres") { if *newp != 5432 { let _ = run_cmd("ufw", &["deny","5432/tcp"]).await; } } }
                if let Some(sp) = &cfg.service_ports { if let Some(newp) = sp.get("squid") { if *newp != 3128 { let _ = run_cmd("ufw", &["deny","3128/tcp"]).await; } } }
                if let Some(sp) = &cfg.service_ports { if let Some(newp) = sp.get("openvpn") { if *newp != 1194 { let _ = run_cmd("ufw", &["deny","1194/udp"]).await; } } }
                if disable_http { let _ = run_cmd("ufw", &["deny","80/tcp"]).await; }
            } else if which::which("firewall-cmd").is_ok() {
                let _ = run_cmd("systemctl", &["enable", "--now", "firewalld"]).await;
                let _ = run_cmd("firewall-cmd", &["--permanent", "--add-service=ssh"]).await;
                let _ = run_cmd("firewall-cmd", &["--reload"]).await;
            }
            Ok(())
        }
    }

    mod kernel {
        use super::*;
        pub async fn harden_kernel(opts: &EngineOptions) -> Result<()> {
            if opts.dry_run { println!("[linux:kernel] dry-run: sysctl hardening, umask, core dumps"); return Ok(()); }
            let sysctl_conf = "/etc/sysctl.conf";
            backup_if_absent(sysctl_conf).await.ok();
            for (k,v) in [
                ("fs.file-max","65535"),("fs.protected_fifos","2"),("fs.protected_regular","2"),("fs.suid_dumpable","0"),
                ("kernel.dmesg_restrict","1"),("kernel.randomize_va_space","2"),("kernel.kptr_restrict","2"),("kernel.perf_event_paranoid","3"),
                ("kernel.kexec_load_disabled","1"),("net.ipv4.icmp_echo_ignore_all","1"),("net.ipv4.tcp_syncookies","1"),("net.ipv4.ip_forward","0"),
                ("net.ipv6.conf.all.disable_ipv6","1"),("net.ipv6.conf.default.disable_ipv6","1")
            ] { ensure_setting(sysctl_conf, k, v).await?; }
            let _ = run_cmd("sysctl", &["-p"]).await;
            ensure_line("/etc/profile", "umask 027\n").await?;
            let limits = "/etc/security/limits.conf"; backup_if_absent(limits).await.ok();
            ensure_line(limits, "* soft core 0\n").await?; ensure_line(limits, "* hard core 0\n").await?;
            Ok(())
        }
    }

    mod interfaces {
        use super::*;
        pub async fn harden_interfaces(opts: &EngineOptions) -> Result<()> {
            if opts.dry_run { println!("[linux:ifaces] dry-run: module blacklists, udev rules, disable services"); return Ok(()); }
            ensure_line("/etc/modprobe.d/disable-usb-storage.conf", "install usb-storage /bin/true\n").await?;
            ensure_line("/etc/modprobe.d/firewire.conf", "blacklist firewire-core\n").await?;
            ensure_line("/etc/modprobe.d/thunderbolt.conf", "blacklist thunderbolt\n").await?;
            let bl = "/etc/modprobe.d/blacklist.conf"; backup_if_absent(bl).await.ok();
            for l in [
                "blacklist bluetooth\n","blacklist usb-storage\n","blacklist uas\n","blacklist xhci_hcd\n","blacklist ehci_hcd\n",
                "blacklist uhci_hcd\n","blacklist ohci_hcd\n","blacklist thunderbolt\n","blacklist firewire-core\n","blacklist firewire-ohci\n","blacklist ieee1394\n","blacklist ohci1394\n"
            ] { ensure_line(bl, l).await?; }
            let rules = "ACTION=\"add\", SUBSYSTEM=\"usb\", ENV{MODALIAS}!=\"\", RUN=\"/bin/false\"\nACTION=\"add\", SUBSYSTEM=\"thunderbolt\", ENV{MODALIAS}!=\"\", RUN=\"/bin/false\"\nACTION=\"add\", SUBSYSTEM=\"firewire\", ENV{MODALIAS}!=\"\", RUN=\"/bin/false\"\n";
            fs::write("/etc/udev/rules.d/99-disable-interfaces.rules", rules).await?;
            let _ = run_cmd("udevadm", &["control", "--reload-rules"]).await;
            if which::which("systemctl").is_ok() {
                for svc in ["avahi-daemon","cups","bluetooth","autofs"] {
                    let _ = run_cmd("systemctl", &["disable", svc]).await;
                    let _ = run_cmd("systemctl", &["stop", svc]).await;
                }
            }
            Ok(())
        }
    }

    mod pam {
        use super::*;
        pub async fn configure_pam(opts: &EngineOptions) -> Result<()> {
            if opts.dry_run { println!("[linux:pam] dry-run: faillock/tally2, minlen, remove nullok"); return Ok(()); }
            let ca = "/etc/pam.d/common-auth"; let cp = "/etc/pam.d/common-password";
            backup_if_absent(ca).await.ok(); backup_if_absent(cp).await.ok();
            if let Ok(mut c) = fs::read_to_string(ca).await { if c.contains("nullok") { c = c.replace("nullok", ""); fs::write(ca, c).await?; } }
            // Choose faillock if present; else fall back to tally2
            let use_faillock = which::which("pam_faillock.so").is_ok() || fs::metadata("/usr/lib/security/pam_faillock.so").await.is_ok();
            if use_faillock {
                ensure_line(ca, "auth required pam_faillock.so preauth deny=5 unlock_time=1\n").await?;
                ensure_line(ca, "auth required pam_faillock.so authfail deny=5 unlock_time=1\n").await?;
            } else {
                ensure_line(ca, "auth required pam_tally2.so deny=5 unlock_time=60 onerr=fail audit\n").await?;
                ensure_line("/etc/pam.d/common-account", "account required pam_tally2.so\n").await.ok();
            }
            ensure_line(cp, "password requisite pam_pwhistory.so remember=5\n").await?;
            if let Ok(c) = fs::read_to_string(cp).await {
                if c.contains("pam_unix.so") && !c.contains("minlen=") {
                    let mut new = String::new();
                    for line in c.lines() { if line.contains("pam_unix.so") { new.push_str(&format!("{} minlen=12\n", line)); } else { new.push_str(line); new.push('\n'); } }
                    fs::write(cp, new).await?;
                }
            }
            Ok(())
        }
    }

    mod login_defs {
        use super::*;
        pub async fn configure_login_defs(opts: &EngineOptions) -> Result<()> {
            if opts.dry_run { println!("[linux:login.defs] dry-run: PASS_* and SHA512 rounds"); return Ok(()); }
            let path = "/etc/login.defs"; backup_if_absent(path).await.ok();
            for (k,v) in [("PASS_MAX_DAYS","30"),("PASS_MIN_DAYS","10"),("PASS_WARN_AGE","7"),("ENCRYPT_METHOD","SHA512"),("SHA_CRYPT_MIN_ROUNDS","12000"),("SHA_CRYPT_MAX_ROUNDS","15000")] {
                ensure_kv_or_replace(path, k, v).await?;
            }
            Ok(())
        }
    }

    mod fail2ban {
        use super::*;
        pub async fn enable_fail2ban(opts: &EngineOptions) -> Result<()> {
            if opts.dry_run { println!("[linux:fail2ban] dry-run: enable/start fail2ban"); return Ok(()); }
            if which::which("systemctl").is_ok() {
                let _ = run_cmd("systemctl", &["enable", "fail2ban"]).await;
                let _ = run_cmd("systemctl", &["start", "fail2ban"]).await;
            }
            Ok(())
        }

        pub async fn tune_fail2ban(opts: &EngineOptions) -> Result<()> {
            if opts.dry_run { println!("[linux:fail2ban] dry-run: write jail.local with stricter defaults"); return Ok(()); }
            let jail_local = "/etc/fail2ban/jail.local";
            let content = "[DEFAULT]\nbantime = 1h\nfindtime = 10m\nmaxretry = 5\nbackend = systemd\n[sshd]\nenabled = true\nmode = aggressive\n";
            fs::write(jail_local, content).await.ok();
            if which::which("systemctl").is_ok() { let _ = run_cmd("systemctl", &["restart","fail2ban"]).await; }
            Ok(())
        }
    }

    mod apparmor {
        use super::*;
        pub async fn enable_apparmor(opts: &EngineOptions) -> Result<()> {
            if opts.dry_run { println!("[linux:apparmor] dry-run: aa-enforce, enable/start apparmor"); return Ok(()); }
            if which::which("aa-enforce").is_ok() { let _ = run_cmd("aa-enforce", &["/etc/apparmor.d/*"]).await; }
            if which::which("systemctl").is_ok() {
                let _ = run_cmd("systemctl", &["enable", "apparmor"]).await;
                let _ = run_cmd("systemctl", &["start", "apparmor"]).await;
            }
            Ok(())
        }
    }

    mod nftables {
        use super::*;
        pub async fn configure_nftables(opts: &EngineOptions, cfg: &Config) -> Result<()> {
            if which::which("nft").is_err() { return Ok(()); }
            if opts.dry_run { println!("[linux:nftables] dry-run: write /etc/nftables.conf, enable/start nftables"); return Ok(()); }
            // Build a simple ruleset based on allowed ports (defaults ssh,http,https)
            let mut allowed_tcp: Vec<u16> = vec![];
            if let Some(fw) = &cfg.firewall {
                if let Some(ports) = &fw.allowed_ports { allowed_tcp.extend(ports.iter().copied()); }
            }
            if allowed_tcp.is_empty() { allowed_tcp.extend([22,80,443]); }
            let ports_str = allowed_tcp.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(", ");
            let nft = format!(
                "#!/usr/sbin/nft -f\n\nflush ruleset\n\ntable inet filter {{\n    chain input {{\n        type filter hook input priority -1; policy drop;\n        ct state established,related accept\n        iif lo accept\n        ip protocol icmp accept\n        tcp dport {{{ports}}} ct state new accept\n    }}\n    chain forward {{ type filter hook forward priority -1; policy drop; }}\n    chain output  {{ type filter hook output  priority -1; policy accept; }}\n}}\n",
                ports=ports_str
            );
            fs::write("/etc/nftables.conf", nft).await?;
            if which::which("systemctl").is_ok() {
                let _ = run_cmd("systemctl", &["enable", "--now", "nftables"]).await;
            }
            Ok(())
        }
    }

    mod ids {
        use super::*;
        pub async fn configure_suricata(opts: &EngineOptions) -> Result<()> {
            if which::which("suricata").is_err() { return Ok(()); }
            if opts.dry_run { println!("[linux:ids] dry-run: write /etc/suricata/suricata.yaml and enable service"); return Ok(()); }
            let yaml = "%YAML 1.1\n---\noutputs:\n  - fast:{ enabled: yes, filename: fast.log, append: yes }\n  - eve-log:{ enabled: yes, filetype: regular, filename: eve.json, types: [alert, http, dns, tls, files, ssh] }\napp-layer:\n  protocols:\n    tls: { enabled: yes }\n    ssh: { enabled: yes }\n    dns: { tcp: { enabled: yes }, udp: { enabled: yes } }\n";
            fs::create_dir_all("/etc/suricata").await.ok();
            fs::write("/etc/suricata/suricata.yaml", yaml).await.ok();
            if which::which("systemctl").is_ok() {
                let _ = run_cmd("systemctl", &["enable", "suricata"]).await;
                let _ = run_cmd("systemctl", &["start", "suricata"]).await;
            }
            Ok(())
        }
    }

    mod web_hardening {
        use super::*;
        pub async fn configure_apache_modsecurity(opts: &EngineOptions, cfg: &Config) -> Result<()> {
            let apache2_present = which::which("apache2").is_ok();
            let httpd_present = which::which("httpd").is_ok();
            if !apache2_present && !httpd_present { return Ok(()); }

            // Check config whitelist: allow only if explicitly listed
            let mut allowed = false;
            if let Some(svcs) = &cfg.allowed_services {
                for s in svcs {
                    let name = s.to_ascii_lowercase();
                    if ["apache","apache2","http","https","web"].iter().any(|k| name.contains(k)) { allowed = true; break; }
                }
            }

            if !allowed {
                if opts.dry_run {
                    println!("[linux:web] dry-run: remove Apache (not in allowed_services)");
                    return Ok(());
                }
                // Stop/disable and purge
                if which::which("systemctl").is_ok() {
                    if apache2_present { let _ = run_cmd("sudo", &["systemctl", "disable", "--now", "apache2"]).await; }
                    if httpd_present { let _ = run_cmd("sudo", &["systemctl", "disable", "--now", "httpd"]).await; }
                }
                if which::which("apt").is_ok() {
                    let _ = run_cmd("sudo", &["apt", "-y", "purge", "apache2", "apache2-bin", "apache2-data", "apache2-utils"]).await;
                    let _ = run_cmd("sudo", &["apt", "-y", "autoremove", "--purge"]).await;
                } else if which::which("dnf").is_ok() {
                    let _ = run_cmd("sudo", &["dnf", "-y", "remove", "httpd", "mod_ssl"]).await;
                }
                return Ok(());
            }

            if opts.dry_run {
                println!("[linux:web] dry-run: enable ModSecurity, headers, security.conf; restart web server");
                return Ok(());
            }

            if apache2_present {
                // Debian/Ubuntu path
                let modsec_rec = "/etc/modsecurity/modsecurity.conf-recommended";
                let modsec_conf = "/etc/modsecurity/modsecurity.conf";
                if fs::metadata(modsec_conf).await.is_err() && fs::metadata(modsec_rec).await.is_ok() {
                    let _ = run_cmd("cp", &[modsec_rec, modsec_conf]).await;
                }
                if let Ok(c) = fs::read_to_string(modsec_conf).await {
                    let n = c.replace("SecRuleEngine DetectionOnly", "SecRuleEngine On");
                    let _ = fs::write(modsec_conf, n).await;
                }
                let security_conf_path = "/etc/apache2/conf-available/security.conf";
                let security_conf = "ServerTokens Prod\nServerSignature Off\nTraceEnable Off\nFileETag None\nHeader set X-Content-Type-Options nosniff\nHeader set X-Frame-Options SAMEORIGIN\nHeader set X-XSS-Protection \"1; mode=block\"\nHeader set Content-Security-Policy \"default-src 'self';\"\n";
                fs::write(security_conf_path, security_conf).await.ok();
                if which::which("a2enmod").is_ok() { let _ = run_cmd("a2enmod", &["headers"]).await; }
                if which::which("a2enconf").is_ok() { let _ = run_cmd("a2enconf", &["security"]).await; }
                if which::which("systemctl").is_ok() {
                    let _ = run_cmd("systemctl", &["enable", "apache2"]).await;
                    let _ = run_cmd("systemctl", &["restart", "apache2"]).await;
                }
            } else if httpd_present {
                // Fedora/RHEL path
                let security_conf_path = "/etc/httpd/conf.d/security-hardening.conf";
                let security_conf = "Header always set X-Content-Type-Options nosniff\nHeader always set X-Frame-Options SAMEORIGIN\nHeader always set X-XSS-Protection \"1; mode=block\"\nHeader set Content-Security-Policy \"default-src 'self';\"\nServerTokens Prod\nServerSignature Off\n";
                fs::write(security_conf_path, security_conf).await.ok();
                if which::which("systemctl").is_ok() {
                    let _ = run_cmd("systemctl", &["enable", "httpd"]).await;
                    let _ = run_cmd("systemctl", &["restart", "httpd"]).await;
                }
            }
            Ok(())
        }

        pub async fn configure_nginx_hardening(opts: &EngineOptions, cfg: &Config) -> Result<()> {
            if which::which("nginx").is_err() { return Ok(()); }
            // Check whitelist
            let mut allowed = false;
            if let Some(svcs) = &cfg.allowed_services {
                for s in svcs {
                    let n = s.to_ascii_lowercase();
                    if n.contains("nginx") || n.contains("http") || n.contains("web") { allowed = true; break; }
                }
            }
            if !allowed {
                if opts.dry_run { println!("[linux:nginx] dry-run: remove nginx (not allowed)"); return Ok(()); }
                if which::which("systemctl").is_ok() { let _ = run_cmd("systemctl", &["disable","--now","nginx"]).await; }
                if which::which("apt-get").is_ok() { let _ = run_cmd_env(&[("DEBIAN_FRONTEND","noninteractive")], "apt-get", &["-y","-q","purge","nginx","nginx-common"]).await; let _ = run_cmd_env(&[("DEBIAN_FRONTEND","noninteractive")], "apt-get", &["-y","-q","autoremove","--purge"]).await; }
                else if which::which("dnf").is_ok() { let _ = run_cmd("dnf", &["-y","remove","nginx"]).await; }
                return Ok(());
            }
            if opts.dry_run { println!("[linux:nginx] dry-run: set security headers and tokens; restart nginx"); return Ok(()); }
            let conf_d = "/etc/nginx/conf.d/security.conf";
            let security = "add_header X-Content-Type-Options \"nosniff\" always;\nadd_header X-Frame-Options \"SAMEORIGIN\" always;\nadd_header X-XSS-Protection \"1; mode=block\" always;\nadd_header Content-Security-Policy \"default-src 'self';\" always;\nserver_tokens off;\n";
            fs::write(conf_d, security).await.ok();
            if which::which("systemctl").is_ok() { let _ = run_cmd("systemctl", &["enable","nginx"]).await; let _ = run_cmd("systemctl", &["restart","nginx"]).await; }
            Ok(())
        }
    }

    mod knockd {
        use super::*;
        pub async fn configure_knockd(opts: &EngineOptions, cfg: &Config) -> Result<()> {
            let enable = cfg.linux.as_ref().and_then(|l| l.knockd_enabled).unwrap_or(false);
            if !enable { return Ok(()); }
            if which::which("knockd").is_err() { return Ok(()); }
            if opts.dry_run { println!("[linux:knockd] dry-run: write /etc/knockd.conf and enable service"); return Ok(()); }
            let cfg = "[options]\n    UseSyslog\n\n[openSSH]\n    sequence    = 7000,8000,9000\n    seq_timeout = 5\n    command     = /sbin/iptables -A INPUT -s %IP% -p tcp --dport 22 -j ACCEPT\n    tcpflags    = syn\n    cmd_timeout = 10\n    stop_command = /sbin/iptables -D INPUT -s %IP% -p tcp --dport 22 -j ACCEPT\n\n[closeSSH]\n    sequence    = 9000,8000,7000\n    seq_timeout = 5\n    command     = /sbin/iptables -D INPUT -s %IP% -p tcp --dport 22 -j ACCEPT\n";
            fs::write("/etc/knockd.conf", cfg).await.ok();
            if which::which("systemctl").is_ok() {
                let _ = run_cmd("systemctl", &["enable", "knockd"]).await;
                let _ = run_cmd("systemctl", &["start", "knockd"]).await;
            }
            Ok(())
        }
    }

    mod hosts_hardening {
        use super::*;
        pub async fn configure_hosts_deny(opts: &EngineOptions) -> Result<()> {
            if opts.dry_run { println!("[linux:hosts] dry-run: append ALL: ALL to /etc/hosts.deny"); return Ok(()); }
            ensure_line("/etc/hosts.deny", "ALL: ALL\n").await.ok();
            Ok(())
        }
    }

    mod apt_settings {
        use super::*;
        pub async fn configure_apt_unattended(opts: &EngineOptions) -> Result<()> {
            if opts.dry_run { println!("[linux:apt] dry-run: configure unattended upgrades and periodic"); return Ok(()); }
            for path in [
                "/etc/apt/apt.conf.d/10periodic",
                "/etc/apt/apt.conf.d/10removal",
                "/etc/apt/apt.conf.d/20auto-upgrades",
                "/etc/apt/apt.conf.d/50unattended-upgrades",
            ] { let _ = fs::File::create(path).await; }
            ensure_line("/etc/apt/apt.conf.d/10periodic", "APT::Periodic::AutocleanInterval \"7\";\n").await?;
            ensure_line("/etc/apt/apt.conf.d/10removal", "APT::Get::Remove-Unused \"true\";\n").await?;
            fs::write(
                "/etc/apt/apt.conf.d/20auto-upgrades",
                "APT::Periodic::Update-Package-Lists \"1\";\nAPT::Periodic::Download-Upgradeable-Packages \"1\";\nAPT::Periodic::AutocleanInterval \"7\";\nAPT::Periodic::Unattended-Upgrade \"1\";\n"
            ).await?;
            Ok(())
        }
    }
    mod session_security {
        use super::*;
        pub async fn configure_screen_timeout(opts: &EngineOptions) -> Result<()> {
            if opts.dry_run { println!("[linux:session] dry-run: set screen lock/timeout via dconf/xset if desktop"); return Ok(()); }
            // Heuristic: if xset present, set DPMS and screensaver timeout
            if which::which("xset").is_ok() { let _ = run_cmd("xset", &["s","300","300"]).await; let _ = run_cmd("xset", &["-dpms"]).await; }
            Ok(())
        }
    }

    mod cron_lockdown {
        use super::*;
        pub async fn configure_cron(opts: &EngineOptions, cfg: &Config) -> Result<()> {
            let lockdown = cfg.security.as_ref().and_then(|s| s.lockdown_cron).unwrap_or(false);
            if !lockdown { return Ok(()); }
            if opts.dry_run { println!("[linux:cron] dry-run: deny all in /etc/cron.deny"); return Ok(()); }
            fs::write("/etc/cron.deny", "ALL\n").await.ok();
            Ok(())
        }
    }

    mod sudoers_login {
        use super::*;
        pub async fn harden_sudoers_and_login(opts: &EngineOptions) -> Result<()> {
            if opts.dry_run { println!("[linux:sudoers] dry-run: remove NOPASSWD, disable guest/autologin in lightdm/gdm"); return Ok(()); }
            // Clean sudoers for NOPASSWD and !authenticate
            let sudoers = "/etc/sudoers";
            if let Ok(c) = fs::read_to_string(sudoers).await {
                let n = c.replace("nopasswd", "");
                let n = n.replace("!authenticate", "");
                fs::write(sudoers, n).await.ok();
            }
            // Disable guest/autologin heuristically
            for path in ["/etc/lightdm/lightdm.conf", "/etc/lightdm/users.conf"] { let _ = ensure_line(path, "allow-guest=false\n").await; }
            let _ = ensure_line("/etc/gdm/custom.conf", "AutomaticLoginEnable=False\n").await;
            Ok(())
        }
    }

    mod users {
        use super::*;
        pub async fn enforce_users_and_passwords(opts: &EngineOptions, cfg: &Config) -> Result<()> {
            if opts.dry_run { println!("[linux:users] dry-run: lock root, ensure admins/users, set passwords, fix groups"); return Ok(()); }
            // Lock root and restrict
            let _ = run_cmd("passwd", &["-l", "root"]).await;
            let _ = run_cmd("usermod", &["-s", "/bin/false", "root"]).await;
            let _ = run_cmd("usermod", &["-L", "root"]).await;

            let admins = cfg.admins.clone().unwrap_or_default();
            let users = cfg.users.clone().unwrap_or_default();
            // Create missing users/admins
            for u in &users {
                if run_cmd("id", &[u]).await.is_err() {
                    let _ = run_cmd("useradd", &[u]).await;
                }
            }
            for a in &admins {
                if run_cmd("id", &[a]).await.is_err() {
                    let _ = run_cmd("useradd", &[a]).await;
                }
            }

            // Ensure group memberships
            for a in &admins {
                let _ = run_cmd("gpasswd", &["-a", a, "sudo"]).await;
                let _ = run_cmd("gpasswd", &["-a", a, "wheel"]).await;
                let _ = run_cmd("gpasswd", &["-a", a, "admin"]).await;
            }
            for u in &users {
                let _ = run_cmd("gpasswd", &["-d", u, "sudo"]).await;
                let _ = run_cmd("gpasswd", &["-d", u, "wheel"]).await;
                let _ = run_cmd("gpasswd", &["-d", u, "admin"]).await;
            }

            // Set default passwords (competition default)
            let default_pw = "CyberPatr!0t";
            for u in users.iter().chain(admins.iter()) {
                let pair = format!("{}:{}\n", u, default_pw);
                let _ = run_cmd_with_stdin("chpasswd", &[], &pair).await;
            }
            let _ = run_cmd_with_stdin("chpasswd", &[], &format!("root:{}\n", default_pw)).await;
            Ok(())
        }
    }

    mod audit {
        use super::*;
        pub async fn enable_audit_and_rsyslog(opts: &EngineOptions) -> Result<()> {
            if opts.dry_run { println!("[linux:audit] dry-run: auditd rules/config and rsyslog tweak"); return Ok(()); }
            // Minimal audit rules
            let rules = "-D\n-w / -p rwax -k filesystem_change\n-a always,exit -S all\n-e 2\n";
            fs::write("/etc/audit/audit.rules", rules).await.ok();
            // rsyslog format change if present
            if let Ok(c) = fs::read_to_string("/etc/rsyslog.conf").await {
                let n = c.replace("RSYSLOG_TraditionalFileFormat", "RSYSLOG_FileFormat");
                fs::write("/etc/rsyslog.conf", n).await.ok();
            }
            if which::which("systemctl").is_ok() {
                let _ = run_cmd("sudo", &["systemctl", "enable", "auditd"]).await;
                let _ = run_cmd("sudo", &["systemctl", "restart", "auditd"]).await;
                let _ = run_cmd("sudo", &["systemctl", "enable", "rsyslog"]).await;
                let _ = run_cmd("sudo", &["systemctl", "restart", "rsyslog"]).await;
            }
            Ok(())
        }
    }

    mod fs_security {
        use super::*;
        pub async fn tighten_filesystem_security(opts: &EngineOptions) -> Result<()> {
            if opts.dry_run { println!("[linux:fs] dry-run: perms on passwd/shadow/tmp, fstab tmpfs entries"); return Ok(()); }
            // Critical perms
            let _ = run_cmd("chmod", &["644", "/etc/passwd"]).await;
            let _ = run_cmd("chmod", &["600", "/etc/shadow"]).await;
            let _ = run_cmd("chmod", &["1777", "/tmp"]).await;
            // Secure tmp and var/tmp via fstab appends
            let _ = ensure_line("/etc/fstab", "tmpfs /tmp tmpfs defaults,noexec,nosuid,nodev 0 0\n").await;
            let _ = ensure_line("/etc/fstab", "tmpfs /var/tmp tmpfs defaults,noexec,nosuid,nodev 0 0\n").await;
            Ok(())
        }
    }
}

pub mod windows {
    use super::*;

    pub async fn run_baseline_with_config(opts: &EngineOptions, cfg: &Config) -> Result<()> {
        let _ = osinfo::print_os_info(opts).await;
        let a = accounts::apply_password_policy_and_users(opts, cfg);
        let g = guest::disable_guest_login(opts);
        let l = lsa::limit_blank_passwords(opts);
        let f = firewall::configure_firewall(opts, cfg);
        let ssh = openssh::configure_openssh(opts, cfg);
        let r = rdp::configure_rdp(opts, cfg);
        let t = features::disable_telnet(opts);
        let v6 = ipv6::disable_ipv6(opts);
        let au = audit::configure_audit_policies(opts);
        let up = updates::configure_updates(opts);
        let svc = service_whitelist::enforce_service_whitelist(opts, cfg);
        let hyg = hygiene::purge_unwanted_software(opts, cfg);
        let svr = server_extras::apply_server_extras(opts, cfg);
        let bl = bitlocker::maybe_enable_bitlocker(opts, cfg);
        let (ra, rg, rl, rf, rr, rt, rv6, rau, rup, rsvc, rhyg, rsvr, rossh, rbl) = tokio::join!(a, g, l, f, r, t, v6, au, up, svc, hyg, svr, ssh, bl);
        ra?; rg?; rl?; rf?; rr?; rt?; rv6?; rau?; rup?; rsvc?; rhyg?; rsvr?; rossh?; rbl?;
        Ok(())
    }
    
    mod osinfo {
        use super::*;
        pub async fn print_os_info(_opts: &EngineOptions) -> Result<()> {
            let ps = "(Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber, ProductType | Format-List | Out-String).Trim()";
            let out = run_cmd_capture("powershell", &["-NoProfile","-ExecutionPolicy","Bypass","-Command", ps]).await.unwrap_or_default();
            let mut caption = "".to_string();
            let mut version = "".to_string();
            let mut product_type: u32 = 1;
            for line in out.lines() {
                let l = line.trim();
                if let Some(rest) = l.strip_prefix("Caption :") { caption = rest.trim().to_string(); }
                if let Some(rest) = l.strip_prefix("Version :") { version = rest.trim().to_string(); }
                if let Some(rest) = l.strip_prefix("ProductType :") { product_type = rest.trim().parse::<u32>().unwrap_or(1); }
            }
            let kind = if matches!(product_type, 2|3) { "Server" } else { "Workstation" };
            let mut year = None;
            for y in ["2025","2022","2019","2016","2012","2008","2003"] { if caption.contains(y) { year = Some(y); break; } }
            if let Some(y) = year { println!("[windows:os] {} ({} | {} {})", caption, version, kind, y); }
            else { println!("[windows:os] {} ({} | {})", caption, version, kind); }
            Ok(())
        }
    }
    mod openssh {
        use super::*;
        pub async fn configure_openssh(opts: &EngineOptions, cfg: &Config) -> Result<()> {
            let enabled = cfg.windows.as_ref().and_then(|w| w.openssh_enabled).unwrap_or(false);
            if !enabled { return Ok(()); }
            let allowed = cfg.allowed_services.as_ref().map(|v| v.iter().any(|s| s.to_ascii_lowercase().contains("ssh"))).unwrap_or(false);
            if !allowed { return Ok(()); }
            let sshd_path = r"C:\ProgramData\ssh\sshd_config";
            let key_only = cfg.windows.as_ref().and_then(|w| w.ssh_key_only).unwrap_or(true);
            let port = cfg.service_ports.as_ref().and_then(|m| m.get("ssh").copied()).unwrap_or(22);
            if opts.dry_run { println!("[windows:ssh] dry-run: manage OpenSSH, port={}, key_only={}", port, key_only); return Ok(()); }
            // Ensure service startup
            let _ = run_cmd("powershell", &["-NoProfile","-ExecutionPolicy","Bypass","-Command","Set-Service -Name sshd -StartupType Automatic; Start-Service sshd"]).await;
            // Edit sshd_config using PowerShell text ops
            let pa = if key_only { "PasswordAuthentication no" } else { "PasswordAuthentication yes" };
            let cmd = format!(
                "$p='{}'; if (Test-Path $p) {{ $c=Get-Content $p; if ($c -notmatch '^Port ') {{ Add-Content $p \"Port {}\" }} else {{ $c -replace '^Port .*', \"Port {}\" | Set-Content $p }}; if ($c -notmatch 'PasswordAuthentication ') {{ Add-Content $p \"{}\" }} else {{ (Get-Content $p) -replace 'PasswordAuthentication .*', \"{}\" | Set-Content $p }} }}",
                sshd_path, port, port, pa, pa
            );
            let _ = run_cmd("powershell", &["-NoProfile","-ExecutionPolicy","Bypass","-Command", &cmd]).await;
            // Restart sshd
            let _ = run_cmd("powershell", &["-NoProfile","-ExecutionPolicy","Bypass","-Command","Restart-Service sshd"]).await;
            // Firewall rules
            let allow_rule = format!("name=AllowWinSSH dir=in action=allow protocol=TCP localport={}", port);
            let _ = run_cmd("netsh", &["advfirewall","firewall","add","rule", &allow_rule]).await;
            if port != 22 { let _ = run_cmd("netsh", &["advfirewall","firewall","add","rule","name=BlockOldSSH dir=in action=block protocol=TCP localport=22"]).await; }
            Ok(())
        }
    }

    mod bitlocker {
        use super::*;
        pub async fn maybe_enable_bitlocker(opts: &EngineOptions, cfg: &Config) -> Result<()> {
            let enable = cfg.security.as_ref().and_then(|s| s.enable_bitlocker).unwrap_or(false);
            if !enable { return Ok(()); }
            if opts.dry_run { println!("[windows:bitlocker] dry-run: would enable BitLocker on C:\\ if prerequisites met"); return Ok(()); }
            // Conservative stub: report status and attempt protection enable if available
            let _ = run_cmd("powershell", &["-NoProfile","-ExecutionPolicy","Bypass","-Command","(Get-BitLockerVolume -MountPoint 'C:') | Format-List -Property *"]).await;
            let _ = run_cmd("powershell", &["-NoProfile","-ExecutionPolicy","Bypass","-Command","Try { Enable-BitLocker -MountPoint 'C:' -UsedSpaceOnly -RecoveryPasswordProtector -ErrorAction Stop } Catch { Write-Host $_ }"]).await;
            Ok(())
        }
    }

    fn build_keep_set(cfg: &Config) -> std::collections::HashSet<String> {
        let mut keep = std::collections::HashSet::new();
        // Essentials commonly needed on Windows
        for e in [
            "Microsoft.WindowsCalculator","Microsoft.WindowsNotepad","Microsoft.Paint",
            "Microsoft.WindowsStore","Microsoft.DesktopAppInstaller",
            // Keep JavaScript-related packages (scoring engine reliance)
            "javascript"
        ] { keep.insert(e.to_ascii_lowercase()); }
        if let Some(extra) = &cfg.keep_packages { for p in extra { keep.insert(p.to_ascii_lowercase()); } }
        if let Some(svcs) = &cfg.allowed_services { for s in svcs { keep.insert(s.to_ascii_lowercase()); } }
        keep
    }

    mod accounts {
        use super::*;
        pub async fn apply_password_policy_and_users(opts: &EngineOptions, cfg: &Config) -> Result<()> {
            if opts.dry_run {
                println!("[windows:accounts] dry-run: net accounts policies; set passwords for cfg users");
                return Ok(());
            }
            // Password policy
            let _ = run_cmd("net", &["accounts","/maxpwage:30"]).await;
            let _ = run_cmd("net", &["accounts","/minpwage:1"]).await;
            let _ = run_cmd("net", &["accounts","/minpwlen:12"]).await;
            let _ = run_cmd("net", &["accounts","/uniquepw:5"]).await;
            let _ = run_cmd("net", &["accounts","/lockoutthreshold:5"]).await;
            let _ = run_cmd("net", &["accounts","/lockoutduration:30"]).await;
            let _ = run_cmd("net", &["accounts","/lockoutwindow:30"]).await;
            // Set passwords for declared users (if present)
            let default_pw = "CyberPatr!0t";
            for u in cfg.users.clone().unwrap_or_default().into_iter().chain(cfg.admins.clone().unwrap_or_default().into_iter()) {
                let _ = run_cmd("net", &["user", &u, default_pw]).await;
            }
            Ok(())
        }
    }

    mod guest {
        use super::*;
        pub async fn disable_guest_login(opts: &EngineOptions) -> Result<()> {
            if opts.dry_run { println!("[windows:guest] dry-run: disable Guest"); return Ok(()); }
            let _ = run_cmd("net", &["user","guest","/active:no"]).await;
            Ok(())
        }
    }

    mod lsa {
        use super::*;
        pub async fn limit_blank_passwords(opts: &EngineOptions) -> Result<()> {
            if opts.dry_run { println!("[windows:lsa] dry-run: LimitBlankPasswordUse=1"); return Ok(()); }
            let _ = run_cmd("reg", &["add","HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa","/v","LimitBlankPasswordUse","/t","REG_DWORD","/d","1","/f"]).await;
            // UAC and consent prompt (stronger prompts)
            let _ = run_cmd("reg", &["add","HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System","/v","EnableLUA","/t","REG_DWORD","/d","1","/f"]).await;
            let _ = run_cmd("reg", &["add","HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System","/v","ConsentPromptBehaviorAdmin","/t","REG_DWORD","/d","4","/f"]).await;
            // PowerShell logging
            let _ = run_cmd("reg", &["add","HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\Transcription","/v","EnableTranscripting","/t","REG_DWORD","/d","1","/f"]).await;
            let _ = run_cmd("reg", &["add","HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging","/v","EnableScriptBlockLogging","/t","REG_DWORD","/d","1","/f"]).await;
            // Defender hardening samples
            let _ = run_cmd("reg", &["add","HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender","/v","DisableAntiSpyware","/t","REG_DWORD","/d","0","/f"]).await;
            let _ = run_cmd("reg", &["add","HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection","/v","DisableRealtimeMonitoring","/t","REG_DWORD","/d","0","/f"]).await;
            Ok(())
        }
    }

    mod firewall {
        use super::*;
        pub async fn configure_firewall(opts: &EngineOptions, cfg: &Config) -> Result<()> {
            if opts.dry_run { println!("[windows:fw] dry-run: enable all profiles; allow cfg ports"); return Ok(()); }
            let _ = run_cmd("netsh", &["advfirewall","set","allprofiles","state","on"]).await;
            let mut ports: Vec<u16> = vec![];
            if let Some(fw) = &cfg.firewall { if let Some(p) = &fw.allowed_ports { ports.extend(p.iter().copied()); } }
            if let Some(sp) = &cfg.service_ports { if let Some(r) = sp.get("rdp") { ports.push(*r); } }
            let disable_http = cfg.security.as_ref().and_then(|s| s.disable_http).unwrap_or(false);
            for p in ports {
                let rule = format!("name=AllowTCP{} dir=in action=allow protocol=TCP localport={}", p, p);
                let _ = run_cmd("netsh", &["advfirewall","firewall","add","rule", &rule]).await;
            }
            if disable_http {
                let _ = run_cmd("netsh", &["advfirewall","firewall","add","rule","name=BlockHTTP dir=in action=block protocol=TCP localport=80"]).await;
            }
            Ok(())
        }
    }

    mod service_whitelist {
        use super::*;
        pub async fn enforce_service_whitelist(opts: &EngineOptions, cfg: &Config) -> Result<()> {
            let allowed = cfg.allowed_services.as_ref().map(|v| v.iter().map(|s| s.to_ascii_lowercase()).collect::<Vec<_>>()).unwrap_or_default();
            let is_allowed = |keys: &[&str]| -> bool {
                keys.iter().any(|k| allowed.iter().any(|a| a.contains(&k.to_ascii_lowercase())))
            };
            // Candidate Windows services (short names)
            let candidates: &[(&[&str], &[&str])] = &[
                (&["telnet"], &["TlntSvr"]),
                (&["ftp"], &["ftpsvc"]),
                (&["snmp"], &["SNMP","SNMPTRAP"]),
                (&["rdp","termservice"], &["TermService","UmRdpService","SessionEnv"]),
                (&["iis","w3svc","http"], &["W3SVC","IISADMIN"]),
                (&["remote-registry"], &["remoteRegistry"]),
                (&["upnp","ssdp"], &["SSDPSRV","upnphost"]),
                (&["ics","sharedaccess"], &["SharedAccess"]),
                (&["homegroup"], &["HomeGroupProvider","HomeGroupListener"]),
            ];
            for (keys, svcs) in candidates.iter() {
                if is_allowed(keys) { continue; }
                if opts.dry_run { println!("[windows:svc] dry-run: disable services for {:?}", keys); continue; }
                for s in *svcs {
                    let _ = run_cmd("sc", &["stop", s]).await;
                    let _ = run_cmd("sc", &["config", s, "start=", "disabled"]).await;
                }
            }
            Ok(())
        }
    }

    mod rdp {
        use super::*;
        pub async fn configure_rdp(opts: &EngineOptions, cfg: &Config) -> Result<()> {
            let allowed = cfg.allowed_services.as_ref().map(|v| v.iter().map(|s| s.to_ascii_lowercase()).collect::<Vec<_>>()).unwrap_or_default();
            // RDP allowed if explicitly allowed service or windows.allow_rdp=true
            let allow_rdp_cfg = cfg.windows.as_ref().and_then(|w| w.allow_rdp).unwrap_or(false);
            let allow_rdp = allow_rdp_cfg || allowed.iter().any(|a| a.contains("rdp") || a.contains("termservice"));
            if opts.dry_run { println!("[windows:rdp] dry-run: allow_rdp={}", allow_rdp); return Ok(()); }
            // Require NLA
            let _ = run_cmd("reg", &["add","HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server","/v","UserAuthentication","/t","REG_DWORD","/d","1","/f"]).await;
            let _ = run_cmd("reg", &["add","HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server","/v","SecurityLayer","/t","REG_DWORD","/d","1","/f"]).await;
            // Optional port change
            if let Some(sp) = &cfg.service_ports { if let Some(port) = sp.get("rdp") {
                let _ = run_cmd("reg", &["add","HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp","/v","PortNumber","/t","REG_DWORD","/d", &port.to_string(), "/f"]).await;
                // Firewall: allow new, block old
                let allow_rule = format!("name=AllowRDP dir=in action=allow protocol=TCP localport={}", port);
                let _ = run_cmd("netsh", &["advfirewall","firewall","add","rule", &allow_rule]).await;
                if *port != 3389 { let _ = run_cmd("netsh", &["advfirewall","firewall","add","rule","name=BlockOldRDP dir=in action=block protocol=TCP localport=3389"]).await; }
            }}
            if allow_rdp {
                let _ = run_cmd("reg", &["add","HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server","/v","fDenyTSConnections","/t","REG_DWORD","/d","0","/f"]).await;
                let _ = run_cmd("sc", &["config","TermService","start=","auto"]).await;
                let _ = run_cmd("sc", &["start","TermService"]).await;
            } else {
                let _ = run_cmd("reg", &["add","HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server","/v","fDenyTSConnections","/t","REG_DWORD","/d","1","/f"]).await;
                let _ = run_cmd("sc", &["stop","TermService"]).await;
                let _ = run_cmd("sc", &["config","TermService","start=","disabled"]).await;
            }
            Ok(())
        }
    }

    mod features {
        use super::*;
        pub async fn disable_telnet(opts: &EngineOptions) -> Result<()> {
            if opts.dry_run { println!("[windows:features] dry-run: disable TelnetClient/TelnetServer"); return Ok(()); }
            let _ = run_cmd("dism", &["/online","/Disable-Feature","/featurename:TelnetClient","/NoRestart"]).await;
            let _ = run_cmd("dism", &["/online","/Disable-Feature","/featurename:TelnetServer","/NoRestart"]).await;
            Ok(())
        }
    }

    mod ipv6 {
        use super::*;
        pub async fn disable_ipv6(opts: &EngineOptions) -> Result<()> {
            if opts.dry_run { println!("[windows:ipv6] dry-run: DisabledComponents=0xFFFFFFFF"); return Ok(()); }
            let _ = run_cmd("reg", &["add","HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters","/v","DisabledComponents","/t","REG_DWORD","/d","0xFFFFFFFF","/f"]).await;
            Ok(())
        }
    }

    mod audit {
        use super::*;
        pub async fn configure_audit_policies(opts: &EngineOptions) -> Result<()> {
            if opts.dry_run { println!("[windows:audit] dry-run: auditpol enable success/failure for core categories"); return Ok(()); }
            for cat in [
                "Account Logon","Account Management","DS Access","Logon/Logoff","Object Access","Policy Change","Privilege Use","Detailed Tracking","System"
            ] {
                let _ = run_cmd("auditpol", &["/set","/category:", cat, "/success:enable"]).await;
                let _ = run_cmd("auditpol", &["/set","/category:", cat, "/failure:enable"]).await;
            }
            Ok(())
        }
    }

    mod updates {
        use super::*;
        pub async fn configure_updates(opts: &EngineOptions) -> Result<()> {
            if opts.dry_run { println!("[windows:update] dry-run: enable wuauserv and auto-update registry"); return Ok(()); }
            let _ = run_cmd("sc", &["config","wuauserv","start=","auto"]).await;
            let _ = run_cmd("sc", &["start","wuauserv"]).await;
            let _ = run_cmd("reg", &["add","HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU","/v","NoAutoUpdate","/t","REG_DWORD","/d","0","/f"]).await;
            let _ = run_cmd("reg", &["add","HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU","/v","AUOptions","/t","REG_DWORD","/d","4","/f"]).await;
            Ok(())
        }
    }

    mod server_extras {
        use super::*;
        pub async fn apply_server_extras(opts: &EngineOptions, _cfg: &Config) -> Result<()> {
            if !detect_is_server().await.unwrap_or(false) { return Ok(()); }
            if opts.dry_run { println!("[windows:server] dry-run: SMB1 off, SMB signing required, LLMNR off, RunAsPPL, AutoShare off, LDAP signing (DC)"); return Ok(()); }
            // LSA and system hardening keys commonly used on servers
            let _ = run_cmd("reg", &["add","HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa","/v","restrictanonymous","/t","REG_DWORD","/d","1","/f"]).await;
            let _ = run_cmd("reg", &["add","HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa","/v","restrictanonymoussam","/t","REG_DWORD","/d","1","/f"]).await;
            let _ = run_cmd("reg", &["add","HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa","/v","disabledomaincreds","/t","REG_DWORD","/d","1","/f"]).await;
            let _ = run_cmd("reg", &["add","HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa","/v","RunAsPPL","/t","REG_DWORD","/d","1","/f"]).await;
            // Disable SMB1
            let _ = run_cmd("dism", &["/online","/Disable-Feature","/featurename:SMB1Protocol","/NoRestart"]).await;
            // Require SMB signing (server and client)
            let _ = run_cmd("reg", &["add","HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters","/v","RequireSecuritySignature","/t","REG_DWORD","/d","1","/f"]).await;
            let _ = run_cmd("reg", &["add","HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters","/v","EnableSecuritySignature","/t","REG_DWORD","/d","1","/f"]).await;
            let _ = run_cmd("reg", &["add","HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters","/v","RequireSecuritySignature","/t","REG_DWORD","/d","1","/f"]).await;
            let _ = run_cmd("reg", &["add","HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters","/v","EnableSecuritySignature","/t","REG_DWORD","/d","1","/f"]).await;
            // Disable LLMNR
            let _ = run_cmd("reg", &["add","HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient","/v","EnableMulticast","/t","REG_DWORD","/d","0","/f"]).await;
            // Disable administrative shares
            let _ = run_cmd("reg", &["add","HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters","/v","AutoShareServer","/t","REG_DWORD","/d","0","/f"]).await;
            let _ = run_cmd("reg", &["add","HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters","/v","AutoShareWks","/t","REG_DWORD","/d","0","/f"]).await;
            // DC-only: require LDAP signing
            if let Some(true) = super::detect_is_domain_controller().await {
                let _ = run_cmd("reg", &["add","HKLM\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters","/v","LDAPServerIntegrity","/t","REG_DWORD","/d","2","/f"]).await;
            }
            // Disable AutoPlay
            let _ = run_cmd("reg", &["add","HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer","/v","NoDriveTypeAutoRun","/t","REG_DWORD","/d","255","/f"]).await;
            Ok(())
        }
    }

    mod hygiene {
        use super::*;
        pub async fn purge_unwanted_software(opts: &EngineOptions, cfg: &Config) -> Result<()> {
            let keep = super::build_keep_set(cfg);
            // Appx patterns (remove unless kept)
            let appx_patterns: &[&str] = &[
                "*xbox*","*zune*","*3dbuilder*","*bingnews*","*solitaire*","*skypeapp*","*getstarted*","*oneconnect*","*people*",
                "*communicationsapps*","*feedbackhub*","*officehub*","*onenote*","*onedrive*","*mixedreality*","*wallet*","*yourphone*",
                "*candycrush*","*twitter*","*netflix*","*javascript*"
            ];
            // Win32 patterns (via product names)
            let win32_patterns: &[&str] = &[
                "*wireshark*","*bittorrent*","*utorrent*","*netcat*","*teamviewer*","*team-viewer*","*webcompanion*","*angryip*","*ipscan*",
                "*telnet*","*tftp*"
            ];
            // Build keep regex for PowerShell -notmatch filter
            let keep_regex = {
                fn esc(s: &str) -> String { let mut o=String::new(); for ch in s.chars(){ match ch { '\\'|'['|']'|'(' |')'|'.'|'+'|'*'|'?'|'^'|'$'|'|'|'{'|'}' => { o.push('\\'); o.push(ch); }, _ => o.push(ch), } } o }
                let mut toks: Vec<String> = keep.iter().cloned().collect();
                toks.sort();
                toks.dedup();
                toks.into_iter().map(|t| esc(&t)).collect::<Vec<_>>().join("|")
            };
            if opts.dry_run {
                println!("[windows:hygiene] dry-run: Appx patterns: {:?}; keep_regex: /{}/", appx_patterns, keep_regex);
                println!("[windows:hygiene] dry-run: Win32 patterns: {:?}; keep_regex: /{}/", win32_patterns, keep_regex);
                return Ok(());
            }
            // Remove Appx
            for patt in appx_patterns {
                let cmd = if keep_regex.is_empty() {
                    format!("Get-AppxPackage -AllUsers | Where-Object {{$_.Name -like '{}'}} | ForEach-Object {{ Remove-AppxPackage -Package $_.PackageFullName -AllUsers -ErrorAction SilentlyContinue }}", patt)
                } else {
                    format!("$k='{}'; Get-AppxPackage -AllUsers | Where-Object {{$_.Name -like '{}' -and ($k -eq '' -or $_.Name -notmatch $k)}} | ForEach-Object {{ Remove-AppxPackage -Package $_.PackageFullName -AllUsers -ErrorAction SilentlyContinue }}", keep_regex, patt)
                };
                let _ = run_cmd("powershell", &["-NoProfile","-ExecutionPolicy","Bypass","-Command", &cmd]).await;
            }
            // Remove Win32 via WMI product names
            for patt in win32_patterns {
                let cmd = if keep_regex.is_empty() {
                    format!("Get-CimInstance -ClassName Win32_Product | Where-Object {{$_.Name -like '{}'}} | ForEach-Object {{$_.Uninstall()}}", patt)
                } else {
                    format!("$k='{}'; Get-CimInstance -ClassName Win32_Product | Where-Object {{$_.Name -like '{}' -and ($k -eq '' -or $_.Name -notmatch $k)}} | ForEach-Object {{$_.Uninstall()}}", keep_regex, patt)
                };
                let _ = run_cmd("powershell", &["-NoProfile","-ExecutionPolicy","Bypass","-Command", &cmd]).await;
            }
            Ok(())
        }
    }

    async fn detect_is_server() -> Option<bool> {
        // CIM: 1=Workstation, 2=Domain Controller, 3=Server
        if let Ok(out) = run_cmd_capture("powershell", &["-NoProfile","-ExecutionPolicy","Bypass","-Command","(Get-CimInstance Win32_OperatingSystem).ProductType"]).await {
            let val = out.trim().lines().last().and_then(|s| s.trim().parse::<u32>().ok());
            return Some(matches!(val, Some(2)|Some(3)));
        }
        None
    }

    async fn detect_is_domain_controller() -> Option<bool> {
        if let Ok(out) = run_cmd_capture("powershell", &["-NoProfile","-ExecutionPolicy","Bypass","-Command","(Get-CimInstance Win32_OperatingSystem).ProductType"]).await {
            let val = out.trim().lines().last().and_then(|s| s.trim().parse::<u32>().ok());
            return Some(matches!(val, Some(2)));
        }
        None
    }
}

async fn run_cmd<S: AsRef<str>>(prog: S, args: &[S]) -> Result<()> {
    let prog_s = prog.as_ref();
    let args_s: Vec<&str> = args.iter().map(|s| s.as_ref()).collect();
    let status = Command::new(prog_s).args(&args_s).status().await
        .with_context(|| format!("running {} {}", prog_s, args_s.join(" ")))?;
    println!("[exec] {} {} -> {}", prog_s, args_s.join(" "), status);
    Ok(())
}

async fn run_cmd_env<S: AsRef<str>>(envs: &[(&str, &str)], prog: S, args: &[S]) -> Result<()> {
    let prog_s = prog.as_ref();
    let args_s: Vec<&str> = args.iter().map(|s| s.as_ref()).collect();
    let mut cmd = Command::new(prog_s);
    for (k, v) in envs { cmd.env(k, v); }
    let status = cmd.args(&args_s).status().await
        .with_context(|| format!("running {} {}", prog_s, args_s.join(" ")))?;
    println!("[exec] {} {} -> {}", prog_s, args_s.join(" "), status);
    Ok(())
}

async fn run_cmd_capture<S: AsRef<str>>(prog: S, args: &[S]) -> Result<String> {
    let prog_s = prog.as_ref();
    let args_s: Vec<&str> = args.iter().map(|s| s.as_ref()).collect();
    let out = Command::new(prog_s).args(&args_s).output().await
        .with_context(|| format!("running {} {}", prog_s, args_s.join(" ")))?;
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    println!("[exec*out] {} {} -> {} bytes", prog_s, args_s.join(" "), stdout.len());
    Ok(stdout)
}

async fn backup_if_absent(path: &str) -> Result<()> { let bak = format!("{}.bak", path); if fs::metadata(&bak).await.is_err() { if let Ok(c) = fs::read(path).await { fs::write(&bak, c).await.ok(); } } Ok(()) }
async fn ensure_setting(path: &str, key: &str, value: &str) -> Result<()> { let mut out=String::new(); let mut replaced=false; if let Ok(c)=fs::read_to_string(path).await{ for line in c.lines(){ if line.trim_start().starts_with(&format!("{} ",key))||line.trim_start()==key{ out.push_str(&format!("{} {}\n",key,value)); replaced=true;} else { out.push_str(line); out.push('\n'); } } } if !replaced{ out.push_str(&format!("{} {}\n",key,value)); } fs::write(path,out).await?; Ok(()) }
async fn ensure_kv_or_replace(path: &str, key: &str, value: &str) -> Result<()> { ensure_setting(path, key, value).await }
async fn ensure_line(path: &str, line: &str) -> Result<()> { let mut content=String::new(); if let Ok(c)=fs::read_to_string(path).await{ content=c; } if !content.contains(line){ content.push_str(line); fs::write(path, content).await?; } Ok(()) }
async fn run_cmd_with_stdin<S: AsRef<str>>(prog: S, args: &[S], stdin_data: &str) -> Result<()> { use tokio::io::AsyncWriteExt; let prog_s = prog.as_ref(); let args_s: Vec<&str> = args.iter().map(|s| s.as_ref()).collect(); let mut child = Command::new(prog_s).args(&args_s).stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::inherit()).stderr(std::process::Stdio::inherit()).spawn().with_context(|| format!("spawning {} {}", prog_s, args_s.join(" ")))?; if let Some(mut stdin) = child.stdin.take() { stdin.write_all(stdin_data.as_bytes()).await.ok(); } let status = child.wait().await?; println!("[exec<-stdin] {} {} -> {}", prog_s, args_s.join(" "), status); Ok(()) }

