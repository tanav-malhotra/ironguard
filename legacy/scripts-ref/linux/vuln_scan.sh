#!/bin/bash
######################################################################################
# Author: Tanav Malhotra (GitHub: https://github.com/tanav-malhotra)
# Email: tanavm2009@gmail.com
# License: GNU General Public License v3.0
# Copyright (c) 2024 Tanav Malhotra
#
# This script is licensed under the GNU General Public License v3.0.
# You may obtain a copy of the license at:
#   https://www.gnu.org/licenses/gpl-3.0.html
#
# The script is provided "as-is", without any warranty of any kind,
# express or implied, including but not limited to the implied warranties
# of merchantability and fitness for a particular purpose. See the GPL-3.0
# for full details.
#
# You can also view the license by running the `debian.sh` script
# with the '--license' option.
######################################################################################

##### VARS #####
LOGFILE="./vuln_scan_script.log"

##### CHECK FOR SUDO #####
if [[ $EUID -ne 0 ]]; then
    echo "\`sudo\` access is required. Please run \`sudo !!\`"
    exit 1
fi

##### FUNCTIONS #####
# line seperator
line_sep() {
    echo "----------------------------------"
}
# unusual or suspicious processes
check_processes() {
    echo "Checking for suspicious processes (\`ps aux\`)..." | tee -a $LOGFILE
    log "Press 'Enter' to continue..."; read
    ps aux | tee -a $LOGFILE
    line_sep | tee -a $LOGFILE
}
# open listening ports
check_ports() {
    echo "Installing netstat..." | tee -a $LOGFILE
    apt install -y net-tools
    echo "Checking for open ports (\`netstat -tulnp\`)..." | tee -a $LOGFILE
    log "Press 'Enter' to continue..."; read
    netstat -tulnp | tee -a $LOGFILE | tee -a ./open_ports.log
    line_sep | tee -a $LOGFILE
}
# check cron jobs
check_cron_jobs() {
    echo "Checking for suspicious cron jobs..." | tee -a $LOGFILE

    echo "\`crontab -l -u root\`..." | tee -a $LOGFILE
    log "Press 'Enter' to continue..."; read
    crontab -l -u root | tee -a $LOGFILE
    log "Press 'Enter' to continue..."; read

    echo "\`ls /etc/cron.d\`..." | tee -a $LOGFILE
    log "Press 'Enter' to continue..."; read
    ls /etc/cron.d | tee -a $LOGFILE
    log "Press 'Enter' to continue..."; read

    echo "\`ls /etc/cron.hourly\`..." | tee -a $LOGFILE
    log "Press 'Enter' to continue..."; read
    ls /etc/cron.hourly | tee -a $LOGFILE
    log "Press 'Enter' to continue..."; read

    echo "\`ls /etc/cron.daily\`..." | tee -a $LOGFILE
    log "Press 'Enter' to continue..."; read
    ls /etc/cron.daily | tee -a $LOGFILE
    log "Press 'Enter' to continue..."; read

    echo "\`ls /etc/cron.weekly\`..." | tee -a $LOGFILE
    log "Press 'Enter' to continue..."; read
    ls /etc/cron.weekly | tee -a $LOGFILE
    line_sep | tee -a $LOGFILE
}
# check SSH configuration and logs
check_ssh() {
    echo "Checking SSH configuration and logs..." | tee -a $LOGFILE
    echo "\`cat /etc/ssh/sshd_config\`..." | tee -a $LOGFILE
    log "Press 'Enter' to continue..."; read
    cat /etc/ssh/sshd_config | tee -a $LOGFILE
    log "Press 'Enter' to continue..."; read
    echo "\`/var/log/auth.log | grep ssh\`..." | tee -a $LOGFILE
    log "Press 'Enter' to continue..."; read
    cat /var/log/auth.log | grep ssh | tee -a $LOGFILE
    line_sep | tee -a $LOGFILE
}
#TODO: check configs for other critical services supported by debian.sh script
# check for unusual user accounts
check_users() {
    echo "Checking for unusual user accounts..." | tee -a $LOGFILE
    echo "\`cat /etc/passwd\`..." | tee -a $LOGFILE
    log "Press 'Enter' to continue..."; read
    cat /etc/passwd | tee -a $LOGFILE
    log "Press 'Enter' to continue..."; read
    echo "\`cat /etc/shadow\`..." | tee -a $LOGFILE
    log "Press 'Enter' to continue..."; read
    cat /etc/shadow | tee -a $LOGFILE
    log "Press 'Enter' to continue..."; read
    cut -d: -f1 /etc/passwd | while read user; do
        if id -nG "$user" | grep -qwE 'sudo|wheel|admin'; then
            ROLE="admin"
        else
            ROLE="user"
        fi
        echo "Groups for $ROLE $user:" | tee -a $LOGFILE
        groups $user | tee -a $LOGFILE
        log "Press 'Enter' to continue..."; read
    done
    line_sep | tee -a $LOGFILE
}
# check sudoers configuration
check_sudoers() {
    echo "Checking sudoers configuration..." | tee -a $LOGFILE
    echo "\`visudo -c\`..." | tee -a $LOGFILE
    log "Press 'Enter' to continue..."; read
    visudo -c | tee -a $LOGFILE
    line_sep | tee -a $LOGFILE
}
# check for hidden network connections
check_network_connections() {
    echo "Checking for hidden network connections..." | tee -a $LOGFILE
    echo "\`lsof -i\`..." | tee -a $LOGFILE | tee -a ./hidden_network_connections.log
    log "Press 'Enter' to continue..."; read
    lsof -i | tee -a $LOGFILE
    line_sep | tee -a $LOGFILE
}
# check for loaded kernel modules
check_kernel_modules() {
    echo "Checking for unusual kernel modules..." | tee -a $LOGFILE
    echo "\`lsmod\`..." | tee -a $LOGFILE
    log "Press 'Enter' to continue..."; read
    lsmod | tee -a $LOGFILE | tee -a ./kernel_modules.log
    line_sep | tee -a $LOGFILE
}
# check for suspicious GRUB modifications
check_grub() {
    echo "Checking for suspicious GRUB configurations..." | tee -a $LOGFILE
    echo "\`cat /etc/default/grub\`..." | tee -a $LOGFILE
    log "Press 'Enter' to continue..."; read
    cat /etc/default/grub | tee -a $LOGFILE | tee -a ./default_grub_config.log
    line_sep | tee -a $LOGFILE
}
# check suspicious services
check_services() {
    echo "Checking for suspicious services..." | tee -a $LOGFILE
    echo "\`systemctl list-units --type=service --state=running\`..." | tee -a $LOGFILE
    log "Press 'Enter' to continue..."; read
    systemctl list-units --type=service --state=running | tee -a $LOGFILE | tee -a ./running_services.log
    line_sep | tee -a $LOGFILE
}
# check system logs
check_logs() {
    echo "Checking system logs..." | tee -a $LOGFILE
    echo "\`cat /var/log/auth.log\`..." | tee -a $LOGFILE
    log "Press 'Enter' to continue..."; read
    cat /var/log/auth.log | tee -a $LOGFILE
    log "Press 'Enter' to continue..."; read
    echo "\`cat /var/log/syslog\`..." | tee -a $LOGFILE
    log "Press 'Enter' to continue..."; read
    cat /var/log/syslog | tee -a $LOGFILE
    log "Press 'Enter' to continue..."; read
    echo "\`cat /var/log/daemon.log\`..." | tee -a $LOGFILE
    log "Press 'Enter' to continue..."; read
    cat /var/log/daemon.log | tee -a $LOGFILE
    line_sep | tee -a $LOGFILE
}
# check network traffic
traffic_analysis() {
    # Monitor suspicious connections
    nethogs -t | grep -v "localhost" | tee -a $LOGFILE | tee -a ./traffic_monitor.log
    # Monitor packet statistics
    iftop -t -s 10 | tee -a $LOGFILE | tee -a ./bandwidth_usage.log
    # Check for unusual ports
    netstat -tulpn | grep LISTEN | tee -a $LOGFILE | tee -a ./open_ports.log
    # Monitor DNS queries
    tcpdump -i any port 53 | tee -a $LOGFILE | tee -a ./dns_queries.log
    line_sep | tee -a $LOGFILE
}
# lynis to check potential vulnerabilities
lynis_scan() {
    #TODO
    line_sep | tee -a $LOGFILE
}

##### RUN FUNCTIONS #####
echo "Note: This script will not perform any in-depth search for potential malware. Please use the \`malware_scan.sh\` script instead."
sleep 0.5
echo "Updating apt..." | tee -a $LOGFILE
apt update
echo "Searching for vulnerabilities..." | tee -a $LOGFILE
line_sep | tee -a $LOGFILE
check_processes
log "Press 'Enter' to continue..."; read
check_ports
log "Press 'Enter' to continue..."; read
check_cron_jobs
log "Press 'Enter' to continue..."; read
check_ssh
log "Press 'Enter' to continue..."; read
check_users
log "Press 'Enter' to continue..."; read
check_sudoers
log "Press 'Enter' to continue..."; read
check_network_connections
log "Press 'Enter' to continue..."; read
check_kernel_modules
log "Press 'Enter' to continue..."; read
check_grub
log "Press 'Enter' to continue..."; read
check_services
log "Press 'Enter' to continue..."; read
check_logs
log "Press 'Enter' to continue..."; read
traffic_analysis
log "Press 'Enter' to continue..."; read
lynis_scan
log "Press 'Enter' to continue..."; read
echo "Finished searching for vulnerabilities..."
echo "Log saved to: $LOGFILE"

##### WISH GOOD LUCK #####
echo;echo;echo;
echo "Thank you for using this script. Good luck for the competition!"
echo
echo "==================================="
echo "Copyright (c) 2024 Tanav Malhotra"
echo "GNU General Public License v3.0"
echo "==================================="
echo
exit 0