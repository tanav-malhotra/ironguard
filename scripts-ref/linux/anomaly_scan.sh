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

##### VARIABLES #####
LOGFILE="./anomaly_scan.log"

##### CHECK FOR SUDO #####
if [[ $EUID -ne 0 ]]; then
    echo "\`sudo\` access is required. Please run \`sudo !!\`"
    exit 1
fi

##### SCAN FOR ANOMALIES #####
# Check for unusual system load
echo "Checking for unusual system load..." | tee -a $LOGFILE
load=$(cat /proc/loadavg | cut -d ' ' -f1)
if (( $(echo "$load > 10" | bc -l) )); then
    echo "High system load detected: $load" >> $LOGFILE
    echo "High system load detected: $load" > ./high_system_load.log
fi
# Check for unusual network connections
echo "Checking for unusual network connections..." | tee -a $LOGFILE
netstat -ant | grep ESTABLISHED | wc -l | while read connections; do
    if [ $connections -gt 100 ]; then
        echo "Unusual number of connections: $connections" >> $LOGFILE
        echo "Unusual number of connections: $connections" > ./unusual_network_connections.log
    fi
done
# Check for large files in /tmp
echo "Checking for large files in /tmp..." | tee -a $LOGFILE
find /tmp -type f -size +100M -exec ls -lh {} \; >> $LOGFILE
find /tmp -type f -size +100M -exec ls -lh {} \; > ./large_files_in_tmp.log
# Monitor failed SSH attempts
echo "Monitoring failed SSH attempts..." | tee -a $LOGFILE
grep "Failed password" /var/log/auth.log | grep -c "ssh2" | while read attempts; do
    if [ $attempts -gt 10 ]; then
        echo "High number of failed SSH attempts: $attempts" >> $LOGFILE
        echo "High number of failed SSH attempts: $attempts" > ./high_failed_ssh_attempts.log
    fi
done
# Check for modified system binaries
#TODO: use implementation from `debian.sh`

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