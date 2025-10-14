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

##### CHECK FOR SUDO #####
if [[ $EUID -ne 0 ]]; then
    echo "\`sudo\` access is required. Please run \`sudo !!\`"
    exit 1
fi

apt update -y && apt install -y ufw libpam-google-authenticator
ufw allow OpenSSH
ufw enable
ufw logging on
ufw logging high

# ALLOWED_IPS=("192.168.1.100" "203.0.113.50")  # Replace with IPs
# for IP in "${ALLOWED_IPS[@]}"; do
#     ufw allow from "$IP" to any port 22
# done

##### SET UP GOOGLE AUTH #####
if [ -f "/home/$USER/.google_authenticator" ]; then
    echo "Google Authenticator is already set up for user $USER."
else
    echo "Setting up Google Authenticator for user $USER."
    google-authenticator -t -d -f -r 3 -R 30 -w 3
    echo "Please scan the QR code displayed and save the emergency codes."
fi

##### CONFIGURE PAM #####
echo "Updating PAM configuration for SSH."
if ! grep -q "auth required pam_google_authenticator.so" /etc/pam.d/sshd; then
    echo "auth required pam_google_authenticator.so" | tee -a /etc/pam.d/sshd
fi

##### SSH CONFIG FOR 2FA #####
echo "Updating SSH configuration."
if ! grep -q "ChallengeResponseAuthentication yes" /etc/ssh/sshd_config; then
    echo "ChallengeResponseAuthentication yes" | tee -a /etc/ssh/sshd_config
fi

##### RESTART SSH #####
systemctl restart sshd
echo "UFW is configured and Google Authenticator setup is complete."

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