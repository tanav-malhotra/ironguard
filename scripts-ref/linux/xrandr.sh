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

##### CHANGE SCREEN RESOULTION #####
RESOLUTION="1920x1080"
OUTPUT=$(xrandr | grep " connected" | awk '{ print $1 }')
AVAILABLE_RESOLUTIONS=$(xrandr | grep "$OUTPUT" -A 10 | grep -oP "\d+x\d+")
if echo "$AVAILABLE_RESOLUTIONS" | grep -q "$RESOLUTION"; then
    echo "Resolution $RESOLUTION is already available. Applying it..."
    xrandr -s $RESOLUTION
else
    echo "Resolution $RESOLUTION is not available. Adding it now..."
    MODELINE=$(cvt 1920 1080 60 | grep -oP 'Modeline.*')
    xrandr --newmode $MODELINE
    xrandr --addmode "$OUTPUT" "$RESOLUTION"
    echo "Applying resolution $RESOLUTION..."
    xrandr -s $RESOLUTION
fi

##### SET RESOLUTION ON REBOOT #####
# echo "Setting resolution on system startup..."
# (crontab -l; echo "@reboot $0") | crontab -
# ORIGINAL_USER_HOME=$(eval echo "~$SUDO_USER")
# echo "xrandr -s $RESOLUTION" >> $ORIGINAL_USER_HOME/.xprofile # TODO: fix error
# SERVICE_FILE="/etc/systemd/system/set-resolution.service"
# cat > "$SERVICE_FILE" <<EOL
# [Unit]
# Description=Set Display Resolution

# [Service]
# ExecStart=/usr/bin/xrandr -s $RESOLUTION
# User=$SUDO_USER
# Environment=DISPLAY=:0

# [Install]
# WantedBy=default.target
# EOL
# chmod 644 "$SERVICE_FILE"
# systemctl daemon-reload
# systemctl enable set-resolution.service

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