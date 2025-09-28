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

##### DECODE BASE64 STRING #####
if [ -z "$1" ]; then
    read -r -p "Enter Base64 encoded string: " encoded_string
else
    encoded_string="$1"
decoded_string=$(echo "$encoded_string" | base64 --decode)
echo "Decoded string: $decoded_string"
log "Press 'Enter' to continue..."
read

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