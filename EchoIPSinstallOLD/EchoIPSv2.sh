#!/bin/bash

# Variables
CON_NAME="shelter"
IP_ADDRESS=""
GATEWAY="192.168.100.0/24"
SNORT_CONF="/etc/snort/snort.conf"
RULES_VERSION=""
OINK_CODE="3bec5be2c7c9652c036d98fcf5c82680cc0973c9"
PULLEDPORK_VERSION=""
CRON_MINS=$((RANDOM % 60))
CRON_HOUR=$((RANDOM % 24))
CRON_DAY=$((RANDOM % 7)) # 0-6 for Sunday through Saturday respectively

# Function to validate IP address format
validate_ip() {
    local ip="$1"
    local valid_ip_regex="^([0-9]{1,3}\.){3}[0-9]{1,3}$"
    if [[ $ip =~ $valid_ip_regex ]]; then
        for octet in $(echo "$ip" | tr '.' ' '); do
            if ((octet < 0 || octet > 255)); then
                return 1
            fi
        done
        return 0
    else
        return 1
    fi
}

# Function to get a valid IP address from user input
get_ip_input() {
    local prompt="$1"
    local ip_variable
    while true; do
        echo -n "$prompt"
        read -r ip_variable
        if validate_ip "$ip_variable"; then
            echo "$ip_variable"
            return 0
        else
            echo "Invalid IP address. Please try again."
        fi
    done
}

# Function to display a message
display_message() {
    echo -e "\n#############################"
    echo "# $1"
    echo "#############################\n"
}

# Function for logging
log() {
    echo "[ $(date +'%Y-%m-%d %H:%M:%S') ] $1"
}

# Function for error handling
check_error() {
    if [ $? -ne 0 ]; then
        log "Error: $1"
        exit 1
    else
        log "Success: $1"
    fi
}

# Check if required commands are available
command -v nmcli >/dev/null 2>&1 || { echo "nmcli command not found. Please install NetworkManager."; exit 1; }
command -v awk >/dev/null 2>&1 || { echo "awk command not found. Please install it."; exit 1; }

log "Starting setup..."

# Prompt the user for the new IP address
IP_ADDRESS=$(get_ip_input "Please enter the new IP address: ")

# Display the entered IP address
echo "You entered: $IP_ADDRESS"

DHCP_LEASE_END=$(echo "$IP_ADDRESS" | awk -F. '{print $1"."$2"."$3"."($4+100)}')

# Step 2: Update and upgrade
log "Updating and upgrading system..."
display_message "Updating and upgrading the system..."
sudo apt update && sudo apt upgrade -y
check_error "System update and upgrade"

# Step 3: Install NetworkManager
log "Installing NetworkManager..."
sudo apt-get install network-manager -y
check_error "NetworkManager installation"

# Step 5: Create pass-through connection
log "Creating pass-through connection..."
sudo nmcli c add con-name "$CON_NAME" type ethernet ifname eth0 ipv4.method share ipv6.method ignore
check_error "Adding NetworkManager connection"

sudo nmcli c mod "$CON_NAME" ipv4.addresses "$IP_ADDRESS/24"
check_error "Modifying NetworkManager connection"

sudo nmcli c up "$CON_NAME"
check_error "Bringing up NetworkManager connection"
