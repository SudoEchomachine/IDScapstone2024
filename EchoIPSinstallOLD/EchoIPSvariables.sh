#!/bin/bash

# Variables
CON_NAME=""
IP_ADDRESS=""
GATEWAY=""
OINK_CODE="3bec5be2c7c9652c036d98fcf5c82680cc0973c9"
CRON_MINS=$((RANDOM % 61))
CRON_HOUR=$((RANDOM % 24))
CRON_DAY=$((RANDOM % 7))  # 0-6 for Sunday through Saturday respectively


# Function to validate IP address format
validate_ip() {
    local ip="$1"
    local valid_ip_regex="^([0-9]{1,3}\.){3}[0-9]{1,3}$"
    if [[ $ip =~ $valid_ip_regex ]]; then
        for octet in $(echo $ip | tr '.' ' '); do
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
    while true; do
        read -p "$prompt" ip_variable
        if validate_ip "$ip_variable" && [[ ${ip_variable##*.} -ne 0 ]]; then
            echo "$ip_variable"
            return 0
        else
            echo "Invalid IP address. Please try again. Ensure the last octet is not 0 for the host IP."
        fi
    done
}

# Function to confirm variable values with the user
confirm_variables() {
    local prompt="$1"
    local var_name="$2"
    local var_value="$3"
    while true; do
        read -p "$prompt [Current: $var_value]: " new_value
        if [ -z "$new_value" ]; then
            new_value="$var_value"
        fi
        echo "You entered: $new_value"
        read -p "Is this correct? (y/n) " answer
        case $answer in
            [Yy]*) eval $var_name=\"$new_value\"; break ;;
            [Nn]*) echo "Let's try again." ;;
            *) echo "Please answer with 'y' or 'n'." ;;
        esac
    done
}

# Function for logging
log() {
    echo "[`date +'%Y-%m-%d %H:%M:%S'`] $1"
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

# Prompt the user for the new IP address and other variables
IP_ADDRESS=$(get_ip_input "Please enter the new IP address:")
confirm_variables "Enter the connection name" "CON_NAME" "$CON_NAME"
#confirm_variables "Enter the OINK_CODE" "OINK_CODE" "$OINK_CODE"

log "Starting setup..."
# Step 2: Update and upgrade
log "Updating and upgrading system..."
apt update && apt upgrade -y
check_error "System update and upgrade"

# Step 3: Install NetworkManager
log "Installing NetworkManager..."
apt-get install network-manager -y
check_error "NetworkManager installation"

# Step 4: install 
log "Installing gawk"
apt-get install gawk
GATEWAY=$(echo "$IP_ADDRESS" | awk -F. '{print $1"."$2"."$3".0"}')
check_error "Installing awk"

# Step 5: Create pass-through connection
log "Creating pass-through connection..."
nmcli c add con-name "$CON_NAME" type ethernet ifname eth0 ipv4.method share ipv6.method ignore
check_error "Adding NetworkManager connection"

nmcli c mod "$CON_NAME" ipv4.addresses "$IP_ADDRESS/24"
check_error "Modifying NetworkManager connection"

reboot