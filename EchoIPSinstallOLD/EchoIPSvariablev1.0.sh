#!/bin/bash

# Variables
CON_NAME="$(whoami)"
IP_ADDRESS=""
GATEWAY=""
OINK_CODE="3bec5be2c7c9652c036d98fcf5c82680cc0973c9"
SUDOERS_TEMP_FILE=/etc/sudoers.d/timeout

# sudo timeout function
set_sudo_timeout() {
    echo "Defaults timestamp_timeout=60" | sudo tee $SUDOERS_TEMP_FILE
    sudo visudo -cf /etc/sudoers.d/timeout
    if [ $? -eq 0 ]; then
        echo "Sudoers file syntax is correct."
    else   
        echo "Syntax error in sudoers file."
        sudo rm $SUDOERS_TEMP_FILE
        exit 1
    fi
}

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
            echo "Invalid IP address. Please try again.Ensure the last octet is not 0 for the host IP."
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
GATEWAY=$(echo "$IP_ADDRESS" | awk -F. '{print $1"."$2"."$3".0"}')
confirm_variables "Enter the connection name" "CON_NAME" "$CON_NAME"
confirm_variables "Enter the OINK_CODE" "OINK_CODE" "$OINK_CODE"

SERVICE_NAME="${CON_NAME}.service"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}"

log "Creating swap file, this may take a while..."
sudo dd if=/dev/zero of=/swapfile.img bs=4M count=256
sudo mkswap /swapfile.img
sudo chmod 600 /swapfile.img
sudo swapon /swapfile.img
check_error "Creating and enabling swap file"

log "Starting setup..."
set_sudo_timeout
# Step 2: Update and upgrade
log "Updating and upgrading system..."
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
