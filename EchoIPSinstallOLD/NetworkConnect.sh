## Network connect script   ##
##                          ##
## Author: Jonathan Johnson ##
## In association with:     ##
##      Liam MacLeod        ##
##      Ayodeji Ogunlana    ##
##      Declan Campbell     ##
## For: SAIT - ITSC309,     ##
## ISS capstone 2024        ##
## Completed August 2024    ##

#!/bin/bash

# Network variables
INTERNET_IF="wlan0"  # Interface connected to the internet
LOCAL_IF="eth0"      # Interface connected to the local network
NETPLAN_CONFIG_FILE="/etc/netplan/01-netcfg.yaml"

## Function: To confirm variable values with the user
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

## Function: Connect to network
SetNetwork() {
    while true; do
        SSID=$(get_ip_input "Enter the SSID of the WiFi network: ")
        confirm_variables "Enter the network password" "PASSWORD" "$PASSWORD"

# Create the Netplan configuration file
        sudo bash -c "cat > $NETPLAN_CONFIG_FILE" <<EOL
network:
  version: 2
  wifis:
    ${INTERNET_IF}:
      dhcp4: true
      access-points:
        ${SSID}:
          password: ${PASSWORD}
EOL

# Apply the new Netplan configuration
        sudo chmod 600 $NETPLAN_CONFIG_FILE
        sudo netplan apply
        echo "Waiting 30 seconds for connection to establish"
        sleep 30

 # Check if the connection was successful
        if [ $? -eq 0 ]; then
            echo "Successfully connected to $SSID"
            break
        else
            echo "Failed to connect to $SSID. Please retry"
        fi
    done
}

SetNetwork