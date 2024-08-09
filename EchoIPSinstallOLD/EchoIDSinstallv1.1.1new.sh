## MobileIDS install script ##
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
INTERNET_IF="wlan0" # Interface connected to the internet
LOCAL_IF="eth0"   # Interface connected to the local network
CON_NAME="$(whoami)"
IP_ADDRESS=""
GATEWAY=""

# Pork variables
OINK_CODE="3bec5be2c7c9652c036d98fcf5c82680cc0973c9"
RULES_VERSION=""
RULE_PATH="/etc/snort/rules"
PULLEDPORK_VERSION=""
CRON_MINS=$((RANDOM % 61)) # These are set randomly to avoid stress on the download servers
CRON_HOUR=$((RANDOM % 24)) # To set manually edit crontab -l
CRON_DAY=$((RANDOM % 7)) # 0-7 for Sunday through Saturday respectively

# Config and Log variables
NETPLAN_CONFIG_FILE="/etc/netplan/01-netcfg.yaml"
SUDOERS_TEMP_FILE=/etc/sudoers.d/timeout
SNORT_CONF="/etc/snort/snort.conf"
LOG_FILE="/home/$(whoami)/EchoIDSinstall.log"
CHECKPOINT_FILE="/home/$(whoami)/checkpoint"
TEMP_VAR_FILE="/home/$(whoami)/TempVariables"

## Function: To validate IP address format
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

## Function: To get a valid IP address from user input
get_ip_input() {
    local prompt="$1"
    while true; do
        read -p "$prompt" ip_variable
        if validate_ip "$ip_variable" && [[ ${ip_variable##*.} -ne 0 ]]; then
            echo "$ip_variable"
            return 0
        else
            echo "Invalid IP address. Please try again."
            echo "Ensure the last octet is not 0 for the host IP."
        fi
    done
}

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

save_variables() {
    echo "CON_NAME=\"$CON_NAME\"" >> "$TEMP_VAR_FILE"
    echo "IP_ADDRESS=\"$IP_ADDRESS\"" >> "$TEMP_VAR_FILE"
    echo "GATEWAY=\"$GATEWAY\"" >> "$TEMP_VAR_FILE"
    echo "LOCAL_IF=\"$LOCAL_IF\"" >> "$TEMP_VAR_FILE"
    echo "INTERNET_IF=\"$INTERNET_IF\"" >> "$TEMP_VAR_FILE"
    echo "OINK_CODE=\"$OINK_CODE\"" >> "$TEMP_VAR_FILE"
    echo "SNORT_CONF=\"$SNORT_CONF\"" >> "$TEMP_VAR_FILE"
# Add any other variables that need to be preserved
}

## Function: To increase sudo timeout limit
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

## Function: To reset sudo timeout limit
restore_sudo_timeout() {
    sudo rm -f $SUDOERS_TEMP_FILE
}

## Function: Logging
log() {
    echo "[`date +'%Y-%m-%d %H:%M:%S'`] $1"
    echo "[`date +'%Y-%m-%d %H:%M:%S'`] $1" >> "$LOG_FILE"
}

## Function: Error handling
check_error() {
    if [ $? -ne 0 ]; then
        log "Error: $1"
        exit 1
    else
        log "Success: $1"
    fi
}

## Function: Update checkpoint file
update_checkpoint() {
    echo "$1" > "$CHECKPOINT_FILE"
}

## Function: Get checkpoint position
get_checkpoint() {
    if [ -f "$CHECKPOINT_FILE" ]; then
        cat "$CHECKPOINT_FILE"
    else
        echo "Start"
    fi
}

## Function: Connect to network
SetNetwork() {
    while true; do
        confirm_variables "Enter the SSID of the WiFi network:" "SSID" "$SSID"
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

# Check if the connection was successful
        if [ $? -eq 0 ]; then
            echo "Successfully connected to $SSID"
            break
        else
            echo "Failed to connect to $SSID. Please retry"
        fi
    done
}

START_TIME=$(date +%s)
source "$TEMP_VAR_FILE"

while true; do
    CHECKPOINT=$(get_checkpoint)
    case $CHECKPOINT in
        "Start")
            SetNetwork

## Step : Get user input for IP address and other variables
            IP_ADDRESS=$(get_ip_input "Please enter the new IP address:")
            GATEWAY=$(echo "$IP_ADDRESS" | awk -F. '{print $1"."$2"."$3".0"}')
            confirm_variables "Enter desired connection name" "CON_NAME" "$CON_NAME"
            confirm_variables "Enter your OINK_CODE" "OINK_CODE" "$OINK_CODE"

            log "Starting setup..."
            set_sudo_timeout
            save_variables
            check_error "Setting sudo timeout"
            update_checkpoint "Starting setup"
            ;;
        "Starting setup")

## Step : Create swap file to ensure ample resources
            if sudo swapon --show | grep -q "/swapfile.img"; then
                log "Swap file exists and is mounted"
            else
                log "Creating swap file..."
                echo "this may take a while!"
                sudo dd if=/dev/zero of=/swapfile.img bs=4M count=256
                sudo chmod 600 /swapfile.img
                sudo mkswap /swapfile.img
                sudo swapon /swapfile.img
            fi
            check_error "Creating and enabling swap file"
            update_checkpoint "Creating swap file"
            ;;
        "Creating swap file")

## Step : Update and upgrade
            log "Updating and upgrading system..."
            echo "this may take a while!"
            sudo apt update && sudo apt upgrade -y
            check_error "System update and upgrade"
            update_checkpoint "Updating and upgrading"
            ;;
        "Updating and upgrading")

## Step : Install NetworkManager and configure
            log "Installing NetworkManager..."
            sudo apt-get install network-manager -y
            check_error "NetworkManager installation"
            update_checkpoint "Installing NetworkManager"
            ;;
        "Installing NetworkManager")

    # Create pass-through connection
            log "Creating pass-through connection..."
            sudo nmcli c add con-name $CON_NAME type ethernet ifname $LOCAL_IF ipv4.method share ipv6.method ignore
            check_error "Adding NetworkManager connection"

            sudo nmcli c mod "$CON_NAME" ipv4.addresses "${IP_ADDRESS}/24"
            check_error "Modifying NetworkManager connection"

            sudo nmcli g reload
            sudo nmcli c up "$CON_NAME"
            check_error "Bringing up NetworkManager connection"
            update_checkpoint "Creating pass-through connection"
            ;;
        "Creating pass-through connection")

## Step : Install Apache2 and configure
            log "Installing Apache2..."
            sudo apt install apache2 -y
            check_error "Apache2 installation"

            log "Enabling Apache2 to start on boot..."
            sudo systemctl enable apache2
            check_error "Enabling Apache2 on boot"

            log "Starting Apache2 service..."
            sudo systemctl start apache2
            check_error "Starting Apache2 service"
            update_checkpoint "Installing Apache2"
            ;;
        "Installing Apache2")

## Step : Set up a basic HTML page
            log "Setting up a basic HTML page..."
            wget "https://www.github.com/SudoEchomachine/IDScapstone2024/raw/main/IPS-SAIT.html"
            sudo rm /var/www/html/index.html
            sudo mv IPS-SAIT.html /var/www/html/
            check_error "Setting up HTML page"

    # Adjust permissions
            log "Adjusting permissions for /var/www/html..."
            sudo chown -R www-data:www-data /var/www/html
            sudo chmod -R 755 /var/www/html
            check_error "Adjusting permissions"

    # Restart Apache2 to apply changes
            log "Restarting Apache2 to apply changes..."
            sudo systemctl restart apache2
            check_error "Restarting Apache2"
            update_checkpoint "Setting up a basic HTML page"
            ;;
        "Setting up a basic HTML page")

## Step : Install PHP and configure
            log "Installing PHP..."
            sudo apt install php libapache2-mod-php -y
            check_error "PHP installation"

            echo "<?php phpinfo(); ?>" | sudo tee /var/www/html/info.php
            check_error "Setting up PHP info page"

            sudo systemctl restart apache2
            check_error "Restarting Apache2 for PHP"
            update_checkpoint "Installing PHP"
            ;;
        "Installing PHP")

## Step : Modify /etc/sysctl.conf
            log "Modifying /etc/sysctl.conf..."
            sudo cp /etc/sysctl.conf /etc/sysctl.conf.bak
            echo "net.ipv4.conf.default.rp_filter = 1" >> "/etc/sysctl.conf"
            echo "net.ipv4.conf.all.rp_filter = 1" >> "/etc/sysctl.conf"
            echo "net.ipv4.tcp_syncookies = 1" >> "/etc/sysctl.conf"
            echo "net.ipv4.ip_forward = 1" >> "/etc/sysctl.conf"
            echo "net.ipv4.conf.all.accept_redirects = 0" >> "/etc/sysctl.conf"
            echo "net.ipv4.conf.${LOCAL_IF}.accept_redirects = 0" >> "/etc/sysctl.conf"
            echo "net.ipv4.conf.all.send_redirects = 0" >> "/etc/sysctl.conf"
            echo "net.ipv4.conf.default.send_redirects = 0" >> "/etc/sysctl.conf"
            echo "net.ipv4.conf.${LOCAL_IF}.send_redirects = 0" >> "/etc/sysctl.conf"
            echo "net.ipv4.all.log_martians = 1" >> "/etc/sysctl.conf"
            echo "net.ipv4.icmp_echo_ignore_broadcasts = 1" >> "/etc/sysctl.conf"
            echo "net.ipv4.icmp_ignore_bogus_error_responses = 1" >> "/etc/sysctl.conf"
            echo "vm.min_free_kbytes = 8192" >> "/etc/sysctl.conf"
            check_error "Modifying /etc/sysctl.conf"

            sudo sysctl -p
            update_checkpoint "Modifying /etc/sysctl.conf"
            ;;
        "Modifying /etc/sysctl.conf")

## Step : Install DNSmasq and configure
            log "Installing DNSmasq..."
            sudo apt-get install dnsmasq -y
            check_error "DNSmasq installation"

    # Modify /etc/dnsmasq.conf
            log "Modifying /etc/dnsmasq.conf..."
            sudo bash -c 'cat <<EOL >> /etc/dnsmasq.conf
            domain-needed
            bogus-priv
            server=8.8.8.8
            #interface=${LOCAL_IF}
            #listen-address='$IP_ADDRESS'
            bind-interfaces
            dhcp-range='$IP_ADDRESS','$DHCP_LEASE_END',12h
            dhcp-authoritative
            cache-size=300
            dns-forward-max=150
            EOL'
            check_error "Modifying /etc/dnsmasq.conf"

            sudo systemctl enable dnsmasq.service
            check_error "Enabling DNSmasq service"
            update_checkpoint "Installing DNSmasq"
            ;;
        "Installing DNSmasq")

## Step : Set IPtables rules and persistence
    # Flush existing rules
            sudo iptables -F
            sudo iptables -t nat -F
            sudo iptables -t mangle -F
            sudo iptables -X

    # Set default policies to drop all traffic
            sudo iptables -P INPUT DROP
            sudo iptables -P FORWARD DROP
            sudo iptables -P OUTPUT ACCEPT

    # Allow loopback traffic
            sudo iptables -A INPUT -i lo -j ACCEPT
            sudo iptables -A OUTPUT -o lo -j ACCEPT

    # Allow established and related incoming traffic
            sudo iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
            sudo iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

    # Allow SSH access (if needed)
            sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT

    # Allow HTTP (port 80) and HTTPS (port 443) traffic to the Apache2 server
            sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT
            sudo iptables -A INPUT -p tcp --dport 443 -j ACCEPT

    # Allow ping (optional)
            sudo iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT

    # Allow forwarding traffic from local network to the internet
            sudo iptables -A FORWARD -i $LOCAL_IF -o $INTERNET_IF -j ACCEPT
            sudo iptables -A FORWARD -i $INTERNET_IF -o $LOCAL_IF -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

    # Enable NAT for internet connection sharing
            sudo iptables -t nat -A POSTROUTING -o $INTERNET_IF -j MASQUERADE

    # Log dropped packets (optional, for debugging)
            sudo iptables -A INPUT -m limit --limit 5/min -j LOG --log-prefix "sudo iptables_INPUT_DROP: " --log-level 7
            sudo iptables -A FORWARD -m limit --limit 5/min -j LOG --log-prefix "sudo iptables_FORWARD_DROP: " --log-level 7

    # Drop all other traffic
            sudo iptables -A INPUT -j DROP
            sudo iptables -A FORWARD -j DROP

            sudo apt-get install sudo iptables-persistent -y 
            log "sudo iptables rules have been set and saved."
            update_checkpoint "Set sudo IPtables rules"
            ;;
        "Set sudo IPtables rules")

## Step : Install and configure Snort
            log "Installing Snort..."
            sudo apt-get install snort -y
            check_error "Snort installation"

            log "Backing up original Snort configuration..."
            sudo cp $SNORT_CONF ${SNORT_CONF}.bak
            check_error "Backing up Snort configuration"

            log "Modifying Snort configuration..."
            sudo sed -i "s|^ipvar HOME_NET .*|ipvar HOME_NET "${GATEWAY}"|" "$SNORT_CONF"
            sudo sed -i "s|^ipvar EXTERNAL_NET .*|#ipvar EXTERNAL_NET any|" "$SNORT_CONF"
            sudo sed -i "s|^#ipvar EXTERNAL_NET .*|ipvar EXTERNAL_NET !"\$HOME_NET"|" "$SNORT_CONF"
            sudo sed -i "s|^ipvar DNS_SERVERS .*|ipvar DNS_SERVERS "$IP_ADDRESS"|" "$SNORT_CONF"
            sudo sed -i "s|^ipvar SSH_SERVERS .*|ipvar SSH_SERVERS "$IP_ADDRESS"|" "$SNORT_CONF"
            sudo sed -i "s|^portvar HTTP_PORTS .*|portvar HTTP_PORTS 80|" "$SNORT_CONF"
            sudo sed -i "s|^portvar SSH_PORTS .*|portvar SSH_PORTS [22,15507]|" "$SNORT_CONF"
            sudo sed -i "s|^config detection:.*|config detection: search-method lowmem search-optimize max-pattern-len 20|" "$SNORT_CONF"
            sudo sed -i "s|^config event_queue:.*|config event_queue: max_queue 8 log 3 order_events content_length|" "$SNORT_CONF"
            sudo sed -i "s|^preprocessor ssh:.*|preprocessor ssh: server_ports { 22 15507 } \\\|" "$SNORT_CONF"
            check_error "Modifying Snort configuration"

            log "Modifying whitelist and blacklist in Snort configuration..."
            sudo sed -i "s|^#preprocessor reputation: \\|preprocessor reputation: \\|" "$SNORT_CONF"
            sudo sed -i "s|^#  memcap 500, \\|memcap 500, \\|" "$SNORT_CONF"
            sudo sed -i "s|^#  priority whitelist, \\|priority whitelist, \\|" "$SNORT_CONF"
            sudo sed -i "s|^#  nested_ip inner, \\|nested_ip inner, \\|" "$SNORT_CONF"
            sudo sed -i "s|^#  whitelist \\$WHITE_LIST_PATH/whitelist.rules, \\|whitelist \$WHITE_LIST_PATH/whitelist.rules, \\|" "$SNORT_CONF"
            sudo sed -i "s|^#  blacklist \\$BLACK_LIST_PATH/blacklist.rules|blacklist \$BLACK_LIST_PATH/blacklist.rules|" "$SNORT_CONF"
            check_error "Modifying whitelist and blacklist in Snort configuration"

            log "Updating Snort rules path..."
            sudo sed -i "s/include \$RULE_PATH/#include \$RULE_PATH/" $SNORT_CONF
            echo "include ${RULE_PATH}/local.rules" | sudo tee -a $SNORT_CONF
            check_error "Updating Snort rules path"
            update_checkpoint "Installing Snort"
            ;;
        "Installing Snort")

## Step : Download and install Snort rules
            log "Fetching latest Snort rules version..."
            RULES_VERSION=$(curl -s https://www.snort.org/downloads \
                | grep -oP 'snortrules-snapshot-29[0-9]{3}\.tar\.gz' \
                | grep -oP '[0-9]{5}' \
                | sort -nr \
                | head -n 1)
            check_error "Fetching Snort rules version"

            log "Latest Snort rules version is: $RULES_VERSION"

            log "Downloading Snort rules..."
            wget "https://www.snort.org/reg-rules/snortrules-snapshot-$RULES_VERSION.tar.gz/$OINK_CODE" -O ./snortrules.tar.gz
            check_error "Downloading Snort rules"

            log "Extracting Snort rules..."
            tar zxf snortrules.tar.gz
            check_error "Extracting Snort rules"

            sudo mv ./preproc_rules/ /etc/snort
            sudo mv ./so_rules/ /etc/snort
            sudo cp -r ./rules/ /etc/snort
            check_error "Moving Snort rules"

            log "Creating rules folders for Snort..."
            sudo touch ${RULE_PATH}/whitelist.rules
            check_error "Creating Snort rules folders"
            update_checkpoint "Fetching latest Snort rules"
            ;;
        "Fetching latest Snort rules")

## Step : Ensure oven is ready for PulledPork
            log "Installing prerequisites for PulledPork..."
            sudo apt-get install -y libcrypt-ssleay-perl liblwp-useragent-determined-perl
            check_error "Installing prerequisites for PulledPork"

            log "Fetching PulledPork version..."
            PULLEDPORK_VERSION=$(curl -s https://github.com/shirkdog/pulledpork/releases \
                | grep -oP 'href="/shirkdog/pulledpork/releases/tag/v[0-9]+\.[0-9]+\.[0-9]+"' \
                | grep -oP 'v[0-9]+\.[0-9]+\.[0-9]+' \
                | sort -V \
                | tail -n 1)
            check_error "Fetching PulledPork version"

## Step : Download and configure PulledPork
            log "Downloading PulledPork..."
            wget "https://www.github.com/shirkdog/pulledpork/archive/refs/tags/$PULLEDPORK_VERSION.tar.gz" -O ./pulledpork.tar.gz
            check_error "Downloading PulledPork"

            log "Extracting PulledPork..."
            sudo mkdir pulledpork
            sudo tar zxf "pulledpork.tar.gz" -C pulledpork --strip-components=1
            check_error "Extracting PulledPork"

            sudo chmod +x /home/${CON_NAME}/pulledpork/pulledpork.pl
            sudo cp /home/${CON_NAME}/pulledpork/pulledpork.pl /usr/local/bin
            sudo cp /home/${CON_NAME}/pulledpork/etc/*.conf /etc/snort
            check_error "Setting up PulledPork"
            update_checkpoint "Downloading PulledPork"
            ;;
        "Downloading PulledPork")

            log "Modifying PulledPork configuration..."
            sudo sed -i "s/^rule_url=https:\/\/www.snort.org\/reg-rules\/|snortrules-snapshot.tar.gz|<oinkcode>/rule_url=https:\/\/www.snort.org\/reg-rules\/|snortrules-snapshot.tar.gz|${OINK_CODE}/" /etc/snort/pulledpork.conf
            sudo sed -i "s|^rule_path=.*|rule_path=${RULE_PATH}|" /etc/snort/pulledpork.conf
            sudo sed -i "s|^# out_path=.*|out_path=${RULE_PATH}/|" /etc/snort/pulledpork.conf
            sudo sed -i "s|^local_rules=.*|local_rules=${RULE_PATH}/local.rules|" /etc/snort/pulledpork.conf
            sudo sed -i "s|^sid_msg=.*|sid_msg=/etc/snort/sid-msg.map|" /etc/snort/pulledpork.conf
            sudo sed -i "s|^sid_msg_version=.*|sid_msg_version=2|" /etc/snort/pulledpork.conf
            sudo sed -i "s|^sid_changelog=.*|sid_changelog=/var/log/sid_changes.log|" /etc/snort/pulledpork.conf
            sudo sed -i "s|^sorule_path=.*|sorule_path=/usr/local/lib/snort_dynamicrules/|" /etc/snort/pulledpork.conf
            sudo sed -i "s|^snort_path=.*|snort_path=/usr/sbin/snort|" /etc/snort/pulledpork.conf
            sudo sed -i "s|^config_path=.*|config_path=${SNORT_CONF}|" /etc/snort/pulledpork.conf
            sudo sed -i "s|^distro=.*|distro=Ubuntu-18-4|" /etc/snort/pulledpork.conf
            sudo sed -i "s|^IPRVersion=.*|IPRVersion=/etc/snort/rules|" /etc/snort/pulledpork.conf
            sudo sed -i "s|^block_list=.*|block_list=${RULE_PATH}/blacklist.rules|" /etc/snort/pulledpork.conf
            check_error "Modifying PulledPork configuration"

## Step : Pull the pork and taste
            log "Running PulledPork..."
            sudo /usr/local/bin/pulledpork.pl -T -c /etc/snort/pulledpork.conf -l
            check_error "Running PulledPork"
            update_checkpoint "Running PulledPork"
            ;;
        "Running PulledPork")

            log "Modifying snort.conf..."
            sudo sed -i '/^include \$RULE_PATH\/snort.rules$/d' ${SNORT_CONF}
            echo 'include $RULE_PATH/snort.rules' | sudo tee -a ${SNORT_CONF}
            sudo touch ${RULE_PATH}/local.rules
            check_error "Modifying snort.conf"

            log "Testing Snort configuration..."
            sudo snort -T -c ${SNORT_CONF} -i ${LOCAL_IF}
            check_error "Testing Snort configuration"
            update_checkpoint "Modifying PulledPork"
            ;;
        "Modifying PulledPork")

## Step : Add to crontab and set logrotate length
            log "Adding PulledPork to crontab..."
            (crontab -l 2>/dev/null; echo "$CRON_MINS $CRON_HOUR * * $CRON_DAY /usr/local/bin/pulledpork.pl -c /etc/snort/pulledpork.conf -l") | sudo crontab -
            check_error "Adding PulledPork to crontab"

            log "Updating /etc/logrotate.conf..."
            sudo sed -i '/rotate [0-9]*/c\rotate 12' /etc/logrotate.conf
            check_error "Updating /etc/logrotate.conf"
            update_checkpoint "Finished"
            ;;
        "Finished")

## Step : Cleanup and reboot
        restore_sudo_timeout
        rm $CHECKPOINT_FILE
        rm $TEMP_VAR_FILE
# Calculate the duration
        END_TIME=$(date +%s)
        DURATION=$((END_TIME - START_TIME))
        HOURS=$((DURATION / 3600))
        MINUTES=$(((DURATION % 3600) / 60))
        SECONDS=$((DURATION % 60))
        log "Installation script completed."
        log "Total time: $HOURS hours, $MINUTES minutes, and $SECONDS seconds."
        #sudo systemctl reboot -i
    esac
done
