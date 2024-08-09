#!/bin/bash

# Variables
CON_NAME=""
IP_ADDRESS=""
GATEWAY=""
SNORT_CONF="/etc/snort/snort.conf"
RULES_VERSION=""
OINK_CODE="3bec5be2c7c9652c036d98fcf5c82680cc0973c9"
PULLEDPORK_VERSION=""
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

# Function to display a message
display_message() {
    echo -e "\n#############################"
    echo "# $1"
    echo "#############################\n"
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

log "Starting setup..."

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

# Install Apache2
display_message "Installing Apache2..."
sudo apt install apache2 -y
check_error "Apache2 installation"

# Enable Apache2 to start on boot
display_message "Enabling Apache2 to start on boot..."
sudo systemctl enable apache2
check_error "Enabling Apache2 on boot"

# Start Apache2 service
display_message "Starting Apache2 service..."
sudo systemctl start apache2
check_error "Starting Apache2 service"

sudo rm /var/www/html/index.html

# Set up a basic HTML page
display_message "Setting up a basic HTML page..."
echo "<!DOCTYPE html>
<html>
<head>
    <title>Welcome to Your Apache Server!</title>
</head>
<body>
    <h1>It works!</h1>
    <p>This is the default web page for this server.</p>
    <p>The web server software is running but no content has been added yet.</p>
</body>
</html>" | sudo tee /var/www/html/index.html
check_error "Setting up HTML page"

# Adjust permissions
display_message "Adjusting permissions for /var/www/html..."
sudo chown -R www-data:www-data /var/www/html
sudo chmod -R 755 /var/www/html
check_error "Adjusting permissions"

# Restart Apache2 to apply changes
display_message "Restarting Apache2 to apply changes..."
sudo systemctl restart apache2
check_error "Restarting Apache2"

# Install and configure PHP
display_message "Installing PHP..."
sudo apt install php libapache2-mod-php -y
check_error "PHP installation"

echo "<?php phpinfo(); ?>" | sudo tee /var/www/html/info.php
check_error "Setting up PHP info page"

sudo systemctl restart apache2
check_error "Restarting Apache2 for PHP"

# Step 6: Modify /etc/sysctl.conf
log "Modifying /etc/sysctl.conf..."
sudo bash -c 'cat <<EOL >> /etc/sysctl.conf
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.ip_forward = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.eth0.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.eth0.send_redirects = 0
net.ipv4.all.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
vm.min_free_kbytes = 8192
EOL'
check_error "Modifying /etc/sysctl.conf"

sudo sysctl -p
check_error "Applying sysctl settings"

# Step 7: Install DNSmasq
log "Installing DNSmasq..."
sudo apt-get install dnsmasq -y
check_error "DNSmasq installation"

# Step 8: Modify /etc/dnsmasq.conf
log "Modifying /etc/dnsmasq.conf..."
sudo bash -c 'cat <<EOL >> /etc/dnsmasq.conf
domain-needed
bogus-priv
server=8.8.8.8
#interface=eth0
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

# Step 11: Install Snort
log "Installing Snort..."
sudo apt-get install snort -y
check_error "Snort installation"

# Step 12: Configure Snort
log "Backing up original Snort configuration..."
sudo cp $SNORT_CONF ${SNORT_CONF}.bak
check_error "Backing up Snort configuration"

log "Modifying Snort configuration..."
sudo sed -i -e 's/^#\(ipvar HOME_NET\) .*/\1 '"$GATEWAY"'/' \
           -e 's/^#\(ipvar EXTERNAL_NET\) .*/\1 !$HOME_NET/' \
           -e 's/^#\(ipvar DNS_SERVERS\) .*/\1 '"$IP_ADDRESS"'/' \
           -e 's/^#\(ipvar SSH_SERVERS\) .*/\1 '"$IP_ADDRESS"'/' \
           -e 's/^#\(portvar HTTP_PORTS\) .*/\1 80/' \
           -e 's/^#\(portvar SSH_PORTS\) .*/\1 [22,15507]/' \
           -e 's/^#\(config detection: search-method lowmem search-optimize max-pattern-len 20\)/\1/' \
           -e 's/^#\(config event_queue: max_queue 8 log 3 order_events content_length max_spaces 0 \\\)/\1/' \
           -e 's/^#\(preprocessor ssh: server_ports { 22 15507 } \\\)/\1/' $SNORT_CONF
check_error "Modifying Snort configuration"

# Modify whitelist and blacklist
log "Modifying whitelist and blacklist in Snort configuration..."
sudo sed -i -e 's/^#\(preprocessor reputation: \\\)/\1/' \
           -e 's/^#\(memcap 500, \\\)/\1/' \
           -e 's/^#\(priority whitelist, \\\)/\1/' \
           -e 's/^#\(nested_ip inner, \\\)/\1/' \
           -e 's/^#\(whitelist \$WHITE_LIST_PATH\/whitelist.rules, \\\)/\1/' \
           -e 's/^#\(blacklist \$BLACK_LIST_PATH\/blacklist.rules\)/\1/' $SNORT_CONF
check_error "Modifying whitelist and blacklist in Snort configuration"

log "Updating Snort rules path..."
sudo sed -i "s/include \$RULE_PATH/#include \$RULE_PATH/" $SNORT_CONF
echo "include $RULE_PATH/local.rules" | sudo tee -a $SNORT_CONF
check_error "Updating Snort rules path"

# Step 13: Download and install Snort rules
log "Fetching latest Snort rules version..."
RULES_VERSION=$(curl -s https://www.snort.org/downloads \
    | grep -oP 'snortrules-snapshot-29[0-9]{3}\.tar\.gz' \
    | grep -oP '[0-9]{5}' \
    | sort -nr \
    | head -n 1)
check_error "Fetching Snort rules version"

log "Latest Snort rules version starting with 29 is: $RULES_VERSION"

log "Downloading Snort rules..."
wget "https://www.snort.org/reg-rules/snortrules-snapshot-$RULES_VERSION.tar.gz/$OINK_CODE" -O ./snortrules.tar.gz
check_error "Downloading Snort rules"

log "Extracting Snort rules..."
tar zxpvf snortrules.tar.gz
check_error "Extracting Snort rules"

sudo mv ./preproc_rules/ /etc/snort
sudo mv ./so_rules/ /etc/snort
sudo cp -r ./rules/ /etc/snort
check_error "Moving Snort rules"

# Step 14: Create rules folders for Snort
log "Creating rules folders for Snort..."
sudo touch /etc/snort/rules/whitelist.rules
check_error "Creating Snort rules folders"

# Step 15: Ensure prerequisites are installed for PulledPork
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

# Step 16: Download and configure PulledPork
log "Downloading PulledPork..."
wget "https://www.github.com/shirkdog/pulledpork/archive/refs/tags/$PULLEDPORK_VERSION.tar.gz" -O ./pulledpork.tar.gz
check_error "Downloading PulledPork"

log "Extracting PulledPork..."
tar xzpf "pulledpork.tar.gz"
check_error "Extracting PulledPork"

sudo mv pull* pulledpork
sudo chmod +x pulledpork/pulledpork.pl
sudo cp pulledpork/pulledpork.pl /usr/local/bin
sudo cp pulledpork/etc/*.conf /etc/snort
check_error "Setting up PulledPork"

log "Modifying PulledPork configuration..."
sudo sed -i "s|^rule_url=.*|rule_url=https://www.snort.org/reg-rules/snortrules-snapshot.tar.gz|$OINK_CODE|" /etc/snort/pulledpork.conf
sudo sed -i "s|^rule_path=.*|rule_path=/etc/snort/rules/snort.rules|" /etc/snort/pulledpork.conf
sudo sed -i "s|^out_path=.*|out_path=/etc/snort/rules/|" /etc/snort/pulledpork.conf
sudo sed -i "s|^local_rules=.*|local_rules=/etc/snort/rules/local.rules|" /etc/snort/pulledpork.conf
sudo sed -i "s|^sid_msg=.*|sid_msg=/etc/snort/sid-msg.map|" /etc/snort/pulledpork.conf
sudo sed -i "s|^sid_msg_version=.*|sid_msg_version=2|" /etc/snort/pulledpork.conf
sudo sed -i "s|^sid_changelog=.*|sid_changelog=/var/log/sid_changes.log|" /etc/snort/pulledpork.conf
sudo sed -i "s|^sorule_path=.*|sorule_path=/usr/local/lib/snort_dynamicrules/|" /etc/snort/pulledpork.conf
sudo sed -i "s|^snort_path=.*|snort_path=/usr/sbin/snort|" /etc/snort/pulledpork.conf
sudo sed -i "s|^config_path=.*|config_path=/etc/snort/snort.conf|" /etc/snort/pulledpork.conf
sudo sed -i "s|^distro=.*|distro=Ubuntu-18-4|" /etc/snort/pulledpork.conf
sudo sed -i "s|^block_list=.*|block_list=/etc/snort/rules/blacklist.rules|" /etc/snort/pulledpork.conf
sudo sed -i "s|^IPRVersion=.*|IPRVersion=/etc/snort/rules/|" /etc/snort/pulledpork.conf
sudo sed -i "s|^Snort_control=.*|Snort_control=/usr/local/bin/snort_control|" /etc/snort/pulledpork.conf
sudo sed -i "s|^Version=.*|Version=$PULLEDPORK_VERSION|" /etc/snort/pulledpork.conf
check_error "Modifying PulledPork configuration"

log "Creating swap file..."
sudo dd if=/dev/zero of=/swapfile.img bs=4M count=256
sudo mkswap /swapfile.img
sudo chmod 600 /swapfile.img
sudo swapon /swapfile.img
check_error "Creating and enabling swap file"

log "Running PulledPork..."
sudo /usr/local/bin/pulledpork.pl -T -c /etc/snort/pulledpork.conf -l
check_error "Running PulledPork"

# Step 17: Modify snort.conf again
log "Modifying snort.conf..."
sudo sed -i '/^include \$RULE_PATH\/snort.rules$/d' /etc/snort/snort.conf
echo 'include $RULE_PATH/snort.rules' | sudo tee -a /etc/snort/snort.conf
check_error "Modifying snort.conf"

log "Testing Snort configuration..."
sudo snort -T -c /etc/snort/snort.conf -i eth0
check_error "Testing Snort configuration"

# Step 18: Add to crontab to run automatically
log "Adding PulledPork to crontab..."
(crontab -l 2>/dev/null; echo "$CRON_MINS $CRON_HOUR * * $CRON_DAY /usr/local/bin/pulledpork.pl -c /etc/snort/pulledpork.conf -l") | sudo crontab -
check_error "Adding PulledPork to crontab"

log "Updating /etc/logrotate.conf..."
sudo sed -i '/rotate [0-9]*/c\rotate 12' /etc/logrotate.conf
check_error "Updating /etc/logrotate.conf"

log "Setup complete."
