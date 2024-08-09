#!/bin/bash

# Variables
CON_NAME=""
IP_ADDRESS=""
GATEWAY=""
SNORT_CONF="/etc/snort/snort.conf"
RULES_VERSION=""
OINK_CODE=""
PULLEDPORK_VERSION=""
CRON_MINS=$((RANDOM % 61))
CRON_HOUR=$((RANDOM % 24))
CRON_DAY=$((RANDOM % 7)) # 0-6 for Sunday through Saturday respectively
LOG_FILE="/var/log/MobileIPS.log"

# Function to validate IP address format
validate_ip() {
    local ip="$1"
    local valid_ip_regex="^([0-9]{1,3}\.){3}[0-9]{1,3}$"
    if [[ $ip =~ $valid_ip_regex ]]; then
		#IFS='.' read -r -a octets <<< "$ip"
        #for octet in "${octets[@]}"; do
        for octet in $(echo $ip | tr '.' ' '); do
            if ((octet < 0 || octet > 255)); then
                return 1
            fi
        done
		 # Ensure that the last octet is not 0 for a general IP address (unless it's the gateway)
        #if [[ "${octets[3]}" -eq 0 ]]; then
         #   return 1
        #fi
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
        read ip_variable
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
    echo "[`date +'%Y-%m-%d %H:%M:%S'`] $1" >> "$LOG_FILE"
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

# Function to confirm variable values with the user
confirm_variables() {
    local prompt_message="$1"
    local variable_list=("${!2}")

    while true; do
        # Display the current values of the variables
        echo -e "\nCurrent values:"
        for var in "${variable_list[@]}"; do
            echo "$var: ${!var}"
        done

        # Ask the user to confirm
        echo -n "$prompt_message (yes/no): "
        read confirmation

        if [[ "$confirmation" == "yes" ]]; then
            # User confirmed the values
            break
        else
            # User did not confirm, clear variables and re-prompt
            echo "Let's re-enter the values."

            # Clear variables
            for var in "${variable_list[@]}"; do
                unset "$var"
            done

            # Re-prompt user to enter values
            for var in "${variable_list[@]}"; do
                if [[ "$var" == "IP_ADDRESS" ]]; then
                    eval "$var=$(get_ip_input 'Please enter the new IP address\nX.X.X.0 is reserved for the gateway: ')"
                    eval "GATEWAY=\"\${$var%.*}.0/24\""
                else
                    eval "$var=$(get_user_input 'Enter the $var: ')"
                fi
            done
        fi
    done
}

log "Starting setup..."

# Step 2: Update and upgrade
display_message "Updating and upgrading the system..."
log "Updating and upgrading system..."
sudo apt update && sudo apt upgrade -y
check_error "System update and upgrade"

# Step 3: Install NetworkManager
display_message "Installing NetworkManager..."
log "Installing NetworkManager..."
sudo apt-get install network-manager -y
check_error "NetworkManager installation"

display_message "Installing awk..."
log "Installing awk..."
sudo apt-get install awk -y
check_error "awk installation"

# Get user input
CON_NAME=$(get_user_input "Enter the desired connection name: ")

OINK_CODE=$(get_user_input "Enter your OINK code: \nSignup at snort.org to get one")

# Prompt the user for the new IP address
IP_ADDRESS=$(get_ip_input "Please enter desired IP address\nX.X.X.0 is reserved for the gateway: ")

confirm_variables "Are these values correct?" "CON_NAME OINK_CODE IP_ADDRESS GATEWAY"

GATEWAY="${IP_ADDRESS%.*}.0/24"
DHCP_LEASE_END=$(echo "$IP_ADDRESS" | awk -F. '{print $1"."$2"."$3"."($4+100)}')

# Step 5: Create pass-through connection
display_message "Configuring NetworkManager connection..."
log "Creating pass-through connection..."
sudo nmcli c add con-name "$CON_NAME" type ethernet ifname eth0 ipv4.method share ipv6.method ignore
check_error "Adding NetworkManager connection"

sudo nmcli c mod "$CON_NAME" ipv4.addresses "$IP_ADDRESS/24"
check_error "Modifying NetworkManager connection"

sudo nmcli c up "$CON_NAME"
check_error "Bringing up NetworkManager connection"

# Install Apache2
display_message "Installing Apache2"
log "Installing Apache2..."
sudo apt install apache2 -y
check_error "Apache2 installation"

# Enable Apache2 to start on boot
display_message "Configuring Apache2..."
log "Enabling Apache2 to start on boot..."
sudo systemctl enable apache2
check_error "Enabling Apache2"

# Start Apache2 service
log "Starting Apache2 service..." 
sudo systemctl start apache2
check_error "Starting Apache2"

# Set up a basic HTML page
log "Setting up a basic HTML page..."
sudo rm /var/www/html/index.html
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

# Adjust permissions
log "Adjusting permissions for /var/www/html..."
sudo chown -R www-data:www-data /var/www/html
sudo chmod -R 755 /var/www/html
check_error "Adjusting permissions for /var/www/html"

# Restart Apache2 to apply changes
log "Restarting Apache2 to apply changes..."
sudo systemctl restart apache2
check_error "Restarting Apache2"

# Provide the user with the IP address to access the server
display_message "Apache2 setup is complete!"
echo "You can access your web server at: http://$IP_ADDRESS"

# Install and configure PHP
display_message "Installing PHP..."
log "Installing PHP..."
sudo apt install php libapache2-mod-php -y
check_error "PHP installation"

echo "<?php phpinfo(); ?>" | sudo tee /var/www/html/info.php
log "Restarting Apache2 after PHP installation"
sudo systemctl restart apache2
check_error "Restarting Apache2 after PHP installation"

echo "PHP has been installed. You can view the PHP info page at: http://$IP_ADDRESS/info.php"

# Step 6: Modify /etc/sysctl.conf
display_message "Modifying sysctl.conf..."
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

log "Applying sysctl settings"
sudo sysctl -p
check_error "Applying sysctl settings"

# Step 7: Install DNSmasq
display_message "Installing DNSmasq..."
log "Installing DNSmasq..."
sudo apt-get install dnsmasq -y
check_error "DNSmasq installation"

# Step 8: Modify /etc/dnsmasq.conf
display_message "Modifying dnsmasq.conf..."
log "Modifying /etc/dnsmasq.conf..."
sudo bash -c "cat <<EOL >> /etc/dnsmasq.conf
domain-needed
bogus-priv
server=8.8.8.8
bind-interfaces
dhcp-range=$IP_ADDRESS,$DHCP_LEASE_END,12h
dhcp-authoritative
cache-size=300
dns-forward-max=150
EOL"
check_error "Modifying /etc/dnsmasq.conf"

display_message "Enabling DNSmasq"
log "Enabling DNSmasq service"
sudo systemctl enable dnsmasq.service
check_error "Enabling DNSmasq service"

# Step 11: Install Snort
display_message "Installing Snort..."
log "Installing Snort..."
sudo apt-get install snort -y
check_error "Snort installation"

# Step 12: Configure Snort
display_message "Configuring Snort..."
log "Configuring Snort..."

# Backup the original configuration file
log "Backing up Snort configuration"
sudo cp $SNORT_CONF ${SNORT_CONF}.bak
check_error "Backing up Snort configuration"

# Uncomment and replace the lines
log "Modifying /etc/snort/snort.conf"
sudo sed -i -e 's/^#\(ipvar HOME_NET\) .*/\1 '"$GATEWAY"'/' \
       -e 's/^#\(ipvar EXTERNAL_NET\) .*/\1 !$HOME_NET/' \
       -e 's/^#\(ipvar DNS_SERVERS\) .*/\1 '"$IP_ADDRESS"'/' \
       -e 's/^#\(ipvar SSH_SERVERS\) .*/\1 '"$IP_ADDRESS"'/' \
       -e 's/^#\(portvar HTTP_PORTS\) .*/\1 80/' \
       -e 's/^#\(portvar SSH_PORTS\) .*/\1 [22,15507]/' \
       -e 's/^#\(config detection: search-method lowmem search-optimize max-pattern-len 20\)/\1/' \
       -e 's/^#\(config event_queue: max_queue 8 log 3 order_events content_length max_spaces 0 \\\)/\1/' \
       -e 's/^#\(preprocessor ssh: server_ports { 22 15507 } \\\)/\1/' $SNORT_CONF
check_error "Configuring Snort"

# Modify whitelist and blacklist
sudo sed -i -e 's/^#\(preprocessor reputation: \\\)/\1/' \
       -e 's/^#\(memcap 500, \\\)/\1/' \
       -e 's/^#\(priority whitelist, \\\)/\1/' \
       -e 's/^#\(nested_ip inner, \\\)/\1/' \
       -e 's/^#\(whitelist \$WHITE_LIST_PATH\/whitelist.rules, \\\)/\1/' \
       -e 's/^#\(blacklist \$BLACK_LIST_PATH\/blacklist.rules\)/\1/' $SNORT_CONF
check_error "Modifying Snort whitelist and blacklist"

# Comment out the old rules and include the new rules path
sudo sed -i "s/include \$RULE_PATH/#include \$RULE_PATH/" /etc/snort/snort.conf
echo "include \$RULE_PATH/local.rules" | sudo tee -a /etc/snort/snort.conf
check_error "Updating Snort configuration with local rules"

# Step 13: Download and install Snort rules
display_message "Fetching latest Snort rules..."
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

display_message "Configuring Snort rules..."
log "Moving Snort rules"
sudo mv ./preproc_rules/ /etc/snort
sudo mv ./so_rules/ /etc/snort
sudo cp -r ./rules/ /etc/snort
check_error "Moving Snort rules"

# Step 14: Create rules folders for Snort
log "Creating rules folders for Snort..."
sudo touch /etc/snort/rules/whitelist.rules
check_error "Creating Snort rules folders"

# Step 15: Ensure prerequisites are installed for PulledPork
display_message "Installing prerequisites for PulledPork..."
log "Installing prerequisites for PulledPork..."
sudo apt-get install -y libcrypt-ssleay-perl liblwp-useragent-determined-perl
check_error "Installing PulledPork prerequisites"


display_message "Fetching PulledPork"
log "Fetching PulledPork version"
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

log "Pulling the Pork..."
tar xzpf pulledpork.tar.gz
check_error "Extracting PulledPork"

display_message "Configuring PulledPork"
log "Moving pulledpork files..."
sudo mv pulledpork-* pulledpork
sudo chmod +x pulledpork/pulledpork.pl
sudo cp pulledpork/pulledpork.pl /usr/local/bin
sudo cp pulledpork/etc/*.conf /etc/snort
check_error "Setting up PulledPork"

# Modify pulledpork.conf
log "Modifying pulledpork.conf..."
sudo sed -i "s|^rule_url=.*|rule_url=https://www.snort.org/reg-rules/snortv2-current.tar.gz|$OINK_CODE|" /etc/snort/pulledpork.conf
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

# Create a swap file
display_message "Creating a swap file..."
log "Creating a swap file..."
sudo dd if=/dev/zero of=/swapfile.img bs=4M count=256
sudo mkswap /swapfile.img
sudo chmod 600 /swapfile.img
sudo swapon /swapfile.img
check_error "Creating swap file"

# Run PulledPork
display_message "starting PulledPork"
log "Running PulledPork..."
sudo /usr/local/bin/pulledpork.pl -T -c /etc/snort/pulledpork.conf -l
check_error "Running PulledPork"

# Step 17: Modify snort.conf again
log "Modifying snort.conf, again..."
sudo sed -i '/^include \$RULE_PATH\/snort.rules$/d' /etc/snort/snort.conf
echo 'include $RULE_PATH/snort.rules' | sudo tee -a /etc/snort/snort.conf
check_error "Modifying snort.conf"

# Test Snort configuration
log "Testing Snort configuration..."
sudo snort -T -c /etc/snort/snort.conf -i eth0
check_error "Testing Snort configuration"

# Step 18: Add PulledPork to crontab
display_message "Adding PulledPork to crontab..."
log "Adding PulledPork to crontab..."
(crontab -l 2>/dev/null; echo "$CRON_MINS $CRON_HOUR * * $CRON_DAY /usr/local/bin/pulledpork.pl -c /etc/snort/pulledpork.conf -l") | sudo crontab -
check_error "Adding PulledPork to crontab"

# Update logrotate configuration
display_message "Updating /etc/logrotate.conf..."
log "Updating /etc/logrotate.conf..."

# Modify the logrotate.conf file
sudo sed -i '/rotate [0-9]*/c\rotate 12' /etc/logrotate.conf
check_error "Updating logrotate.conf"

display_message "Setup complete!"