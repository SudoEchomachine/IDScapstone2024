#!/bin/bash

# Variables
CON_NAME="shelter"
IP_ADDRESS="192.168.100.3"
GATEWAY="192.168.100.0/24"
SNORT_CONF="/etc/snort/snort.conf"
#RULES_VERSION="<version>"
OINK_CODE="3bec 5be2 c7c9 652c 036d 98fc f5c8 2680 cc09 73c9"
#PULLEDPORK_VERSION="0.7.4"
CRON_MINS="22"
CRON_HOUR="17"
CRON_DAY="0" #0-7 for sunday through saturday respectively

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

log "Starting setup..."

# Step 2: Update and upgrade
log "Updating and upgrading system..."
sudo apt update && sudo apt upgrade -y
check_error "System update and upgrade"

# Step 3: Install NetworkManager
log "Installing NetworkManager..."
sudo apt-get install network-manager -y
check_error "NetworkManager installation"

add apache2 install and config here

# Step 5: Create pass-through connection
log "Creating pass-through connection..."
sudo nmcli c add con-name "$CON_NAME" type ethernet ifname eth0 ipv4.method share ipv6.method ignore
check_error "Adding NetworkManager connection"

sudo nmcli c mod "$CON_NAME" ipv4.addresses "$IP_ADDRESS/24"
check_error "Modifying NetworkManager connection"

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
interface=eth0
listen-address=$IP_ADDRESS
bind-interfaces
dhcp-range=$IP_ADDRESS,$IP_ADDRESS,12h
dhcp-authoritative
cache-size=300
dns-forward-max=150
EOL'
check_error "Modifying /etc/dnsmasq.conf"

sudo systemctl enable dnsmasq.service
check_error "Enabling DNSmasq service"

if fail, stop and disable systemd-resolved?
	sudo systemctl stop systemd-resolved
	sudo systemctl disable systemd-resolved
	sudo systemctl mask systemd-resolved
	
# Step 9: Download firewall scripts to /etc
#log "Downloading firewall scripts..."
# Example: wget <URL_to_firewall_script> -O /etc/firewall.sh
# Uncomment the below line and add the actual URL
# wget <URL_to_firewall_script> -O /etc/firewall.sh
# check_error "Downloading firewall script"

# Step 10: Execute firewall setup scripts
#log "Executing firewall setup scripts..."
#sudo chmod u+x /etc/firewall.*
#check_error "Changing permissions for firewall scripts"

#sudo bash /etc/firewall.sh
#check_error "Executing firewall script"

# Step 11: Install Snort
log "Installing Snort..."
sudo apt-get install snort -y
check_error "Snort installation"

# Step 12: configure Snort
# Backup the original file
cp $SNORT_CONF ${SNORT_CONF}.bak (backup all conf files?)

# Uncomment and replace the lines
sed -i -e 's/^#\(ipvar HOME_NET\) .*/\1 '"$GATEWAY"'/' \
       -e 's/^#\(ipvar EXTERNAL_NET\) .*/\1 !$HOME_NET/' \
       -e 's/^#\(ipvar DNS_SERVERS\) .*/\1 '"$IP_ADDRESS"'/' \
       -e 's/^#\(ipvar SSH_SERVERS\) .*/\1 '"$IP_ADDRESS"'/' \
       -e 's/^#\(portvar HTTP_PORTS\) .*/\1 80/' \
       -e 's/^#\(portvar SSH_PORTS\) .*/\1 [22,15507]/' \
       -e 's/^#\(config detection: search-method lowmem search-optimize max-pattern-len 20\)/\1/' \
       -e 's/^#\(config event_queue: max_queue 8 log 3 order_events content_length max_spaces 0 \\\)/\1/' \
       -e 's/^#\(preprocessor ssh: server_ports { 22 15507 } \\\)/\1/' $SNORT_CONF

# Modify whitelist and blacklist
sed -i -e 's/^#\(preprocessor reputation: \\\)/\1/' \
       -e 's/^#\(memcap 500, \\\)/\1/' \
       -e 's/^#\(priority whitelist, \\\)/\1/' \
       -e 's/^#\(nested_ip inner, \\\)/\1/' \
       -e 's/^#\(whitelist \$WHITE_LIST_PATH\/whitelist.rules, \\\)/\1/' \
       -e 's/^#\(blacklist \$BLACK_LIST_PATH\/blacklist.rules\)/\1/' $SNORT_CONF

# Uncomment and comment specific rules
sed -i -e 's/^#\(include \$RULE_PATH\/botnet-cnc.rules\)/\1/' \
       -e 's/^#\(include \$RULE_PATH\/phishing-spam.rules\)/\1/' \
       -e 's/^include \$RULE_PATH\/rservices.rules/#\0/' \
       -e 's/^#\(include \$RULE_PATH\/shellcode.rules\)/\1/' \
       -e 's/^include \$RULE_PATH\/snmp.rules/#\0/' \
       -e 's/^#\(include \$RULE_PATH\/specific-threats.rules\)/\1/' \
       -e 's/^#\(include \$RULE_PATH\/spyware-put.rules\)/\1/' \
       -e 's/^include \$RULE_PATH\/sql.rules/#\0/' \
       -e 's/^include \$RULE_PATH\/tftp.rules/#\0/' \
       -e 's/^include \$RULE_PATH\/web-activex.rules/#\0/' \
       -e 's/^include \$RULE_PATH\/web-attacks.rules/#\0/' \
       -e 's/^include \$RULE_PATH\/web-cgi.rules/#\0/' \
       -e 's/^include \$RULE_PATH\/web-coldfusion.rules/#\0/' \
       -e 's/^include \$RULE_PATH\/web-frontpage.rules/#\0/' \
       -e 's/^include \$RULE_PATH\/web-iis.rules/#\0/' \
       -e 's/^include \$RULE_PATH\/web-misc.rules/#\0/' \
       -e 's/^include \$RULE_PATH\/web-php.rules/#\0/' \
       -e 's/^include \$RULE_PATH\/x11.rules/#\0/' $SNORT_CONF

# Confirm changes
echo "Updated $SNORT_CONF with the new variables, uncommented, and commented specific rules."

# Step 13: Download and install Snort rules

# Get latest Snort rules version starting with 29
log "Fetching latest Snort rules version..."
RULES_VERSION=$(curl -s https://www.snort.org/downloads \
    | grep -oP 'snortrules-snapshot-29[0-9]{3}\.tar\.gz' \
    | grep -oP '[0-9]{5}' \
    | sort -nr \
    | head -n 1)
check_error "fetching Snort rules version"

log "Latest Snort rules version starting with 29 is: $RULES_VERSION"

log "Downloading Snort rules..."
wget "https://www.snort.org/reg-rules/snortrules-snapshot-$RULES_VERSION.tar.gz/$OINK_CODE" -O ./snortrules.tar.gz
#wget -qO- https://www.snort.org/downloads | grep -oP 'snortrules-snapshot-\K[0-9.]+(?=.tar.gz)' | head -n 1
check_error "Downloading Snort rules"

log "Extracting Snort rules..."
tar zxpvf snortrules.tar.gz
check_error "Extracting Snortrules"

sudo mv ./preproc_rules/ /etc/snort
sudo mv ./so_rules/ /etc/snort
sudo cp -r ./rules/ /etc/snort
check_error "Moving Snort rules"

# Step 14: Create rules folders for Snort
log "Creating rules folders for Snort..."
sudo touch /etc/snort/rules/whitelist.rules
#sudo touch /etc/snort/rules/black_list.rules
#sudo mkdir -p /etc/snort
check_error "Creating Snort rules folders"

# Step 15: Ensure prerequisites are installed for PulledPork
log "Installing prerequisites..."
sudo apt-get install -y libcrypt-ssleay-perl liblwp-useragent-determined-perl
check_error "Installing prerequisites"

PULLEDPORK_VERSION=$(curl -s https://github.com/shirkdog/pulledpork/releases \
    | grep -oP 'href="/shirkdog/pulledpork/releases/tag/v[0-9]+\.[0-9]+\.[0-9]+"' \
    | grep -oP 'v[0-9]+\.[0-9]+\.[0-9]+' \
    | sort -V \
    | tail -n 1)

# Step 16: Download and configure PulledPork
log "Downloading PulledPork..."
wget "https://www.github.com/shirkdog/pulledpork/archive/refs/tags/$PULLEDPORK_VERSION.tar.gz" -O ./pulledpork.tar.gz
check_error "Downloading PulledPork"

log "Extracting PulledPork..."
tar xzpf "pulledpork.tar.gz"
check_error "Extracting PulledPork"

#cd "pulledpork-$PULLEDPORK_VERSION"
sudo mv pull* pulledpork
sudo chmod +x pulledpork/pulledpork.pl
sudo cp pulledpork/pulledpork.pl /usr/local/bin
sudo cp pulledpork/etc/*.conf /etc/snort
check_error "Setting up PulledPork"

# Modify pulledpork.conf
log "Modifying pulledpork.conf..."
sudo sed -i "s|^rule_url=.*|rule_url=https://www.snort.org/reg-rules/|snortrules-snapshot.tar.gz|$OINK_CODE|" /etc/snort/pulledpork.conf
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
check_error "Modifying pulledpork.conf"

log "Running PulledPork..."
sudo /usr/local/bin/pulledpork.pl -c /etc/snort/pulledpork.conf -l
check_error "Running PulledPork"
# or
# sudo /usr/local/bin/pulledpork.pl -k -c /etc/snort/pulledpork.conf -K /etc/snort/rules -o /etc/snort/rules

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

log "Setup complete."
