## Basic new user script    ##
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

# Function to prompt for a new username and create the user
create_new_user() {
read -p "Enter the username for the new user: " NEW_USER
sudo adduser "$NEW_USER"
sudo usermod -aG sudo "$NEW_USER"
sudo cp -r /home/$(whoami)/. /home/$NEW_USER/
sudo chown $NEW_USER:$NEW_USER /home/$NEW_USER/
su $NEW_USER
    
if [ $? -eq 0 ]; then
    echo "User $NEW_USER has been created."
else
    echo "Failed to create the user $NEW_USER."
    exit 1
fi
}

# Function to delete the default user
delete_default_user() {
read -p "Enter the username of the default user to delete: " DEFAULT_USER
# Double-check with the user before deleting
read -p "Are you sure you want to delete the user $DEFAULT_USER? This cannot be undone! (y/n): " CONFIRM
    
if [[ "$CONFIRM" =~ ^[Yy]$ ]]; then
    sudo deluser --remove-home "$DEFAULT_USER"
    if [ $? -eq 0 ]; then
        echo "User $DEFAULT_USER has been deleted."
    else
        echo "Failed to delete the user $DEFAULT_USER."
        exit 1
    fi
else
        echo "User deletion cancelled."
fi
}
create_new_user
read -p "Do you want to delete the default user? (y/n): " DELETE_DEFAULT
if [[ "$DELETE_DEFAULT" =~ ^[Yy]$ ]]; then
    delete_default_user
else
    echo "Default user was not deleted."
fi
sudo systemctl reboot -i