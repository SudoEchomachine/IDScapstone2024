# IDScapstone2024

An intrusion detection system built for raspberry pi hardware. 

Created for Information System Security capstone project 

August 2024

In association with:

    Liam MacLeod

    Ayodeji Ogunlana
    
    Declan Campbell

Original project was made using Raspberry Pi 3b and 5, Based on the Ubuntu Server 24.04 
OS. 

This project uses open-source software


Installation:

Choose an option:

        1. Bash script install. allows for full customization including OS.

            Requires installed OS

            Download bash install script & NetworkConnect.sh

            Run install script on first boot

            Run NetworkConnect.sh when accessing a new network

        2. Ubuntu image self install. allows for partial customization.

            Run install script on first boot

            Run NetworkConnect.sh when accessing a new network

            Run NewUserSetup.sh on first boot

        3. Ubuntu image no install. No customization options.

            Run NewUserSetup.sh on first boot

            Run 'sudo apt update && sudo apt upgrade -y'


Fill in user prompts as desired

Use a hotspot on your phone for initial install and to make connecting to future networks easier via SSH

IP address X.X.X.0 is reserved for Network purposes

Sign up at www.snort.org to get your oink code.

Select yes, then no when prompted to save IPtable rules

Delete entry when prompted for Address range, then hit ok.

Reboot when done. Screen and keyboard are only necessary for intial setup.

Alert site (WIP) can be accessed at the first ip address found by using command 'hostname -I'

        

Default login credentials

user: shelter

pass: truffle
