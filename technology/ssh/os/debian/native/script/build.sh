#!/usr/bin/env bash

# ============================================================ #
# Tool Created date: 11 jan 2023                               #
# Tool Created by: Henrique Silva (rick.0x00@gmail.com)        #
# Tool Name: ssh Install                                       #
# Description: My simple script to provision ssh Server        #
# License: software = MIT License | hardware = apache          #
# Remote repository 1: https://github.com/rick0x00/srv_ssh     #
# Remote repository 2: https://gitlab.com/rick0x00/srv_ssh     #
# ============================================================ #
# base content:
#   

# ============================================================ #
# start root user checking
if [ $(id -u) -ne 0 ]; then
    echo "Please use root user to run the script."
    exit 1
fi
# end root user checking
# ============================================================ #
# start set variables

DATE_NOW="$(date +Y%Ym%md%d-H%HM%MS%S)" # extracting date and time now

os_distribution="Debian"
os_version=("11" "bullseye")

port_ssh[0]="22" # ssh number Port
port_ssh[1]="tcp" # ssh protocol Port 

build_path="/usr/local/src"
workdir="/etc/ssh/"
persistence_volumes=("/etc/ssh/" "/var/log/")
expose_ports="${port_ssh[0]}/${port_ssh[1]}}"
# end set variables
# ============================================================ #
# start definition functions
# ============================== #
# start complement functions

function remove_space_from_beginning_of_line {
    #correct execution
    #remove_space_from_beginning_of_line "<number of spaces>" "<file to remove spaces>"

    # Remove a white apace from beginning of line
    #sed -i 's/^[[:space:]]\+//' "$1"
    #sed -i 's/^[[:blank:]]\+//' "$1"
    #sed -i 's/^ \+//' "$1"

    # check if 2 arguments exist
    if [ $# -eq 2 ]; then
        #echo "correct quantity of args"
        local spaces="${1}"
        local file="${2}"
    else
        #echo "incorrect quantity of args"
        local spaces="4"
        local file="${1}"
    fi 
    sed -i "s/^[[:space:]]\{${spaces}\}//" "${file}"
}

function massager_sharp() {
    line_divisor="###########################################################################################"
    echo "${line_divisor}"
    echo "$*"
    echo "${line_divisor}"
}

function massager_line() {
    line_divisor="-------------------------------------------------------------------------------------------"
    echo "${line_divisor}"
    echo "$*"
    echo "${line_divisor}"
}

function massager_plus() {
    line_divisor="++++++++++++++++++++++++++++++++++++++++++++++++++"
    echo "${line_divisor}"
    echo "$*"
    echo "${line_divisor}"
}

# end complement functions
# ============================== #
# start main functions

function pre_install_server () {
    massager_line "Pre install server step"

    function install_generic_tools() {
        # update repository
        apt update

        #### start generic tools
        # install basic network tools
        apt install -y net-tools iproute2 traceroute iputils-ping mtr
        # install advanced network tools
        apt install -y tcpdump nmap netcat
        # install DNS tools
        apt install -y dnsutils
        # install process inspector
        apt install -y procps htop
        # install text editors
        apt install -y nano vim 
        # install web-content downloader tools
        apt install -y wget curl
        # install uncompression tools
        apt install -y unzip tar
        # install file explorer with CLI
        apt install -y mc
        # install task scheduler 
        apt install -y cron
        # install log register 
        apt install -y rsyslog
        #### stop generic tools
    }

    function install_dependencies () {
        massager_plus "Install Dependencies"
        apt install -y libssh2-1
    }

    function install_complements () {
        echo "step not necessary"
        exit 1;
    }

    install_generic_tools
    install_dependencies;
    #install_complements;
}

##########################
## install steps

function install_ssh () {
    # installing ssh
    massager_plus "Installing ssh"

    function install_from_source () {
        # Installing from Source
        echo "step not configured"
        exit 1;
    }

    function install_from_apt () {
        # Installing from APT
        massager_plus " Installing from APT"
        apt install -y openssh-server openssh-client openssh-sftp-server 
    }

    ## Installing ssh From Source ##
    #install_from_source

    ## Installing ssh From APT (Debian package manager) ##
    install_from_apt
}
#############################

function install_server () {
    massager_line "Install server step"

    ##  ssh
    install_ssh
}

#############################
## start/stop steps ##

function start_ssh () {
    # starting ssh
    massager_plus "Starting ssh"

    #service ssh start
    #systemctl start sshd
    /etc/init.d/ssh start

    # Daemon running on foreground mode
    #/usr/sbin/sshd -ddd
}

function stop_ssh () {
    # stopping ssh
    massager_plus "Stopping ssh"

    #service ssh stop
    #systemctl stop sshd
    /etc/init.d/ssh stop

    # ensuring it will be stopped
    # for Daemon running on foreground mode
    killall ssh
}

################################

function start_server () {
    massager_line "Starting server step"
    # Starting Service

    # starting ssh
    start_ssh
}

function stop_server () {
    massager_line "Stopping server step"

    # stopping server
    stop_ssh
}

################################
## configuration steps ##
function configure_ssh() {
    # Configuring ssh
    massager_plus "Configuring ssh"

    local port_ssh="${port_ssh:-22}"


    function configure_ssh_security() {
        # Configuring ssh Security
        massager_plus "Configuring ssh Security"

        echo "Setting: Disable banner..."
        echo "DebianBanner no" > /etc/ssh/sshd_config.d/banner.conf
        echo "Banner none" >> /etc/ssh/sshd_config.d/banner.conf
        echo "VersionAddendum none" >> /etc/ssh/sshd_config.d/banner.conf

        echo "Setting: no password autehtication..."
        echo "PasswordAuthentication no" > /etc/ssh/sshd_config.d/auth.conf

        echo "Setting: no permit root..."
        echo "PermitRootLogin no" > /etc/ssh/sshd_config.d/root_login.conf

        echo "Setting: strict SSH client(any} for IP/NET(RFC 1918)..."
        echo "AllowUsers *@10.0.0.0/8" > /etc/ssh/sshd_config.d/allow_user.conf
        echo "AllowUsers *@172.16.0.0/12 " >> /etc/ssh/sshd_config.d/allow_user.conf
        echo "AllowUsers *@192.168.0.0/16" >> /etc/ssh/sshd_config.d/allow_user.conf

    }

    function configure_ssh_configs() {
        # Configuring ssh 
        massager_plus "Configuring ssh"

        # configure 
        echo "Setting: SSH port..."
        echo "Port ${port_ssh}" > /etc/ssh/sshd_config.d/linten_port.conf

    }

    # configuring security on ssh
    configure_ssh_security

    # setting ssh site
    configure_ssh_configs
}

################################

function configure_server () {
    # configure server
    massager_line "Configure server"

    # configure ssh 
    configure_ssh
}

################################
## check steps ##

function check_configs_ssh() {
    # Check config of ssh
    massager_plus "Check config of ssh"

    /usr/sbin/sshd -t 
}

#####################

function check_configs () {
    massager_line "Check Configs server"

    # check if the configuration file is ok.
    check_configs_ssh

}

################################
## test steps ##

function test_ssh () {
    # Testing ssh
    massager_plus "Testing of ssh"


    # is running ????
    #service ssh status
    #systemctl status  --no-pager -l sshd
    /etc/init.d/ssh status
    ps -ef --forest | grep sshd

    # is listening ?
    ss -pultan | grep :${port_ssh[0]}

    # is creating logs ????
    tail /var/log/auth.log | grep sshd

    # Validating...

    ## scanning ssh ports using NETCAT
    nc -zv localhost ${port_ssh[0]}
    #root@ssh:/etc/ssh#  nc -zv localhost 22
    #localhost [127.0.0.1] 22 (ssh) open


    ## scanning ssh ports using NMAP
    nmap -A localhost -sT -p ${port_ssh[0]} 
	#root@ssh:/etc/ssh# nmap -A localhost -sT -p 22
	#Starting Nmap 7.80 ( https://nmap.org ) at 2024-01-17 04:35 UTC
	#Nmap scan report for localhost (127.0.0.1)
	#Host is up (0.000090s latency).
	#Other addresses for localhost (not scanned): ::1
	#
	#PORT   STATE SERVICE VERSION
	#22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u2 (protocol 2.0)
	#Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
	#Device type: general purpose
	#Running: Linux 2.6.X
	#OS CPE: cpe:/o:linux:linux_kernel:2.6.32
	#OS details: Linux 2.6.32
	#Network Distance: 0 hops
	#Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
	#
	#OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
	#Nmap done: 1 IP address (1 host up) scanned in 2.52 seconds
	#root@ssh:/etc/ssh# 
	
    # specific tool of commands to test

}


################################

function test_server () {
    massager_line "Testing server"

    # testing ssh
    test_ssh

}

################################

# end main functions
# ============================== #

# end definition functions
# ============================================================ #
# start argument reading

# end argument reading
# ============================================================ #
# start main executions of code
massager_sharp "Starting ssh installation script"
pre_install_server;
install_server;
stop_server;
configure_server;
check_configs;
start_server;
test_server;
massager_sharp "Finished ssh installation script"


