#!/bin/bash
# Linux Security Hardening
# Compatible system: CentOS6
# Author:Jankin

# Configuration area:
# Administrator account
username="superuser"
password="P@ssw0rd"

# ssh port
ssh_port="1024"

#Program area:
#shell color
red_color="\E[0;31m"
RED_color="\E[1;31m"
green_color="\E[0;32m"
GREEN_color="\E[1;32m"
yellow_color="\E[0;33m"
YELLOW_color="\E[1;33m"
blue_color="\E[0;34m"
BLUE_color="\E[1;34m"
default_color="\E[0m"

check_status="${yellow_color}[*]${default_color}"
CHECK_status="${YELLOW_color}[*]${default_color}"
finish_status="${blue_color}[*]${default_color}"
FINISH_status="${BLUE_color}[*]${default_color}"
correct_status="${green_color}[+]${default_color}"
CORRECT_status="${GREEN_color}[+]${default_color}"
error_status="${red_color}[-]${default_color}"
ERROR_status="${RED_color}[-]${default_color}"

echo -e "${CHECK_status} Start of Linux security baseline hardening...\n"

# Output current Linux information
echo -e "${FINISH_status} Current Linux information:"
current_user=`whoami`
echo "Host Name：`hostname`"
echo "Current Users：${current_user}"
echo -e "Current IP：`/sbin/ifconfig | grep 'inet addr' | sed 's/^.*addr://' | sed 's/ Bcast.*$//' | sed '/127.*/d'`\n"

# Determine if it is root
if [ $current_user != 'root' ]
then
	echo -e "${ERROR_status} Please use the root user to execute the script!"
	exit 123
fi

# Account password reinforcement
echo -e "${CHECK_status} Account password reinforcement is underway..."
# 1, password complexity
# Backups /etc/pam.d/system-auth-ac
cp -p /etc/pam.d/system-auth-ac /etc/pam.d/system-auth-ac_bak_$(date +%Y-%m-%d_%H:%M)
sed -i '/password\s\+requisite\s\+pam_cracklib.so/{s/pam_cracklib.so .*/pam_cracklib.so try_first_pass retry=3 minlen=8 minclass=3/}' /etc/pam.d/system-auth-ac
echo -e "${finish_status} Completed password complexity hardening"

# 2. Password lifecycle
cp -p /etc/login.defs /etc/login.defs_bak_$(date +%Y-%m-%d_%H:%M)
sed -i '/^PASS_MAX_DAYS\s\+[0-9]*/{s/[0-9]\+/90/}' /etc/login.defs
sed -i '/^PASS_MIN_DAYS\s\+[0-9]*/{s/[0-9]\+/0/}' /etc/login.defs
sed -i '/^PASS_WARN_AGE\s\+[0-9]*/{s/[0-9]\+/7/}' /etc/login.defs
chage -M 90 root
echo -e "${finish_status} Completed password survival hardening"

echo -e "${FINISH_status} Completed account password reinforcement"
echo  "----------------------------------"

# Permission hardening
echo -e "${CHECK_status} Permissions are being reinforced..."
chown root:root /etc/passwd /etc/group /etc/shadow /etc/gshadow /etc/profile /tmp /var/log/ /etc/grub.conf /boot/grub/grub.conf
chmod 644 /etc/passwd /etc/group /etc/profile
chmod 000 /etc/shadow /etc/gshadow
chmod 750 /tmp
chmod 740 /var/log/
chmod 600 /boot/grub/grub.conf
echo -e "${FINISH_status} Permissions reinforcement completed"
echo  "----------------------------------"

# Log audit service hardening
echo -e "${CHECK_status} Ongoing log audit service hardening..."
# Server Check，Used to check if the service is running properly, if not then
function serverCheck(){
	status=`service $1 status`
	echo ${status}|grep 'running' > /dev/null
	if [ $? == 0 ]		#If running is in the return value, then it will return 0. If it is not in the return value, then it will return 1.
	then
		chkconfig $1 on
		echo -e "${correct_status} $1 service is running"
	else
		echo -e "${error_status} $1 Service is not running and is restarting..."
		chkconfig $1 on
		service $1 start
		if [ $? == 0 ]
		then
			echo -e "${correct_status} $1 The service has been successfully started."
		else
			echo -e "${ERROR_status} $1 The service could not be started, please troubleshoot the problem manually."
		fi
	fi
}
# Call serverCheck function for reinforcement
serverCheck rsyslog
serverCheck auditd
echo -e "${FINISH_status} Log audit service hardening completed"
echo  "----------------------------------"

# Protocol security hardening
echo -e "${CHECK_status} Protocol security hardening is underway..."
# Protocol Security Hardening_SSH Hardening
echo -e "${check_status} SSH protocol being hardened"
cp -p /etc/ssh/sshd_config /etc/ssh/sshd_bak_$(date +%Y-%m-%d_%H:%M)
sed -i "s/.*Port\s\+[0-9]*/Port ${ssh_port}/" /etc/ssh/sshd_config
iptables -D INPUT -m state --state NEW -m tcp -p tcp --dport 22 -j ACCEPT
iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport ${ssh_port} -j ACCEPT
service iptables save
echo -e "${correct_status} The SSH port has been changed to: ${ssh_port}"
sed -i 's/.*Protocol\s\+[0-9]*/Protocol 2/' /etc/ssh/sshd_config
echo -e "${correct_status} SSH protocol version has been set to Protocol 2"
sed -i 's/.*PermitEmptyPasswords\s\+.*/PermitEmptyPasswords no/' /etc/ssh/sshd_config
echo -e "${correct_status} Empty password login to SSH is disabled"
sed -i 's/.*PermitRootLogin\s\+\(yes\|no\)/PermitRootLogin no/' /etc/ssh/sshd_config
echo -e "${correct_status} Root login to SSH has been disabled"
sed -i 's/.*MaxAuthTries\s\+[0-9]\+/MaxAuthTries 5/' /etc/ssh/sshd_config
echo -e "${correct_status} The maximum number of failed SSH password attempts is 5"
sed -i 's/.*ClientAliveInterval\s\+[0-9]\+/ClientAliveInterval 600/' /etc/ssh/sshd_config
sed -i 's/.*ClientAliveCountMax\s\+[0-9]\+/ClientAliveCountMax 0/' /etc/ssh/sshd_config
echo -e "${correct_status} User automatically logs out of SSH after 10 minutes of inactivity"
sed -i 's/.*LogLevel\s\+.\+/LogLevel INFO/' /etc/ssh/sshd_config
echo -e "${correct_status} SSH log level is INFO level"
service sshd restart
echo -e "${FINISH_status} Protocol security hardening has been completed"
echo  "----------------------------------"


# System security hardening
echo -e "${CHECK_status} System security hardening is underway..."
# 1. Restrict users to su to root and allow only administrator accounts to su to root
# (1) Create administrator account
useradd -G wheel ${username}
echo -e "${correct_status} Created administrator user：${username}"
echo ${password} | passwd --stdin ${username}
# (2)Back up /etc/pam.d/su and modify the su file
cp -p /etc/pam.d/su /etc/pam.d/su_bak_$(date +%Y-%m-%d_%H:%M)
sed -i '/auth\s\+required\s\+pam_wheel.so/{s/^#//}' /etc/pam.d/su
# (3)Back up /etc/login.defs and add "SU_WHEEL_ONLY yes" at the bottom of the file
cp -p /etc/login.defs /etc/login.defs_bak_$(date +%Y-%m-%d_%H:%M)
wheel_info=`grep 'SU_WHEEL_ONLY' /etc/login.defs`
if [ $? == 0 ]
then
	sed -i 's/SU_WHEEL_ONLY\s\+.*/SU_WHEEL_ONLY yes/' /etc/login.defs
else
	echo "SU_WHEEL_ONLY yes" >> /etc/login.defs
fi
echo -e "${correct_status} has disabled normal user su to root, only allows admin account [${username}] su to root"

# 2、GRUB Encryption
cp -p /boot/grub/grub.conf /boot/grub/grub.conf_bak_$(date +%Y-%m-%d_%H:%M)
grub_passwd=`grep "password" /boot/grub/grub.conf`
if [ $? == 0 ]
then    
	echo -e "${check_status} GRUB file already has password information：`echo ${grub_passwd} | sed 's/password\s\+//'`，is being replaced with ${password}"
	sed -i "s/^password\s\+.*/password ${password}/" /boot/grub/grub.conf
else
	sed -i "/^title/ipassword ${password}" /boot/grub/grub.conf
fi
echo -e "${finish_status} GRUB encryption is complete, GRUB password is set to ${password}"
echo -e "${FINISH_status} System security hardening has been completed"
echo  "----------------------------------"

echo -e "${FINISH_status} Completed Linux security baseline hardening"
