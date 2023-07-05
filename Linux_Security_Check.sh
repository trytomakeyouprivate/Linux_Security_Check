#!/bin/bash
# Linux Security Check
# Compatible system: CentOS6
# Author:Jankin

# Configuration area:
# Administrator account
username="superuser"

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

echo -e "${CHECK_status} Starting a Linux security baseline test... \n"

# Output current Linux information
echo -e "${FINISH_status} Current Linux information:"
current_user=`whoami`
echo "Host Name：`hostname`"
echo "Current Users：${current_user}"
echo -e "Current IP：`/sbin/ifconfig | grep 'inet addr' | sed 's/^.*addr://' | sed 's/ Bcast.*$//' | sed '/127.*/d'`\n"

# Determine if it is root
if [ $current_user != 'root' ]
then
	echo -e "${ERROR_status} Please execute the script as root user！"
	exit 123
fi

# The following program uses grep to detect,
# while the check() function uses $? return status
# to determine whether the conditions are met
function check(){
	if [ $? == 0 ]
	then
		echo -e "${correct_status} $1Meets the requirements"
	else
		echo -e "${error_status} $1Does not meet the requirements"
	fi
}

# Account password detection
echo -e "${CHECK_status} Account password detection in progress..."

# 1. Complexity of password
grep '^password\s\+requisite\s\+pam_cracklib.so\s\+.*minlen=8' /etc/pam.d/system-auth-ac | grep 'minclass=3' > /dev/null
check Password Complexity

# 2. Password lifecycle
grep '^PASS_MAX_DAYS\s\+90' /etc/login.defs > /dev/null
check Password lifecycle
chage -l root | grep 'Maximum number of days between password change\s\+:\s\+90' > /dev/null
check root User password lifecycle
echo -e "${FINISH_status} Completed account password detection"
echo  "----------------------------------"

# Permission detection
echo -e "${CHECK_status} Permission detection in progress..."
# Check /etc/passwd, /etc/group and /etc/profile whether the file owner and all groups are root and whether the permission is 644
for f in /etc/passwd /etc/group /etc/profile
do
	 ls -l ${f} | grep 'root root' | grep 'rw-r--r--' > /dev/null
	check ${f} File Permissions
done
# Check /etc/shadow, /etc/gshadow Whether the file owner and all groups are root and whether the permission is 000
for f in /etc/shadow /etc/gshadow
do
	 ls -l ${f} | grep 'root root' | grep -- "---------" > /dev/null
	check ${f} File Permissions
done
# Check if the /tmp directory belongs to root, all groups and permissions are 750
ls -ld /tmp/ | grep 'root root' | grep 'rwxr-x---' > /dev/null
check /tmp Directory Permissions
# Check that the /var/log/ directory belongs to root, all groups, and that permissions are 740
ls -ld /var/log/ | grep 'root root' | grep 'rwxr-----' > /dev/null
check /var/log Directory Permissions
# Check if the /boot/grub/grub.conf file is owned by root, all groups are root, and the permissions are 600
ls -l /boot/grub/grub.conf | grep 'root root' | grep 'rw-------' > /dev/null
check /boot/grub/grub.conf File Permissions
echo -e "${FINISH_status} Permission detection completed"
echo  "----------------------------------"

# Log audit detection
echo -e "${CHECK_status} Ongoing log audit service detection..."
service rsyslog status > /dev/null
check "rsyslog Service Status"
service auditd status > /dev/null
check "auditd Service Status"
echo -e "${FINISH_status} Completed log audit service detection"
echo  "----------------------------------"

# Protocol Security Testing
echo -e "${CHECK_status} Protocol security testing in progress..."
# Protocol Security Inspection_SSH Inspection
echo -e "${check_status} SSH protocol is being detected..."
grep "^Port $ssh_port" /etc/ssh/sshd_config > /dev/null
check SSH Port number
grep "^Protocol 2" /etc/ssh/sshd_config > /dev/null
check SSH Security protocols
grep "^PermitEmptyPasswords no" /etc/ssh/sshd_config > /dev/null
check SSH Empty password restriction
grep "^PermitRootLogin no" /etc/ssh/sshd_config > /dev/null
check SSH Disable root login
grep "^MaxAuthTries 5" /etc/ssh/sshd_config > /dev/null
check SSH Limit on the number of failed login attempts
grep "^ClientAliveInterval 600" /etc/ssh/sshd_config > /dev/null
check SSH Timeout logout parameter ClientAliveInterval configuration
grep "^ClientAliveCountMax 0" /etc/ssh/sshd_config > /dev/null
check SSH timeout logout parameter ClientAliveCountMax configuration
grep "^LogLevel INFO" /etc/ssh/sshd_config > /dev/null
check SSH log level configuration
echo -e "${FINISH_status} Completed protocol security testing"
echo  "----------------------------------"

# System security testing
# 1. Restrict users to su to root and only allow admin accounts to su to root
echo -e "${CHECK_status} System security testing in progress..."
grep "^wheel.*${username}" /etc/group > /dev/null
check ${username} Add to wheel group
grep "^auth\s\+required\s\+pam_wheel.so" /etc/pam.d/su > /dev/null
check /etc/pam.d/su File Configuration
grep "^SU_WHEEL_ONLY yes" /etc/login.defs > /dev/null
check /etc/login.defs File SU_WHEEL_ONLY parameter configuration
echo -e "${finish_status} Restrict user su to root detection complete"

# 2. GRUB Encryption
grep "password ${password}" /boot/grub/grub.conf > /dev/null
check GRUB Encryption
echo -e "${finish_status} GRUB encryption detection complete"
echo -e "${FINISH_status} System security testing has been completed"
echo  "----------------------------------"

echo -e "${FINISH_status} Completed Linux security baseline testing"
