#!/bin/env bash
# WARNING: For use on RHEL/CentOS 7.x and up only.
#       -Use at your own risk!
#       -Use only for new installations of Guacamole!
#       -Read all documentation (wiki) prior to using this script!
#       -Test prior to deploying on a production system!
#
######  PRE-RUN CHECKS  ##############################################
if ! [ $(id -u) = 0 ]; then echo "This script must be run as sudo or root, try again..."; exit 1; fi
if ! [ $(getenforce) = "Enforcing" ]; then echo "This script requires SELinux to be active and in \"Enforcing mode\""; exit 1; fi
if ! [ $(uname -m) = "x86_64" ]; then echo "This script will only run on 64 bit versions of RHEL/CentOS"; exit 1; fi
# Check that firewalld is installed
if ! rpm -q --quiet "firewalld"; then echo "This script requires firewalld to be installed on the system"; exit 1; fi

# Allow trap to work in functions
set -E

######################################################################
######  VARIABLES  ###################################################
######################################################################

######  UNIVERSAL VARIABLES  #########################################
# USER CONFIGURABLE #
# Generic

# Key Sizes
LE_KEY_SIZE_DEF="4096" # Default Let's Encrypt key-size
SSL_KEY_SIZE_DEF="4096" # Default Self-signed SSL key-size

DOMAIN_NAME_DEF="localhost" # Default domain name of server
GUAC_URIPATH_DEF="/" # Default URI for Guacamole
DEL_TMP_VAR=true # Default behavior to delete the temp var file used by error handler on completion. Set to false to keep the file to review last values
TMP_VAR_FILE="guac_tmp_vars" # Temp file name used to store varaibles for the error handler
# Formats
Black=`tput setaf 0`	#${Black}
Red=`tput setaf 1`	#${Red}
Green=`tput setaf 2`	#${Green}
Yellow=`tput setaf 3`	#${Yellow}
Blue=`tput setaf 4`	#${Blue}
Magenta=`tput setaf 5`	#${Magenta}
Cyan=`tput setaf 6`	#${Cyan}
White=`tput setaf 7`	#${White}
Bold=`tput bold`	#${Bold}
UndrLn=`tput sgr 0 1`	#${UndrLn}
Rev=`tput smso`		#${Rev}
Reset=`tput sgr0`	#${Reset}
######  END UNIVERSAL VARIABLES  #####################################

######  INITIALIZE COMMON VARIABLES  #################################
# ONLY CHANGE IF NOT WORKING #
init_vars () {
# Get the release version of Guacamole from/for Git
GUAC_GIT_VER=`curl -s https://raw.githubusercontent.com/apache/guacamole-server/master/configure.ac | grep 'AC_INIT([guacamole-server]*' | awk -F'[][]' -v n=2 '{ print $(2*n) }'`
PWD=`pwd` # Current directory

# Set full path/file name of file used to stored temp variables used by the error handler
VAR_FILE="${PWD}/${TMP_VAR_FILE}"
echo "-1" > "${VAR_FILE}" # create file with -1 to set not as background process

# Determine if OS is RHEL, CentOS or something else
if grep -q "CentOS" /etc/redhat-release; then
	OS_NAME="CentOS"
elif grep -q "Red Hat Enterprise" /etc/redhat-release; then
	OS_NAME="RHEL"
else
	echo "Unable to verify OS from /etc/redhat-release as CentOS or RHEL, this script is intended only for those distro's, exiting."
	exit 1
fi
OS_NAME_L="$(echo $OS_NAME | tr '[:upper:]' '[:lower:]')" # Set lower case rhel or centos for use in some URLs

# Outputs the major.minor.release number of the OS, Ex: 7.6.1810 and splits the 3 parts.
MAJOR_VER=`cat /etc/redhat-release | grep -oP "[0-9]+" | sed -n 1p` # Return the leftmost digit representing major version
MINOR_VER=`cat /etc/redhat-release | grep -oP "[0-9]+" | sed -n 2p` # Returns the middle digit representing minor version
# Placeholder in case this info is ever needed. RHEL does not have release number, only major.minor
# RELEASE_VER=`cat /etc/redhat-release | grep -oP "[0-9]+" | sed -n 3p` # Returns the rightmost digits representing release number

#Set arch used in some paths
MACHINE_ARCH=`uname -m`
ARCH="64"

# Set nginx url for RHEL or CentOS
NGINX_URL="https://nginx.org/packages/$OS_NAME_L/$MAJOR_VER/$MACHINE_ARCH/"
}

######  SOURCE VARIABLES  ############################################
src_vars () {

# Dirs and file names
FILENAME="${PWD}/guacamole-proxy_"$(date +"%d-%y-%b")"" # Script generated log filename
logfile="${FILENAME}.log" # Script generated log file full name
fwbkpfile="${FILENAME}.firewall.bkp" # Firewall backup file name
}

######################################################################
######  MENUS  #######################################################
######################################################################

######  SOURCE MENU  #################################################
src_menu () {
clear

echo -e "   ${Reset}${Bold}----====Gucamole Nginx Installation Script====----\n       ${Reset}Guacamole Remote Desktop Gateway\n"
echo -e "   ${Bold}***        Source Menu     ***\n"
echo "   OS: ${Yellow}${OS_NAME} ${MAJOR_VER}.${MINOR_VER} ${MACHINE_ARCH}${Reset}"

tput sgr0
}

######  START EXECUTION  #############################################
init_vars
src_menu
src_vars

######  MENU HEADERS  ################################################
# Called by each menu and summary menu to display the dynamic header
menu_header () {
tput sgr0
clear

echo -e "   ${Reset}${Bold}----====Gucamole Installation Script====----\n       ${Reset}Guacamole Remote Desktop Gateway\n"
echo -e "   ${Bold}***     ${SUB_MENU_TITLE}     ***\n"
echo "   OS: ${Yellow}${OS_NAME} ${MAJOR_VER}.${MINOR_VER} ${MACHINE_ARCH}${Reset}"
}

######  SSL CERTIFICATE TYPE MENU  ###################################
ssl_cert_type_menu () {
SUB_MENU_TITLE="SSL Certificate Type Menu"

menu_header

echo "${Green} What kind of SSL certificate should be used (default 2)?${Yellow}"
PS3="${Green} Enter the number of the desired SSL certificate type: ${Yellow}"
options=("LetsEncrypt" "Self-signed" "None")
select opt in "${options[@]}"
do
	case $opt in
		"LetsEncrypt") SSL_CERT_TYPE="LetsEncrypt"; le_menu; break;;
		"Self-signed"|"") SSL_CERT_TYPE="Self-signed"; ss_menu; break;;
		"None")
			SSL_CERT_TYPE="None"
			OCSP_USE=false
			echo -e "\n\n${Red} No SSL certificate selected. This can be configured manually at a later time."
			sleep 3
			break;;
		* ) echo "${Green} ${REPLY} is not a valid option, enter the number representing your desired cert type.";;
		esac
done
}

######  LETSENCRYPT MENU  ############################################
le_menu () {
SUB_MENU_TITLE="LetsEncrypt Menu"

menu_header

echo -n "${Green} Enter a valid e-mail for let's encrypt certificate: ${Yellow}"
	read EMAIL_NAME
echo -n "${Green} Enter the Let's Encrypt key-size to use (default ${LE_KEY_SIZE_DEF}): ${Yellow}"
	read LE_KEY_SIZE
	LE_KEY_SIZE=${LE_KEY_SIZE:-${LE_KEY_SIZE_DEF}}

while true; do
	echo -n "${Green} Use OCSP Stapling (default yes): ${Yellow}"
	read yn
	case $yn in
		[Yy]*|"" ) OCSP_USE=true; break;;
		[Nn]* ) OCSP_USE=false; break;;
		* ) echo "${Green} Please enter yes or no. ${Yellow}";;
		esac
done
}

######  SELF-SIGNED SSL CERTIFICATE MENU  ############################
ss_menu () {
OCSP_USE=false
SUB_MENU_TITLE="Self-signed SSL Certificate Menu"

menu_header

echo -n "${Green} Enter the Self-Signed SSL key-size to use (default ${SSL_KEY_SIZE_DEF}): ${Yellow}"
	read SSL_KEY_SIZE
	SSL_KEY_SIZE=${SSL_KEY_SIZE:-${SSL_KEY_SIZE_DEF}}
}

######  NGINX OPTIONS MENU  ##########################################
nginx_menu () {
SUB_MENU_TITLE="Nginx Menu"

menu_header

# Server LAN IP
GUAC_LAN_IP_DEF=$(hostname -I | sed 's/ .*//')

echo -n "${Green} Enter the IP/hostname of the Guacamole server (default ${GUAC_LAN_IP_DEF}): ${Yellow}"
	read GUAC_LAN_IP
	GUAC_LAN_IP=${GUAC_LAN_IP:-${GUAC_LAN_IP_DEF}}
echo -n "${Green} Enter a valid hostname or public domain such as mydomain.com (default ${DOMAIN_NAME_DEF}): ${Yellow}"
	read DOMAIN_NAME
	DOMAIN_NAME=${DOMAIN_NAME:-${DOMAIN_NAME_DEF}}
echo -n "${Green} Enter the URI path, starting and ending with / for example /guacamole/ (default ${GUAC_URIPATH_DEF}): ${Yellow}"
	read GUAC_URIPATH
	GUAC_URIPATH=${GUAC_URIPATH:-${GUAC_URIPATH_DEF}}

# Only prompt if SSL will be used
if [ $SSL_CERT_TYPE != "None" ]; then
	while true; do
		echo -n "${Green} Use only >= 256-bit SSL ciphers (More secure, less compatible. default: yes)?: ${Yellow}"
		read yn
		case $yn in
			[Yy]*|"" ) NGINX_SEC=true; break;;
			[Nn]* ) NGINX_SEC=false; break;;
			* ) echo "${Green} Please enter yes or no. ${Yellow}";;
		esac
	done

	while true; do
		echo -n "${Green} Use Content-Security-Policy [CSP] (More secure, less compatible. default: yes)?: ${Yellow}"
		read yn
		case $yn in
			[Yy]*|"" ) USE_CSP=true; break;;
			[Nn]* ) USE_CSP=false; break;;
			* ) echo "${Green} Please enter yes or no. ${Yellow}";;
		esac
	done
else
	NGINX_SEC=false
	USE_CSP=false
fi
}

######################################################################
######  SUMMARY MENUS  ###############################################
######################################################################

######  MAIN SUMMARY MENU  ###########################################
sum_menu () {
SUB_MENU_TITLE="Summary Menu"

menu_header

RUN_INSTALL=false
RET_SUM=false

# List categories/menus to review or change
echo "${Green} Select a category to review selections: ${Yellow}"
PS3="${Green} Enter the number of the category to review: ${Yellow}"
options=("SSL Cert Type" "Nginx" "Accept and Run Installation" "Cancel and Start Over" "Cancel and Exit Script")
select opt in "${options[@]}"
do
        case $opt in
                "SSL Cert Type") sum_ssl; break;;
                "Nginx") sum_nginx; break;;
                "Accept and Run Installation") RUN_INSTALL=true; break;;
                "Cancel and Start Over") ScriptLoc=$(readlink -f "$0"); exec "$ScriptLoc"; break;;
                "Cancel and Exit Script") tput sgr0; exit 1; break;;
                * ) echo "${Green} ${REPLY} is not a valid option, enter the number representing the category to review.";;
                esac
done
}

######  SSL CERTIFICATE SUMMARY  #####################################
sum_ssl () {
SUB_MENU_TITLE="SSL Certificate Summary"

menu_header

echo -e "${Green} Certficate Type: ${Yellow}${SSL_CERT_TYPE}\n"

# Check the certificate selection to display proper information for selection
case $SSL_CERT_TYPE in
	"LetsEncrypt")
		echo "${Green} e-mail for LetsEncrypt certificate: ${Yellow}${EMAIL_NAME}"
		echo "${Green} LetEncrypt key-size: ${Yellow}${LE_KEY_SIZE}"
		echo -e "${Green} Use OCSP Stapling?: ${Yellow}${OCSP_USE}\n"
		;;
	"Self-signed")
		echo -e "${Green} Self-Signed SSL key-size: ${Yellow}${SSL_KEY_SIZE}\n"
		;;
	"None")
		echo -e "${Yellow} As no certificate type was selected, an SSL certificate can be configured manually at a later time.\n"
		;;
esac

while true; do
	echo -n "${Green} Would you like to change these selections (default no)? ${Yellow}"
	read yn
	case $yn in
		[Yy]* ) ssl_cert_type_menu; break;;
		[Nn]*|"" ) break;;
		* ) echo "${Green} Please enter yes or no. ${Yellow}";;
	esac
done

sum_menu
}

######  NGINX SUMMARY  ###############################################
sum_nginx () {
SUB_MENU_TITLE="Nginx Summary"

menu_header

echo "${Green} Guacamole Server LAN IP address: ${Yellow}${GUAC_LAN_IP}"
echo "${Green} Guacamole Server hostname or public domain: ${Yellow}${DOMAIN_NAME}"
echo "${Green} URI path: ${Yellow}${GUAC_URIPATH}"
echo "${Green} Using only 256-bit >= ciphers?: ${Yellow}${NGINX_SEC}"
echo -e "${Green} Content-Security-Policy [CSP] enabled?: ${Yellow}${USE_CSP}\n"

while true; do
	echo -n "${Green} Would you like to change these selections (default no)? ${Yellow}"
	read yn
	case $yn in
		[Yy]* ) nginx_menu; break;;
		[Nn]*|"" ) break;;
		* ) echo "${Green} Please enter yes or no. ${Yellow}";;
	esac
done

sum_menu
}

######  MENU EXECUTION  ##############################################
ssl_cert_type_menu
nginx_menu
sum_menu

# Sets file descriptor to 3 for this special echo function and spinner
exec 3>&1

######################################################################
######  UTILITY FUNCTIONS  ###########################################
######################################################################

######  PROGRESS SPINNER FUNCTION  ###################################
# Used to show a process is making progress/running
spinner () {
pid=$!
#Store the background process id in a temp file to use in err_handler
echo $(jobs -p) > "${VAR_FILE}"

spin[0]="-"
spin[1]="\\"
spin[2]="|"
spin[3]="/"

# Loop while the process is still running
while kill -0 $pid 2>/dev/null
do
	for i in "${spin[@]}"
	do
		if kill -0 $pid 2>/dev/null; then #Check that the process is running to prevent a full 4 character cycle on error
			# Display the spinner in 1/4 states
			echo -ne "\b\b\b${Bold}[${Green}$i${Reset}${Bold}]" >&3
			sleep .5 # time between each state
		else #process has ended, stop next loop from finishing iteration
			break
		fi
	done
done

# Check if background process failed once complete
if wait $pid; then # Exit 0
	echo -ne "\b\b\b${Bold}[${Green}-done-${Reset}${Bold}]" >&3
else # Any other exit
	false
fi

#Set background process id value to -1 representing no background process running to err_handler
echo "-1" > "${VAR_FILE}"

tput sgr0 >&3
}

######  SPECIAL ECHO FUNCTION  #######################################
# This allows echo to log and stdout (now fd3) while sending all else to log by default via exec
s_echo () {
# Use first arg $1 to determine if echo skips a line (yes/no)
# Second arg $2 is the message
case $1 in
	# No preceeding blank line
	[Nn])
		echo -ne "\n${2}" | tee -a /dev/fd/3
		echo # add new line after in log only
		;;
	# Preceeding blank line
	[Yy]|*)
		echo -ne "\n\n${2}" | tee -a /dev/fd/3
		echo # add new line after in log only
		;;
esac
}

# Used to force all stdout and stderr to the log file
# s_echo function will be used when echo needs to be displayed and logged
exec &> "${logfile}"

######  ERROR HANDLER FUNCTION  ######################################
# Called by trap to display/log error info and exit script
err_handler () {
EXITCODE=$?

#Read values from temp file used to store cross process values
F_BG=$(sed -n 1p "${VAR_FILE}")

# Check if the temp variable file is greater than 1 line of text
if [ $(wc -l < "${VAR_FILE}") -gt 1 ]; then
	# If so, set variable according to value of the 2nd line in the file.
	H_ERR=$(sed -n 2p "${VAR_FILE}")
else # Otherwise, set to false, error was not triggered previously
	H_ERR=false
fi

#Check this is the first time the err_handler has triggered
if [ $H_ERR = false ]; then
	#Check if error occured with a background process running
	if [ $F_BG -gt 0 ]; then
		echo -ne "\b\b\b${Bold}[${Red}-FAILED-${Reset}${Bold}]" >&3
	fi

	FAILED_COMMAND=$(eval echo "$BASH_COMMAND") # Used to expand the variables in the command returned by BASH_COMMAND
	s_echo "y" "${Reset}${Red}%%% ${Reset}${Bold}ERROR (Script Failed) | Line${Reset} ${BASH_LINENO[0]} ${Bold}| Command:${Reset} ${FAILED_COMMAND} ${Bold}| Exit code:${Reset} ${EXITCODE} ${Red}%%%${Reset}\n\n"

	#Flag as trap having been run already skipping double error messages
	echo "true" >> "${VAR_FILE}"
fi

# Log cleanup to remove escape sequences caused by tput for formatting text
sed -i 's/\x1b\[[0-9;]*m\|\x1b[(]B\x1b\[m//g' ${logfile}

tput sgr0 >&3
exit $EXITCODE
}

######  CHECK INSTALLED PACKAGE FUNCTION  ############################
# Query rpm for package without triggering trap when not found
chk_installed () {
if rpm -q "$@"; then
	RETVAL=$?
else
	RETVAL=$?
fi
}

######  ERROR TRAP  ##################################################
# Trap to call error function to display and log error details
trap err_handler ERR SIGINT SIGQUIT

###### REPOS INSTALLATION  ##########################################
reposinstall () {
s_echo "n" "${Bold}   ----==== INSTALLING GUACAMOLE NGINX ====----"
s_echo "y" "Installing Repos"

# Install Nginx Repo
{ echo "[nginx-stable]
name=Nginx Stable Repo
baseurl=${NGINX_URL}
gpgcheck=1
enabled=1
gpgkey=https://nginx.org/keys/nginx_signing.key
module_hotfixes=true" > /etc/yum.repos.d/nginx.repo; } &
s_echo "n" "${Reset}-Installing Nginx repo...    "; spinner
yumupdate
}
######  YUM UPDATES  #################################################
yumupdate () {

# Update OS/packages
{ yum update -y; } &
s_echo "y" "${Bold}Updating ${OS_NAME}, please wait...    "; spinner

baseinstall
}

######  INSTALL BASE PACKAGES  #######################################
baseinstall () {

# Install Required Packages
{
        yum install -y nginx
} &
s_echo "n" "${Reset}-Installing Nginx...    "; spinner

nginxcfg
}

######  NGINX CONFIGURATION  #########################################
nginxcfg () {
s_echo "y" "${Bold}Nginx Configuration"

# Backup Nginx Configuration
{ [ -f /etc/nginx/conf.d/default.conf ] && mv -n /etc/nginx/conf.d/default.conf /etc/nginx/conf.d/default.conf.ori.bkp; } &
s_echo "n" "${Reset}-Making Nginx config backup...    "; spinner

# HTTP Nginx Conf
{ echo "server {
	listen 80;
	listen [::]:80;
	server_name ${DOMAIN_NAME};
	return 301 https://\$host\$request_uri;
	location ${GUAC_URIPATH} {
	proxy_pass http://${GUAC_LAN_IP}:8080/guacamole/;
	proxy_buffering off;
	proxy_http_version 1.1;
	proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
	proxy_set_header Upgrade \$http_upgrade;
	proxy_set_header Connection \$http_connection;
	proxy_cookie_path /guacamole/ ${GUAC_URIPATH};
	access_log off;
	}
}" > /etc/nginx/conf.d/guacamole.conf 
} &
s_echo "n" "${Reset}-Generate Nginx guacamole.config...    "; spinner

# HTTPS/SSL Nginx Conf
{
	echo "server {
		#listen 443 ssl http2 default_server;
		#listen [::]:443 ssl http2 default_server;
		server_name ${DOMAIN_NAME};
		server_tokens off;
		#ssl_certificate guacamole.crt;
		#ssl_certificate_key guacamole.key; " > /etc/nginx/conf.d/guacamole_ssl.conf

	# If OCSP Stapling was selected add lines
	if [ $OCSP_USE = true ]; then
		if [[ -r /etc/resolv.conf ]]; then
	            NAME_SERVERS=$(awk '/^nameserver/{print $2}' /etc/resolv.conf | xargs)
	        fi
		    
		if [[ -z $NAME_SERVERS ]]; then
		    NAME_SERVERS=$NAME_SERVERS_DEF
		fi
		
		echo "	#ssl_trusted_certificate guacamole.pem;
		ssl_stapling on;
		ssl_stapling_verify on;
		resolver ${NAME_SERVERS} valid=30s;
		resolver_timeout 30s;" >> /etc/nginx/conf.d/guacamole_ssl.conf
	fi

	# If using >= 256-bit ciphers
	if [ $NGINX_SEC = true ]; then
		echo "	ssl_ciphers 'TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-SHA384';" >> /etc/nginx/conf.d/guacamole_ssl.conf
	else
		echo "	ssl_ciphers 'TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-SHA256';" >> /etc/nginx/conf.d/guacamole_ssl.conf
	fi

	# Rest of HTTPS/SSL Nginx Conf
	echo "	ssl_protocols TLSv1.3 TLSv1.2;
		ssl_ecdh_curve secp521r1:secp384r1:prime256v1;
		ssl_prefer_server_ciphers on;
		ssl_session_cache shared:SSL:10m;
		ssl_session_timeout 1d;
		ssl_session_tickets off;
		add_header Referrer-Policy \"no-referrer\";
		add_header Strict-Transport-Security \"max-age=15768000; includeSubDomains\" always;" >> /etc/nginx/conf.d/guacamole_ssl.conf
		
	# If CSP was enabled, add line, otherwise add but comment out (to allow easily manual toggle of the feature)
	if [ $USE_CSP = true ]; then
		echo "	add_header Content-Security-Policy \"default-src 'none'; script-src 'self' 'unsafe-eval'; connect-src 'self' wss://${DOMAIN_NAME}; object-src 'self'; frame-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; font-src 'self'; form-action 'self'; base-uri 'self'; frame-ancestors 'self';\" always;" >> /etc/nginx/conf.d/guacamole_ssl.conf
	else
		echo "	#add_header Content-Security-Policy \"default-src 'none'; script-src 'self' 'unsafe-eval'; connect-src 'self' wss://${DOMAIN_NAME}; object-src 'self'; frame-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; font-src 'self'; form-action 'self'; base-uri 'self'; frame-ancestors 'self';\" always;" >> /etc/nginx/conf.d/guacamole_ssl.conf
	fi

	echo "	add_header X-Frame-Options \"SAMEORIGIN\" always;
		add_header X-Content-Type-Options \"nosniff\" always;
		add_header X-XSS-Protection \"1; mode=block\" always;
		proxy_hide_header Server;
		proxy_hide_header X-Powered-By;
		client_body_timeout 10;
		client_header_timeout 10;
		location ${GUAC_URIPATH} {
		proxy_pass http://${GUAC_LAN_IP}:8080/guacamole/;
		proxy_buffering off;
		proxy_http_version 1.1;
		proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
		proxy_set_header Upgrade \$http_upgrade;
		proxy_set_header Connection \$http_connection;
		proxy_cookie_path /guacamole/ \"${GUAC_URIPATH}; HTTPOnly; Secure; SameSite\";
		access_log /var/log/nginx/guac_access.log;
		error_log /var/log/nginx/guac_error.log;
		}
	}" >> /etc/nginx/conf.d/guacamole_ssl.conf
} &
s_echo "n" "-Generate Nginx guacamole_ssl.config...    "; spinner

# Nginx CIS hardening v1.0.0
{
	# 2.3.2 Restrict access to Nginx files
	find /etc/nginx -type d | xargs chmod 750
	find /etc/nginx -type f | xargs chmod 640

	# 2.4.3 & 2.4.4 set keepalive_timeout and send_timeout to 1-10 seconds, default 65/60.
	sed -i '/keepalive_timeout/c\keepalive_timeout 10\;' /etc/nginx/nginx.conf
	# sed -i '/send_timeout/c\send_timeout 10\;' /etc/nginx/nginx.conf

	# 2.5.2 Reoving mentions of Nginx from index and error pages
	! read -r -d '' BLANK_HTML <<"EOF"
<!DOCTYPE html>
<html>
<head>
</head>
<body>
</body>
</html>
EOF

	echo "${BLANK_HTML}" > /usr/share/nginx/html/index.html
	echo "${BLANK_HTML}" > /usr/share/nginx/html/50x.html

	# 3.4 Ensure logs are rotated (may set this as a user defined parameter)
	sed -i "s/daily/weekly/" /etc/logrotate.d/nginx
	sed -i "s/rotate 52/rotate 13/" /etc/logrotate.d/nginx
} &
s_echo "n" "-Hardening Nginx config...    "; spinner

# Enable/Start Nginx Service
{
	systemctl enable nginx
	systemctl restart nginx
} &
s_echo "n" "-Enable & Start Nginx Service...    "; spinner

selinuxsettings
}

######  SELINUX SETTINGS  ############################################
selinuxsettings () {
{
	# Set Booleans
	setsebool -P httpd_can_network_connect 1
	setsebool -P httpd_can_network_relay 1
	setsebool -P tomcat_can_network_connect_db 1

} &

s_echo "y" "${Bold}Setting SELinux Context...    "; spinner

# Log SEL status
sestatus

firewallsettings
}

######  FIREWALL SETTINGS  ###########################################
firewallsettings () {
s_echo "y" "${Bold}Firewall Configuration"

chk_installed "firewalld"

# Ensure firewalld is enabled and started
{
	if [ $RETVAL -eq 0 ]; then
		systemctl enable firewalld
		systemctl restart firewalld
	fi
} &
s_echo "n" "${Reset}-firewalld is installed and started on the system...    "; spinner

# Backup firewall public zone config
{ cp /etc/firewalld/zones/public.xml $fwbkpfile; } &
s_echo "n" "-Backing up firewall public zone to: $fwbkpfile    "; spinner

# Open HTTP and HTTPS ports
{
	echo -e "Add new rule...\nfirewall-cmd --permanent --zone=public --add-service=http"
	firewall-cmd --permanent --zone=public --add-service=http
	echo -e "Add new rule...\nfirewall-cmd --permanent --zone=public --add-service=https"
	firewall-cmd --permanent --zone=public --add-service=https

} &
s_echo "n" "-Opening HTTP and HTTPS service ports...    "; spinner

#echo -e "Reload firewall...\nfirewall-cmd --reload\n"
{ firewall-cmd --reload; } &
s_echo "n" "-Reloading firewall...    "; spinner

sslcerts

}
######  SSL CERTIFICATE  #############################################
sslcerts () {
s_echo "y" "${Bold}SSL Certificate Configuration"

if [ $SSL_CERT_TYPE != "None" ]; then
	# Lets Encrypt Setup (If selected)
	if [ $SSL_CERT_TYPE = "LetsEncrypt" ]; then
		# Install certbot from repo
		{ yum install -y certbot python2-certbot-nginx; } &
		s_echo "n" "${Reset}-Downloading certboot tool...    "; spinner

		# OCSP
		{
			if [ $OCSP_USE = true ]; then
				certbot certonly --nginx --must-staple -n --agree-tos --rsa-key-size ${LE_KEY_SIZE} -m "${EMAIL_NAME}" -d "${DOMAIN_NAME}"
			else # Generate without OCSP --must-staple
				certbot certonly --nginx -n --agree-tos --rsa-key-size ${LE_KEY_SIZE} -m "${EMAIL_NAME}" -d "${DOMAIN_NAME}"
			fi
		} &
		s_echo "n" "-Generating a ${SSL_CERT_TYPE} SSL Certificate...    "; spinner

		# Symlink Lets Encrypt certs so renewal does not break Nginx
		{
			ln -vs "/etc/letsencrypt/live/${DOMAIN_NAME}/fullchain.pem" /etc/nginx/guacamole.crt
			ln -vs "/etc/letsencrypt/live/${DOMAIN_NAME}/privkey.pem" /etc/nginx/guacamole.key
			ln -vs "/etc/letsencrypt/live/${DOMAIN_NAME}/chain.pem" /etc/nginx/guacamole.pem
		} &
		s_echo "n" "-Creating symlinks to ${SSL_CERT_TYPE} SSL certificates...    "; spinner

		# Setup automatic cert renewal
		{
			systemctl enable certbot-renew.service
			systemctl enable certbot-renew.timer
			systemctl list-timers --all | grep certbot
		} &
		s_echo "n" "-Setup automatic ${SSL_CERT_TYPE} SSL certificate renewals...    "; spinner

	else # Use a Self-Signed Cert
		{ openssl req -x509 -sha512 -nodes -days 365 -newkey rsa:${SSL_KEY_SIZE} -keyout /etc/nginx/guacamole.key -out /etc/nginx/guacamole.crt -subj "/C=''/ST=''/L=''/O=''/OU=''/CN=''"; } &
		s_echo "n" "${Reset}-Generating ${SSL_CERT_TYPE} SSL Certificate...    "; spinner
	fi

	# Nginx CIS v1.0.0 - 4.1.3 ensure private key permissions are restricted
	{
		ls -l /etc/nginx/guacamole.key
		chmod 400 /etc/nginx/guacamole.key
	} &
	s_echo "n" "${Reset}-Changing permissions on SSL private key...    "; spinner

	{
		# Uncomment listen lines from Nginx guacamole_ssl.conf (fixes issue introduced by Nginx 1.16.0)
		sed -i 's/#\(listen.*443.*\)/\1/' /etc/nginx/conf.d/guacamole_ssl.conf
		# Uncomment cert lines from Nginx guacamole_ssl.conf
		sed -i 's/#\(.*ssl_.*certificate.*\)/\1/' /etc/nginx/conf.d/guacamole_ssl.conf
	} &
	s_echo "n" "${Reset}-Enabling SSL certificate in guacamole_ssl.conf...    "; spinner

	HTTPS_ENABLED=true
else # Cert is set to None
	s_echo "n" "${Reset}-No SSL Cert selected..."

	# Will not force/use HTTPS without a cert, comment out redirect
	{ sed -i '/\(return 301 https\)/s/^/#/' /etc/nginx/conf.d/guacamole.conf; } &
	s_echo "n" "${Reset}-Update guacamole.conf to allow HTTP connections...    "; spinner

	HTTPS_ENABLED=false
fi

showmessages
}

######  COMPLETION MESSAGES  #########################################
showmessages () {
s_echo "y" "${Bold}Services"

# Restart all services and log status
{
	systemctl restart nginx
	systemctl status nginx

} &
s_echo "n" "${Reset}-Restarting all services...    "; spinner

# Completion messages
s_echo "y" "${Bold}${Green}##### Installation Complete! #####${Reset}"

s_echo "y" "${Bold}Log Files"
s_echo "n" "${Reset}-Log file: ${logfile}"
s_echo "n" "-firewall backup file: ${fwbkpfile}"

# Determine Guac server URL for web GUI
if [ ${DOMAIN_NAME} = "localhost" ]; then
	GUAC_URL=${GUAC_LAN_IP}${GUAC_URIPATH}
else # Not localhost
	GUAC_URL=${DOMAIN_NAME}${GUAC_URIPATH}
fi

# Determine if HTTPS is used or not
if [ ${HTTPS_ENABLED} = true ]; then
	HTTPS_MSG="${Reset} or ${Bold}https://${GUAC_URL}${Reset}"
else # HTTPS not used
	HTTPS_MSG="${Reset}. Without a cert, HTTPS is not forced/available."
fi

# Manage Guac
s_echo "y" "${Bold}To manage Guacamole"
s_echo "n" "${Reset}-go to: ${Bold}http://${GUAC_URL}${HTTPS_MSG}"

# Recommendations
s_echo "y" "${Red}Important${Reset}"
s_echo "n" "-Please make sure to run the guac-install.sh script"

s_echo "y" "${Green}While not technically required, you should consider a reboot after verifying installation\n${Reset}"

# Log cleanup to remove escape sequences caused by tput for formatting text
sed -i 's/\x1b\[[0-9;]*m\|\x1b[(]B\x1b\[m//g' ${logfile}

tput sgr0 >&3
}

######  INSTALLATION EXECUTION  ######################################
# Runs the install if the option was selected from the summary menu
if [ ${RUN_INSTALL} = true ]; then
	tput sgr0 >&3
	clear >&3
	reposinstall
	if [ $DEL_TMP_VAR = true ]; then
		rm "$VAR_FILE"
	fi
	exit 0
fi
