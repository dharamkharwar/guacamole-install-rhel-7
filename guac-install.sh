#!/bin/env bash
######  NOTES  #######################################################
# WARNING: For use on RHEL/CentOS 7.x and up only.
#	-Use at your own risk!
#	-Use only for new installations of Guacamole!
#	-Test prior to deploying on a production system!
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
# Versions
GUAC_STBL_VER="1.4.0" # Latest stable version of Guac from https://guacamole.apache.org/releases/
MYSQL_CON_VER="8.0.21" # Working stable release of MySQL Connecter J
TOMCAT_VER="9.0.62"

# Ports
GUAC_PORT="4822"
MYSQL_PORT="3306"

# Proxy
PROXY_IP_DEF="1.2.3.4" # Default guacamole proxy IP

# Key Sizes
JKSTORE_KEY_SIZE_DEF="4096" # Default Java Keystore key-size
LE_KEY_SIZE_DEF="4096" # Default Let's Encrypt key-size
SSL_KEY_SIZE_DEF="4096" # Default Self-signed SSL key-size

# Default Credentials
MYSQL_PASSWD_DEF="guacamole" # Default MySQL/MariaDB root password
DB_NAME_DEF="guac_db" # Defualt database name
DB_USER_DEF="guac_adm" # Defualt database user name
DB_PASSWD_DEF="guacamole" # Defualt database password
JKS_GUAC_PASSWD_DEF="guacamole" # Default Java Keystore password
JKS_CACERT_PASSWD_DEF="guacamole" # Default CACert Java Keystore password, used with LDAPS

# Default OpenID Configuration
OPENID_AUTH_ENDPOINT_DEF="http://localhost:8081/auth/realms/guacamole/protocol/openid-connect/auth" # Default OPENID Auth Endpoint
OPENID_JKWS_ENDPOINT_DEF="http://localhost:8081/auth/realms/guacamole/protocol/openid-connect/certs" # Default OPENID JKWS Endpoint
OPENID_ISSUER_DEF="http://localhost:8081/auth/realms/guacamole" # Default OPENID Issuer
OPENID_CLIENT_ID_DEF="guacamole" # Default OPENID Client ID
OPENID_REDIRECT_URI_DEF="http://localhost:8081/guacamole" # Default OPENID Redirect URI
OPENID_CLAIM_DEF="preferred_username" # Default OPENID Username Claim Type
OPENID_SCOPE_DEF="openid email profile" # Default OPENID Scope

# Misc
GUACD_USER="guacd" # The user name and group of the user running the guacd service
GUAC_URIPATH_DEF="/" # Default URI for Guacamole
DOMAIN_NAME_DEF="localhost" # Default domain name of server
H_ERR=false # Defualt value of if an error has been triggered, should be false
LIBJPEG_EXCLUDE="exclude=libjpeg-turbo-[0-9]*,libjpeg-turbo-*.*.9[0-9]-*"
DEL_TMP_VAR=true # Default behavior to delete the temp var file used by error handler on completion. Set to false to keep the file to review last values
NAME_SERVERS_DEF="1.1.1.1 1.0.0.1 2606:4700:4700::1111 2606:4700:4700::1001" # OCSP resolver DNS name servers defaults !!Only used if the host does not have name servers in resolv.conf!!

# ONLY CHANGE IF NOT WORKING #
# URLS
MYSQL_CON_URL="https://dev.mysql.com/get/Downloads/Connector-J/" #Direct URL for download
LIBJPEG_REPO="https://libjpeg-turbo.org/pmwiki/uploads/Downloads/libjpeg-turbo.repo"

# Dirs and File Names
LIB_DIR="/var/lib/guacamole/"
GUAC_CONF="guacamole.properties" # Guacamole configuration/properties file
MYSQL_CON="mysql-connector-java-${MYSQL_CON_VER}"
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

#Set arch used in some paths
MACHINE_ARCH=`uname -m`
ARCH="64"

}

######  SOURCE VARIABLES  ############################################
src_vars () {
# Check if selected source is Git or stable release, set variables based on selection
if [ $GUAC_SOURCE == "Git" ]; then
	GUAC_VER=${GUAC_GIT_VER}
	GUAC_URL="git://github.com/apache/"
	GUAC_SERVER="guacamole-server.git"
	GUAC_CLIENT="guacamole-client.git"
else # Stable release
	GUAC_VER=${GUAC_STBL_VER}
	GUAC_URL="https://apache.org/dyn/closer.cgi?action=download&filename=guacamole/${GUAC_VER}/"
	GUAC_CLIENT_URL="https://dlcdn.apache.org/guacamole/${GUAC_VER}/"
	GUAC_SERVER="guacamole-server-${GUAC_VER}"
	GUAC_CLIENT="guacamole-${GUAC_VER}"
fi

# JDBC Extension file name
GUAC_JDBC="guacamole-auth-jdbc-${GUAC_VER}"


# OPENID Extension file name
GUAC_OPENID="guacamole-auth-sso-${GUAC_VER}"

# Dirs and file names
INSTALL_DIR="/usr/local/src/guacamole/${GUAC_VER}/" # Guacamole installation dir
FILENAME="${PWD}/guacamole-${GUAC_VER}_"$(date +"%d-%y-%b")"" # Script generated log filename
logfile="${FILENAME}.log" # Script generated log file full name
fwbkpfile="${FILENAME}.firewall.bkp" # Firewall backup file name
}

######################################################################
######  MENUS  #######################################################
######################################################################

######  SOURCE MENU  #################################################
src_menu () {
clear

echo -e "   ${Reset}${Bold}----====Gucamole Installation Script====----\n       ${Reset}Guacamole Remote Desktop Gateway\n"
echo -e "   ${Bold}***        Source Menu     ***\n"
echo "   OS: ${Yellow}${OS_NAME} ${MAJOR_VER}.${MINOR_VER} ${MACHINE_ARCH}${Reset}"
echo -e "   ${Bold}Stable Version: ${Yellow}${GUAC_STBL_VER}${Reset} || ${Bold}Git Version: ${Yellow}${GUAC_GIT_VER}${Reset}\n"

GUAC_SOURCE="Stable"

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
echo -e "   ${Bold}Source/Version: ${Yellow}${GUAC_SOURCE} ${GUAC_VER}${Reset}\n"
}

######  DATABASE AND JKS MENU  #######################################
db_menu () {
SUB_MENU_TITLE="Database and JKS Menu"

menu_header

echo -n "${Green} Enter the Guacamole DB name (default ${DB_NAME_DEF}): ${Yellow}"
	read DB_NAME
	DB_NAME=${DB_NAME:-${DB_NAME_DEF}}
echo -n "${Green} Enter the Guacamole DB username (default ${DB_USER_DEF}): ${Yellow}"
	read DB_USER
	DB_USER=${DB_USER:-${DB_USER_DEF}}
echo -n "${Green} Enter the Java KeyStore key-size to use (default ${JKSTORE_KEY_SIZE_DEF}): ${Yellow}"
	read JKSTORE_KEY_SIZE
	JKSTORE_KEY_SIZE=${JKSTORE_KEY_SIZE:-${JKSTORE_KEY_SIZE_DEF}}
}

######  OPENID MENU  #######################################
openid_menu () {
SUB_MENU_TITLE="OPENID Menu"

menu_header

echo -n "${Green} Enter the OpenID Authorization Endpoint (example http://openidhost/auth/realms/guacamole/protocol/openid-connect/auth): ${Yellow}"
        read OPENID_AUTH_ENDPOINT
        #OPENID_AUTH_ENDPOINT=${OPENID_AUTH_ENDPOINT:-${OPENID_AUTH_ENDPOINT_DEF}}
echo -n "${Green} Enter the OpenID JKWS Endpoint (example http://openidhost/auth/realms/guacamole/protocol/openid-connect/certs): ${Yellow}"
        read OPENID_JKWS_ENDPOINT
        #OPENID_JKWS_ENDPOINT=${OPENID_JKWS_ENDPOINT:-${OPENID_JKWS_ENDPOINT_DEF}}
echo -n "${Green} Enter the OpenID Issuer (example http://openidhost/auth/realms/guacamole): ${Yellow}"
        read OPENID_ISSUER
        #OPENID_ISSUER=${OPENID_ISSUER:-${OPENID_ISSUER_DEF}}
echo -n "${Green} Enter the OpenID Client ID (example guacamole): ${Yellow}"
        read OPENID_CLIENT_ID
        #OPENID_CLIENT_ID=${OPENID_CLIENT_ID:-${OPENID_CLIENT_ID_DEF}}
echo -n "${Green} Enter the OpenID Redirect URI (example http://guacamole.company.com): ${Yellow}"
        read OPENID_REDIRECT_URI
        #OPENID_REDIRECT_URI=${OPENID_REDIRECT_URI:-${OPENID_REDIRECT_URI_DEF}}
echo -n "${Green} Enter the OpenID Username Claim Type (example preferred_username): ${Yellow}"
        read OPENID_CLAIM
        #OPENID_CLAIM=${OPENID_CLAIM:-${OPENID_CLAIM_DEF}}
echo -n "${Green} Enter the OpenID Scope (example openid email profile): ${Yellow}"
        read OPENID_SCOPE
        #OPENID_SCOPE=${OPENID_SCOPE:-${OPENID_SCOPE_DEF}}
}

######  PASSWORDS MENU  ##############################################
pw_menu () {
SUB_MENU_TITLE="Passwords Menu"

menu_header

echo -n "${Green} Enter the root password for MariaDB: ${Yellow}"
	read MYSQL_PASSWD
	MYSQL_PASSWD=${MYSQL_PASSWD:-${MYSQL_PASSWD_DEF}}
echo -n "${Green} Enter the Guacamole DB password: ${Yellow}"
	read DB_PASSWD
	DB_PASSWD=${DB_PASSWD:-${DB_PASSWD_DEF}}
echo -n "${Green} Enter the Guacamole Java KeyStore password, must be 6 or more characters: ${Yellow}"
	read JKS_GUAC_PASSWD
	JKS_GUAC_PASSWD=${JKS_GUAC_PASSWD:-${JKS_GUAC_PASSWD_DEF}}
}

######  PRIMARY AUTHORIZATION EXTENSIONS MENU  #######################
prime_auth_ext_menu () {
SUB_MENU_TITLE="Primary Authentication Extensions Menu"

menu_header

INSTALL_OPENID=true

}

######  OPENID MENU  #################################################
OpenID_ext_menu () {
INSTALL_OPENID=true
SUB_MENU_TITLE="OpenID Extension Menu"

menu_header

####o "${Red} CAS extension not currently available via this script."
sleep 3
}

######  PROXY MENU  ##############################################
proxy_menu () {
SUB_MENU_TITLE="Proxy Menu"

menu_header

echo -n "${Green} Enter the IP address of the Proxy server: ${Yellow}"
        read PROXY_IP
        PROXY_IP=${PROXY_IP:-${PROXY_IP_DEF}}
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
options=("Database" "OpenID" "Passwords" "Primary Authentication Extension" "Proxy" "Accept and Run Installation" "Cancel and Start Over" "Cancel and Exit Script")
select opt in "${options[@]}"
do
	case $opt in
		"Database") sum_db; break;;
		"OpenID") sum_openid; break;;
		"Passwords") sum_pw; break;;
		"Primary Authentication Extension") sum_prime_auth_ext; break;;
                "Proxy") sum_proxy; break;;
		"Accept and Run Installation") RUN_INSTALL=true; break;;
		"Cancel and Start Over") ScriptLoc=$(readlink -f "$0"); exec "$ScriptLoc"; break;;
		"Cancel and Exit Script") tput sgr0; exit 1; break;;
		* ) echo "${Green} ${REPLY} is not a valid option, enter the number representing the category to review.";;
		esac
done
}

######  DATABASE SUMMARY  ############################################
sum_db () {
SUB_MENU_TITLE="Database Summary"

menu_header

echo "${Green} Guacamole DB name: ${Yellow}${DB_NAME}"
echo "${Green} Guacamole DB username: ${Yellow}${DB_USER}"
echo -e "${Green} Java KeyStore key-size: ${Yellow}${JKSTORE_KEY_SIZE}\n"

while true; do
	echo -n "${Green} Would you like to change these selections (default no)? ${Yellow}"
	read yn
	case $yn in
		[Yy]* ) db_menu; break;;
		[Nn]*|"" ) break;;
		* ) echo "${Green} Please enter yes or no. ${Yellow}";;
	esac
done

sum_menu
}

######  OPENID SUMMARY  ############################################
sum_openid () {
SUB_MENU_TITLE="OpenID Summary"

menu_header

echo "${Green} OPENID Authorization Endpoint: ${Yellow}${OPENID_AUTH_ENDPOINT}"
echo "${Green} OPENID JKWS Endpoint: ${Yellow}${OPENID_JKWS_ENDPOINT}"
echo "${Green} OPENID Issuer: ${Yellow}${OPENID_ISSUER}"
echo "${Green} OPENID Client ID: ${Yellow}${OPENID_CLIENT_ID}"
echo "${Green} OPENID Redirect URI: ${Yellow}${OPENID_REDIRECT_URI}"
echo "${Green} OPENID Username Claim Type: ${Yellow}${OPENID_CLAIM}"
echo -e "${Green} OPENID Scope: ${Yellow}${OPENID_SCOPE}\n"

while true; do
        echo -n "${Green} Would you like to change these selections (default no)? ${Yellow}"
        read yn
        case $yn in
                [Yy]* ) openid_menu; break;;
                [Nn]*|"" ) break;;
                * ) echo "${Green} Please enter yes or no. ${Yellow}";;
        esac
done

sum_menu
}

######  PASSWORD SUMMARY  ############################################
sum_pw () {
SUB_MENU_TITLE="Passwords Summary"

menu_header

echo "${Green} MariaDB root password: ${Yellow}${MYSQL_PASSWD}"
echo "${Green} Guacamole DB password: ${Yellow}${DB_PASSWD}"
echo -e "${Green} Guacamole Java KeyStore password: ${Yellow}${JKS_GUAC_PASSWD}\n"

while true; do
	echo -n "${Green} Would you like to change these selections (default no)? ${Yellow}"
	read yn
	case $yn in
		[Yy]* ) pw_menu; break;;
		[Nn]*|"" ) break;;
		* ) echo "${Green} Please enter yes or no. ${Yellow}";;
	esac
done

sum_menu
}

######  STANDARD EXTENSIONS SUMMARY  #################################
sum_prime_auth_ext () {
SUB_MENU_TITLE="Primary Authentication Extension Summary"

menu_header

echo -e "${Green} Primary Authentication type: ${Yellow}${PRIME_AUTH_TYPE}\n"

echo "${Yellow}${Bold} -- MariaDB is used with all authentication implementations --${Reset}"
echo "${Green} Default Guacamole username: ${Yellow}guacadmin"
echo -e "${Green} Default Guacamole password: ${Yellow}guacadmin\n"

# Check the authentication selection to display proper information for the selection
case $PRIME_AUTH_TYPE in
	"LDAP")
		echo -e "${Reset}${Bold} -- LDAP Specific Parameters --${Reset}\n"
		echo "${Green} Use LDAPS instead of LDAP: ${Yellow}${SECURE_LDAP}"
		echo -e "${Green} LDAP(S) port: ${Yellow}${LDAP_PORT}\n"

		if [ $SECURE_LDAP = true ]; then
			echo "${Green} LDAPS full filename and path: ${Yellow}${LDAPS_CERT_FULL}"
			echo -e "${Green} CACert Java Keystroe password: ${Yellow}${JKS_CACERT_PASSWD}\n"
		fi

		echo "${Green} LDAP Server Hostname (should be FQDN, Ex: ldaphost.domain.com): ${Yellow}${LDAP_HOSTNAME}"
		echo "${Green} LDAP User-Base-DN (Ex: dc=domain,dc=com): ${Yellow}${LDAP_BASE_DN}"
		echo "${Green} LDAP Search-Bind-DN (Ex: cn=user,ou=Admins,dc=domain,dc=com): ${Yellow}${LDAP_BIND_DN}"
		echo "${Green} LDAP Search-Bind-Password: ${Yellow}${LDAP_BIND_PW}"
		echo "${Green} LDAP Username-Attribute: ${Yellow}${LDAP_UNAME_ATTR}"
		echo -e "${Green} LDAP user search filter: ${Yellow}${LDAP_SEARCH_FILTER}\n"
		;;
	"RADIUS")
		echo -e "${Red} RADIUS cannot currently be installed by this script.\n"
		;;
	"OpenID")
		echo -e "${Red} OpenID cannot currently be installed by this script.\n"
		;;
	"CAS")
		echo -e "${Red} CAS cannot currently be installed by this script.\n"
		;;
esac

while true; do
	echo -n "${Green} Would you like to change the authentication method and properties (default no)? ${Yellow}"
	read yn
	case $yn in
		[Yy]* ) prime_auth_ext_menu; break;;
		[Nn]*|"" ) break;;
		* ) echo "${Green} Please enter yes or no. ${Yellow}";;
	esac
done

sum_menu
}

######  PROXY SUMMARY  ############################################
sum_proxy () {
SUB_MENU_TITLE="Proxy Summary"

menu_header

echo -e "${Green} Proxy IP Address: ${Yellow}${PROXY_IP}\n"

while true; do
        echo -n "${Green} Would you like to change these selections (default no)? ${Yellow}"
        read yn
        case $yn in
                [Yy]* ) proxy_menu; break;;
                [Nn]*|"" ) break;;
                * ) echo "${Green} Please enter yes or no. ${Yellow}";;
        esac
done

sum_menu
}

######  MENU EXECUTION  ##############################################
db_menu
pw_menu
openid_menu
prime_auth_ext_menu
proxy_menu
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

######################################################################
######  INSALLATION  #################################################
######################################################################

######  REPOS INSTALLATION  ##########################################
reposinstall () {
s_echo "n" "${Bold}   ----==== INSTALLING GUACAMOLE ${GUAC_SOURCE} ${GUAC_VER} ====----"
s_echo "y" "Installing Repos"

# Install EPEL Repo
chk_installed "epel-release"

if [ $RETVAL -eq 0 ]; then
	s_echo "n" "${Reset}-EPEL is installed."
else
	{ rpm -Uvh https://dl.fedoraproject.org/pub/epel/epel-release-latest-${MAJOR_VER}.noarch.rpm; } &
	s_echo "n" "${Reset}-EPEL is missing. Installing...    "; spinner
fi

# Install RPMFusion Repo
chk_installed "rpmfusion-free-release"

if [ $RETVAL -eq 0 ]; then
	s_echo "n" "-RPMFusion is installed."
else
	{ rpm -Uvh https://download1.rpmfusion.org/free/el/rpmfusion-free-release-${MAJOR_VER}.noarch.rpm; } &
	s_echo "n" "-RPMFusion is missing. Installing...    "; spinner
fi

# Install libjpeg-turbo Repo
{
	yum install -y wget
	wget ${LIBJPEG_REPO} -P /etc/yum.repos.d/ --no-check-certificate

	# Exclude beta releases
	sed -i "s/exclude.*/${LIBJPEG_EXCLUDE}/g" /etc/yum.repos.d/libjpeg-turbo.repo
} &
s_echo "n" "-Installing libjpeg-turbo repo...    "; spinner

# Install MariaDB Repo
{ yum install wget -y
wget https://downloads.mariadb.com/MariaDB/mariadb_repo_setup
chmod +x mariadb_repo_setup
./mariadb_repo_setup
rm mariadb_repo_setup ;} &
s_echo "n" "${Reset}-Installing MariaDB repo...    "; spinner

# Enable repos needed if using RHEL
if [ $OS_NAME == "RHEL" ] ; then
	{ subscription-manager repos --enable "rhel-*-optional-rpms" --enable "rhel-*-extras-rpms"; } &
	s_echo "n" "-Enabling ${OS_NAME} optional and extras repos...    "; spinner
fi

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
s_echo "y" "${Bold}Installing Required Dependencies"

# Remove unnecessary packages
{ yum remove java-1.8.0-openjdk-headless java-1.8.0-openjdk -y ;} &
s_echo "n" "${Reset}-Removing unnecessary packages...    "; spinner

# Install Required Packages
{
	yum install -y java-11-openjdk-devel cairo-devel ffmpeg-devel freerdp-devel freerdp-plugins gcc gnu-free-mono-fonts libjpeg-turbo-devel libjpeg-turbo-official libpng-devel libssh2-devel libtelnet-devel libvncserver-devel libvorbis-devel libwebp-devel libwebsockets-devel mariadb mariadb-server openssl-devel pango-devel policycoreutils-python pulseaudio-libs-devel setroubleshoot uuid-devel
} &
s_echo "n" "${Reset}-Installing required packages...    "; spinner

# Install Tomcat
{
useradd -m -U -d /opt/tomcat -s /bin/false tomcat || echo "User already exists."
cd /tmp
wget https://archive.apache.org/dist/tomcat/tomcat-9/v${TOMCAT_VER}/bin/apache-tomcat-${TOMCAT_VER}.tar.gz
tar -xf apache-tomcat-${TOMCAT_VER}.tar.gz
mv -n apache-tomcat-${TOMCAT_VER} /opt/tomcat/
ln -sfn /opt/tomcat/apache-tomcat-${TOMCAT_VER} /opt/tomcat/latest
chown -R tomcat: /opt/tomcat
chmod +x /opt/tomcat/latest/bin/*.sh
cat <<EOF >/etc/systemd/system/tomcat.service 
[Unit]
Description=Tomcat 9 servlet container
After=network.target

[Service]
Type=forking

User=tomcat
Group=tomcat

Environment="JAVA_HOME=/usr/lib/jvm/jre"
Environment="JAVA_OPTS=-Djava.security.egd=file:///dev/urandom"

Environment="CATALINA_BASE=/opt/tomcat/latest"
Environment="CATALINA_HOME=/opt/tomcat/latest"
Environment="CATALINA_PID=/opt/tomcat/latest/temp/tomcat.pid"
Environment="CATALINA_OPTS=-Xms512M -Xmx1024M -server -XX:+UseParallelGC"

ExecStart=/opt/tomcat/latest/bin/startup.sh
ExecStop=/opt/tomcat/latest/bin/shutdown.sh

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable tomcat
systemctl start tomcat ;} &
s_echo "n" "${Reset}-Installing tomcat...    "; spinner


# Additional packages required by git
if [ $GUAC_SOURCE == "Git" ]; then
	{ yum install -y git libtool; } &
	s_echo "n" "-Installing packages required for git...    "; spinner

fi

createdirs
}

######  CREATE DIRECTORIES  ##########################################
createdirs () {
{
	rm -fr ${INSTALL_DIR}
	mkdir -vp /etc/guacamole/extensions
	mkdir -vp ${INSTALL_DIR}{client,selinux}
	mkdir -vp ${LIB_DIR}{extensions,lib}
	mkdir -vp /usr/share/tomcat/.guacamole/
	mkdir -vp /opt/tomcat
} &
s_echo "y" "${Bold}Creating Required Directories...    "; spinner

cd ${INSTALL_DIR}

downloadguac
}

######  DOWNLOAD GUACAMOLE  ##########################################
downloadguac () {
s_echo "y" "${Bold}Downloading Guacamole Packages"

	# MySQL Connector
	downloadmysqlconn () {
		{ wget ${MYSQL_CON_URL}${MYSQL_CON}.tar.gz; } &
		s_echo "n" "-Downloading MySQL Connector package for installation...    "; spinner
	}

if [ $GUAC_SOURCE == "Git" ]; then
	{ git clone ${GUAC_URL}${GUAC_SERVER}; } &
	s_echo "n" "${Reset}-Cloning Guacamole Server package from git...    "; spinner
	{ git clone ${GUAC_URL}${GUAC_CLIENT}; } &
	s_echo "n" "-Cloning Guacamole Client package from git...    "; spinner
	downloadmysqlconn
else # Stable release
	{ wget "${GUAC_CLIENT_URL}binary/${GUAC_CLIENT}.war" -O ${INSTALL_DIR}client/guacamole.war; } &
	s_echo "n" "-Downloading Guacamole Client package for installation...    "; spinner
	{ wget "${GUAC_URL}binary/${GUAC_JDBC}.tar.gz" -O ${GUAC_JDBC}.tar.gz; } &
	s_echo "n" "-Downloading Guacamole JDBC Extension package for installation...    "; spinner
        { wget "${GUAC_URL}binary/${GUAC_OPENID}.tar.gz" -O ${GUAC_OPENID}.tar.gz; } &
        s_echo "n" "-Downloading Guacamole OpenID Extension package for installation...    "; spinner
	downloadmysqlconn

	# Decompress Guacamole Packages
	s_echo "y" "${Bold}Decompressing Guacamole Packages"

	{
		tar xzvf ${GUAC_JDBC}.tar.gz
		rm -f ${GUAC_JDBC}.tar.gz
		mv -v ${GUAC_JDBC} extension
		mv -v extension/mysql/guacamole-auth-jdbc-mysql-${GUAC_VER}.jar /etc/guacamole/extensions/guacamole-auth-2-jdbc-mysql-${GUAC_VER}.jar
	} &
	s_echo "n" "-Decompressing Guacamole JDBC extension...    "; spinner

        {
                tar xzvf ${GUAC_OPENID}.tar.gz
                rm -f ${GUAC_OPENID}.tar.gz
                mv -v ${GUAC_OPENID} extension 
                mv -v extension/guacamole-auth-sso-${GUAC_VER}/openid/guacamole-auth-sso-openid-${GUAC_VER}.jar /etc/guacamole/extensions/guacamole-auth-1-openid-${GUAC_VER}.jar
        } &
        s_echo "n" "-Decompressing Guacamole OpenID extension...    "; spinner
fi

{
	tar xzvf ${MYSQL_CON}.tar.gz
	rm -f ${MYSQL_CON}.tar.gz
	mv -v ${MYSQL_CON}/${MYSQL_CON}.jar /opt/tomcat/latest/lib/
} &
s_echo "n" "-Decompressing MySQL Connector...    "; spinner

installguacserver
}

######  INSTALL GUACAMOLE SERVER  ####################################
installguacserver () {
s_echo "y" "${Bold}Install Guacamole Server"

if [ $GUAC_SOURCE == "Git" ]; then
	cd guacamole-server/
	{ autoreconf -fi; } &
	s_echo "n" "${Reset}-Guacamole Server compile prep...    "; spinner
else # Stable release
	yum install guacd -y &
        s_echo "n" "-Installing Guacamole Server...    "; spinner
fi

installguacclient
}

######  INSTALL GUACAMOLE CLIENT  ####################################
installguacclient () {
s_echo "y" "${Bold}Install Guacamole Client"

if [ $GUAC_SOURCE == "Git" ]; then
	cd guacamole-client/
	{ mvn package; } &
	s_echo "n" "${Reset}-Compiling Guacamole Client...    "; spinner

	{ mv -v guacamole/target/guacamole-${GUAC_VER}.war ${LIB_DIR}guacamole.war; } &
	s_echo "n" "-Moving Guacamole Client...    "; spinner
	cd ..
else # Stable release
	{ mv -v client/guacamole.war ${LIB_DIR}guacamole.war; } &
	s_echo "n" "${Reset}-Moving Guacamole Client...    "; spinner
fi

finishguac
}

######  FINALIZE GUACAMOLE INSTALLATION  #############################
finishguac () {
s_echo "y" "${Bold}Setup Guacamole"

# Generate Guacamole Configuration File
{ echo "# Hostname and port of guacamole proxy
guacd-hostname: localhost
guacd-port:     ${GUAC_PORT}
# OpenID properties
openid-authorization-endpoint: ${OPENID_AUTH_ENDPOINT}
openid-jwks-endpoint: ${OPENID_JKWS_ENDPOINT}
openid-issuer: ${OPENID_ISSUER}
openid-client-id: ${OPENID_CLIENT_ID}
openid-redirect-uri: ${OPENID_REDIRECT_URI}
openid-username-claim-type: ${OPENID_CLAIM}
openid-scope: ${OPENID_SCOPE}
# MySQL properties
mysql-hostname: localhost
mysql-port: ${MYSQL_PORT}
mysql-database: ${DB_NAME}
mysql-username: ${DB_USER}
mysql-password: ${DB_PASSWD}
mysql-default-max-connections-per-user: 0
mysql-default-max-group-connections-per-user: 0
mysql-user-required: false
mysql-auto-create-accounts: true" > /etc/guacamole/${GUAC_CONF}; } &
s_echo "n" "${Reset}-Generating Guacamole configuration file...    "; spinner

# Create Required Symlinks for Guacamole
{
	ln -vfs ${LIB_DIR}guacamole.war /opt/tomcat/latest/webapps
	ln -vfs /etc/guacamole/${GUAC_CONF} /usr/share/tomcat/.guacamole/
	ln -vfs ${LIB_DIR}lib/ /usr/share/tomcat/.guacamole/
	ln -vfs ${LIB_DIR}extensions/ /usr/share/tomcat/.guacamole/
	ln -vfs /usr/local/lib/freerdp/guac* /usr/lib${ARCH}/freerdp
} &
s_echo "n" "-Making required symlinks...    "; spinner

# Copy JDBC if using git
if [ $GUAC_SOURCE == "Git" ]; then
	# Get JDBC from compiled client
	{ find ./guacamole-client/extensions -name "guacamole-auth-jdbc-mysql-${GUAC_VER}.jar" -exec mv -v {} ${LIB_DIR}extensions/ \;; } &
	s_echo "n" "-Moving Guacamole JDBC extension to extensions dir...    "; spinner
fi

appconfigs
}

######  DATABASE/TOMCAT/JKS SETUP  ###################################
appconfigs () {
s_echo "y" "${Bold}Configure MariaDB"

# Enable/Start MariaDB/MySQL Service
{
	systemctl enable mariadb.service
	systemctl restart mariadb.service
} &
s_echo "n" "${Reset}-Enable & start MariaDB service...    "; spinner

# Set MariaDB/MySQL Root Password
{ mysqladmin -u root password ${MYSQL_PASSWD}; } &
s_echo "n" "-Setting root password for MariaDB...    "; spinner

# Run MariaDB/MySQL Secure Install
{
	mariadb-secure-installation <<EOF
${MYSQL_PASSWD}
n
y
y
y
y
EOF
} &
s_echo "n" "-Harden MariaDB...    "; spinner

# Create Database and user
{
	mysql -u root -p${MYSQL_PASSWD} -e "CREATE DATABASE IF NOT EXISTS ${DB_NAME};"
	mysql -u root -p${MYSQL_PASSWD} -e "GRANT SELECT,INSERT,UPDATE,DELETE ON ${DB_NAME}.* TO '${DB_USER}'@'localhost' IDENTIFIED BY '${DB_PASSWD}';"
	mysql -u root -p${MYSQL_PASSWD} -e "FLUSH PRIVILEGES;"
} &
s_echo "n" "-Creating Database & User for Guacamole...    "; spinner

# Create Guacamole Table
{
	if [ $GUAC_SOURCE == "Git" ]; then
		cat guacamole-client/extensions/guacamole-auth-jdbc/modules/guacamole-auth-jdbc-mysql/schema/*.sql | mysql -u root -p${MYSQL_PASSWD} -D ${DB_NAME}
	else # Stable release
		cat extension/mysql/schema/*.sql | mysql -u root -p${MYSQL_PASSWD} -D ${DB_NAME}
	fi
} &
s_echo "n" "-Creating Guacamole Tables...    "; spinner

# Populate mysql database with time zones from system
# Fixes timezone issues when using MySQLConnectorJ 8.x or geater
{
	mysql_tzinfo_to_sql /usr/share/zoneinfo | mysql -u root mysql -p${MYSQL_PASSWD}
	MY_CNF_LINE=`grep -n "\[mysqld\]" /etc/my.cnf.d/server.cnf | grep -o '^[0-9]*'`
	MY_CNF_LINE=$((MY_CNF_LINE + 1 ))
	MY_TZ=`readlink /etc/localtime | sed "s/.*\/usr\/share\/zoneinfo\///"`
	sed -i "${MY_CNF_LINE}i default-time-zone='${MY_TZ}'" /etc/my.cnf.d/server.cnf
	systemctl restart mariadb
} &
s_echo "n" "-Setting Time Zone Database & Config...    "; spinner

# Setup Tomcat
s_echo "y" "${Bold}Setup Tomcat Server"

{
	sed -i '72i URIEncoding="UTF-8"' /opt/tomcat/latest/conf/server.xml
	sed -i '92i <Connector port="8443" protocol="HTTP/1.1" SSLEnabled="true" \
							maxThreads="150" scheme="https" secure="true" \
							clientAuth="false" sslProtocol="TLS" \
							keystoreFile="/opt/tomcat/latest/webapps/.keystore" \
							keystorePass="JKS_GUAC_PASSWD" \
							URIEncoding="UTF-8" />' /opt/tomcat/latest/conf/server.xml
	sed -i "s/JKS_GUAC_PASSWD/${JKS_GUAC_PASSWD}/g" /opt/tomcat/latest/conf/server.xml
} &
s_echo "n" "${Reset}-Base Tomcat configuration...    "; spinner

{
# Tomcat RemoteIpValve (to pass remote host IP's from proxy to tomcat. Allows Guacamole to log remote host IPs)
	sed -i '/<\/Host>/i\<Valve className="org.apache.catalina.valves.RemoteIpValve" \
							internalProxies="GUAC_SERVER_IP" \
							remoteIpHeader="x-forwarded-for" \
							remoteIpProxiesHeader="x-forwarded-by" \
							protocolHeader="x-forwarded-proto" />' /opt/tomcat/latest/conf/server.xml

	sed -i "s/GUAC_SERVER_IP/${GUAC_LAN_IP}/g" /opt/tomcat/latest/conf/server.xml
} &
s_echo "n" "-Set RemoteIpValve in Tomcat configuration...    "; spinner

{
# Add ErrorReportingValve to prevent displaying tomcat info on error pages
	sed -i '/<\/Host>/i\<Valve className="org.apache.catalina.valves.ErrorReportValve" \
							showReport="false" \
							showServerInfo="false"/>' /opt/tomcat/latest/conf/server.xml
} &
s_echo "n" "-Set ErrorReportingVavle in Tomcat configuration...    "; spinner

# Java KeyStore Setup
{ keytool -genkey -alias Guacamole -keyalg RSA -keysize ${JKSTORE_KEY_SIZE} -keystore /opt/tomcat/latest/webapps/.keystore -storepass ${JKS_GUAC_PASSWD} -keypass ${JKS_GUAC_PASSWD} -noprompt -dname "CN='', OU='', O='', L='', S='', C=''"; } &
s_echo "y" "${Bold}Configuring the Java KeyStore...    "; spinner

# Enable/Start Tomcat and Guacamole Services
{
	systemctl enable tomcat
	systemctl restart tomcat
	systemctl enable guacd
	systemctl restart guacd
} &
s_echo "y" "${Bold}Enable & Start Tomcat and Guacamole Services...    "; spinner

selinuxsettings
}

######  SELINUX SETTINGS  ############################################
selinuxsettings () {
{
	# Set Booleans
	setsebool -P httpd_can_network_connect 1
	setsebool -P httpd_can_network_relay 1
	setsebool -P tomcat_can_network_connect_db 1

	# Guacamole Client Context
	semanage fcontext -a -t tomcat_exec_t "${LIB_DIR}guacamole.war"
	restorecon -v "${LIB_DIR}guacamole.war"

	# Guacamole JDBC Extension Context
	semanage fcontext -a -t tomcat_exec_t "/etc/guacamole/extensions/guacamole-auth-2-jdbc-mysql-${GUAC_VER}.jar"
	restorecon -v "/etc/guacamole/extensions/guacamole-auth-2-jdbc-mysql-${GUAC_VER}.jar"

	# MySQL Connector Extension Context
	semanage fcontext -a -t tomcat_exec_t "/opt/tomcat/latest/lib/${MYSQL_CON}.jar"
	restorecon -v "/opt/tomcat/latest/lib/${MYSQL_CON}.jar"

	# Guacamole OpenID Extension Context (If selected)
	if [ $INSTALL_OPENID = true ]; then
		# Placehold until extension is added
		echo "openid true"
        	semanage fcontext -a -t tomcat_exec_t "/etc/guacamole/extensions/guacamole-auth-1-openid-${GUAC_VER}.jar"
        	restorecon -v "/etc/guacamole/extensions/guacamole-auth-1-openid-${GUAC_VER}.jar"
	fi

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

# Open 8080 port. Need to review if this is required or not
{
	echo -e "Add new rule...\nfirewall-cmd --permanent --zone=public --add-port=8080/tcp"
	firewall-cmd --permanent --zone=public --add-rich-rule='rule family="ipv4" source address='"${PROXY_IP}/32"' port protocol="tcp" port="8080" accept'

} &
s_echo "n" "-Opening ports 8080 on TCP...    "; spinner

#echo -e "Reload firewall...\nfirewall-cmd --reload\n"
{ firewall-cmd --reload; } &
s_echo "n" "-Reloading firewall...    "; spinner

showmessages
}

######  COMPLETION MESSAGES  #########################################
showmessages () {
s_echo "y" "${Bold}Services"

# Restart all services and log status
{
	systemctl restart tomcat
	systemctl status tomcat
	systemctl restart guacd
	systemctl status guacd
	systemctl restart mariadb
	systemctl status mariadb

	# Verify that the guacd user is running guacd
	ps aux | grep ${GUACD_USER}
	ps -U ${GUACD_USER}
} &
s_echo "n" "${Reset}-Restarting all services...    "; spinner

# Completion messages
s_echo "y" "${Bold}${Green}##### Installation Complete! #####${Reset}"

s_echo "y" "${Bold}Log Files"
s_echo "n" "${Reset}-Log file: ${logfile}"
s_echo "n" "-firewall backup file: ${fwbkpfile}"

# Manage Guac

# Recommendations
s_echo "y" "${Red}Important${Reset}"

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
