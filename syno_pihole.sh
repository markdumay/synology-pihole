#!/bin/sh

#======================================================================================================================
# Title         : syno_pihole.sh
# Description   : Install or Update Pi-Hole as Docker Container on a Synology NAS with a Static IP Address
# Author        : Mark Dumay
# Date          : September 19th, 2020
# Version       : 0.9
# Usage         : sudo ./syno_pihole.sh [OPTIONS] COMMAND
# Repository    : https://github.com/markdumay/synology-pihole.git
# License       : MIT - https://github.com/markdumay/synology-pihole/blob/master/LICENSE
# Credits       : Inspired by https://gist.github.com/xirixiz/ecad37bac9a07c2a1204ab4f9a17db3c
#======================================================================================================================

#======================================================================================================================
# Constants
#======================================================================================================================
RED='\033[0;31m' # Red color
GREEN='\033[0;32m' # Green color
NC='\033[0m' # No Color
BOLD='\033[1m' #Bold color

DSM_SUPPORTED_VERSION=6
SYNO_DOCKER_SERV_NAME=pkgctl-Docker
DEFAULT_PIHOLE_VERSION='5.1.2'
COMPOSE_FILE='docker-compose.yml'
TEMPLATE_FILE='docker-compose-template.yml'
GITHUB_API_PIHOLE=https://api.github.com/repos/pi-hole/docker-pi-hole/releases/latest
PIHOLE_CONTAINER='pihole'
PI_TIMEOUT=120 # timeout to wait for Pi-hole response (in seconds)
NW_TIMEOUT=600 # timeout to wait for network response (in seconds)


#======================================================================================================================
# Variables
#======================================================================================================================
PARAM_PIHOLE_IP=''
PARAM_SUBNET=''
PARAM_GATEWAY=''
PARAM_IP_RANGE=''
PARAM_VLAN_NAME=''
PARAM_INTERFACE=''
PARAM_MAC_ADDRESS=''
PARAM_DOMAIN_NAME=''
PARAM_PIHOLE_HOSTNAME=''
PARAM_TIMEZONE=''
PARAM_DNS1=''
PARAM_DNS2=''
PARAM_DATA_PATH=''
PARAM_WEBPASSWORD=''
PARAM_LOG_FILE=''
INFO_NETWORK_IP=''
INFO_BROADCAST_IP=''
FORCE='false'
LOG_PREFIX=''
COMMAND=''
STEP=0
TOTAL_STEPS=1
WORKDIR="$(dirname "$(readlink -f "$0")")" # initialize working directory


#======================================================================================================================
# Helper Functions
#======================================================================================================================

# Display script header
show_header() {
    [ ! -z "$LOG_PREFIX" ] && return

    echo "Install or Update Pi-hole as Docker container on Synology"
    echo
}

# Display usage message
usage() { 
    echo "Usage: $0 [OPTIONS] COMMAND" 
    echo
    echo "Options:"
    echo "  -f, --force            Force update (bypass compatibility check and confirmation check)"
    echo "  -l, --log [LOG FILE]   Display messages in log format, adding to [LOG FILE] if provided"
    echo
    echo "Commands:"
    echo "  install [PARAMETERS]   Install Pi-hole"
    echo "  network                Create or recreate virtual network"
    echo "  update                 Update Pi-hole to latest version using existing settings"
    echo
    echo "Installation parameters:"
    echo "  -i, --ip               Static IP address of Pi-hole (required)"
    echo "  -s, --subnet           Subnet of the virtual network"
    echo "  -g, --gateway          Gateway of the virtual network"
    echo "  -r, --range            IP range with CIDR notation of the virtual network"
    echo "  -v, --vlan             Name of the virtual network"
    echo "  -n, --interface        Physical interface of the virtual network"
    echo "  -m, --mac              Unicast MAC address"
    echo "  -d, --domain           Fully qualified domain name"
    echo "  -H, --host             Hostname of Pi-hole"
    echo "  -t, --timezone         Timezone for Pi-hole"
    echo "      --DNS1             Primary DNS provider"
    echo "      --DNS2             Alternative DNS provider"
    echo "      --path             Path where to store Pi-hole data"
    echo "  -p, --password         Password for the Pi-hole admin"
    echo
}

# Display error message and terminate with non-zero error
terminate() {
    echo -e "${RED}${BOLD}${LOG_PREFIX}ERROR: $1${NC}" 1>&2
    if [ ! -z "$PARAM_LOG_FILE" ] ; then
        echo "${LOG_PREFIX}ERROR: $1" >> "$PARAM_LOG_FILE"
    fi
    exit 1
}

# Prints current progress to the console
print_status() {
    ((STEP++))
    echo -e "${BOLD}${LOG_PREFIX}Step $STEP from $TOTAL_STEPS: $1${NC}"
    if [ ! -z "$PARAM_LOG_FILE" ] ; then
        echo "${LOG_PREFIX}Step $STEP from $TOTAL_STEPS: $1" >> "$PARAM_LOG_FILE"
    fi
}

# Prints current progress to the console in normal or logging format
log() {
    echo "${LOG_PREFIX}$1"
    if [ ! -z "$PARAM_LOG_FILE" ] ; then
        echo "${LOG_PREFIX}$1" >> "$PARAM_LOG_FILE"
    fi
}

# Returns 0 (successful) is data path is available or successfully created; adjusts $PARAM_DATA_PATH" to absolute path
validate_provided_path() {
    # cut trailing '/' and convert to absolute path
    PARAM_DATA_PATH=$(readlink -f "$PARAM_DATA_PATH")

    # create path if needed
    mkdir -p "$PARAM_DATA_PATH"

    # check path exists
    [ -d "$PARAM_DATA_PATH" ] && return 0 || return 1
}

# Returns 0 (successful) is file path is available; adjusts $PARAM_LOG_FILE" to absolute path
is_valid_log_file() {
    # cut trailing '/' and convert to absolute path
    PARAM_LOG_FILE=$(readlink -f "$PARAM_LOG_FILE")

    # check path exists
    local DIR=$(dirname "$PARAM_LOG_FILE")
    [ -d "$DIR" ] && return 0 || return 1
}

# Returns 0 (successful) if version string complies with expected format
is_valid_version() {
    local IP_VERSION='([0-9]+\.)?([0-9]+\.)?(\*|[0-9]+)'
    [[ $1 =~ ^$IP_VERSION$ ]] && return 0 || return 1
}

# Returns 0 (successful) if an IPv4 address complies with expected format
is_valid_ip() {
    local IP_REGEX='(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}'
    [[ $1 =~ ^$IP_REGEX$ ]] && return 0 || return 1
}

# Returns 0 (successful) if an IPv4 address and routing suffix (CIDR format) comply with expected format
is_valid_cidr_network() {
    local CIDR_REGEX='(((25[0-5]|2[0-4][0-9]|1?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|1?[0-9][0-9]?))'
    CIDR_REGEX+='(\/([8-9]|[1-2][0-9]|3[0-2]))([^0-9.]|$)'
    [[ $1 =~ ^$CIDR_REGEX$ ]] && return 0 || return 1
}

# Returns 0 (successful) if a MAC address complies with expected unicast format (using ':' separator)
is_valid_mac_address() {
    local MAC_REGEX='([a-fA-F0-9]{2}:){5}[a-fA-F0-9]{2}'
    local UNICAST=$(echo "$1" | sed -e 's/^\(.\)[13579bdf]/\10/') # parses unicast MAC from input
    [[ $1 =~ ^$MAC_REGEX$ ]] && [[ $1 == "$UNICAST" ]]  && return 0 || return 1
}

# Converts an IP address ($1) to an integer
function convert_ip_to_int() {
    local IFS_BACKUP="$IFS"
    IFS=. read -r a b c d <<< "$1"
    echo "$((a * 256 ** 3 + b * 256 ** 2 + c * 256 + d))"
    IFS="$IFS_BACKUP"
}

# Returns 0 if an IP address ($1) is in available CIDR range ($2), returns 1 otherwise
# Assumes IP address and CIDR range are valid parameters
# Note: the network address and broadcast address are considered unavailable
function is_ip_in_range() {
    local IP=($1)
    local IP_CIDR=($2)

    local IP_INT=$(convert_ip_to_int "$IP")
    local HOSTMIN=$(ipcalc -n "$IP_CIDR" | cut -f2 -d=)  # network address is start of the range
    local HOSTMAX=$(ipcalc -b "$IP_CIDR" | cut -f2 -d=)  # broadcast address is end of the range
    local HOSTMIN_INT=$(convert_ip_to_int "$HOSTMIN")
    local HOSTMAX_INT=$(convert_ip_to_int "$HOSTMAX")

    [ "$IP_INT" -gt "$HOSTMIN_INT" ] && [ "$IP_INT" -lt "$HOSTMAX_INT" ] && return 0 || return 1
}

# Detects available versions for Pi-hole
detect_available_versions() {
    # Detect latest available stable Pi-hole version (ignores release candidates)
    if [ -z "$TARGET_PIHOLE_VERSION" ] ; then
        TARGET_PIHOLE_VERSION=$(curl -s "$GITHUB_API_PIHOLE" | grep "tag_name" | egrep -o "[0-9]+.[0-9]+.[0-9]+")

        if [ -z "$TARGET_PIHOLE_VERSION" ] ; then
            log "Could not detect latest available Pi-hole version, setting default value"
            TARGET_PIHOLE_VERSION="$DEFAULT_PIHOLE_VERSION"
        fi
    fi
}

# Initialize environment variables and default settings
init_env() {
    # read environment variables if .env file is present
    local ENV_FILE="$WORKDIR/.env"
    if [ -f "$ENV_FILE" ]; then
        export $(echo $(cat "$ENV_FILE" | sed 's/#.*//g'| xargs))
    fi

    # initialize optional parameters with either provided or default values
    [ -z "$PARAM_VLAN_NAME" ] && PARAM_VLAN_NAME=${VLAN_NAME:-macvlan0}
    [ -z "$PARAM_PIHOLE_HOSTNAME" ] && PARAM_PIHOLE_HOSTNAME=${PIHOLE_HOSTNAME:-pihole}
    [ -z "$PARAM_DNS1" ] && PARAM_DNS1=${DNS1:-1.1.1.1}
    [ -z "$PARAM_DNS2" ] && PARAM_DNS2=${DNS2:-1.0.0.1}
    [ -z "$PARAM_DATA_PATH" ] && PARAM_DATA_PATH=${DATA_PATH:-./data}
    [ -z "$PARAM_DOMAIN_NAME" ] && PARAM_DOMAIN_NAME=${DOMAIN_NAME:-"$PARAM_PIHOLE_HOSTNAME".local}

    # initialize provided parameters
    [ -z "$PARAM_PIHOLE_IP" ] && PARAM_PIHOLE_IP=${PIHOLE_IP}
    [ -z "$PARAM_SUBNET" ] && PARAM_SUBNET=${SUBNET}
    [ -z "$PARAM_GATEWAY" ] && PARAM_GATEWAY=${GATEWAY}
    [ -z "$PARAM_IP_RANGE" ] && PARAM_IP_RANGE=${IP_RANGE}
    [ -z "$PARAM_INTERFACE" ] && PARAM_INTERFACE=${INTERFACE}
    [ -z "$PARAM_MAC_ADDRESS" ] && PARAM_MAC_ADDRESS=${MAC_ADDRESS}
    [ -z "$PARAM_TIMEZONE" ] && PARAM_TIMEZONE=${TIMEZONE}
    [ -z "$PARAM_WEBPASSWORD" ] && PARAM_WEBPASSWORD=${WEBPASSWORD}

    # validate mandatory parameters are available
    is_valid_ip "$PARAM_PIHOLE_IP"
    [ $? == 1 ] && terminate "No valid IP address provided"
}

# initialize auto-detected settings for omitted parameters
init_auto_detected_values() {
    # add auto-detected settings for omitted parameters
    if [ -z "$PARAM_SUBNET" ] ; then
        HOST_IP=$(ip route list | grep "default" | awk '{print $7}')
        PARAM_SUBNET=$(ip route list | grep "proto" | grep "$HOST_IP" | awk '{print $1}')
    fi

    if [ -z "$PARAM_GATEWAY" ] ; then
        PARAM_GATEWAY=$(ip route list | grep "default" | awk '{print $3}')
    fi
    
    if [ -z "$PARAM_IP_RANGE" ] && [ ! -z "$PARAM_PIHOLE_IP" ] ; then
        # Find network address for minimum range containing Pi-hole IP (4 addresses)
        # Note: the network address or broadcast address might clash with the Pi-hole IP (validate with is_ip_in_range)
        local HOSTMIN=$(ipcalc -n "$PARAM_PIHOLE_IP/30" | cut -f2 -d=)  # network address is start of the range
        PARAM_IP_RANGE="$HOSTMIN/30"
    fi

    if [ -z "$PARAM_INTERFACE" ] ; then
        PARAM_INTERFACE=$(ip route list | grep "default" | awk '{print $5}')
    fi

    if [ -z "$PARAM_MAC_ADDRESS" ] ; then
        # generate random unicast MAC address
        PARAM_MAC_ADDRESS=$(od -An -N6 -tx1 /dev/urandom | \
            sed -e 's/^  *//' -e 's/  */:/g' -e 's/:$//' -e 's/^\(.\)[13579bdf]/\10/')
    fi

    if [ -z "$PARAM_TIMEZONE" ] ; then
        PARAM_TIMEZONE=$(find /usr/share/zoneinfo/ -type f -exec sh -c "diff -q /etc/localtime '{}' \
            > /dev/null && echo {}" \; | sed 's|/usr/share/zoneinfo/||g')
    fi

    # initialize informational parameters
    is_valid_cidr_network "$PARAM_IP_RANGE"
    if [ $? == 0 ] ; then
        INFO_NETWORK_IP=$(ipcalc -n "$PARAM_IP_RANGE" | cut -f2 -d=)  # network address of the range
        INFO_BROADCAST_IP=$(ipcalc -b "$PARAM_IP_RANGE" | cut -f2 -d=)  # broadcast address of the range
    fi
}

# Replaces escaped old string $1 with escaped new string $2 in file $3
safe_replace_in_file() {
    local OLD="$1"
    local NEW="$2"
    local FILE="${3:--}"
    local ESC_OLD=$(sed 's/[^^\\]/[&]/g; s/\^/\\^/g; s/\\/\\\\/g' <<< "$OLD")
    local ESC_NEW=$(sed 's/[&/\]/\\&/g' <<< "$NEW")
    sed -i "s/$ESC_OLD/$ESC_NEW/g" "$3"
}

# Validate parameter settings
validate_settings() {
    local INVALID_SETTINGS=""

    # validate mandatory parameters conform to expected value
    is_valid_ip "$PARAM_PIHOLE_IP"
    [ $? == 1 ] && terminate "No valid IP address provided"

    # validate parameters conform to expected value
    is_valid_ip "$PARAM_PIHOLE_IP"
    [ $? == 1 ] && INVALID_SETTINGS+="Invalid Pi-hole IP:   ${PARAM_PIHOLE_IP}\n"

    is_valid_cidr_network "$PARAM_SUBNET"
    [ $? == 1 ] && INVALID_SETTINGS+="Invalid subnet:       ${PARAM_SUBNET}\n"

    is_valid_ip "$PARAM_GATEWAY"
    [ $? == 1 ] && INVALID_SETTINGS+="Invalid gateway:      ${PARAM_GATEWAY}\n"

    is_valid_cidr_network "$PARAM_IP_RANGE"
    [ $? == 1 ] && INVALID_SETTINGS+="Invalid IP range:     ${PARAM_IP_RANGE}\n"

    is_ip_in_range "$PARAM_PIHOLE_IP" "$PARAM_IP_RANGE"
    [ $? == 1 ] && INVALID_SETTINGS+="IP '$PARAM_PIHOLE_IP' not available in range '$PARAM_IP_RANGE'\n"

    is_valid_mac_address "$PARAM_MAC_ADDRESS"
    [ $? == 1 ] && INVALID_SETTINGS+="Invalid MAC address:  ${PARAM_MAC_ADDRESS}\n"

    is_valid_ip "$PARAM_DNS1"
    [ $? == 1 ] && INVALID_SETTINGS+="Invalid DNS1:         ${PARAM_DNS1}\n"

    is_valid_ip "$PARAM_DNS2"
    [ $? == 1 ] && INVALID_SETTINGS+="Invalid DNS2:         ${PARAM_DNS2}\n"

    validate_provided_path
    [ $? == 1 ] && INVALID_SETTINGS+="Invalid data path:    ${PARAM_DATA_PATH}\n"

    if [ "$INVALID_SETTINGS" ] ; then
        log "$INVALID_SETTINGS"
        terminate "Invalid parameters"
    fi
}

# Validates current versions for DSM, Docker, and Docker Compose
validate_host_version() {
    # Test if host is DSM 6, exit otherwise
    if [ "$DSM_MAJOR_VERSION" != "$DSM_SUPPORTED_VERSION" ] ; then
        terminate "This script supports DSM 6.x only, use --force to override"
    fi

    # Test Docker version is present, exit otherwise
    if [ -z "$DOCKER_VERSION" ] ; then
        terminate "Could not confirm Docker availability, use --force to override"
    fi

    # Test Docker Compose version is present, exit otherwise
    if [ -z "$COMPOSE_VERSION" ] ; then
        terminate "Could not confirm Docker Compose availability, use --force to override"
    fi
}


#======================================================================================================================
# Workflow Functions
#======================================================================================================================

# Detects current versions for DSM, Docker, Docker Compose, and Pi-hole
detect_host_versions() {
    print_status "Validating DSM, Docker, and Docker Compose versions on host"

    # Detect current DSM version
    DSM_VERSION=$(cat /etc.defaults/VERSION 2> /dev/null | grep '^productversion' | cut -d'=' -f2 | sed "s/\"//g")
    DSM_MAJOR_VERSION=$(cat /etc.defaults/VERSION 2> /dev/null | grep '^majorversion' | cut -d'=' -f2 | sed "s/\"//g")
    DSM_BUILD=$(cat /etc.defaults/VERSION 2> /dev/null | grep '^buildnumber' | cut -d'=' -f2 | sed "s/\"//g")

    # Detect current Docker version
    DOCKER_VERSION=$(docker -v 2>/dev/null | egrep -o "[0-9]*.[0-9]*.[0-9]*," | cut -d',' -f 1)

    # Detect current Docker Compose version
    COMPOSE_VERSION=$(docker-compose -v 2>/dev/null | egrep -o "[0-9]*.[0-9]*.[0-9]*," | cut -d',' -f 1)

    log "Current DSM: ${DSM_VERSION:-Unknown}"
    log "Current Docker: ${DOCKER_VERSION:-Unknown}"
    log "Current Docker Compose: ${COMPOSE_VERSION:-Unknown}"
    if [ "$FORCE" != 'true' ] ; then
        validate_host_version
    fi
}

# Defines current and target Pi-hole version
define_pihole_versions() {
    print_status "Detecting current and available Pi-hole versions"

    # Detect current Pi-hole version (should comply with 'version.release.modification')
    PIHOLE_VERSION=$(docker exec -it "$PIHOLE_CONTAINER" pihole -v 2>/dev/null | grep 'Pi-hole' | awk '{print $4}' \
        | cut -c2-)
    is_valid_version "$PIHOLE_VERSION"
    [ $? == 1 ] && PIHOLE_VERSION=''

    log "Current Pi-hole: ${PIHOLE_VERSION:-Unavailable}"

    detect_available_versions

    log "Target Pi-hole version: ${TARGET_PIHOLE_VERSION:-Unknown}"

    if [ "$FORCE" != 'true' ] ; then
        # Confirm update is necessary
        if [ "$PIHOLE_VERSION" = "$TARGET_PIHOLE_VERSION" ] ; then
            terminate "Already on latest version of Pi-hole"
        fi
    fi
}

# Initialize network and Pi-hole settings
init_settings() {
    print_status "Initializing network and Pi-hole settings"
    init_auto_detected_values
    validate_settings

    log "Pi-hole IP:   $PARAM_PIHOLE_IP"
    log "Subnet:       $PARAM_SUBNET"
    log "Gateway:      $PARAM_GATEWAY"
    log "IP range:     $PARAM_IP_RANGE"
    log "Network IP:   $INFO_NETWORK_IP"
    log "Broadcast IP: $INFO_BROADCAST_IP"
    log "VLAN:         $PARAM_VLAN_NAME"
    log "Interface:    $PARAM_INTERFACE"
    log "MAC address:  $PARAM_MAC_ADDRESS"
    log "Domain name:  $PARAM_DOMAIN_NAME"
    log "Hostname:     $PARAM_PIHOLE_HOSTNAME"
    log "Timezone:     $PARAM_TIMEZONE"
    log "DNS1:         $PARAM_DNS1"
    log "DNS2:         $PARAM_DNS2"
    log "Data path:    $PARAM_DATA_PATH"
    if [ -z "$PARAM_WEBPASSWORD" ] ; then 
        log "Web password: (not set)"
    else
        log "Web password: *****"
    fi

}

# Ask user to confirm operation
confirm_operation() {
    if [ "$FORCE" != 'true' ] ; then
        echo
        echo "WARNING! This will install or update Pi-hole as Docker container on your Synology"
        echo
        read -p "Are you sure you want to continue? [y/N] " CONFIRMATION

        if [ "$CONFIRMATION" != 'y' ] && [ "$CONFIRMATION" != 'Y' ] ; then
            exit
        fi 
    fi
}

# Generates a Docker compose file with substituted variables
create_docker_compose_file() {
    print_status "Generating Docker Compose file"

    # create generated compose file
    if [ -f "$WORKDIR/$TEMPLATE_FILE" ] ; then
        cp "$WORKDIR/$TEMPLATE_FILE" "$WORKDIR/$COMPOSE_FILE" > /dev/null 2>&1
    else
        terminate "File '$COMPOSE_FILE' unavailable"
    fi

    # substitute variables
    safe_replace_in_file '${INTERFACE}' "$PARAM_INTERFACE" "$WORKDIR/$COMPOSE_FILE"
    safe_replace_in_file '${SUBNET}' "$PARAM_SUBNET" "$WORKDIR/$COMPOSE_FILE"
    safe_replace_in_file '${GATEWAY}' "$PARAM_GATEWAY" "$WORKDIR/$COMPOSE_FILE"
    safe_replace_in_file '${IP_RANGE}' "$PARAM_IP_RANGE" "$WORKDIR/$COMPOSE_FILE"
    safe_replace_in_file '${PIHOLE_HOSTNAME}' "$PARAM_PIHOLE_HOSTNAME" "$WORKDIR/$COMPOSE_FILE"
    safe_replace_in_file '${TIMEZONE}' "$PARAM_TIMEZONE" "$WORKDIR/$COMPOSE_FILE"
    safe_replace_in_file '${WEBPASSWORD}' "$PARAM_WEBPASSWORD" "$WORKDIR/$COMPOSE_FILE"
    safe_replace_in_file '${DOMAIN_NAME}' "$PARAM_DOMAIN_NAME" "$WORKDIR/$COMPOSE_FILE"
    safe_replace_in_file '${DNS1}' "$PARAM_DNS1" "$WORKDIR/$COMPOSE_FILE"
    safe_replace_in_file '${DNS2}' "$PARAM_DNS2" "$WORKDIR/$COMPOSE_FILE"
    safe_replace_in_file '${PIHOLE_IP}' "$PARAM_PIHOLE_IP" "$WORKDIR/$COMPOSE_FILE"
    safe_replace_in_file '${DATA_PATH}' "$PARAM_DATA_PATH" "$WORKDIR/$COMPOSE_FILE"
    safe_replace_in_file '${MAC_ADDRESS}' "$PARAM_MAC_ADDRESS" "$WORKDIR/$COMPOSE_FILE"
    safe_replace_in_file '${PIHOLE_HOSTNAME}' "$PARAM_PIHOLE_HOSTNAME" "$WORKDIR/$COMPOSE_FILE"
}

# Test Docker service availability by invoking synoservicectl
execute_wait_for_docker() {
    print_status "Testing Docker service availability"

    local DOCKER='false'
    local I=1
    local SPINNER="/-\|"
    local START=$(date +%s)
    local ELAPSED=0

    [ -z "$LOG_PREFIX" ] && echo -n 'Testing...  '

    while [ "$ELAPSED" -le "$NW_TIMEOUT" ] ; do
        # validate Docker service is running
        $(synoservicectl --status "$SYNO_DOCKER_SERV_NAME" | grep -q running)
        if [ "$?" -eq 0 ] ; then
            DOCKER='true'
            break
        else
            [ -z "$LOG_PREFIX" ] && printf "\b${SPINNER:I++%${#SPINNER}:1}"  # print spinner
            sleep 0.5
        fi
        CURRENT=$(date +%s)
        ELAPSED=$(($CURRENT - $START))
    done

    if [ "$DOCKER" == 'true' ] ; then
        [ -z "$LOG_PREFIX" ] && printf "\b "
        log "Docker service detected"
    else
        [ -z "$LOG_PREFIX" ] && printf "\b \n"
        terminate "Timeout waiting for Docker availability"
    fi
}

# Test network service availability by checking status of interface
execute_wait_for_network() {
    print_status "Testing network service availability"

    local INTERFACE="$PARAM_INTERFACE"
    local NETWORK='false'
    local I=1
    local SPINNER="/-\|"
    local START=$(date +%s)
    local ELAPSED=0

    [ -z "$LOG_PREFIX" ] && echo -n 'Testing...  '

    while [ "$ELAPSED" -le "$NW_TIMEOUT" ] ; do
        # try to identify main interface if not provided as parameter
        # Note: this could fail as the the network service might not be available yet
        if [ -z "$INTERFACE" ] ; then
            INTERFACE=$(ip route list | grep "default" | awk '{print $5}')
        fi

        # validate interface state is UP (the variable might be undefined)
        $(ip a s "$INTERFACE" | grep -q 'state UP')
        if [ ! -z "$INTERFACE" ] && [ "$?" -eq 0 ] ; then
            NETWORK='true'
            break
        else
            [ -z "$LOG_PREFIX" ] && printf "\b${SPINNER:I++%${#SPINNER}:1}"  # print spinner
            sleep 0.5
        fi
        CURRENT=$(date +%s)
        ELAPSED=$(($CURRENT - $START))
    done

    if [ "$NETWORK" == 'true' ] ; then
        [ -z "$LOG_PREFIX" ] && printf "\b "
        log "Network service detected"
    else
        [ -z "$LOG_PREFIX" ] && printf "\b \n"
        terminate "Timeout waiting for network availability"
    fi
}

# Create macvlan interface
execute_create_macvlan() {
    print_status "Creating network interface"

    local STATUS

    # (re-)create macvlan bridge network attached to the physical interface
    STATUS=$(ip link | grep "$PARAM_VLAN_NAME")
    if [ "$STATUS" ] ; then
        log "Removing existing link '$PARAM_VLAN_NAME'"
        ip link set "$PARAM_VLAN_NAME" down > /dev/null 2>&1
        ip link delete "$PARAM_VLAN_NAME" > /dev/null 2>&1
    fi
    log "Adding link '$PARAM_VLAN_NAME' for macvlan in bridge mode"
    ip link add "$PARAM_VLAN_NAME" link "$PARAM_INTERFACE" type macvlan mode bridge
    
    # reserve part of the interface scope for macvlan
    STATUS=$(ip addr | grep "$PARAM_VLAN_NAME")
    if [ -z "$STATUS" ] ; then
        log "Allocating IP range '$PARAM_IP_RANGE' to '$PARAM_VLAN_NAME'"
        ip addr add "$PARAM_IP_RANGE" dev "$PARAM_VLAN_NAME" > /dev/null 2>&1
    else
        log "Updating current IP range of '$PARAM_VLAN_NAME' to '$PARAM_IP_RANGE'"
        ip addr change "$PARAM_IP_RANGE" dev "$PARAM_VLAN_NAME" > /dev/null 2>&1
    fi

    # bring macvlan interface up
    log "Bringing up interface '$PARAM_VLAN_NAME'"
    ip link set "$PARAM_VLAN_NAME" up > /dev/null 2>&1

    # add route to Pi-hole IP on macvlan interface
    STATUS=$(ip route | grep "$PARAM_VLAN_NAME" | grep "$PARAM_PIHOLE_IP")
    if [ -z "$STATUS" ] ; then
        log "Adding static route from '$PARAM_PIHOLE_IP/32' to '$PARAM_VLAN_NAME'"
        ip route add "$PARAM_PIHOLE_IP/32" dev "$PARAM_VLAN_NAME" > /dev/null 2>&1
    fi

    # check virtual adapter status
    STATUS=$(ip route | grep "$PARAM_VLAN_NAME")
    if [ -z "$STATUS" ] ; then
        terminate "Could not create macvlan interface"
    fi
}

# Create Pi-hole Docker network and container
execute_create_container() {
    print_status "Creating Pi-hole container"

    local COMPOSE_LOG COMPOSE_CODE

    # pull latest image
    COMPOSE_LOG=$(docker-compose -f "$WORKDIR/$COMPOSE_FILE" pull 2>&1)
    COMPOSE_CODE="$?"

    if [ "$COMPOSE_CODE" -ne 0 ] ; then
        log "$COMPOSE_LOG"
        terminate "Could not download latest Docker image"
    fi

    # start network and container in daemon mode
    COMPOSE_LOG=$(docker-compose -f "$WORKDIR/$COMPOSE_FILE" up -d 2>&1)
    COMPOSE_CODE="$?"

    if [ "$COMPOSE_CODE" -ne 0 ] ; then
        log "$COMPOSE_LOG"
        terminate "Could not create Docker network and/or container"
    fi
}

# Test Pi-hole availability by testing connection to admin portal
execute_test_pihole() {
    print_status "Testing Pi-hole availability"

    local URL="http://$PARAM_PIHOLE_IP/admin/"
    local CODE=0
    local I=1
    local SPINNER="/-\|"
    local START=$(date +%s)
    local ELAPSED=0

    [ -z "$LOG_PREFIX" ] && echo -n 'Testing...  '
    while [ "$ELAPSED" -le "$PI_TIMEOUT" ] ; do
        CODE=$(curl -o /dev/null -I -L -s -w "%{http_code}" "$URL")
        if [ "$CODE" == 200 ] ; then
            break
        else
            [ -z "$LOG_PREFIX" ] && printf "\b${SPINNER:I++%${#SPINNER}:1}"  # print spinner
            sleep 0.5
        fi
        CURRENT=$(date +%s)
        ELAPSED=$(($CURRENT - $START))
    done

    if [ "$CODE" == 200 ] ; then
        [ -z "$LOG_PREFIX" ] && printf "\b "
        log "Successfully connected to Pi-hole portal ($URL)"
    else
        [ -z "$LOG_PREFIX" ] && printf "\b \n"
        terminate "Timeout connecting to Pi-hole"
    fi
}

# Create Pi-hole password
execute_create_password() {
    print_status "Setting Pi-hole password"
    
    if [ -z "$PARAM_WEBPASSWORD" ] && [ "$FORCE" != 'true' ] ; then
        docker exec -it pihole pihole -a -p
    else
        log "Skipped in forced mode"
    fi
}

#======================================================================================================================
# Main Script
#======================================================================================================================

# Show header
show_header

# Test if script has root privileges, exit otherwise
if [[ $(id -u) -ne 0 ]]; then 
    usage
    terminate "You need to be root to run this script"
fi

# Process and validate command-line arguments
while [ "$1" != "" ]; do
    case "$1" in
        -f | --force )
            FORCE='true'
            ;;
        -l | --log )
            LOG_PREFIX="[$(date --rfc-3339=seconds)] [SYNO_PIHOLE] "
            shift
            PARAM_LOG_FILE="$1"
            is_valid_log_file
            [ $? == 1 ] && terminate "Invalid log file"
            ;;
        -h | --help )
            usage
            exit
            ;;
        -i | --ip )
            shift
            PARAM_PIHOLE_IP="$1"
            is_valid_ip "$PARAM_PIHOLE_IP"
            [ $? == 1 ] && terminate "Invalid IP address"
            ;;
        -s | --subnet )
            shift
            PARAM_SUBNET="$1"
            is_valid_cidr_network "$PARAM_SUBNET"
            [ $? == 1 ] && terminate "Invalid subnet"
            ;;
        -g | --gateway )
            shift
            PARAM_GATEWAY="$1"
            is_valid_ip "$PARAM_GATEWAY"
            [ $? == 1 ] && terminate "Invalid gateway"
            ;;
        -r | --range )
            shift
            PARAM_IP_RANGE="$1"
            is_valid_cidr_network "$PARAM_IP_RANGE"
            [ $? == 1 ] && terminate "Invalid IP range"
            ;;
        -v | --vlan )
            shift
            PARAM_VLAN_NAME="$1"
            ;;
        -n | --interface )
            shift
            PARAM_INTERFACE="$1"
            ;;
        -m | --mac )
            shift
            PARAM_MAC_ADDRESS="$1"
            is_valid_mac_address "$PARAM_MAC_ADDRESS"
            [ $? == 1 ] && terminate "Invalid unicast MAC address"
            ;;
        -d | --domain )
            shift
            PARAM_DOMAIN_NAME="$1"
            ;;
        -H | --host )
            shift
            PARAM_PIHOLE_HOSTNAME="$1"
            ;;
        -t | --timezone )
            shift
            PARAM_TIMEZONE="$1"
            ;;
        --DNS1 )
            shift
            PARAM_DNS1="$1"
            is_valid_ip "$PARAM_DNS1"
            [ $? == 1 ] && terminate "Invalid DNS"
            ;;
        --DNS2 )
            shift
            PARAM_DNS2="$1"
            is_valid_ip "$PARAM_DNS2"
            [ $? == 1 ] && terminate "Invalid DNS"
            ;;
        --path )
            shift
            PARAM_DATA_PATH="$1"
            validate_provided_path
            [ $? == 1 ] && terminate "Invalid data path"
            ;;
        -p | --password )
            shift
            PARAM_WEBPASSWORD="$1"
            ;;
        install | network | update  )
            COMMAND="$1"
            ;;
        * )
            usage
            terminate "Unrecognized parameter ($1)"
    esac
    shift
done

# Execute workflows
case "$COMMAND" in
    install )
        TOTAL_STEPS=8
        init_env
        detect_host_versions
        define_pihole_versions
        init_settings
        confirm_operation
        create_docker_compose_file
        execute_create_macvlan
        execute_create_container
        execute_test_pihole
        execute_create_password
        ;;
    network )
        TOTAL_STEPS=5
        init_env
        execute_wait_for_docker
        detect_host_versions
        execute_wait_for_network
        init_settings
        confirm_operation
        execute_create_macvlan
        ;;
    update )
        TOTAL_STEPS=4
        detect_host_versions
        define_pihole_versions
        execute_create_container
        execute_test_pihole
        ;;
    * )
        usage
        terminate "No command specified"
esac

log "Done."