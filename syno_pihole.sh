#!/bin/sh

#=======================================================================================================================
# Title         : syno_pihole.sh
# Description   : Install or Update Pi-Hole as Docker Container on a Synology NAS with a Static IP Address
# Author        : Mark Dumay
# Date          : September 12th, 2021
# Version       : 1.0.2
# Usage         : sudo ./syno_pihole.sh [OPTIONS] command
# Repository    : https://github.com/markdumay/synology-pihole.git
# License       : MIT - https://github.com/markdumay/synology-pihole/blob/master/LICENSE
# Credits       : Inspired by https://gist.github.com/xirixiz/ecad37bac9a07c2a1204ab4f9a17db3c
#=======================================================================================================================

#=======================================================================================================================
# Constants
#=======================================================================================================================
RED='\033[0;31m' # Red color
NC='\033[0m' # No Color
BOLD='\033[1m' #Bold color

DSM_SUPPORTED_VERSION=6
SYNO_DOCKER_SERV_NAME=pkgctl-Docker
DEFAULT_PIHOLE_VERSION='2021.09'
COMPOSE_FILE='docker-compose.yml'
TEMPLATE_FILE='docker-compose-template.yml'
GITHUB_API_PIHOLE='https://api.github.com/repos/pi-hole/docker-pi-hole/releases/latest'
PI_TIMEOUT=120 # timeout to wait for Pi-hole response (in seconds)
NW_TIMEOUT=600 # timeout to wait for network response (in seconds)


#=======================================================================================================================
# Variables
#=======================================================================================================================
param_pihole_ip=''
param_subnet=''
param_host_ip=''
param_gateway=''
param_ip_range=''
param_vlan_name=''
param_interface=''
param_mac_address=''
param_domain_name=''
param_pihole_hostname=''
param_timezone=''
param_dns1=''
param_dns2=''
param_data_path=''
param_webpassword=''
param_log_file=''
dsm_major_version=''
docker_version=''
compose_version=''
force='false'
log_prefix=''
command=''
target_pihole_version=''
step=0
total_steps=1
workdir="$(dirname "$(readlink -f "$0")")" # initialize working directory


#=======================================================================================================================
# Helper Functions
#=======================================================================================================================

#=======================================================================================================================
# Display script header (only in interactive mode).
#=======================================================================================================================
# Globals:
#   - log_prefix
# Outputs:
#   Writes message to stdout.
#=======================================================================================================================
show_header() {
    [ -n "${log_prefix}" ] && return

    echo "Install or Update Pi-hole as Docker container on Synology"
    echo
}

#=======================================================================================================================
# Display usage message.
#=======================================================================================================================
# Outputs:
#   Writes message to stdout.
#=======================================================================================================================
usage() { 
    echo "Usage: $0 [OPTIONS] COMMAND" 
    echo
    echo "Options:"
    echo "  -f, --force            Force update (bypass compatibility check and confirmation check)."
    echo "  -l, --log [LOG FILE]   Display messages in log format, adding to [LOG FILE] if provided."
    echo
    echo "Commands:"
    echo "  install (-i|--ip) <address> [PARAMETERS]   Install Pi-hole."
    echo "  network (-i|--ip) <address> [PARAMETERS]   Create or recreate virtual network."
    echo "  update                                     Update Pi-hole to latest version using "
    echo "                                             existing settings."
    echo
    echo "Parameters:"
    echo "  -d, --domain           Container fully qualified domain name."
    echo "      --DNS1             Primary DNS provider."
    echo "      --DNS2             Alternative DNS provider."
    echo "  -g, --gateway          Gateway of the LAN."
    echo "  -h, --help             Print this usage guide and exit."
    echo "  -H, --host             Hostname of Pi-hole."
    echo "      --host-ip          Host IP address to communicate with Pi-hole container. Defaults"
    echo "                         to the lowest address not the Pi-hole address (i) starting at"
    echo "                         the first address of range (r). It's recommended to set this to"
    echo "                         avoid possible collisions."
    echo "  -i, --ip               (Required) static IP address of Pi-hole."
    echo "  -m, --mac              Pi-hole container unicast MAC address"
    echo "  -n, --interface        Physical interface to bind docker network to."
    echo "  -p, --password         Password for the Pi-hole admin."
    echo "      --path             Path where to store Pi-hole data."
    echo "  -r, --range            IP range (CIDR notation) from local subnet. Designates the pool"
    echo "                         of addresses reserved for containers attached to the generated"
    echo "                         docker macvlan network. Range should not overlap LAN DHCP pool."
    echo "  -s, --subnet           The LAN subnet to interface with."
    echo "  -t, --timezone         Timezone for Pi-hole."
    echo "  -v, --vlan             Name of the generated macvlan docker network."
    echo
}

#======================================================================================================================
# Displays error message on console and log file, terminate with non-zero error.
#======================================================================================================================
# Arguments:
#   $1 - Error message to display.
# Outputs:
#   Writes error message to stderr and optional log file, non-zero exit code.
#======================================================================================================================
# shellcheck disable=SC2059
terminate() {
    printf "${RED}${BOLD}${log_prefix}ERROR: $1${NC}\n" 1>&2
    if [ -n "${param_log_file}" ] ; then
        echo "${log_prefix}ERROR: $1" >> "${param_log_file}"
    fi
    exit 1
}

#======================================================================================================================
# Print current progress to the console and log file, shows progress against total number of steps.
#======================================================================================================================
# Arguments:
#   $1 - Progress message to display.
# Outputs:
#   Writes message to stdout and optional log file.
#======================================================================================================================
print_status() {
    step=$((step + 1))
    printf "${BOLD}%s${NC}\n" "Step ${step} from ${total_steps}: $1"
    if [ -n "${param_log_file}" ] ; then
        echo "${log_prefix}Step ${step} from ${total_steps}: $1" >> "${param_log_file}"
    fi
}

#======================================================================================================================
# Prints current progress to the console in normal or logging format.
#======================================================================================================================
# Arguments:
#   $1 - Log message to display.
# Outputs:
#   Writes message to stdout and optional log file.
#======================================================================================================================
# shellcheck disable=SC2059
log() {
    printf "${log_prefix}$1\n"
    if [ -n "${param_log_file}" ] ; then
        echo "${log_prefix}$1" >> "${param_log_file}"
    fi
}

#======================================================================================================================
# Validates the data path parameter and creates directories if needed. It adjusts the path to an absolute path.
#======================================================================================================================
# Globals:
#   - param_data_path
# Outputs:
#   Returns 0 (successful) or 1 (not successful).
#======================================================================================================================
validate_provided_path() {
    # cut trailing '/' and convert to absolute path
    param_data_path=$(readlink -f "${param_data_path}")

    # create base path and child directories if needed
    mkdir -p "${param_data_path}" "${param_data_path}/pihole" "${param_data_path}/dnsmasq.d"

    # check path exists
    [ -d "${param_data_path}" ] && return 0 || return 1
}

#======================================================================================================================
# Validates the log path and file parameter. It adjusts the path to an absolute path.
#======================================================================================================================
# Globals:
#   - param_log_file
# Outputs:
#   Returns 0 (successful) or 1 (not successful).
#======================================================================================================================
is_valid_log_file() {
    # cut trailing '/' and convert to absolute path
    param_log_file=$(readlink -f "${param_log_file}")

    # check path exists
    dir=$(dirname "${param_log_file}")
    [ -d "${dir}" ] && return 0 || return 1
}

#======================================================================================================================
# Validates if a version string complies with the expected format.
#======================================================================================================================
# Arguments:
#   $1 - Version string.
# Outputs:
#   Returns 0 (successful) or 1 (not successful).
#======================================================================================================================
is_valid_version() {
    re='^([0-9]+\.)?([0-9]+\.)?(\*|[0-9]+)$'
    echo "$1" | grep -qE "${re}"
}

#======================================================================================================================
# Validates if an IPv4 address complies with expected format.
#======================================================================================================================
# Arguments:
#   $1 - IPv4 string.
# Outputs:
#   Returns 0 (successful) or 1 (not successful).
#======================================================================================================================
is_valid_ip() {
    re='(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}'
    echo "$1" | grep -qE "${re}"
}

#======================================================================================================================
# Validates if an IPv4 address and routing suffix (CIDR format) comply with expected format.
#======================================================================================================================
# Arguments:
#   $1 - IPv4 and suffix string.
# Outputs:
#   Returns 0 (successful) or 1 (not successful).
#======================================================================================================================
is_valid_cidr() {
    re='(((25[0-5]|2[0-4][0-9]|1?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|1?[0-9][0-9]?))(\/([8-9]|[1-2][0-9]|3[0-2]))$'
    echo "$1" | grep -qE "${re}"
}

#======================================================================================================================
# Validates if a MAC address complies with expected format. As ':' separator is expected.
#======================================================================================================================
# Arguments:
#   $1 - MAC address string.
# Outputs:
#   Returns 0 (successful) or 1 (not successful).
#======================================================================================================================
is_valid_mac_address() {
    re='([a-fA-F0-9]{2}:){5}[a-fA-F0-9]{2}'
    unicast=$(echo "$1" | sed -e 's/^\(.\)[13579bdf]/\10/') # parses unicast MAC from input
    (echo "$1" | grep -qE "${re}") && [ "$1" = "${unicast}" ] && return 0 || return 1
}

#======================================================================================================================
# Converts an IP address into its integer representation.
#======================================================================================================================
# Arguments:
#   $1 - IP address string.
# Outputs:
#   IP integer.
#======================================================================================================================
convert_ip_to_int() {
    echo "$1" | tr . '\n' | awk '{s = s*256 + $1} END{print s}'
}

#======================================================================================================================
# Converts a decimal integer to a dotted IPv4 address.
# https://stackoverflow.com/questions/10768160/ip-address-converter
#======================================================================================================================
# Arguments:
#   $1 - IP address decimal integer.
# Outputs:
#   IP address string.
#======================================================================================================================
convert_int_to_ip() {
    a=$((~(-1<<8))) b=$1; 
    set -- "$((b>>24&a))" "$((b>>16&a))" "$((b>>8&a))" "$((b&a))";
    IFS=.;
    echo "$*";
}

#======================================================================================================================
# Validates if an IP address is within an available CIDR range. Assumes IP address and CIDR range are valid parameters.
#======================================================================================================================
# Arguments:
#   $1 - IP address.
#   $2 - CIDR range.
# Outputs:
#   Returns 0 if an IP address is in available CIDR range, returns 1 otherwise.
#======================================================================================================================
is_ip_in_range() {
    ip="$1"
    ip_cidr="$2"

    ip_int=$(convert_ip_to_int "${ip}")
    cidr_min_ip=$(ipcalc -n "${ip_cidr}" | cut -f2 -d=)  # network address is start of the range
    cidr_max_ip=$(ipcalc -b "${ip_cidr}" | cut -f2 -d=)  # broadcast address is end of the range
    cidr_min_ip_int=$(convert_ip_to_int "${cidr_min_ip}")
    cidr_max_ip_int=$(convert_ip_to_int "${cidr_max_ip}")

    [ "${ip_int}" -ge "${cidr_min_ip_int}" ] && [ "${ip_int}" -le "${cidr_max_ip_int}" ] && return 0 || return 1
}


#======================================================================================================================
# Validates if a CIDR range is a valid unicast address range of a provided subnet. Assumes both arguments are are valid 
# CIDR values.
#======================================================================================================================
# Arguments:
#   $1 - Unicast address range in CIDR notation.
#   $2 - Range of subnet in CIDR notation.
# Outputs:
#   Returns 0 if CIDR range is a valid unicast address range of the subnet, returns 1 otherwise.
#======================================================================================================================
is_cidr_in_subnet() {
    range_cidr="$1"
    subnet_cidr="$2"
    range_prefix_size=$(echo "${range_cidr}" | cut -d/ -f2)
    subnet_prefix_size=$(echo "${subnet_cidr}" | cut -d/ -f2)

    # range prefix must be bigger than local subnets
    [ "${range_prefix_size}" -le "${subnet_prefix_size}" ] && return 1

    # local broadcast address conflict?
    subnet_bcast=$(ipcalc -b "${subnet_cidr}" | cut -f2 -d=)
    subnet_bcast_int=$(convert_ip_to_int "${subnet_bcast_int}")
    if is_ip_in_range "${subnet_bcast}" "${range_cidr}"; then return 1; fi

    # if a single range address is in the subnet then range is contained
    range_ip=$(echo "${range_cidr}" | cut -d/ -f1)
    if is_ip_in_range "${range_ip}" "${subnet_cidr}"; then return 0; else return 1; fi
}

#======================================================================================================================
# Detects latest available stable Pi-hole version, ignoring release candidates. FTL is considered to be the leading
# development release version. If no release is found, the constant DEFAULT_PIHOLE_VERSION is used instead.
#======================================================================================================================
# Globals:
#   - target_pihole_version
#======================================================================================================================
detect_available_versions() {
    if [ -z "${target_pihole_version}" ] ; then
        target_pihole_version=$(curl -s "${GITHUB_API_PIHOLE}" | grep "tag_name" | grep -Eo "[0-9]+.[0-9]+(.[0-9]+)?")
        target_pihole_version=$(echo "${target_pihole_version}" | sed 's/v//g')

        if [ -z "${target_pihole_version}" ] ; then
            log "Could not detect latest available Pi-hole version, setting default value"
            target_pihole_version="${DEFAULT_PIHOLE_VERSION}"
        fi
    fi
}

#======================================================================================================================
# Initializes environment variables from a .env file if available. Command line arguments take precedence. The only
# mandatory parameter is the Pi-hole IP address.
#======================================================================================================================
# Globals:
#   - target_pihole_version
#   - param_vlan_name
#   - param_pihole_hostname
#   - param_dns1
#   - param_dns2
#   - param_data_path
#   - param_domain_name
#   - param_pihole_ip
#   - param_subnet
#   - param_gateway
#   - param_ip_range
#   - param_host_ip
#   - param_interface
#   - param_mac_address
#   - param_timezone
#   - param_webpassword
#   - param_pihole_ip
# Outputs:
#   Exits with a non-zero exit code code if no valid IP address is provided for Pi-hole.
#======================================================================================================================
init_env() {
    # read environment variables if .env file is present
    env_file="${workdir}/.env"
    if [ -f "${env_file}" ]; then
        vars=$(sed 's/#.*//g' < "${env_file}" | xargs)
        eval "export ${vars}"
    fi

    # initialize optional parameters with either provided or default values
    [ -z "${param_vlan_name}" ] && param_vlan_name="${VLAN_NAME:-macvlan0}"
    [ -z "${param_pihole_hostname}" ] && param_pihole_hostname="${PIHOLE_HOSTNAME:-pihole}"
    [ -z "${param_dns1}" ] && param_dns1="${DNS1:-1.1.1.1}"
    [ -z "${param_dns2}" ] && param_dns2="${DNS2:-1.0.0.1}"
    [ -z "${param_data_path}" ] && param_data_path="${DATA_PATH:-./data}"
    [ -z "${param_domain_name}" ] && param_domain_name="${DOMAIN_NAME:-${param_pihole_hostname}.local}"

    # initialize provided parameters
    [ -z "${param_pihole_ip}" ] && param_pihole_ip="${PIHOLE_IP}"
    [ -z "${param_subnet}" ] && param_subnet="${SUBNET}"
    [ -z "${param_gateway}" ] && param_gateway="${GATEWAY}"
    [ -z "${param_ip_range}" ] && param_ip_range="${IP_RANGE}"
    [ -z "${param_host_ip}" ] && param_host_ip="${HOST_IP}"
    [ -z "${param_interface}" ] && param_interface="${INTERFACE}"
    [ -z "${param_mac_address}" ] && param_mac_address="${MAC_ADDRESS}"
    [ -z "${param_timezone}" ] && param_timezone="${TIMEZONE}"
    [ -z "${param_webpassword}" ] && param_webpassword="${WEBPASSWORD}"

    # validate mandatory parameters are available
    is_valid_ip "${param_pihole_ip}" || terminate "No valid IP address provided"
}

#======================================================================================================================
# Initializes auto-detected settings for any omitted parameters.
#======================================================================================================================
# Globals:
#   - param_subnet
#   - param_gateway
#   - param_ip_range
#   - param_host_ip
#   - param_interface
#   - param_mac_address
#   - param_timezone
# Outputs:
#   Initialized parameters.
#======================================================================================================================
init_auto_detected_values() {
    # add auto-detected settings for omitted parameters
    if [ -z "${param_subnet}" ] ; then
        default_host_ip=$(ip route list | grep "default" | awk '{print $7}')
        param_subnet=$(ip route list | grep "proto" | grep "${default_host_ip}" | awk '{print $1}')
    fi

    if [ -z "${param_gateway}" ] ; then
        param_gateway=$(ip route list | grep "default" | awk '{print $3}')
    fi
    
    if [ -z "${param_ip_range}" ] && [ -n "${param_pihole_ip}" ] ; then
        # Reserve minimal range
        param_ip_range="${param_pihole_ip}/32"
    fi

    if [ -z "${param_interface}" ] ; then
        param_interface=$(ip route list | grep "default" | awk '{print $5}')
    fi

    if [ -z "${param_mac_address}" ] ; then
        # generate random unicast MAC address
        param_mac_address=$(od -An -N6 -tx1 /dev/urandom | \
            sed -e 's/^  *//' -e 's/  */:/g' -e 's/:$//' -e 's/^\(.\)[13579bdf]/\10/')
    fi

    if [ -z "${param_timezone}" ] ; then
        param_timezone=$(find /usr/share/zoneinfo/ -type f -exec sh -c \
            'diff -q /etc/localtime "$1" > /dev/null && echo "$1"' _ {} \; | sed 's|/usr/share/zoneinfo/||g')
    fi
}

#======================================================================================================================
# Generates any required omitted parameters.
#======================================================================================================================
# Globals:
#   - param_host_ip
# Outputs:
#   Initialized parameters.
#======================================================================================================================
init_generated_values() {
    # host macvlan bridge ip
    if [ -z "${param_host_ip}" ] ; then
        ip=$(ipcalc -n "${param_ip_range}" | cut -f2 -d=)
        ip_int=$(convert_ip_to_int "${ip}")
        ph_int=$(convert_ip_to_int "${param_pihole_ip}")

        [ "${ip_int}" = "${ph_int}" ] && ip_int=$((ip_int + 1))
        param_host_ip=$(convert_int_to_ip "${ip_int}")
    fi
}

#======================================================================================================================
# Replaces an old value in a file with a new value. The strings are escaped to avoid processing errors.
#======================================================================================================================
# Arguments:
#   $1 - Old string.
#   $2 - New string.
#   $3 - Filename.
# Outputs:
#   Replaced value in file.
#======================================================================================================================
safe_replace_in_file() {
    old=$(echo "$1" | sed 's/[^^\\]/[&]/g; s/\^/\\^/g; s/\\/\\\\/g')
    new=$(echo "$2" | sed 's/[&/\]/\\&/g')
    file="${3:--}"
    sed -i "s/${old}/${new}/g" "${file}"
}

#=======================================================================================================================
# Parse a YAML file into a flat list of variables.
#=======================================================================================================================
# Source: https://gist.github.com/briantjacobs/7753bf850ca5e39be409
# Arguments:
#   $1 - YAML file to use as input
# Outputs:
#   Writes flat variable list to stdout, returns 1 if not successful
#=======================================================================================================================
parse_yaml() {
    [ ! -f "$1" ] && return 1
    
    s='[[:space:]]*'
    w='[a-zA-Z0-9_]*'
    fs="$(echo @|tr @ '\034')"
    sed -ne "s|^\($s\)\($w\)$s:$s\"\(.*\)\"$s\$|\1$fs\2$fs\3|p" 2> /dev/null \
        -e "s|^\($s\)\($w\)${s}[:-]$s\(.*\)$s\$|\1$fs\2$fs\3|p" "$1" 2> /dev/null |
    awk -F"$fs" '{
    indent = length($1)/2;
    vname[indent] = $2;
    for (i in vname) {if (i > indent) {delete vname[i]}}
        if (length($3) > 0) {
            vn=""; for (i=0; i<indent; i++) {vn=(vn)(vname[i])("_")}
            printf("%s%s=\"%s\"\n", vn, $2, $3);
        }
    }' | sed 's/_=/+=/g'
}

#======================================================================================================================
# Validates the gateway does not conflict with existing Docker networks.
#======================================================================================================================
# Globals:
#   - param_gateway
# Outputs:
#   Displays the names of Docker networks with conflicting gateways, if any.
#======================================================================================================================
validate_gateway() {
    [ -z "${param_gateway}" ] && exit

    # list all active networks with the same gateway
    networks=$(docker network ls --quiet | xargs docker network inspect \
        --format '{{ .Name }}: Gateway={{range .IPAM.Config}}{{.Gateway}}{{end}}' | 
        grep "Gateway=${param_gateway}" | awk -F':' '{print $1}')

    # find the configured network name (typically 'synology-pihole_macvlan')
    yaml=$(parse_yaml "${TEMPLATE_FILE}")
    network_name=$(echo "${yaml}" | grep "networks__macvlan__name" | awk -F'"' '{print $2}')
    default_service_name=$(basename "${workdir}")
    network_name="${network_name:-${default_service_name}_macvlan}"

    # remove network name from the list
    echo "${networks}" | sed "s/${network_name}//g"
}


#======================================================================================================================
# Validates parameter settings.
#======================================================================================================================
# Globals:
#   - param_subnet
#   - param_gateway
#   - param_subnet
#   - param_pihole_ip
#   - param_subnet
#   - param_host_ip
#   - param_ip_range
#   - param_ip_range
#   - param_mac_address
#   - param_dns1
#   - param_dns2
#   - param_data_path
# Outputs:
#   Displays warnings and errors if applicable, terminates on error.
#======================================================================================================================
validate_settings() {
    invalid_settings=""
    warning_settings=""

    #
    # validate parameters conform to expected value
    #

    # -- IP parameters --
    # Check the subnet first, this is the (L3) network we intend to interface with.

    is_valid_cidr "${param_subnet}"
    [ $? = 1 ] && invalid_settings="${invalid_settings}Invalid subnet:       ${param_subnet}\n"

    is_valid_ip "${param_gateway}"
    [ $? = 1 ] && invalid_settings="${invalid_settings}Invalid gateway:      ${param_gateway}\n"
    is_cidr_in_subnet "${param_gateway}/32" "${param_subnet}"
    [ $? = 1 ] && invalid_settings="${invalid_settings}Gateway address '${param_gateway}' is not in subnet: \
        '${param_subnet}'\n"
    conflicts=$(validate_gateway)
    conflicts=$(echo "${conflicts}" | sed -z 's/\n/,/g;s/,$/\n/;s/,/, /g;')
    [ -n "${conflicts}" ] && \
        warning_settings="${warning_settings}Gateway address '${param_gateway}' has a network conflict: ${conflicts}\n"

    # A valid docker network range should be contained by the local subnet.
    # The IP range designates a pool of IP addresses that docker allocates (by default) to containers
    # attached to the docker network.
    # This script defines Pi-hole a static IP address and only requires it be valid in the subnet,
    # the user is free to pass their own valid address outside the range.
    is_valid_ip "${param_pihole_ip}"
    [ $? = 1 ] && invalid_settings="${invalid_settings}Invalid Pi-hole IP:   ${param_pihole_ip}\n"
    is_cidr_in_subnet "${param_pihole_ip}/32" "${param_subnet}"
    [ $? = 1 ] && invalid_settings="${invalid_settings}Pi-hole IP address '${param_pihole_ip}' is not valid in subnet '${param_subnet}\n"

    is_valid_ip "${param_host_ip}"
    [ $? = 1 ] && invalid_settings="${invalid_settings}Invalid Host IP:   ${param_host_ip}\n"
    is_cidr_in_subnet "${param_host_ip}/32" "${param_subnet}"
    [ $? = 1 ] && invalid_settings="${invalid_settings}Host IP address '${param_host_ip}' is not valid in subnet '${param_subnet}'\n"

    is_valid_cidr "${param_ip_range}"
    [ $? = 1 ] && invalid_settings="${invalid_settings}Invalid IP range:     ${param_ip_range}\n"
    is_cidr_in_subnet "${param_ip_range}" "${param_subnet}"
    [ $? = 1 ] && invalid_settings="${invalid_settings}Docker network IP address range is not in subnet '${param_subnet}'\n"

    is_ip_in_range "${param_pihole_ip}" "${param_ip_range}"
    [ $? = 1 ] && warning_settings="${warning_settings}IP '${param_pihole_ip}' not in Docker network range '${param_ip_range}'\n"
    
    is_valid_mac_address "${param_mac_address}"
    [ $? = 1 ] && invalid_settings="${invalid_settings}Invalid MAC address:  ${param_mac_address}\n"

    is_valid_ip "${param_dns1}"
    [ $? = 1 ] && invalid_settings="${invalid_settings}Invalid DNS1:         ${param_dns1}\n"

    is_valid_ip "${param_dns2}"
    [ $? = 1 ] && invalid_settings="${invalid_settings}Invalid DNS2:         ${param_dns2}\n"

    validate_provided_path
    [ $? = 1 ] && invalid_settings="${invalid_settings}Invalid data path:    ${param_data_path}\n"

    [ -n "${invalid_settings}" ] && log "${invalid_settings}" && terminate "Invalid parameters"
    [ -n "${warning_settings}" ] && log "WARNING: ${warning_settings}"
}

#======================================================================================================================
# Validates availability of the current versions for DSM, Docker, and Docker Compose. The function fails if the 
# detected version of DSM is not supported, or if either Docker Community Engine or Docker Compose cannot be found. The
# script can only upgrade an existing Docker installation, typically installed via a Synology package.
#======================================================================================================================
# Globals:
#   - dsm_major_version
#   - docker_version
#   - compose_version
# Outputs:
#   Exits with a non-zero exit code if the DSM version is not supported, or if the Docker binaries cannot be found.
#======================================================================================================================
validate_host_version() {
    # Test if host is DSM 6 or later, exit otherwise
    if [ "${dsm_major_version}" -lt "${DSM_SUPPORTED_VERSION}" ] ; then
        terminate "This script supports DSM 6.x or later only, use --force to override"
    fi

    # Test Docker version is present, exit otherwise
    if [ -z "${docker_version}" ] ; then
        terminate "Could not confirm Docker availability, use --force to override"
    fi

    # Test Docker Compose version is present, exit otherwise
    if [ -z "${compose_version}" ] ; then
        terminate "Could not confirm Docker Compose availability, use --force to override"
    fi
}


#=======================================================================================================================
# Workflow Functions
#=======================================================================================================================

#======================================================================================================================
# Detects the current versions for DSM, Docker, Docker Compose. It validates compatibility too, unless in force mode.
#======================================================================================================================
# Globals:
#   - dsm_major_version
#   - docker_version
#   - compose_version
#   - force
# Outputs:
#   Exits with a non-zero exit code if the DSM version is not supported, or if the Docker binaries cannot be found.
#======================================================================================================================
detect_host_versions() {
    print_status "Validating DSM, Docker, and Docker Compose versions on host"

    # Detect current DSM version
    dsm_version='Unknown'
    file='/etc.defaults/VERSION'
    [ -f "${file}" ] && dsm_version=$(grep '^productversion' < "${file}"  | cut -d'=' -f2 | sed "s/\"//g") && \
        dsm_major_version=$(grep '^majorversion' < "${file}"  | cut -d'=' -f2 | sed "s/\"//g")

    # Detect current Docker version
    docker_version=$(docker -v 2>/dev/null | grep -Eo "[0-9]*.[0-9]*.[0-9]*," | cut -d',' -f 1)

    # Detect current Docker Compose version
    compose_version=$(docker-compose -v 2>/dev/null | grep -Eo "[0-9]*.[0-9]*.[0-9]*," | cut -d',' -f 1)

    log "Current DSM:               ${dsm_version:-Unknown}"
    log "Current Docker:            ${docker_version:-Unknown}"
    log "Current Docker Compose:    ${compose_version:-Unknown}"
    if [ "${force}" != 'true' ] ; then
        validate_host_version
    fi
}

#======================================================================================================================
# Defines the current and target version of Pi-hole. Exits if the installed version is already the latest version
# available, unless in force mode. The FTL release is considered as the leading release.
#======================================================================================================================
# Globals:
#   - pihole_version
#   - target_pihole_version
#   - force
# Outputs:
#   Exits with a non-zero exit code if Pi-hole is already on the latest version.
#======================================================================================================================
define_pihole_versions() {
    print_status "Detecting current and available Pi-hole versions"

    # Detect current Pi-hole version (should comply with 'version.release.modification')
    # Repository has stated FTL is the leading developement release version listed as latest.
    pihole_version=$(docker exec "${param_pihole_hostname}" pihole -v 2>/dev/null | grep 'FTL' | awk '{print $4}' \
        | cut -c2-)
    is_valid_version "${pihole_version}" || pihole_version=''

    log "Current Pi-hole:           ${pihole_version:-Unavailable}"

    detect_available_versions

    log "Target Pi-hole version:    ${target_pihole_version:-Unknown}"

    if [ "${force}" != 'true' ] ; then
        # Confirm update is necessary
        if [ "${pihole_version}" = "${target_pihole_version}" ] ; then
            terminate "Already on latest version of Pi-hole"
        fi
    fi
}

#======================================================================================================================
# Initializes the network and Pi-hole settings.
#======================================================================================================================
# Globals:
#   - param_interface
#   - param_subnet
#   - param_gateway
#   - param_host_ip
#   - param_vlan_name
#   - param_mac_address
#   - param_pihole_ip
#   - param_ip_range
#   - param_domain_name
#   - param_pihole_hostname
#   - param_timezone
#   - param_dns1
#   - param_dns2
#   - param_data_path
#   - param_webpassword
# Outputs:
#   Displays settings.
#======================================================================================================================
init_settings() {
    print_status "Initializing network and Pi-hole settings"
    init_auto_detected_values
    init_generated_values
    validate_settings

    log "Interface:                 ${param_interface}"
    log "Subnet:                    ${param_subnet}"
    log "Gateway:                   ${param_gateway}"
    log "Host IP address:           ${param_host_ip}"
    log "VLAN:                      ${param_vlan_name}"
    log "Pi-hole MAC address:       ${param_mac_address}"
    log "Pi-hole IP address:        ${param_pihole_ip}"
    log "Docker network IP range:   ${param_ip_range}"
    log "Domain name:               ${param_domain_name}"
    log "Hostname:                  ${param_pihole_hostname}"
    log "Timezone:                  ${param_timezone}"
    log "DNS1:                      ${param_dns1}"
    log "DNS2:                      ${param_dns2}"
    log "Data path:                 ${param_data_path}"
    if [ -z "${param_webpassword}" ] ; then 
        log "Web password:              (not set)"
    else
        log "Web password:              *****"
    fi
}

#======================================================================================================================
# Asks the user to confirm the operation, unless in force mode.
#======================================================================================================================
# Outputs:
#   Exits with a zero error code if the user does not confirm the operation.
#======================================================================================================================
confirm_operation() {
    if [ "${force}" != 'true' ] ; then
        echo
        echo "WARNING! This will install or update Pi-hole as Docker container on your Synology"
        echo
  
        while true; do
            printf "Are you sure you want to continue? [y/N] "
            read -r yn
            yn=$(echo "${yn}" | tr '[:upper:]' '[:lower:]')

            case "${yn}" in
                y | yes )     break;;
                n | no | "" ) exit;;
                * )           echo "Please answer y(es) or n(o)";;
            esac
        done
    fi
}

#======================================================================================================================
# Generates a Docker compose file with substituted variables using a template.
#======================================================================================================================
# Globals:
#   - workdir
#   - param_interface
#   - param_subnet
#   - param_gateway
#   - param_ip_range
#   - param_pihole_hostname
#   - param_timezone
#   - param_webpassword
#   - param_domain_name
#   - param_dns1
#   - param_dns2
#   - param_pihole_ip
#   - param_data_path
#   - param_mac_address
#   - param_pihole_hostname
# Outputs:
#   A generated Docker Compose file in the working directory.
#======================================================================================================================
# shellcheck disable=SC2016
create_docker_compose_file() {
    print_status "Generating Docker Compose file"

    # create generated compose file
    if [ -f "${workdir}/${TEMPLATE_FILE}" ] ; then
        cp "${workdir}/${TEMPLATE_FILE}" "${workdir}/${COMPOSE_FILE}" > /dev/null 2>&1
    else
        terminate "File '${COMPOSE_FILE}' unavailable"
    fi

    # substitute variables
    safe_replace_in_file '${INTERFACE}' "${param_interface}" "${workdir}/${COMPOSE_FILE}"
    safe_replace_in_file '${SUBNET}' "${param_subnet}" "${workdir}/${COMPOSE_FILE}"
    safe_replace_in_file '${GATEWAY}' "${param_gateway}" "${workdir}/${COMPOSE_FILE}"
    safe_replace_in_file '${IP_RANGE}' "${param_ip_range}" "${workdir}/${COMPOSE_FILE}"
    safe_replace_in_file '${PIHOLE_HOSTNAME}' "${param_pihole_hostname}" "${workdir}/${COMPOSE_FILE}"
    safe_replace_in_file '${TIMEZONE}' "${param_timezone}" "${workdir}/${COMPOSE_FILE}"
    safe_replace_in_file '${WEBPASSWORD}' "${param_webpassword}" "${workdir}/${COMPOSE_FILE}"
    safe_replace_in_file '${DOMAIN_NAME}' "${param_domain_name}" "${workdir}/${COMPOSE_FILE}"
    safe_replace_in_file '${DNS1}' "${param_dns1}" "${workdir}/${COMPOSE_FILE}"
    safe_replace_in_file '${DNS2}' "${param_dns2}" "${workdir}/${COMPOSE_FILE}"
    safe_replace_in_file '${PIHOLE_IP}' "${param_pihole_ip}" "${workdir}/${COMPOSE_FILE}"
    safe_replace_in_file '${DATA_PATH}' "${param_data_path}" "${workdir}/${COMPOSE_FILE}"
    safe_replace_in_file '${MAC_ADDRESS}' "${param_mac_address}" "${workdir}/${COMPOSE_FILE}"
    safe_replace_in_file '${PIHOLE_HOSTNAME}' "${param_pihole_hostname}" "${workdir}/${COMPOSE_FILE}"
}

#======================================================================================================================
# Invokes synoservicectl to test the availability of the Docker daemon.
#======================================================================================================================
# Globals:
#   - log_prefix
# Outputs:
#   Exits with a non-zero exit code if the Docker service is not running, or a timeout occurred.
#======================================================================================================================
execute_wait_for_docker() {
    print_status "Testing Docker service availability"

    docker='false'
    i=0
    start=$(date +%s)
    elapsed=0

    [ -z "${log_prefix}" ] && printf 'Testing...  '

    while [ "${elapsed}" -le "${NW_TIMEOUT}" ] ; do
        # validate Docker service is running
        if synoservicectl --status "${SYNO_DOCKER_SERV_NAME}" | grep -q 'running'; then
            docker='true'
            break
        else
            i=$(((i + 1) % 4))
            spinner=$(echo '/-\|' | cut -c "$((i + 1))")
            [ -z "${log_prefix}" ] && printf "\b%s" "${spinner}"  # print spinner
            sleep 0.5
        fi
        current=$(date +%s)
        elapsed=$((current - start))
    done

    if [ "${docker}" = 'true' ] ; then
        [ -z "${log_prefix}" ] && printf "\b "
        log "Docker service detected"
    else
        [ -z "${log_prefix}" ] && printf "\b \n"
        terminate "Timeout waiting for Docker availability"
    fi
}

#======================================================================================================================
# Tests availability of the network service by checking the status of network interface.
#======================================================================================================================
# Globals:
#   - log_prefix
# Outputs:
#   Exits with a non-zero exit code if the network service is not available, or a timeout occurred.
#======================================================================================================================
execute_wait_for_network() {
    print_status "Testing network service availability"

    interface="${param_interface}"
    network='false'
    i=0
    start=$(date +%s)
    elapsed=0

    [ -z "${log_prefix}" ] && printf 'Testing...  '

    while [ "$elapsed" -le "${NW_TIMEOUT}" ] ; do
        # try to identify main interface if not provided as parameter
        # Note: this could fail as the the network service might not be available yet
        if [ -z "${interface}" ] ; then
            interface=$(ip route list | grep "default" | awk '{print $5}')
        fi

        # validate interface state is UP (the variable might be undefined)
        ip a s "${interface}" | grep -q 'state UP'
        result="$?"
        if [ -n "${interface}" ] && [ "${result}" -eq 0 ] ; then
            network='true'
            break
        else
            i=$(((i + 1) % 4))
            spinner=$(echo '/-\|' | cut -c "$((i + 1))")
            [ -z "${log_prefix}" ] && printf "\b%s" "${spinner}"  # print spinner
            sleep 0.5
        fi
        current=$(date +%s)
        elapsed=$((current - start))
    done

    if [ "${network}" = 'true' ] ; then
        [ -z "${log_prefix}" ] && printf "\b "
        log "Network service detected"
    else
        [ -z "${log_prefix}" ] && printf "\b \n"
        terminate "Timeout waiting for network availability"
    fi
}

#======================================================================================================================
# Creates a macvlan interface for the given interface. Is assigns the vlan name, host IP address, and Pi-hole IP 
# address.
#======================================================================================================================
# Globals:
#   - param_vlan_name
#   - param_interface
#   - param_host_ip
#   - param_pihole_ip
# Outputs:
#   Exits with a non-zero exit code if the macvlan network could not be created or reached.
#======================================================================================================================
execute_create_macvlan() {
    print_status "Creating interface to bridge host and docker network"

    status=''

    # (re-)create macvlan bridge attached to the network interface
    status=$(ip link | grep "${param_vlan_name}")
    if [ -z "$status" ] ; then
        log "Removing existing link '${param_vlan_name}'"
        ip link set "${param_vlan_name}" down > /dev/null 2>&1
        ip link delete "${param_vlan_name}" > /dev/null 2>&1
    fi
    log "Adding macvlan interface '${param_vlan_name}' "
    ip link add "${param_vlan_name}" link "${param_interface}" type macvlan mode bridge
    
    # assign host address to macvlan
    status=$(ip addr | grep "${param_vlan_name}")
    if [ -z "${status}" ] ; then
        log "Assign IP address '${param_host_ip}' to '${param_vlan_name}'"
        ip addr add "${param_host_ip}/32" dev "${param_vlan_name}" > /dev/null 2>&1
    else # this should never happen because link is deleted above if exists
        log "Updating current IP address of '${param_vlan_name}' to '${param_host_ip}'"
        ip addr change "${param_host_ip}/32" dev "${param_vlan_name}" > /dev/null 2>&1
    fi

    # bring macvlan interface up
    log "Bringing up interface '${param_vlan_name}'"
    ip link set "${param_vlan_name}" up > /dev/null 2>&1

    # add route to Pi-hole IP on macvlan interface
    status=$(ip route | grep "${param_vlan_name}" | grep "${param_pihole_ip}")
    if [ -z "${status}" ] ; then
        log "Adding static route from '${param_pihole_ip}/32' to '${param_vlan_name}'"
        ip route add "${param_pihole_ip}/32" dev "${param_vlan_name}" > /dev/null 2>&1
    fi

    # check virtual adapter status
    status=$(ip route | grep "${param_vlan_name}")
    if [ -z "${status}" ] ; then
        terminate "Could not create macvlan interface"
    fi
}

#======================================================================================================================
# Creates the Pi-hole Docker network and Docker container using a (generated) Docker compose file.
#======================================================================================================================
# Globals:
#   - workdir
# Outputs:
#   Exits with a non-zero exit code if the Docker network and/or container could not be created.
#======================================================================================================================
execute_create_container() {
    print_status "Creating Pi-hole container"

    # pull latest image
    if ! compose_log=$(docker-compose -f "${workdir}/$COMPOSE_FILE" pull 2>&1); then
        log "${compose_log}"
        terminate "Could not download latest Docker image"
    fi

    # start network and container in daemon mode
    if ! compose_log=$(docker-compose -f "${workdir}/$COMPOSE_FILE" up -d 2>&1); then
        log "${compose_log}"
        terminate "Could not create Docker network and/or container"
    fi
}

#======================================================================================================================
# Tests Pi-hole availability by establishing a connection to the admin portal.
#======================================================================================================================
# Globals:
#   - param_pihole_ip
#   - log_prefix
# Outputs:
#   Exits with a non-zero exit code if the Pi-hole portal could not be reached, or if a timeout occurred.
#======================================================================================================================
execute_test_pihole() {
    print_status "Testing Pi-hole availability"

    url="http://${param_pihole_ip}/admin/"
    code=0
    i=0
    start=$(date +%s)
    elapsed=0

    [ -z "${log_prefix}" ] && printf 'Testing...  '
    while [ "$elapsed" -le "$PI_TIMEOUT" ] ; do
        code=$(curl -o /dev/null -I -L -s -w "%{http_code}" "${url}")
        if [ "$code" = 200 ] ; then
            break
        else
            i=$(((i + 1) % 4))
            spinner=$(echo '/-\|' | cut -c "$((i + 1))")
            [ -z "${log_prefix}" ] && printf "\b%s" "${spinner}"  # print spinner
            sleep 0.5
        fi
        current=$(date +%s)
        elapsed=$((current - start))
    done

    if [ "${code}" = 200 ] ; then
        [ -z "${log_prefix}" ] && printf "\b "
        log "Successfully connected to Pi-hole portal (${url})"
    else
        [ -z "${log_prefix}" ] && printf "\b \n"
        terminate "Timeout connecting to Pi-hole"
    fi
}

#======================================================================================================================
# Assigns the Pi-hole password if applicable, skipped in force mode.
#======================================================================================================================
# Globals:
#   - param_webpassword
# Outputs:
#   Assigned Pi-hole password if applicable.
#======================================================================================================================
execute_create_password() {
    print_status "Setting Pi-hole password"
    
    if [ -z "${param_webpassword}" ] && [ "${force}" != 'true' ] ; then
        docker exec -it "${param_pihole_hostname}" pihole -a -p
    else
        log "Skipped in forced mode"
    fi
}

#=======================================================================================================================
# Main Script
#=======================================================================================================================

#======================================================================================================================
# Entrypoint for the script.
#======================================================================================================================
main() {
    # Show header
    show_header

    # Test if script has root privileges, exit otherwise
    current_id=$(id -u)
    if [ "${current_id}" -ne 0 ]; then 
        usage
        terminate "You need to be root to run this script"
    fi

    # Process and validate command-line arguments
    while [ "$1" != "" ]; do
        case "$1" in
            -f | --force )
                force='true'
                ;;
            -l | --log )
                log_prefix="[$(date --rfc-3339=seconds)] [SYNO_PIHOLE] "
                shift
                param_log_file="$1"
                is_valid_log_file || terminate "Invalid log file"
                ;;
            -h | --help )
                usage
                exit
                ;;
            -i | --ip )
                shift
                param_pihole_ip="$1"
                is_valid_ip "${param_pihole_ip}" || terminate "Invalid IP address"
                ;;
            -s | --subnet )
                shift
                param_subnet="$1"
                is_valid_cidr "${param_subnet}" || terminate "Invalid subnet"
                ;;
            -g | --gateway )
                shift
                param_gateway="$1"
                is_valid_ip "${param_gateway}" || terminate "Invalid gateway"
                ;;
            -r | --range )
                shift
                param_ip_range="$1"
                is_valid_cidr "${param_ip_range}" || terminate "Invalid IP range"
                ;;
            -v | --vlan )
                shift
                param_vlan_name="$1"
                ;;
            -n | --interface )
                shift
                param_interface="$1"
                ;;
            -m | --mac )
                shift
                param_mac_address="$1"
                is_valid_mac_address "${param_mac_address}" || terminate "Invalid unicast MAC address"
                ;;
            -d | --domain )
                shift
                param_domain_name="$1"
                ;;
            -H | --host )
                shift
                param_pihole_hostname="$1"
                ;;
            -t | --timezone )
                shift
                param_timezone="$1"
                ;;
            --DNS1 )
                shift
                param_dns1="$1"
                is_valid_ip "${param_dns1}" || terminate "Invalid DNS"
                ;;
            --DNS2 )
                shift
                param_dns2="$1"
                is_valid_ip "${param_dns2}" || terminate "Invalid DNS"
                ;;
            --path )
                shift
                param_data_path="$1"
                validate_provided_path || terminate "Invalid data path"
                ;;
            -p | --password )
                shift
                param_webpassword="$1"
                ;;
            --host-ip )
                shift
                param_host_ip="$1"
                ;;
            install | network | update  )
                command="$1"
                ;;
            * )
                usage
                terminate "Unrecognized parameter ($1)"
        esac
        shift
    done

    # Execute workflows
    case "${command}" in
        install )
            total_steps=8
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
            total_steps=5
            init_env
            execute_wait_for_docker
            detect_host_versions
            execute_wait_for_network
            init_settings
            confirm_operation
            execute_create_macvlan
            ;;
        update )
            total_steps=4
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
}

main "$@"