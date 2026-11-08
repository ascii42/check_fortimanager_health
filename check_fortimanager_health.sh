#!/bin/bash
#
# Monitor plugin for checking Fortinet FortiManager via JSON-RPC API
#
# Author:
#   Felix Longardt <monitoring@longardt.com>
#
# Version history:
# 1.0.0  2026-11-04  Initial release: -eSys -eDevices
# 1.1.0  2026-11-04  -eRes: FMG system performance (CPU/mem/disk); enhanced -eDevices
#                    with sig versions, HA, VDOMs, managed counts, last_checked age;
#                    better user/pass auth error; fixed version fields (mr/patch)
# 1.2.0  2026-11-04  -eADOMs: ADOM list and status check; -eFirmware: compare managed
#                    device FortiOS version against FMG update catalog; fix -eRes error
#                    message (/sys/performance not supported on FMG VM)
# 1.3.0  2026-11-04  -eTasks: recent task queue check for failed/stuck background tasks
# 1.4.0  2026-11-04  SNMP support: v2c (-SC) and v3 (-u/-a/-x/-X); -eRes via SNMP
#                    (CPU/mem/disk) replaces UNKNOWN-on-VM; -eUp: uptime via SNMP
# 1.5.0  2026-11-04  -eFGD: FortiGuard FDS server connectivity via SNMP walk;
#                    -eDevices: aggregate FAP/FSW/FEX totals in summary and perfdata
# 1.6.0  2026-11-04  -eFGD: add FortiGuard service subscription status (SNMP table
#                    walk of .103.11.3); --warn-lic/--crit-lic expiry thresholds;
#                    fix unreachable FDS server prefix ([-] neutral, not [WARNING])
#                    fix subscription 0/N valid + [OK] mismatch when SNMP lacks
#                    license columns (VM/unlicensed: show "N found (no license data)")
# 1.6.1  2026-11-04  -eFGD: add --warn-fds/--crit-fds thresholds; WARN when fewer
#                    than N FDS servers reachable (default warn<2, crit<1); per-server
#                    prefix now matches section severity ([WARNING]/[CRITICAL]/[-])
# 1.7.0  2026-11-04  -eNTP: NTP sync status and configured servers via API;
#                    -eSyslog: syslog server list via API; --no-ntp-warn/--no-syslog-warn
# 1.7.1  2026-11-04  -eDNS: configured DNS servers via API (requires full-admin);
#                    -eNTP verbose: ntpv3/auth/poll-interval per server;
#                    fix enable-all guard missing enable_up/enable_res/enable_dns
#

## VARIABLES
PROGNAME="${0##*/}"
PROGPATH="${0%/*}"
REVISION="1.7.1"
JQ="$(which jq)"
CURL="$(which curl)"
AWK="$(which awk)"
SNMPGET="$(which snmpget 2>/dev/null)"
SNMPWALK="$(which snmpwalk 2>/dev/null)"

# OIDs: standard MIB-2
OID_UPTIME=".1.3.6.1.2.1.1.3.0"              # sysUpTime (TimeTicks, hundredths of seconds)
OID_SYSNAME=".1.3.6.1.2.1.1.5.0"             # sysName

# OIDs: FORTINET-FORTIMANAGER-MIB (.1.3.6.1.4.1.12356.103)
OID_FMM_CPU=".1.3.6.1.4.1.12356.103.2.1.1.0"       # fmmSysCpuUsage (%)
OID_FMM_MEM_USED=".1.3.6.1.4.1.12356.103.2.1.2.0"  # fmmSysMemUsage (KB)
OID_FMM_MEM_CAP=".1.3.6.1.4.1.12356.103.2.1.3.0"   # fmmSysMemCapacity (KB)
OID_FMM_DISK_USED=".1.3.6.1.4.1.12356.103.2.1.4.0" # fmmSysDiskUsage (MB)
OID_FMM_DISK_CAP=".1.3.6.1.4.1.12356.103.2.1.5.0"  # fmmSysDiskCapacity (MB)
OID_FMM_UPTIME=".1.3.6.1.4.1.12356.103.2.1.8.0"    # fmmSysUpTime (Counter64, centiseconds)

# OIDs: FORTINET-FORTIMANAGER-MIB - FortiGuard FDS server table (.103.11.2.1.2.1)
OID_FGD_FDS_ADDR=".1.3.6.1.4.1.12356.103.11.2.1.2.1.2"   # fmmFdsSvrIpAddr (server address/hostname)
OID_FGD_FDS_STATUS=".1.3.6.1.4.1.12356.103.11.2.1.2.1.5" # fmmFdsSvrStatus (1=connected, 2=fail)

# OIDs: FORTINET-FORTIMANAGER-MIB - FortiGuard service license table (.103.11.3.1.1)
# Columns: 1=service-type-id, 2=status (1=ok/2=fail), 3=expiry-date, 4=version
OID_FGD_SVC_TABLE=".1.3.6.1.4.1.12356.103.11.3.1.1"

exit_unknown() {
	echo "Unknown parameter: ${1}"
	print_usage
	exit 4
}

print_usage() {
	echo "Usage: ${PROGNAME} [-h] [-V] -H <host> -T <api_token> [-opts]"
}

print_revision() {
	echo "${1} - v${2}"
}

print_help() {
	print_revision "${PROGNAME}" "${REVISION}"
	echo ""
	print_usage
cat << EOM


 This plugin monitors Fortinet FortiManager via the JSON-RPC API
 (https://<host>/jsonrpc).

 Uses HTTPS, accepts self-signed certificates by default (curl --insecure).
 Authentication via API token or username/password.
 For user/password login, the admin account must have JSON API Access set to
 Read-Write in FortiManager (System > Admin > Administrators > <user>).

 NOTE: -eADOMs, -eFirmware, and -eTasks require full-admin access (user/password
 or full-access API token). Read-only API tokens can only access -eSys/-eDevices.
 SNMP (-SC or -u) is optional and supplements API: provides -eRes CPU/mem/disk data
 (the /sys/performance API endpoint is not available on FortiManager VMs) and
 enables -eUp uptime monitoring. SNMP v3 passphrases must be at least 8 characters.

Options:
 -h, --help
    Print detailed help screen
 -V, --version
    Print version information

 -H, --host <hostname|IP>
    Hostname or IP address of the FortiManager
 -T, --token <token>
    API token (FortiManager GUI: System > Admin > REST API Admin)
 -U, --username <user>
    Username for login (alternative to -T)
 -P, --password <pass>
    Password for login (use with -U)
 --https-port <port>
    HTTPS/API port (default: 443)

 SNMP options (supplement API access for -eRes and -eUp):
 -SC, --snmp-community <community>
    SNMPv2c community string (enables SNMP-based resource/uptime collection)
 -u, --snmp-user <user>
    SNMPv3 security name (enables SNMPv3 mode)
 -l, --snmp-auth-proto <SHA|MD5>
    SNMPv3 auth protocol (default: SHA)
 -a, --snmp-auth-pass <pass>
    SNMPv3 auth passphrase (min 8 chars)
 -x, --snmp-priv-proto <AES|DES>
    SNMPv3 priv protocol (default: AES)
 -X, --snmp-priv-pass <pass>
    SNMPv3 priv passphrase (min 8 chars)
 -L, --snmp-sec-level <noAuthNoPriv|authNoPriv|authPriv>
    SNMPv3 security level (auto-detected from credentials when omitted)
 --snmp-port <port>
    SNMP UDP port (default: 161)

 Enable flags (opt-in; if any -eX is given, only those checks run):
 -eSys,     --enable-system
    System info: hostname, FortiManager version, HA mode, license status
 -eDevices, --enable-devices
    Managed device check: connection state, config sync, DB sync per device
    CRITICAL when any device is disconnected; WARNING when out of sync
    --warn-devices-down N    WARN when N or more devices are down (default: 1)
    --crit-devices-down N    CRIT when N or more devices are down (default: 1)
    --warn-devices-unsynced N  WARN when N+ devices unsynced (default: 1)
    --crit-devices-unsynced N  CRIT when N+ devices unsynced (default: -1=off)
    --warn-dev-age <minutes>   WARN when device last-check older than N min (-1=off)
    --crit-dev-age <minutes>   CRIT when device last-check older than N min (-1=off)
    Verbose: serial, FortiOS version, AV/IPS signatures, HA mode, VDOM count,
    managed FortiAP/FortiSwitch/FortiExtender counts
 -eADOMs,   --enable-adoms
    ADOM list: show all FortiGate-type ADOMs (restricted_prds=1) with quota info
    CRITICAL on disabled ADOMs; use --all-adoms to include product/system ADOMs
    Requires full-admin access (not available with read-only API token)
 -eFirmware,--enable-firmware
    Compare managed device FortiOS versions against the FMG update catalog
    (/um/image/version/list); WARN when any device has available updates
    Default: only warn on Mature (M) releases; use --firmware-all to include Fresh
    --no-firmware-warn: suppress update warnings (informational only)
    --firmware-all: include Fresh (F) release candidates in update detection
    Requires full-admin access
 -eRes,     --enable-resources
    System resources: CPU, memory, disk usage with thresholds
    When SNMP credentials are provided (-SC or -u): uses FORTINET-FORTIMANAGER-MIB
    OIDs (works on VM builds). Without SNMP: uses /sys/performance API (hardware only)
    -wCPU <N>  WARNING threshold for CPU % (default: 80)
    -cCPU <N>  CRITICAL threshold for CPU % (default: 90)
    -wMem <N>  WARNING threshold for memory % (default: 80)
    -cMem <N>  CRITICAL threshold for memory % (default: 90)
    --warn-disk <N>  WARNING threshold for disk % (default: 80)
    --crit-disk <N>  CRITICAL threshold for disk % (default: 90)
 -eUp,      --enable-uptime
    System uptime (SNMP only - requires -SC or -u/-a/-x/-X)
    --warn-reboot-minutes N  WARN if uptime < N minutes (default: -1=off)
 -eTasks,   --enable-tasks
    Recent task queue: alert on failed or stuck background tasks (policy installs,
    device adds, firmware upgrades, etc.)
    CRITICAL on task state=error; WARNING on tasks completed with errors
    --task-hours N         Only check tasks started within last N hours (default: 24)
    --warn-tasks-failed N  WARN when N or more tasks have errors (default: 1)
    --crit-tasks-failed N  CRIT when N or more tasks have errors (default: 1)
    --task-stuck-minutes N WARN if a running task exceeds N minutes (default: -1=off)
    Requires full-admin access
 -eFGD,     --enable-fortiguard
    FortiGuard FDS server connectivity + service subscription status (SNMP only)
    Requires -SC or -u/-a/-x/-X. When used with -A and no SNMP, skipped silently.
    FDS connectivity: walks FORTINET-FORTIMANAGER-MIB FDS server table.
      --warn-fds N  WARN when fewer than N FDS servers connected (default: 2)
      --crit-fds N  CRIT when fewer than N FDS servers connected (default: 1)
      Unreachable server lines use [-], [WARNING], or [CRITICAL] to match the
      section severity so sub-line prefixes never cause false state escalation.
    Subscriptions: walks service license table (.103.11.3.1.1) for each registered
      FortiGuard service (AV, IPS, AppCtrl, etc.): status and expiry date.
      --warn-lic N  WARN when a subscription expires in less than N days (default: 30)
      --crit-lic N  CRIT when a subscription expires in less than N days (default: 15)
 -eNTP,     --enable-ntp
    NTP configuration: sync status and configured server list via API
    WARNING when NTP sync is disabled; WARNING when enabled but no servers configured
    --no-ntp-warn: suppress warning when NTP is disabled (informational only)
 -eSyslog,  --enable-syslog
    Syslog configuration: list of configured syslog servers via API
    WARNING when no syslog servers are configured (best practice)
    --no-syslog-warn: suppress warning when no syslog configured
 -eDNS,     --enable-dns
    DNS server configuration via API (/cli/global/system/dns)
    Shows primary, secondary, tertiary DNS servers; WARNING if none configured
    Requires full-admin access (not available with read-only API token)
 -A,        --enable-all
    Enable all available checks (default when no -eX flags given)

 Disable flags (opt-out from -A):
 --disable-system    --disable-devices    --disable-adoms
 --disable-firmware  --disable-resources  --disable-tasks
 --disable-fortiguard  --disable-uptime
 --disable-ntp       --disable-syslog     --disable-dns

 --blacklist-device <list>
    Comma-separated list of device names to skip entirely
 --adom <name>
    Only check devices in this ADOM (affects -eDevices endpoint)
 --all-adoms
    In -eADOMs, include product/system ADOMs (FortiMail, FortiProxy, etc.)

 --no-perfdata
    Suppress the perfdata section entirely (no | output)
 -s,  --silent
    Show only problem lines (suppress OK detail)
 -v,  --verbose
    Print section headers and extra detail
 -d,  --debug
    Enable bash debug output (set -x)

Example: ${PROGNAME} -H 10.0.0.1 -T MyReadOnlyToken -eSys -eDevices
         ${PROGNAME} -H 10.0.0.1 -U admin -P secret -A
         ${PROGNAME} -H 10.0.0.1 -U admin -P secret -eDevices --warn-dev-age 60
         ${PROGNAME} -H 10.0.0.1 -U admin -P secret -eFirmware --no-firmware-warn
         ${PROGNAME} -H 10.0.0.1 -U admin -P secret -eTasks --task-hours 48
         ${PROGNAME} -H 10.0.0.1 -U admin -P secret -SC monitor -eRes -eUp
         ${PROGNAME} -H 10.0.0.1 -U admin -P secret -SC monitor -eFGD
         ${PROGNAME} -H 10.0.0.1 -U admin -P secret -eNTP -eSyslog
         ${PROGNAME} -H 10.0.0.1 -U admin -P secret -u monitor -a monit0r1 -x monit0r1 -A

EOM
}

## BEGIN
while [[ -n "${1}" ]]; do
	case "${1}" in
	-h|--help)
		print_help
		exit 0
		;;
	-V|--version)
		print_revision "${PROGNAME}" "${REVISION}"
		exit 0
		;;
	-H|--host)
		shift ; fmg_host="${1}" ;;
	-T|--token|--api-token)
		shift ; api_token="${1}" ;;
	-U|--username)
		shift ; api_user="${1}" ;;
	-P|--password)
		shift ; api_pass="${1}" ;;
	--https-port)
		shift ; https_port="${1}" ;;
	# SNMP credentials
	-SC|--snmp-community)  shift ; snmp_community="${1}" ;;
	-u|--snmp-user)        shift ; snmp_user="${1}" ;;
	-l|--snmp-auth-proto)  shift ; snmp_auth_proto="${1}" ;;
	-a|--snmp-auth-pass)   shift ; snmp_auth_pass="${1}" ;;
	-x|--snmp-priv-proto)  shift ; snmp_priv_proto="${1}" ;;
	-X|--snmp-priv-pass)   shift ; snmp_priv_pass="${1}" ;;
	-L|--snmp-sec-level)   shift ; snmp_sec_level="${1}" ;;
	--snmp-port)           shift ; snmp_port="${1}" ;;
	# Enable flags
	-eSys|--enable-system)       enable_sys=1 ;;
	-eDevices|--enable-devices)  enable_devices=1 ;;
	-eADOMs|--enable-adoms)      enable_adoms=1 ;;
	-eFirmware|--enable-firmware) enable_firmware=1 ;;
	-eRes|--enable-resources)    enable_res=1 ;;
	-eUp|--enable-uptime)        enable_up=1 ;;
	-A|--enable-all)             enable_all=1 ;;
	# Disable flags
	--disable-system)    disable_sys=1 ;;
	--disable-devices)   disable_devices=1 ;;
	--disable-adoms)     disable_adoms=1 ;;
	--disable-firmware)  disable_firmware=1 ;;
	--disable-resources) disable_res=1 ;;
	--disable-uptime)    disable_up=1 ;;
	# Resource thresholds
	-wCPU)        shift ; warn_cpu="${1}" ;;
	-cCPU)        shift ; crit_cpu="${1}" ;;
	-wMem)        shift ; warn_mem="${1}" ;;
	-cMem)        shift ; crit_mem="${1}" ;;
	--warn-disk)  shift ; warn_disk="${1}" ;;
	--crit-disk)  shift ; crit_disk="${1}" ;;
	# Device thresholds
	--warn-devices-down)      shift ; warn_devices_down="${1}" ;;
	--crit-devices-down)      shift ; crit_devices_down="${1}" ;;
	--warn-devices-unsynced)  shift ; warn_devices_unsynced="${1}" ;;
	--crit-devices-unsynced)  shift ; crit_devices_unsynced="${1}" ;;
	--warn-dev-age)           shift ; warn_dev_age="${1}" ;;
	--crit-dev-age)           shift ; crit_dev_age="${1}" ;;
	# Options
	--blacklist-device)   shift ; device_blacklist="${1}" ;;
	--adom)               shift ; filter_adom="${1}" ;;
	--all-adoms)          all_adoms=1 ;;
	--no-firmware-warn)   no_firmware_warn=1 ;;
	--firmware-all)       firmware_all=1 ;;
	# Task options
	-eTasks|--enable-tasks)  enable_tasks=1 ;;
	--disable-tasks)         disable_tasks=1 ;;
	--task-hours)            shift ; task_hours="${1}" ;;
	-eFGD|--enable-fortiguard|--enable-fortiGuard)  enable_fgd=1 ;;
	--disable-fortiguard|--disable-fortiGuard)      disable_fgd=1 ;;
	--warn-lic)   shift ; warn_lic="${1}" ;;
	--crit-lic)   shift ; crit_lic="${1}" ;;
	--warn-fds)   shift ; warn_fds="${1}" ;;
	--crit-fds)   shift ; crit_fds="${1}" ;;
	-eNTP|--enable-ntp)      enable_ntp=1 ;;
	--disable-ntp)           disable_ntp=1 ;;
	--no-ntp-warn)           no_ntp_warn=1 ;;
	-eSyslog|--enable-syslog) enable_syslog=1 ;;
	--disable-syslog)         disable_syslog=1 ;;
	--no-syslog-warn)         no_syslog_warn=1 ;;
	-eDNS|--enable-dns)      enable_dns=1 ;;
	--disable-dns)           disable_dns=1 ;;
	--warn-tasks-failed)     shift ; warn_tasks_failed="${1}" ;;
	--crit-tasks-failed)     shift ; crit_tasks_failed="${1}" ;;
	--task-stuck-minutes)    shift ; task_stuck_minutes="${1}" ;;
	--no-perfdata)        no_perfdata=1 ;;
	-s|--silent)          silent=1 ;;
	-v|--verbose)         verbose=1 ;;
	-d|--debug)           debug=1 ;;
	*)
		exit_unknown "${1}"
		;;
	esac
	shift
done

# Check mandatory parameters
[[ -z "${JQ}" ]]   && { echo "${PROGNAME}: jq is required - please install it";   exit 4; }
[[ -z "${CURL}" ]] && { echo "${PROGNAME}: curl is required - please install it"; exit 4; }
[[ -z "${AWK}" ]]  && { echo "${PROGNAME}: awk is required - please install it";  exit 4; }
[[ -z "${fmg_host}" ]] && exit_unknown "FortiManager hostname or IP (-H) is required!"
[[ -z "${api_token}" && ( -z "${api_user}" || -z "${api_pass}" ) && -z "${snmp_community}" && -z "${snmp_user}" ]] && \
	exit_unknown "Authentication required: -T <api_token>  OR  -U <user> -P <pass>  OR  -SC / -u (SNMP supplement)"

# Default thresholds
[[ -z "${warn_cpu}" ]]              && warn_cpu=80
[[ -z "${crit_cpu}" ]]              && crit_cpu=90
[[ -z "${warn_mem}" ]]              && warn_mem=80
[[ -z "${crit_mem}" ]]              && crit_mem=90
[[ -z "${warn_disk}" ]]             && warn_disk=80
[[ -z "${crit_disk}" ]]             && crit_disk=90
[[ -z "${warn_devices_down}" ]]     && warn_devices_down=1
[[ -z "${crit_devices_down}" ]]     && crit_devices_down=1
[[ -z "${warn_devices_unsynced}" ]] && warn_devices_unsynced=1
[[ -z "${crit_devices_unsynced}" ]] && crit_devices_unsynced=-1
[[ -z "${warn_dev_age}" ]]          && warn_dev_age=-1
[[ -z "${crit_dev_age}" ]]          && crit_dev_age=-1
[[ -z "${task_hours}" ]]            && task_hours=24
[[ -z "${warn_tasks_failed}" ]]     && warn_tasks_failed=1
[[ -z "${crit_tasks_failed}" ]]     && crit_tasks_failed=1
[[ -z "${task_stuck_minutes}" ]]    && task_stuck_minutes=-1
[[ -z "${warn_reboot_minutes}" ]]   && warn_reboot_minutes=-1
[[ -z "${snmp_port}" ]]             && snmp_port=161
[[ -z "${warn_lic}" ]]              && warn_lic=30
[[ -z "${crit_lic}" ]]              && crit_lic=15
[[ -z "${warn_fds}" ]]              && warn_fds=2
[[ -z "${crit_fds}" ]]              && crit_fds=1

# SNMPv3 passphrase length validation (USM requires minimum 8 characters)
if [[ -n "${snmp_auth_pass}" && ${#snmp_auth_pass} -lt 8 ]]; then
	echo "[UNKNOWN] - SNMPv3 auth passphrase too short (${#snmp_auth_pass} chars) - USM requires minimum 8 characters"
	exit 4
fi
if [[ -n "${snmp_priv_pass}" && ${#snmp_priv_pass} -lt 8 ]]; then
	echo "[UNKNOWN] - SNMPv3 priv passphrase too short (${#snmp_priv_pass} chars) - USM requires minimum 8 characters"
	exit 4
fi

# If no explicit enable flags -> enable all
[[
-z "${enable_sys}"      &&
-z "${enable_devices}"  &&
-z "${enable_adoms}"    &&
-z "${enable_firmware}" &&
-z "${enable_res}"      &&
-z "${enable_up}"       &&
-z "${enable_tasks}"    &&
-z "${enable_fgd}"      &&
-z "${enable_ntp}"      &&
-z "${enable_syslog}"   &&
-z "${enable_dns}"      &&
-z "${enable_all}"
]] && enable_all=1

# Curl options
CURL_OPTS="--max-time 15"
[[ -z "${https_verify}" ]] && CURL_OPTS="--insecure ${CURL_OPTS}"
if [[ -n "${debug}" ]]; then
	CURL_OPTS="-v ${CURL_OPTS}"
else
	CURL_OPTS="--silent ${CURL_OPTS}"
fi

# Status labels
status_ok="[OK]"
status_warn="[WARNING]"
status_crit="[CRITICAL]"
status_unkn="[UNKNOWN]"

# Base API URL
[[ -n "${https_port}" ]] && _port_str=":${https_port}"
FMG_API="https://${fmg_host}${_port_str}/jsonrpc"

if [[ -n "${debug}" ]]; then
	echo "Debugging mode ON." 1>&2
	set -x
fi

# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------
if [[ -z "${api_token}" && -n "${api_user}" && -n "${api_pass}" ]]; then
	_login_resp=$(${CURL} ${CURL_OPTS} -X POST "${FMG_API}" \
		-H "Content-Type: application/json" \
		-d "$(${JQ} -n --arg u "${api_user}" --arg p "${api_pass}" \
			'{"method":"exec","params":[{"url":"/sys/login/user","data":{"user":$u,"passwd":$p}}],"id":1}')")
	_login_code=$(echo "${_login_resp}" | ${JQ} -r '.result[0].status.code // -1' 2>/dev/null)
	api_token=$(echo "${_login_resp}" | ${JQ} -r '.session // empty' 2>/dev/null)
	if [[ -z "${api_token}" ]]; then
		if [[ "${_login_code}" == "-11" ]]; then
			echo "${status_unkn} - Login to ${fmg_host} failed: No permission (code -11)"
			echo "  -> Enable JSON API Access for the admin account in FortiManager:"
			echo "     System > Admin > Administrators > ${api_user} > JSON API Access: Read-Write"
		else
			echo "${status_unkn} - Login to ${fmg_host} failed (code ${_login_code}) - check credentials"
		fi
		exit 4
	fi
	_fmg_session="${api_token}"
	trap '_fmg_logout' EXIT
fi

_fmg_logout() {
	[[ -z "${_fmg_session}" ]] && return
	${CURL} ${CURL_OPTS} -X POST "${FMG_API}" \
		-H "Content-Type: application/json" \
		-d "$(${JQ} -n --arg s "${_fmg_session}" \
			'{"method":"exec","params":[{"url":"/sys/logout"}],"id":99,"session":$s}')" \
		>/dev/null 2>&1 || true
}

# POST to /jsonrpc: method=get, url=$1
fmg_api_get() {
	local _url="${1}"
	${CURL} ${CURL_OPTS} -X POST "${FMG_API}" \
		-H "Authorization: Bearer ${api_token}" \
		-H "Content-Type: application/json" \
		-d "$(${JQ} -n --arg url "${_url}" --arg s "${api_token}" \
			'{"method":"get","params":[{"url":$url}],"id":1,"session":$s}')"
}

# POST to /jsonrpc: method=get, url=$1, with data.product=FGT and data.platform=$2
fmg_fw_catalog() {
	local _platform="${1}"
	${CURL} ${CURL_OPTS} -X POST "${FMG_API}" \
		-H "Authorization: Bearer ${api_token}" \
		-H "Content-Type: application/json" \
		-d "$(${JQ} -n --arg s "${api_token}" --arg p "${_platform}" \
			'{"method":"get","params":[{"url":"/um/image/version/list","data":{"product":"FGT","platform":$p}}],"id":1,"session":$s}')"
}

# ---------------------------------------------------------------------------
# SNMP helper - v2c (--snmp-community) or v3 (--snmp-user)
# Used by -eRes and -eUp; supplements the JSON-RPC API
# ---------------------------------------------------------------------------
_snmp_avail=""
if [[ -n "${SNMPGET}" ]]; then
	if [[ -n "${snmp_user}" ]]; then
		_snmp_avail=1
		_snmp_sec="${snmp_sec_level}"
		if [[ -z "${_snmp_sec}" ]]; then
			if [[ -n "${snmp_auth_pass}" && -n "${snmp_priv_pass}" ]]; then
				_snmp_sec="authPriv"
			elif [[ -n "${snmp_auth_pass}" ]]; then
				_snmp_sec="authNoPriv"
			else
				_snmp_sec="noAuthNoPriv"
			fi
		fi
		_snmp_get() {
			local -a _cmd=("${SNMPGET}" -v3 -u "${snmp_user}" -l "${_snmp_sec}" -Ovq -t 2 -r 1)
			[[ -n "${snmp_auth_pass}" ]] && _cmd+=(-a "${snmp_auth_proto:-SHA}" -A "${snmp_auth_pass}")
			[[ -n "${snmp_priv_pass}" ]] && _cmd+=(-x "${snmp_priv_proto:-AES}" -X "${snmp_priv_pass}")
			"${_cmd[@]}" "${fmg_host}:${snmp_port}" "$1" 2>/dev/null | tr -d '"' | tr -d ' '
		}
		_snmp_walk() {
			[[ -z "${SNMPWALK}" ]] && return 1
			local -a _wcmd=("${SNMPWALK}" -v3 -u "${snmp_user}" -l "${_snmp_sec}" -Ovqe -t 2 -r 1)
			[[ -n "${snmp_auth_pass}" ]] && _wcmd+=(-a "${snmp_auth_proto:-SHA}" -A "${snmp_auth_pass}")
			[[ -n "${snmp_priv_pass}" ]] && _wcmd+=(-x "${snmp_priv_proto:-AES}" -X "${snmp_priv_pass}")
			"${_wcmd[@]}" "${fmg_host}:${snmp_port}" "$1" 2>/dev/null | tr -d '"'
		}
		_snmp_walk_on() {
			[[ -z "${SNMPWALK}" ]] && return 1
			local -a _wcmd=("${SNMPWALK}" -v3 -u "${snmp_user}" -l "${_snmp_sec}" -Onqe -t 2 -r 1)
			[[ -n "${snmp_auth_pass}" ]] && _wcmd+=(-a "${snmp_auth_proto:-SHA}" -A "${snmp_auth_pass}")
			[[ -n "${snmp_priv_pass}" ]] && _wcmd+=(-x "${snmp_priv_proto:-AES}" -X "${snmp_priv_pass}")
			"${_wcmd[@]}" "${fmg_host}:${snmp_port}" "$1" 2>/dev/null
		}
	elif [[ -n "${snmp_community}" ]]; then
		_snmp_avail=1
		_snmp_get() {
			"${SNMPGET}" -v2c -c "${snmp_community}" -Ovq -t 2 -r 1 \
				"${fmg_host}:${snmp_port}" "$1" 2>/dev/null | tr -d '"' | tr -d ' '
		}
		_snmp_walk() {
			[[ -z "${SNMPWALK}" ]] && return 1
			"${SNMPWALK}" -v2c -c "${snmp_community}" -Ovqe -t 2 -r 1 \
				"${fmg_host}:${snmp_port}" "$1" 2>/dev/null | tr -d '"'
		}
		_snmp_walk_on() {
			[[ -z "${SNMPWALK}" ]] && return 1
			"${SNMPWALK}" -v2c -c "${snmp_community}" -Onqe -t 2 -r 1 \
				"${fmg_host}:${snmp_port}" "$1" 2>/dev/null
		}
	fi
fi

# Output buffers
fmg_output=""
fmg_problem_output=""
fmg_perf=""

# ---------------------------------------------------------------------------
# -eSys: System status
# ---------------------------------------------------------------------------
if [[ ( -n "${enable_sys}" || -n "${enable_all}" ) && -z "${disable_sys}" ]]; then
	if [[ -n "${verbose}" ]]; then
		fmg_output+="System Info:\n---------------------------------------\n"
	fi

	_sys_resp=$(fmg_api_get "/sys/status")
	_sys_code=$(echo "${_sys_resp}" | ${JQ} -r '.result[0].status.code // -1' 2>/dev/null)

	if [[ "${_sys_code}" != "0" ]]; then
		fmg_output+="${status_unkn} - System: cannot retrieve system status (API code ${_sys_code})\n"
	else
		_sys_data=$(echo "${_sys_resp}" | ${JQ} -r '.result[0].data' 2>/dev/null)
		_sys_hostname=$(echo "${_sys_data}" | ${JQ} -r '.Hostname // "unknown"' 2>/dev/null)
		_sys_version=$(echo "${_sys_data}" | ${JQ} -r '.Version // "unknown"' 2>/dev/null)
		_sys_platform=$(echo "${_sys_data}" | ${JQ} -r '."Platform Full Name" // "FortiManager"' 2>/dev/null)
		_sys_hamode=$(echo "${_sys_data}" | ${JQ} -r '."HA Mode" // "unknown"' 2>/dev/null)
		_sys_license=$(echo "${_sys_data}" | ${JQ} -r '."License Status" // "unknown"' 2>/dev/null)
		_sys_offline=$(echo "${_sys_data}" | ${JQ} -r '."Offline Mode" // "unknown"' 2>/dev/null)
		_sys_serial=$(echo "${_sys_data}" | ${JQ} -r '."Serial Number" // "unknown"' 2>/dev/null)

		_sys_sev="${status_ok}"
		if [[ "${_sys_license,,}" != "valid" && "${_sys_license}" != "unknown" ]]; then
			_sys_sev="${status_warn}"
		fi

		fmg_output+="${_sys_sev} - System: ${_sys_hostname} ${_sys_platform} ${_sys_version} (${_sys_hamode})\n"

		if [[ -n "${verbose}" ]]; then
			fmg_output+="\_ ${status_ok} Serial:       ${_sys_serial}\n"
			fmg_output+="\_ ${status_ok} HA Mode:      ${_sys_hamode}\n"
			fmg_output+="\_ ${_sys_sev} License:     ${_sys_license}\n"
			fmg_output+="\_ ${status_ok} Offline Mode: ${_sys_offline}\n"
		fi

		if [[ "${_sys_sev}" != "${status_ok}" ]]; then
			fmg_problem_output+="${_sys_sev} - System: ${_sys_hostname} ${_sys_version} - License: ${_sys_license}\n"
		fi
	fi

	if [[ -n "${verbose}" ]]; then
		fmg_output+="---------------------------------------\n\n"
	fi
fi

# ---------------------------------------------------------------------------
# -eRes: System resources (CPU / memory / disk) via /sys/performance
# This endpoint is only available on hardware appliances, not FortiManager VMs
# ---------------------------------------------------------------------------
if [[ ( -n "${enable_res}" || -n "${enable_all}" ) && -z "${disable_res}" ]]; then
	if [[ -n "${verbose}" ]]; then
		fmg_output+="System Resources:\n---------------------------------------\n"
	fi

	if [[ -n "${_snmp_avail}" ]]; then
		# SNMP path: FORTINET-FORTIMANAGER-MIB (works on VM and hardware)
		_cpu_raw=$(_snmp_get "${OID_FMM_CPU}")
		_mem_used_raw=$(_snmp_get "${OID_FMM_MEM_USED}")
		_mem_cap_raw=$(_snmp_get "${OID_FMM_MEM_CAP}")
		_disk_used_raw=$(_snmp_get "${OID_FMM_DISK_USED}")
		_disk_cap_raw=$(_snmp_get "${OID_FMM_DISK_CAP}")

		[[ "${_cpu_raw}"      =~ ^[0-9]+$ ]] && _cpu_pct="${_cpu_raw}"      || _cpu_pct=-1
		[[ "${_mem_used_raw}" =~ ^[0-9]+$ ]] && _mem_used_kb="${_mem_used_raw}" || _mem_used_kb=0
		[[ "${_mem_cap_raw}"  =~ ^[0-9]+$ ]] && _mem_cap_kb="${_mem_cap_raw}"   || _mem_cap_kb=0
		[[ "${_disk_used_raw}" =~ ^[0-9]+$ ]] && _disk_used_mb="${_disk_used_raw}" || _disk_used_mb=0
		[[ "${_disk_cap_raw}"  =~ ^[0-9]+$ ]] && _disk_cap_mb="${_disk_cap_raw}"  || _disk_cap_mb=0

		if [[ "${_mem_cap_kb}" -gt 0 ]] 2>/dev/null; then
			_mem_pct=$(( _mem_used_kb * 100 / _mem_cap_kb ))
			_mem_used_mb=$(( _mem_used_kb / 1024 ))
			_mem_cap_mb_disp=$(( _mem_cap_kb / 1024 ))
		else
			_mem_pct=-1; _mem_used_mb=0; _mem_cap_mb_disp=0
		fi

		if [[ "${_disk_cap_mb}" -gt 0 ]] 2>/dev/null; then
			_disk_pct=$(( _disk_used_mb * 100 / _disk_cap_mb ))
		else
			_disk_pct=-1
		fi
	else
		# API path - only works on hardware appliances (not FortiManager VMs)
		_res_resp=$(fmg_api_get "/sys/performance")
		_res_code=$(echo "${_res_resp}" | ${JQ} -r '.result[0].status.code // -1' 2>/dev/null)

		if [[ "${_res_code}" == "-11" ]]; then
			fmg_output+="${status_unkn} - Resources: /sys/performance not available on this FortiManager (VM/version limitation); add -SC <community> or -u/-a/-x/-X for SNMP\n"
		elif [[ "${_res_code}" != "0" ]]; then
			fmg_output+="${status_unkn} - Resources: cannot retrieve performance data (API code ${_res_code})\n"
		else
			_res_data=$(echo "${_res_resp}" | ${JQ} -r '.result[0].data' 2>/dev/null)

			_cpu_pct=$(echo "${_res_data}" | ${JQ} -r '
				if .cpu | type == "number" then .cpu
				elif .cpu.usage? then .cpu.usage
				else (100 - (.cpu.idle // 100))
				end // -1' 2>/dev/null)

			_mem_pct=$(echo "${_res_data}" | ${JQ} -r '
				if .mem | type == "number" then .mem
				elif .memory?.used? then
					((.memory.used / .memory.total) * 100 | round)
				else -1
				end // -1' 2>/dev/null)

			_disk_pct=$(echo "${_res_data}" | ${JQ} -r '
				if .disk | type == "number" then .disk
				elif .disk?.used? then
					((.disk.used / .disk.total) * 100 | round)
				elif .flash_disk?.used? then
					((.flash_disk.used / .flash_disk.total) * 100 | round)
				else -1
				end // -1' 2>/dev/null)
		fi
	fi

	if [[ -n "${_snmp_avail}" || "${_res_code}" == "0" ]]; then
		_res_sev="${status_ok}"
		_cpu_sev="${status_ok}"
		_mem_sev="${status_ok}"
		_dsk_sev="${status_ok}"

		if [[ "${_cpu_pct}" != "-1" ]] 2>/dev/null; then
			if (( _cpu_pct >= crit_cpu )) 2>/dev/null; then
				_cpu_sev="${status_crit}"; _res_sev="${status_crit}"
			elif (( _cpu_pct >= warn_cpu )) 2>/dev/null; then
				_cpu_sev="${status_warn}"; [[ "${_res_sev}" == "${status_ok}" ]] && _res_sev="${status_warn}"
			fi
		fi
		if [[ "${_mem_pct}" != "-1" ]] 2>/dev/null; then
			if (( _mem_pct >= crit_mem )) 2>/dev/null; then
				_mem_sev="${status_crit}"; _res_sev="${status_crit}"
			elif (( _mem_pct >= warn_mem )) 2>/dev/null; then
				_mem_sev="${status_warn}"; [[ "${_res_sev}" == "${status_ok}" ]] && _res_sev="${status_warn}"
			fi
		fi
		if [[ "${_disk_pct}" != "-1" ]] 2>/dev/null; then
			if (( _disk_pct >= crit_disk )) 2>/dev/null; then
				_dsk_sev="${status_crit}"; _res_sev="${status_crit}"
			elif (( _disk_pct >= warn_disk )) 2>/dev/null; then
				_dsk_sev="${status_warn}"; [[ "${_res_sev}" == "${status_ok}" ]] && _res_sev="${status_warn}"
			fi
		fi

		_cpu_str="${_cpu_pct}%"; [[ "${_cpu_pct}" == "-1" ]] && _cpu_str="n/a"
		_mem_str="${_mem_pct}%"; [[ "${_mem_pct}" == "-1" ]] && _mem_str="n/a"
		_dsk_str="${_disk_pct}%"; [[ "${_disk_pct}" == "-1" ]] && _dsk_str="n/a"

		fmg_output+="${_res_sev} - Resources: CPU ${_cpu_str}, Memory ${_mem_str}, Disk ${_dsk_str}\n"

		if [[ -n "${verbose}" ]]; then
			fmg_output+="\_ ${_cpu_sev} CPU:    ${_cpu_str} (warn: ${warn_cpu}%, crit: ${crit_cpu}%)\n"
			if [[ -n "${_snmp_avail}" && "${_mem_pct}" != "-1" ]]; then
				fmg_output+="\_ ${_mem_sev} Memory: ${_mem_str} ${_mem_used_mb}MB / ${_mem_cap_mb_disp}MB (warn: ${warn_mem}%, crit: ${crit_mem}%)\n"
				fmg_output+="\_ ${_dsk_sev} Disk:   ${_dsk_str} ${_disk_used_mb}MB / ${_disk_cap_mb}MB (warn: ${warn_disk}%, crit: ${crit_disk}%)\n"
			else
				fmg_output+="\_ ${_mem_sev} Memory: ${_mem_str} (warn: ${warn_mem}%, crit: ${crit_mem}%)\n"
				fmg_output+="\_ ${_dsk_sev} Disk:   ${_dsk_str} (warn: ${warn_disk}%, crit: ${crit_disk}%)\n"
			fi
		fi

		if [[ "${_res_sev}" != "${status_ok}" ]]; then
			fmg_problem_output+="${_res_sev} - Resources: CPU ${_cpu_str} Memory ${_mem_str} Disk ${_dsk_str}\n"
		fi

		if [[ -z "${no_perfdata}" ]]; then
			[[ "${_cpu_pct}"  != "-1" ]] && fmg_perf+=" cpu=${_cpu_pct}%;${warn_cpu};${crit_cpu};0;100"
			[[ "${_mem_pct}"  != "-1" ]] && fmg_perf+=" mem=${_mem_pct}%;${warn_mem};${crit_mem};0;100"
			[[ "${_disk_pct}" != "-1" ]] && fmg_perf+=" disk=${_disk_pct}%;${warn_disk};${crit_disk};0;100"
			[[ -n "${_snmp_avail}" && "${_mem_used_mb}" -gt 0 ]] 2>/dev/null && \
				fmg_perf+=" mem_used_mb=${_mem_used_mb} mem_cap_mb=${_mem_cap_mb_disp}"
			[[ -n "${_snmp_avail}" && "${_disk_used_mb}" -gt 0 ]] 2>/dev/null && \
				fmg_perf+=" disk_used_mb=${_disk_used_mb} disk_cap_mb=${_disk_cap_mb}"
		fi
	fi

	if [[ -n "${verbose}" ]]; then
		fmg_output+="---------------------------------------\n\n"
	fi
fi

# ---------------------------------------------------------------------------
# -eUp: System uptime via SNMP (SNMP only)
# ---------------------------------------------------------------------------
if [[ -n "${enable_up}" && -z "${disable_up}" ]]; then
	if [[ -n "${verbose}" ]]; then
		fmg_output+="Uptime:\n---------------------------------------\n"
	fi

	if [[ -z "${_snmp_avail}" ]]; then
		fmg_output+="${status_unkn} - Uptime: SNMP credentials required (-SC <community> or -u/-a/-x/-X for SNMPv3)\n"
	else
		_up_raw=$(_snmp_get "${OID_FMM_UPTIME}")
		if [[ ! "${_up_raw}" =~ ^[0-9]+$ ]]; then
			_up_raw=$(_snmp_get "${OID_UPTIME}" | grep -o '[0-9]*' | head -1)
		fi

		if [[ -z "${_up_raw}" || ! "${_up_raw}" =~ ^[0-9]+$ ]]; then
			fmg_output+="${status_unkn} - Uptime: cannot retrieve uptime via SNMP\n"
		else
			# Both OIDs return centiseconds (TimeTicks / Counter64 at same scale)
			_up_secs=$(( _up_raw / 100 ))
			_up_days=$(( _up_secs / 86400 ))
			_up_hours=$(( (_up_secs % 86400) / 3600 ))
			_up_mins=$(( (_up_secs % 3600) / 60 ))
			_up_str="${_up_days}d ${_up_hours}h ${_up_mins}m"

			_up_sev="${status_ok}"
			if (( warn_reboot_minutes > 0 && _up_secs / 60 < warn_reboot_minutes )) 2>/dev/null; then
				_up_sev="${status_warn}"
			fi

			fmg_output+="${_up_sev} - Uptime: ${_up_str}\n"
			[[ "${_up_sev}" != "${status_ok}" ]] && \
				fmg_problem_output+="${_up_sev} - Uptime: ${_up_str} (possible recent reboot)\n"

			[[ -z "${no_perfdata}" ]] && fmg_perf+=" uptime_seconds=${_up_secs}"
		fi
	fi

	if [[ -n "${verbose}" ]]; then
		fmg_output+="---------------------------------------\n\n"
	fi
fi

# ---------------------------------------------------------------------------
# -eDevices: Managed devices
# ---------------------------------------------------------------------------
if [[ ( -n "${enable_devices}" || -n "${enable_all}" ) && -z "${disable_devices}" ]]; then
	if [[ -n "${verbose}" ]]; then
		fmg_output+="Managed Devices:\n---------------------------------------\n"
	fi

	if [[ -n "${filter_adom}" ]]; then
		_dev_url="/dvmdb/adom/${filter_adom}/device"
	else
		_dev_url="/dvmdb/device"
	fi

	_dev_resp=$(fmg_api_get "${_dev_url}")
	_dev_code=$(echo "${_dev_resp}" | ${JQ} -r '.result[0].status.code // -1' 2>/dev/null)

	if [[ "${_dev_code}" != "0" ]]; then
		fmg_output+="${status_unkn} - Devices: cannot retrieve device list (API code ${_dev_code})\n"
	else
		_dev_total=0
		_dev_up=0
		_dev_down=0
		_dev_unsynced=0
		_total_fap=0
		_total_fsw=0
		_total_fex=0
		_dev_section=""
		_dev_problems=""
		_now=$(date +%s)

		# version: encoded as major*100 (e.g. 800 = FortiOS 8); mr = minor; patch = patch
		_dev_lines=$(echo "${_dev_resp}" | ${JQ} -r '
			.result[0].data[]? |
			[
				(.name            // "unknown"),
				((.conn_status     // 0) | tostring),
				((.conf_status     // 0) | tostring),
				((.db_status       // 0) | tostring),
				(.ip              // "unknown"),
				((.os_ver          // 0) | tostring),
				((.mr              // 0) | tostring),
				((.patch           // 0) | tostring),
				(.platform_str    // "FortiGate"),
				(.sn              // "unknown"),
				(.av_ver          // ""),
				(.ips_ver         // ""),
				((.ha_mode         // 0) | tostring),
				((.vdom | length)  // 0  | tostring),
				((.fap_cnt         // 0) | tostring),
				((.fsw_cnt         // 0) | tostring),
				((.fex_cnt         // 0) | tostring),
				((.last_checked    // 0) | tostring)
			] | join("\t")
		' 2>/dev/null)

		while IFS=$'\t' read -r \
			_dname _conn _conf _db _dip \
			_osver _osminor _ospatch _platform \
			_sn _av_ver _ips_ver _ha_mode \
			_vdom_cnt _fap_cnt _fsw_cnt _fex_cnt _last_checked; do

			[[ -z "${_dname}" ]] && continue

			# Blacklist check
			if [[ -n "${device_blacklist}" ]]; then
				_bl_skip=0
				IFS=',' read -ra _bl_arr <<< "${device_blacklist}"
				for _bl in "${_bl_arr[@]}"; do
					[[ "${_dname}" == "${_bl}" ]] && _bl_skip=1 && break
				done
				[[ "${_bl_skip}" -eq 1 ]] && continue
			fi

			_dev_total=$(( _dev_total + 1 ))
			[[ "${_fap_cnt}" =~ ^[0-9]+$ ]] && _total_fap=$(( _total_fap + _fap_cnt ))
			[[ "${_fsw_cnt}" =~ ^[0-9]+$ ]] && _total_fsw=$(( _total_fsw + _fsw_cnt ))
			[[ "${_fex_cnt}" =~ ^[0-9]+$ ]] && _total_fex=$(( _total_fex + _fex_cnt ))

			[[ "${_conn}" == "1" ]] && _conn_ok=1 || _conn_ok=0
			if [[ "${_conn_ok}" -eq 1 ]]; then
				_dev_up=$(( _dev_up + 1 ))
			else
				_dev_down=$(( _dev_down + 1 ))
			fi

			[[ "${_conf}" == "1" ]] && _conf_ok=1 || _conf_ok=0
			[[ "${_db}" == "1" ]]   && _db_ok=1   || _db_ok=0

			if [[ "${_conf_ok}" -eq 0 || "${_db_ok}" -eq 0 ]]; then
				_dev_unsynced=$(( _dev_unsynced + 1 ))
			fi

			_dsev="${status_ok}"
			if [[ "${_conn_ok}" -eq 0 ]]; then
				_dsev="${status_crit}"
			elif [[ "${_conf_ok}" -eq 0 || "${_db_ok}" -eq 0 ]]; then
				_dsev="${status_warn}"
			fi

			# Last-checked age
			_age_str=""
			if [[ "${_last_checked}" -gt 0 ]] 2>/dev/null; then
				_age_s=$(( _now - _last_checked ))
				_age_m=$(( _age_s / 60 ))
				if (( crit_dev_age > 0 && _age_m >= crit_dev_age )) 2>/dev/null; then
					[[ "${_dsev}" != "${status_crit}" ]] && _dsev="${status_crit}"
				elif (( warn_dev_age > 0 && _age_m >= warn_dev_age )) 2>/dev/null; then
					[[ "${_dsev}" == "${status_ok}" ]] && _dsev="${status_warn}"
				fi
				_age_str=" / age=${_age_m}m"
			fi

			[[ "${_conn_ok}" -eq 1 ]] && _conn_lbl="Connected"    || _conn_lbl="Disconnected"
			[[ "${_conf_ok}" -eq 1 ]] && _conf_lbl="In Sync"      || _conf_lbl="Out of Sync"
			[[ "${_db_ok}"   -eq 1 ]] && _db_lbl="In Sync"        || _db_lbl="Out of Sync"

			case "${_ha_mode}" in
				0) _ha_lbl="Standalone" ;;
				1) _ha_lbl="Active-Active" ;;
				2) _ha_lbl="Active-Passive" ;;
				*) _ha_lbl="HA-${_ha_mode}" ;;
			esac

			_dos_str="${_osver}.${_osminor}.${_ospatch}"

			if [[ -z "${silent}" || "${_dsev}" != "${status_ok}" ]]; then
				_dev_section+="\_ ${_dsev} ${_dname} (${_dip}) ${_platform} FortiOS ${_dos_str}: conn=${_conn_lbl} / cfg=${_conf_lbl} / db=${_db_lbl}${_age_str}\n"
				if [[ -n "${verbose}" ]]; then
					_dev_section+="   \_ ${status_ok} Serial: ${_sn} / HA: ${_ha_lbl} / VDOMs: ${_vdom_cnt}\n"
					_mngd_str=""
					[[ "${_fap_cnt}" -gt 0 ]] && _mngd_str+=" FortiAP:${_fap_cnt}"
					[[ "${_fsw_cnt}" -gt 0 ]] && _mngd_str+=" FortiSW:${_fsw_cnt}"
					[[ "${_fex_cnt}" -gt 0 ]] && _mngd_str+=" FortiExt:${_fex_cnt}"
					[[ -n "${_mngd_str}" ]] && _dev_section+="   \_ ${status_ok} Managed:${_mngd_str}\n"
					[[ -n "${_av_ver}" ]]   && _dev_section+="   \_ ${status_ok} AV DB:  ${_av_ver}\n"
					[[ -n "${_ips_ver}" ]]  && _dev_section+="   \_ ${status_ok} IPS DB: ${_ips_ver}\n"
				fi
			fi
			[[ "${_dsev}" != "${status_ok}" ]] && \
				_dev_problems+="${_dsev} - Device ${_dname}: conn=${_conn_lbl} cfg=${_conf_lbl} db=${_db_lbl}${_age_str}\n"
		done <<< "${_dev_lines}"

		_dv_sev="${status_ok}"
		if (( _dev_down >= crit_devices_down && crit_devices_down > 0 )) 2>/dev/null; then
			_dv_sev="${status_crit}"
		elif (( _dev_down >= warn_devices_down && warn_devices_down > 0 )) 2>/dev/null; then
			_dv_sev="${status_warn}"
		fi
		if (( _dev_unsynced >= crit_devices_unsynced && crit_devices_unsynced > 0 )) 2>/dev/null; then
			[[ "${_dv_sev}" != "${status_crit}" ]] && _dv_sev="${status_crit}"
		elif (( _dev_unsynced >= warn_devices_unsynced && warn_devices_unsynced > 0 )) 2>/dev/null; then
			[[ "${_dv_sev}" == "${status_ok}" ]] && _dv_sev="${status_warn}"
		fi

		_mngd_summary=""
		[[ "${_total_fap}" -gt 0 ]] && _mngd_summary+=" FAP:${_total_fap}"
		[[ "${_total_fsw}" -gt 0 ]] && _mngd_summary+=" FSW:${_total_fsw}"
		[[ "${_total_fex}" -gt 0 ]] && _mngd_summary+=" FEX:${_total_fex}"
		[[ -n "${_mngd_summary}" ]] && _mngd_summary=" (managed:${_mngd_summary})"

		fmg_output+="${_dv_sev} - Devices: ${_dev_total} total, ${_dev_up} up, ${_dev_down} down, ${_dev_unsynced} unsynced${_mngd_summary}\n"
		fmg_output+="${_dev_section}"
		[[ -n "${_dev_problems}" ]] && fmg_problem_output+="${_dev_problems}"

		[[ -z "${no_perfdata}" ]] && \
			fmg_perf+=" dev_total=${_dev_total} dev_up=${_dev_up} dev_down=${_dev_down} dev_unsynced=${_dev_unsynced} fap_total=${_total_fap} fsw_total=${_total_fsw} fex_total=${_total_fex}"
	fi

	if [[ -n "${verbose}" ]]; then
		fmg_output+="---------------------------------------\n\n"
	fi
fi

# ---------------------------------------------------------------------------
# -eADOMs: ADOM list
# Shows FortiGate-type ADOMs (restricted_prds=1) by default; --all-adoms for all
# Requires full-admin access
# ---------------------------------------------------------------------------
if [[ ( -n "${enable_adoms}" || -n "${enable_all}" ) && -z "${disable_adoms}" ]]; then
	if [[ -n "${verbose}" ]]; then
		fmg_output+="ADOMs:\n---------------------------------------\n"
	fi

	_adom_resp=$(fmg_api_get "/dvmdb/adom")
	_adom_code=$(echo "${_adom_resp}" | ${JQ} -r '.result[0].status.code // -1' 2>/dev/null)

	if [[ "${_adom_code}" == "-11" ]]; then
		fmg_output+="${status_unkn} - ADOMs: access denied (code -11) - requires full-admin access (not read-only token)\n"
	elif [[ "${_adom_code}" != "0" ]]; then
		fmg_output+="${status_unkn} - ADOMs: cannot retrieve ADOM list (API code ${_adom_code})\n"
	else
		# Filter: restricted_prds==1 are FortiGate-type ADOMs; --all-adoms shows everything
		if [[ -z "${all_adoms}" ]]; then
			_adom_filter='.result[0].data[]? | select(.restricted_prds == 1)'
		else
			_adom_filter='.result[0].data[]?'
		fi

		_adom_lines=$(echo "${_adom_resp}" | ${JQ} -r "
			${_adom_filter} |
			[
				(.name     // \"unknown\"),
				((.state    // 0) | tostring),
				((.mode     // 0) | tostring),
				((.os_ver   // 0) | tostring),
				((.mr       // 0) | tostring),
				((.log_disk_quota // 0) | tostring),
				((.log_disk_quota_alert_thres // 90) | tostring)
			] | join(\"\t\")
		" 2>/dev/null)

		_adom_total=0
		_adom_ok=0
		_adom_disabled=0
		_adom_section=""
		_adom_problems=""
		_adom_names=""

		while IFS=$'\t' read -r _aname _astate _amode _aosver _aosminor _aquota _aquota_thres; do
			[[ -z "${_aname}" ]] && continue
			_adom_total=$(( _adom_total + 1 ))
			[[ -n "${_adom_names}" ]] && _adom_names+=", "
			_adom_names+="${_aname}"

			# state: 1=enabled
			_asev="${status_ok}"
			if [[ "${_astate}" != "1" ]]; then
				_asev="${status_crit}"
				_adom_disabled=$(( _adom_disabled + 1 ))
			else
				_adom_ok=$(( _adom_ok + 1 ))
			fi

			# Mode: 1=Normal, 2=Policy Package
			case "${_amode}" in
				1) _amode_lbl="Normal" ;;
				2) _amode_lbl="Policy" ;;
				*) _amode_lbl="mode-${_amode}" ;;
			esac

			# Version target
			_aosver_str="${_aosver}.${_aosminor}"
			[[ "${_aosver}" == "0" ]] && _aosver_str="any"

			# Log quota in human-readable
			if [[ "${_aquota}" -gt 0 ]] 2>/dev/null; then
				_aquota_gb=$(( _aquota / 1024 ))
				_aquota_str="${_aquota_gb}GB (alert: ${_aquota_thres}%)"
			else
				_aquota_str="no quota"
			fi

			if [[ -z "${silent}" || "${_asev}" != "${status_ok}" ]]; then
				_adom_section+="\_ ${_asev} ${_aname} (FortiOS ${_aosver_str}, ${_amode_lbl}, log-quota: ${_aquota_str})\n"
			fi
			[[ "${_asev}" != "${status_ok}" ]] && \
				_adom_problems+="${_asev} - ADOM ${_aname}: state=${_astate} (disabled)\n"
		done <<< "${_adom_lines}"

		_adom_sev="${status_ok}"
		[[ "${_adom_disabled}" -gt 0 ]] && _adom_sev="${status_crit}"

		fmg_output+="${_adom_sev} - ADOMs: ${_adom_total} total, ${_adom_ok} active, ${_adom_disabled} disabled\n"
		fmg_output+="${_adom_section}"
		[[ -n "${_adom_problems}" ]] && fmg_problem_output+="${_adom_problems}"

		[[ -z "${no_perfdata}" ]] && \
			fmg_perf+=" adom_total=${_adom_total} adom_active=${_adom_ok} adom_disabled=${_adom_disabled}"
	fi

	if [[ -n "${verbose}" ]]; then
		fmg_output+="---------------------------------------\n\n"
	fi
fi

# ---------------------------------------------------------------------------
# -eFirmware: Compare managed device FortiOS vs FMG update catalog
# Requires full-admin access for /um/image/version/list
# ---------------------------------------------------------------------------
if [[ ( -n "${enable_firmware}" || -n "${enable_all}" ) && -z "${disable_firmware}" ]]; then
	if [[ -n "${verbose}" ]]; then
		fmg_output+="Firmware:\n---------------------------------------\n"
	fi

	# Get device list to know what platforms/versions to check
	if [[ -n "${filter_adom}" ]]; then
		_fw_dev_url="/dvmdb/adom/${filter_adom}/device"
	else
		_fw_dev_url="/dvmdb/device"
	fi

	_fw_dev_resp=$(fmg_api_get "${_fw_dev_url}")
	_fw_dev_code=$(echo "${_fw_dev_resp}" | ${JQ} -r '.result[0].status.code // -1' 2>/dev/null)

	if [[ "${_fw_dev_code}" != "0" ]]; then
		fmg_output+="${status_unkn} - Firmware: cannot retrieve device list (API code ${_fw_dev_code})\n"
	else
		# Extract device name, platform, current version for each device
		_fw_dev_lines=$(echo "${_fw_dev_resp}" | ${JQ} -r '
			.result[0].data[]? |
			[
				(.name         // "unknown"),
				(.platform_str // "FortiGate-VM64"),
				((.os_ver       // 0) | tostring),
				((.mr           // 0) | tostring),
				((.patch        // 0) | tostring)
			] | join("\t")
		' 2>/dev/null)

		_fw_total=0
		_fw_updates=0
		_fw_section=""
		_fw_problems=""

		# Cache: map platform -> version_list JSON to avoid repeat API calls per platform
		declare -A _fw_cache
		_fw_catalog_err=""

		while IFS=$'\t' read -r _fwname _fwplatform _fwosver _fwminor _fwpatch; do
			[[ -z "${_fwname}" ]] && continue

			# Blacklist check
			if [[ -n "${device_blacklist}" ]]; then
				_bl_skip=0
				IFS=',' read -ra _bl_arr <<< "${device_blacklist}"
				for _bl in "${_bl_arr[@]}"; do
					[[ "${_fwname}" == "${_bl}" ]] && _bl_skip=1 && break
				done
				[[ "${_bl_skip}" -eq 1 ]] && continue
			fi

			_fw_total=$(( _fw_total + 1 ))
			_fw_cur="${_fwosver}.${_fwminor}.${_fwpatch}"

			# Fetch version list for this platform (cached per platform)
			if [[ -z "${_fw_cache[${_fwplatform}]+x}" ]]; then
				_fw_vresp=$(fmg_fw_catalog "${_fwplatform}")
				_fw_vcode=$(echo "${_fw_vresp}" | ${JQ} -r '.result[0].status.code // "-1"' 2>/dev/null)
				[[ -z "${_fw_vcode}" ]] && _fw_vcode="-1"
				if [[ "${_fw_vcode}" == "0" ]]; then
					_fw_cache["${_fwplatform}"]=$(echo "${_fw_vresp}" | ${JQ} -c '.result[0].data.version_list[0].versions // []' 2>/dev/null)
				elif [[ "${_fw_vcode}" == "-11" ]]; then
					_fw_cache["${_fwplatform}"]="DENIED"
				else
					_fw_cache["${_fwplatform}"]="ERROR:${_fw_vcode}"
				fi
			fi

			_fw_versions="${_fw_cache[${_fwplatform}]}"

			if [[ "${_fw_versions}" == "DENIED" ]]; then
				[[ -z "${_fw_catalog_err}" ]] && \
					fmg_output+="${status_unkn} - Firmware: access denied for catalog (requires full-admin access)\n"
				_fw_catalog_err=1
				continue
			elif [[ "${_fw_versions}" == ERROR:* ]]; then
				[[ -z "${_fw_catalog_err}" ]] && \
					fmg_output+="${status_unkn} - Firmware: cannot retrieve catalog for ${_fwplatform} (code ${_fw_versions#ERROR:})\n"
				_fw_catalog_err=1
				continue
			fi

			# Find the latest version newer than current
			# image_type: M=Mature, F=Fresh/Beta, NA=unlabeled (older)
			# By default only check M; with --firmware-all also check F
			if [[ -n "${firmware_all}" ]]; then
				_type_filter='"M","F","NA"'
			else
				_type_filter='"M","NA"'
			fi

			_fw_latest=$(echo "${_fw_versions}" | ${JQ} -r --arg cur "${_fw_cur}" --argjson types "[${_type_filter}]" '
				map(
					select(
						(.image_type as $t | $types | index($t) != null) and
						(
							.version | split("-")[0] | split(".") |
							[(.[0]|tonumber), (.[1]|tonumber), (.[2]|tonumber)] as $v |
							($cur | split(".") | [(.[0]|tonumber), (.[1]|tonumber), (.[2]|tonumber)]) as $c |
							($v[0] > $c[0]) or
							($v[0] == $c[0] and $v[1] > $c[1]) or
							($v[0] == $c[0] and $v[1] == $c[1] and $v[2] > $c[2])
						)
					)
				) |
				sort_by(.version | split("-")[0] | split(".") | [(.[0]|tonumber),(.[1]|tonumber),(.[2]|tonumber)]) |
				last // null |
				if . then .version | split("-")[0] else "none" end
			' 2>/dev/null)

			_fwsev="${status_ok}"
			if [[ "${_fw_latest}" != "none" && "${_fw_latest}" != "null" && -n "${_fw_latest}" ]]; then
				_fw_updates=$(( _fw_updates + 1 ))
				if [[ -z "${no_firmware_warn}" ]]; then
					_fwsev="${status_warn}"
				fi
				_fw_detail="FortiOS ${_fw_cur} -> ${_fw_latest} available"
			else
				_fw_detail="FortiOS ${_fw_cur} (up to date)"
			fi

			if [[ -z "${silent}" || "${_fwsev}" != "${status_ok}" ]]; then
				_fw_section+="\_ ${_fwsev} ${_fwname} (${_fwplatform}): ${_fw_detail}\n"
			fi
			[[ "${_fwsev}" != "${status_ok}" ]] && \
				_fw_problems+="${_fwsev} - Firmware ${_fwname}: ${_fw_detail}\n"
		done <<< "${_fw_dev_lines}"

		_fwsec_sev="${status_ok}"
		[[ "${_fw_updates}" -gt 0 && -z "${no_firmware_warn}" ]] && _fwsec_sev="${status_warn}"

		fmg_output+="${_fwsec_sev} - Firmware: ${_fw_total} devices checked, ${_fw_updates} with available updates\n"
		fmg_output+="${_fw_section}"
		[[ -n "${_fw_problems}" ]] && fmg_problem_output+="${_fw_problems}"

		[[ -z "${no_perfdata}" ]] && \
			fmg_perf+=" fw_checked=${_fw_total} fw_updates=${_fw_updates}"
	fi

	if [[ -n "${verbose}" ]]; then
		fmg_output+="---------------------------------------\n\n"
	fi
fi

# ---------------------------------------------------------------------------
# -eTasks: Recent task queue - check for failed or stuck tasks
# Requires full-admin access
# ---------------------------------------------------------------------------
if [[ ( -n "${enable_tasks}" || -n "${enable_all}" ) && -z "${disable_tasks}" ]]; then
	if [[ -n "${verbose}" ]]; then
		fmg_output+="Tasks:\n---------------------------------------\n"
	fi

	_task_resp=$(fmg_api_get "/task/task")
	_task_code=$(echo "${_task_resp}" | ${JQ} -r '.result[0].status.code // -1' 2>/dev/null)

	if [[ "${_task_code}" == "-11" ]]; then
		fmg_output+="${status_unkn} - Tasks: access denied (code -11) - requires full-admin access\n"
	elif [[ "${_task_code}" != "0" ]]; then
		fmg_output+="${status_unkn} - Tasks: cannot retrieve task list (API code ${_task_code})\n"
	else
		_now=$(date +%s)
		_task_cutoff=$(( _now - task_hours * 3600 ))

		_task_lines=$(echo "${_task_resp}" | ${JQ} -r --arg cutoff "${_task_cutoff}" '
			.result[0].data[]? |
			select(.start_tm >= ($cutoff | tonumber)) |
			[
				((.id       // 0)  | tostring),
				((.state    // 0)  | tostring),
				(.title     // "unknown"),
				(.user      // "system"),
				((.percent  // 0)  | tostring),
				((.num_err  // 0)  | tostring),
				((.num_warn // 0)  | tostring),
				((.start_tm // 0)  | tostring)
			] | join("\t")
		' 2>/dev/null)

		_task_total=0
		_task_failed=0
		_task_running=0
		_task_section=""
		_task_problems=""

		while IFS=$'\t' read -r _tid _tstate _ttitle _tuser _tpct _terr _twarn _tstart; do
			[[ -z "${_tid}" ]] && continue
			_task_total=$(( _task_total + 1 ))

			_age_m=$(( ( _now - _tstart ) / 60 ))
			_tstart_str=$(date -d "@${_tstart}" +"%Y-%m-%d %H:%M" 2>/dev/null || echo "@${_tstart}")

			case "${_tstate}" in
				1) _tstate_lbl="Running" ;;
				2) _tstate_lbl="Error" ;;
				3) _tstate_lbl="Cancelled" ;;
				4) _tstate_lbl="Done" ;;
				*) _tstate_lbl="state-${_tstate}" ;;
			esac

			_tsev="${status_ok}"
			_tdetail="${_tstate_lbl} (${_tpct}%)"

			if [[ "${_tstate}" == "2" ]] 2>/dev/null; then
				_task_failed=$(( _task_failed + 1 ))
				_tsev="${status_crit}"
				_tdetail="Failed: ${_terr} error(s), ${_twarn} warning(s)"
			elif [[ "${_terr}" -gt 0 ]] 2>/dev/null; then
				_task_failed=$(( _task_failed + 1 ))
				_tsev="${status_warn}"
				_tdetail="${_tstate_lbl} with ${_terr} error(s)"
			elif [[ "${_tstate}" == "1" ]]; then
				_task_running=$(( _task_running + 1 ))
				_tdetail="Running ${_age_m}m (${_tpct}%)"
				if (( task_stuck_minutes > 0 && _age_m >= task_stuck_minutes )) 2>/dev/null; then
					_tsev="${status_warn}"
					_tdetail="Stuck running ${_age_m}m (${_tpct}%)"
				fi
			fi

			if [[ -z "${silent}" || "${_tsev}" != "${status_ok}" ]]; then
				_task_section+="\_ ${_tsev} #${_tid} \"${_ttitle}\" by ${_tuser}: ${_tdetail} (started ${_tstart_str})\n"
			fi
			[[ "${_tsev}" != "${status_ok}" ]] && \
				_task_problems+="${_tsev} - Task #${_tid} \"${_ttitle}\" by ${_tuser}: ${_tdetail}\n"
		done <<< "${_task_lines}"

		_tsec_sev="${status_ok}"
		if (( _task_failed >= crit_tasks_failed && crit_tasks_failed > 0 )) 2>/dev/null; then
			_tsec_sev="${status_crit}"
		elif (( _task_failed >= warn_tasks_failed && warn_tasks_failed > 0 )) 2>/dev/null; then
			_tsec_sev="${status_warn}"
		fi

		fmg_output+="${_tsec_sev} - Tasks: ${_task_total} recent (last ${task_hours}h), ${_task_failed} failed, ${_task_running} running\n"
		fmg_output+="${_task_section}"
		[[ -n "${_task_problems}" ]] && fmg_problem_output+="${_task_problems}"

		[[ -z "${no_perfdata}" ]] && \
			fmg_perf+=" task_total=${_task_total} task_failed=${_task_failed} task_running=${_task_running}"
	fi

	if [[ -n "${verbose}" ]]; then
		fmg_output+="---------------------------------------\n\n"
	fi
fi

# ---------------------------------------------------------------------------
# -eFGD: FortiGuard FDS server connectivity + service subscription status (SNMP)
# ---------------------------------------------------------------------------
if [[ ( -n "${enable_fgd}" || -n "${enable_all}" ) && -z "${disable_fgd}" ]]; then
	# When running under -A without explicit -eFGD: skip silently if no SNMP
	if [[ -n "${enable_all}" && -z "${enable_fgd}" && -z "${_snmp_avail}" ]]; then
		: # no SNMP credentials available, skip quietly under -A
	elif [[ -z "${_snmp_avail}" ]]; then
		fmg_output+="${status_unkn} - FortiGuard: SNMP credentials required (-SC <community> or -u/-a/-x/-X for SNMPv3)\n"
	elif [[ -z "${SNMPWALK}" ]]; then
		fmg_output+="${status_unkn} - FortiGuard: snmpwalk not found in PATH (required for FDS table walk)\n"
	else
		if [[ -n "${verbose}" ]]; then
			fmg_output+="FortiGuard:\n---------------------------------------\n"
		fi

		# --- FDS server connectivity ---
		mapfile -t _fgd_addrs < <(_snmp_walk "${OID_FGD_FDS_ADDR}" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
		mapfile -t _fgd_stats < <(_snmp_walk "${OID_FGD_FDS_STATUS}" | sed 's/[[:space:]]//g')

		_fgd_total=${#_fgd_addrs[@]}
		_fgd_connected=0

		for (( _fi=0; _fi<_fgd_total; _fi++ )); do
			[[ -z "${_fgd_addrs[${_fi}]}" ]] && continue
			[[ "${_fgd_stats[${_fi}]:-2}" == "1" ]] && _fgd_connected=$(( _fgd_connected + 1 ))
		done

		if [[ "${_fgd_total}" -eq 0 ]] 2>/dev/null; then
			fmg_output+="${status_unkn} - FortiGuard: no FDS servers found in SNMP table\n"
		else
			# Determine section severity from thresholds
			if (( _fgd_connected < crit_fds )) 2>/dev/null; then
				_fgd_fds_sev="${status_crit}"
			elif (( _fgd_connected < warn_fds )) 2>/dev/null; then
				_fgd_fds_sev="${status_warn}"
			else
				_fgd_fds_sev="${status_ok}"
			fi

			# Per-server prefix for unreachable: match section severity
			case "${_fgd_fds_sev}" in
				"${status_crit}") _fgd_unreach_pfx="${status_crit}" ;;
				"${status_warn}") _fgd_unreach_pfx="${status_warn}" ;;
				*)                _fgd_unreach_pfx="[-]" ;;
			esac

			_fgd_section=""
			_fgd_problems=""
			for (( _fi=0; _fi<_fgd_total; _fi++ )); do
				_faddr="${_fgd_addrs[${_fi}]}"
				[[ -z "${_faddr}" ]] && continue
				if [[ "${_fgd_stats[${_fi}]:-2}" == "1" ]]; then
					_fgd_section+="\_ ${status_ok} ${_faddr}: connected\n"
				else
					_fgd_section+="\_ ${_fgd_unreach_pfx} ${_faddr}: unreachable\n"
					[[ "${_fgd_fds_sev}" != "${status_ok}" ]] && \
						_fgd_problems+="${_fgd_fds_sev} - FortiGuard FDS ${_faddr}: unreachable\n"
				fi
			done

			fmg_output+="${_fgd_fds_sev} - FortiGuard FDS: ${_fgd_connected}/${_fgd_total} servers connected\n"
			[[ -n "${verbose}" || "${_fgd_fds_sev}" != "${status_ok}" ]] && fmg_output+="${_fgd_section}"
			[[ -n "${_fgd_problems}" ]] && \
				fmg_problem_output+="${_fgd_fds_sev} - FortiGuard FDS: ${_fgd_connected}/${_fgd_total} servers connected\n${_fgd_problems}"
		fi

		[[ -z "${no_perfdata}" && "${_fgd_total}" -gt 0 ]] && \
			fmg_perf+=" fgd_servers=${_fgd_total} fgd_connected=${_fgd_connected}"

		# --- FortiGuard service subscription status ---
		# Walk service license table (.103.11.3.1.1); columns: 1=svc-id, 2=status, 3=expiry, 4=version
		declare -A _fgd_svc
		mapfile -t _svc_raw < <(_snmp_walk_on "${OID_FGD_SVC_TABLE}" 2>/dev/null)
		for _svc_line in "${_svc_raw[@]}"; do
			[[ -z "${_svc_line}" ]] && continue
			_soid="${_svc_line%% *}"
			_sval="${_svc_line#* }"
			_sval="${_sval//\"/}"
			_ssuffix="${_soid#${OID_FGD_SVC_TABLE}.}"
			_scol="${_ssuffix%%.*}"
			_srow="${_ssuffix##*.}"
			[[ -n "${_scol}" && "${_scol}" =~ ^[0-9]+$ && "${_srow}" =~ ^[0-9]+$ ]] && \
				_fgd_svc["${_scol}_${_srow}"]="${_sval}"
		done

		declare -A _fgd_svc_rows
		for _k in "${!_fgd_svc[@]}"; do
			_r="${_k##*_}"
			_fgd_svc_rows["${_r}"]=1
		done

		_fgd_svc_total=${#_fgd_svc_rows[@]}

		if [[ "${_fgd_svc_total}" -gt 0 ]] 2>/dev/null; then
			_fgd_svc_ok=0
			_fgd_svc_bad=0
			_fgd_svc_nodata=0
			_fgd_svc_sev="${status_ok}"
			_fgd_svc_section=""
			_fgd_svc_problems=""
			_now_svc=$(date +%s)
			_lic_warn_sec=$(( warn_lic * 86400 ))
			_lic_crit_sec=$(( crit_lic * 86400 ))

			for _srow in "${!_fgd_svc_rows[@]}"; do
				_sid="${_fgd_svc["1_${_srow}"]:-${_srow}}"
				_sstat="${_fgd_svc["2_${_srow}"]:-}"
				_sexp="${_fgd_svc["3_${_srow}"]:-}"
				_sver="${_fgd_svc["4_${_srow}"]:-}"

				case "${_sid}" in
					1)   _sname="FDS" ;;
					2)   _sname="AV" ;;
					3)   _sname="IPS" ;;
					4)   _sname="AppCtrl" ;;
					5)   _sname="WebFilter" ;;
					6)   _sname="AntiSpam" ;;
					7)   _sname="VulnMgmt" ;;
					10)  _sname="Botnet-IP" ;;
					11)  _sname="Botnet-Domain" ;;
					100) _sname="FGT-Updates" ;;
					*)   _sname="Service-${_sid}" ;;
				esac

				_ssev="${status_ok}"
				_sdetail=""

				if [[ "${_sstat}" == "2" ]]; then
					_ssev="${status_warn}"
					_sdetail="not registered"
					(( _fgd_svc_bad++ ))
					[[ "${_fgd_svc_sev}" == "${status_ok}" ]] && _fgd_svc_sev="${status_warn}"
				elif [[ "${_sstat}" == "1" ]]; then
					_sdetail="registered"
					(( _fgd_svc_ok++ ))
				elif [[ -n "${_sstat}" ]]; then
					_sdetail="status-${_sstat}"
				else
					_sdetail="found (no license data via SNMP)"
					(( _fgd_svc_nodata++ ))
				fi

				if [[ -n "${_sexp}" && "${_sexp}" != "0" ]]; then
					_sexp_epoch=$(date -d "${_sexp}" +%s 2>/dev/null || echo "0")
					if [[ "${_sexp_epoch:-0}" -gt 0 ]] 2>/dev/null; then
						_sexp_diff=$(( _sexp_epoch - _now_svc ))
						_sexp_days=$(( _sexp_diff / 86400 ))
						if [[ "${_sexp_diff}" -lt 0 ]]; then
							_ssev="${status_crit}"; _fgd_svc_sev="${status_crit}"
							_sdetail="${_sdetail:+${_sdetail} / }EXPIRED (${_sexp})"
							(( _fgd_svc_bad++ ))
						elif (( _sexp_diff < _lic_crit_sec )) 2>/dev/null; then
							_ssev="${status_crit}"; _fgd_svc_sev="${status_crit}"
							_sdetail="${_sdetail:+${_sdetail} / }expires in ${_sexp_days}d (${_sexp})"
						elif (( _sexp_diff < _lic_warn_sec )) 2>/dev/null; then
							[[ "${_ssev}" == "${status_ok}" ]] && _ssev="${status_warn}"
							[[ "${_fgd_svc_sev}" == "${status_ok}" ]] && _fgd_svc_sev="${status_warn}"
							_sdetail="${_sdetail:+${_sdetail} / }expires in ${_sexp_days}d (${_sexp})"
						else
							_sdetail="${_sdetail:+${_sdetail} / }expires ${_sexp}"
						fi
					fi
				fi

				[[ -n "${_sver}" ]] && _sdetail+=" / db: ${_sver}"
				[[ -z "${_sdetail}" ]] && _sdetail="no detail"
				_fgd_svc_section+="\_ ${_ssev} ${_sname}: ${_sdetail}\n"
				[[ "${_ssev}" != "${status_ok}" ]] && \
					_fgd_svc_problems+="${_ssev} - FortiGuard ${_sname}: ${_sdetail}\n"
			done

			if [[ "${_fgd_svc_nodata}" -eq "${_fgd_svc_total}" ]] 2>/dev/null; then
				# All entries lack status data (VM / no SNMP license columns)
				_fgd_sub_summary="${_fgd_svc_total} service(s) found (no license data via SNMP)"
			else
				_fgd_sub_summary="${_fgd_svc_ok}/${_fgd_svc_total} valid"
				[[ "${_fgd_svc_bad}" -gt 0 ]] && _fgd_sub_summary+=", ${_fgd_svc_bad} issues"
				[[ "${_fgd_svc_nodata}" -gt 0 ]] && _fgd_sub_summary+=", ${_fgd_svc_nodata} no-data"
			fi
			fmg_output+="${_fgd_svc_sev} - FortiGuard subscriptions: ${_fgd_sub_summary}\n"
			[[ -n "${verbose}" || "${_fgd_svc_sev}" != "${status_ok}" ]] && \
				fmg_output+="${_fgd_svc_section}"
			[[ -n "${_fgd_svc_problems}" ]] && fmg_problem_output+="${_fgd_svc_problems}"

			[[ -z "${no_perfdata}" ]] && \
				fmg_perf+=" fgd_svc_total=${_fgd_svc_total} fgd_svc_valid=${_fgd_svc_ok}"
		fi

		unset _fgd_svc _fgd_svc_rows

		if [[ -n "${verbose}" ]]; then
			fmg_output+="---------------------------------------\n\n"
		fi
	fi
fi

# ---------------------------------------------------------------------------
# -eNTP: NTP sync status and configured server list
# ---------------------------------------------------------------------------
if [[ ( -n "${enable_ntp}" || -n "${enable_all}" ) && -z "${disable_ntp}" ]]; then
	if [[ -n "${enable_all}" && -z "${enable_ntp}" && -z "${api_token}" ]]; then
		: # no API credentials available, skip quietly under -A
	elif [[ -z "${api_token}" ]]; then
		fmg_output+="${status_unkn} - NTP: API credentials required (-T <token> or -U/-P; not available in SNMP-only mode)\n"
	else
	if [[ -n "${verbose}" ]]; then
		fmg_output+="NTP:\n---------------------------------------\n"
	fi

	_ntp_resp=$(fmg_api_get "/cli/global/system/ntp")
	_ntp_code=$(echo "${_ntp_resp}" | ${JQ} -r '.result[0].status.code // -1' 2>/dev/null)

	if [[ "${_ntp_code}" != "0" ]]; then
		fmg_output+="${status_unkn} - NTP: cannot retrieve NTP configuration (API code ${_ntp_code})\n"
	else
		_ntp_status=$(echo "${_ntp_resp}" | ${JQ} -r '.result[0].data.status // 0' 2>/dev/null)
		_ntp_srv_lines=$(echo "${_ntp_resp}" | ${JQ} -r '
			.result[0].data.ntpserver[]? |
			[
				(.server // "unknown"),
				((.ntpv3 // 0) | tostring),
				((.authentication // 0) | tostring),
				((.minpoll // 6) | tostring),
				((.maxpoll // 10) | tostring)
			] | join("\t")
		' 2>/dev/null)

		_ntp_srv_count=0
		_ntp_sev="${status_ok}"
		_ntp_section=""
		_ntp_srv_str=""

		while IFS=$'\t' read -r _nsrv _nntpv3 _nauth _nmin _nmax; do
			[[ -z "${_nsrv}" ]] && continue
			_ntp_srv_count=$(( _ntp_srv_count + 1 ))
			[[ -n "${_ntp_srv_str}" ]] && _ntp_srv_str+=", "
			_ntp_srv_str+="${_nsrv}"
			_ndetail="poll:${_nmin}-${_nmax}s"
			[[ "${_nntpv3}" == "1" ]] && _ndetail+=", ntpv3"
			[[ "${_nauth}" == "1" ]] && _ndetail+=", auth"
			_ntp_section+="\_ ${status_ok} ${_nsrv} (${_ndetail})\n"
		done <<< "${_ntp_srv_lines}"

		if [[ "${_ntp_status}" == "0" ]]; then
			if [[ -z "${no_ntp_warn}" ]]; then
				_ntp_sev="${status_warn}"
				fmg_output+="${_ntp_sev} - NTP: sync disabled\n"
				fmg_problem_output+="${_ntp_sev} - NTP: sync disabled\n"
			else
				fmg_output+="${status_ok} - NTP: sync disabled (suppressed)\n"
			fi
		elif [[ "${_ntp_srv_count}" -eq 0 ]]; then
			_ntp_sev="${status_warn}"
			fmg_output+="${_ntp_sev} - NTP: enabled but no servers configured\n"
			fmg_problem_output+="${_ntp_sev} - NTP: enabled but no servers configured\n"
		else
			fmg_output+="${_ntp_sev} - NTP: enabled, ${_ntp_srv_count} server(s): ${_ntp_srv_str}\n"
			[[ -n "${verbose}" ]] && fmg_output+="${_ntp_section}"
		fi

		[[ -z "${no_perfdata}" ]] && fmg_perf+=" ntp_servers=${_ntp_srv_count}"
	fi

	if [[ -n "${verbose}" ]]; then
		fmg_output+="---------------------------------------\n\n"
	fi
	fi  # close if/elif/else api_token check
fi

# ---------------------------------------------------------------------------
# -eSyslog: syslog server configuration
# ---------------------------------------------------------------------------
if [[ ( -n "${enable_syslog}" || -n "${enable_all}" ) && -z "${disable_syslog}" ]]; then
	if [[ -n "${enable_all}" && -z "${enable_syslog}" && -z "${api_token}" ]]; then
		: # no API credentials available, skip quietly under -A
	elif [[ -z "${api_token}" ]]; then
		fmg_output+="${status_unkn} - Syslog: API credentials required (-T <token> or -U/-P; not available in SNMP-only mode)\n"
	else
	if [[ -n "${verbose}" ]]; then
		fmg_output+="Syslog:\n---------------------------------------\n"
	fi

	_slog_resp=$(fmg_api_get "/cli/global/system/syslog")
	_slog_code=$(echo "${_slog_resp}" | ${JQ} -r '.result[0].status.code // -1' 2>/dev/null)

	if [[ "${_slog_code}" != "0" ]]; then
		fmg_output+="${status_unkn} - Syslog: cannot retrieve syslog configuration (API code ${_slog_code})\n"
	else
		_slog_lines=$(echo "${_slog_resp}" | ${JQ} -r '
			.result[0].data[]? |
			[
				(.name // "syslog"),
				(.ip // .server // "unknown"),
				((.port // 514) | tostring),
				(.status // "enable")
			] | join("\t")
		' 2>/dev/null)

		_slog_total=0
		_slog_enabled=0
		_slog_section=""

		while IFS=$'\t' read -r _slname _slip _slport _slstatus; do
			[[ -z "${_slname}" ]] && continue
			_slog_total=$(( _slog_total + 1 ))
			if [[ "${_slstatus}" == "enable" || "${_slstatus}" == "1" ]]; then
				_slog_enabled=$(( _slog_enabled + 1 ))
				_slsev="${status_ok}"
			else
				_slsev="[-]"
			fi
			_slog_section+="\_ ${_slsev} ${_slname}: ${_slip}:${_slport} (${_slstatus})\n"
		done <<< "${_slog_lines}"

		_slog_sev="${status_ok}"
		if [[ "${_slog_total}" -eq 0 ]]; then
			if [[ -z "${no_syslog_warn}" ]]; then
				_slog_sev="${status_warn}"
				fmg_output+="${_slog_sev} - Syslog: no syslog servers configured\n"
				fmg_problem_output+="${_slog_sev} - Syslog: no syslog servers configured\n"
			else
				fmg_output+="${status_ok} - Syslog: none configured (suppressed)\n"
			fi
		else
			fmg_output+="${_slog_sev} - Syslog: ${_slog_total} server(s) configured, ${_slog_enabled} enabled\n"
			[[ -n "${verbose}" ]] && fmg_output+="${_slog_section}"
		fi

		[[ -z "${no_perfdata}" ]] && fmg_perf+=" syslog_total=${_slog_total} syslog_enabled=${_slog_enabled}"
	fi

	if [[ -n "${verbose}" ]]; then
		fmg_output+="---------------------------------------\n\n"
	fi
	fi  # close if/elif/else api_token check
fi

# ---------------------------------------------------------------------------
# -eDNS: DNS server configuration (requires full-admin access)
# ---------------------------------------------------------------------------
if [[ ( -n "${enable_dns}" || -n "${enable_all}" ) && -z "${disable_dns}" ]]; then
	if [[ -n "${enable_all}" && -z "${enable_dns}" && -z "${api_token}" ]]; then
		: # no API credentials available, skip quietly under -A
	elif [[ -z "${api_token}" ]]; then
		fmg_output+="${status_unkn} - DNS: API credentials required (-T <token> or -U/-P; not available in SNMP-only mode)\n"
	else
	if [[ -n "${verbose}" ]]; then
		fmg_output+="DNS:\n---------------------------------------\n"
	fi

	_dns_resp=$(fmg_api_get "/cli/global/system/dns")
	_dns_code=$(echo "${_dns_resp}" | ${JQ} -r '.result[0].status.code // -1' 2>/dev/null)

	if [[ "${_dns_code}" == "-11" ]]; then
		fmg_output+="${status_unkn} - DNS: access denied (code -11) - requires full-admin access\n"
	elif [[ "${_dns_code}" != "0" ]]; then
		fmg_output+="${status_unkn} - DNS: cannot retrieve DNS configuration (API code ${_dns_code})\n"
	else
		_dns_primary=$(echo "${_dns_resp}"   | ${JQ} -r '.result[0].data.primary   // "0.0.0.0"' 2>/dev/null)
		_dns_secondary=$(echo "${_dns_resp}" | ${JQ} -r '.result[0].data.secondary // "0.0.0.0"' 2>/dev/null)
		_dns_tertiary=$(echo "${_dns_resp}"  | ${JQ} -r '.result[0].data.tertiary  // "0.0.0.0"' 2>/dev/null)
		_dns_hostname=$(echo "${_dns_resp}"  | ${JQ} -r '.result[0].data.hostname  // ""'        2>/dev/null)

		_dns_sev="${status_ok}"
		_dns_configured=""

		[[ "${_dns_primary}"   != "0.0.0.0" && -n "${_dns_primary}"   ]] && _dns_configured+="${_dns_primary}"
		[[ "${_dns_secondary}" != "0.0.0.0" && -n "${_dns_secondary}" ]] && _dns_configured+=", ${_dns_secondary}"
		[[ "${_dns_tertiary}"  != "0.0.0.0" && -n "${_dns_tertiary}"  ]] && _dns_configured+=", ${_dns_tertiary}"
		_dns_configured="${_dns_configured#, }"

		if [[ -z "${_dns_configured}" ]]; then
			_dns_sev="${status_warn}"
			fmg_output+="${_dns_sev} - DNS: no DNS servers configured\n"
			fmg_problem_output+="${_dns_sev} - DNS: no DNS servers configured\n"
		else
			fmg_output+="${_dns_sev} - DNS: ${_dns_configured}\n"
			if [[ -n "${verbose}" ]]; then
				[[ "${_dns_primary}"   != "0.0.0.0" ]] && fmg_output+="\_ ${status_ok} primary:   ${_dns_primary}\n"
				[[ "${_dns_secondary}" != "0.0.0.0" ]] && fmg_output+="\_ ${status_ok} secondary: ${_dns_secondary}\n"
				[[ "${_dns_tertiary}"  != "0.0.0.0" ]] && fmg_output+="\_ ${status_ok} tertiary:  ${_dns_tertiary}\n"
				[[ -n "${_dns_hostname}" ]] && fmg_output+="\_ ${status_ok} hostname:  ${_dns_hostname}\n"
			fi
		fi
	fi

	if [[ -n "${verbose}" ]]; then
		fmg_output+="---------------------------------------\n\n"
	fi
	fi  # close if/elif/else api_token check
fi

# ---------------------------------------------------------------------------
# Determine exit state from output content and print result
# ---------------------------------------------------------------------------
if [[ ${fmg_output} =~ "[UNKNOWN]" ]]; then
	state=3
	if [[ -z "${silent}" ]]; then
		fmg_problems="One or more Problems detected:\n---------------------------------------------------------------------\n"
		fmg_problem_output+="---------------------------------------------------------------------\n\nAll Services:\n---------------------------------------------------------------------\n"
	fi
elif [[ ${fmg_output} =~ "[CRITICAL]" ]]; then
	state=2
	if [[ -z "${silent}" ]]; then
		fmg_problems="One or more Problems detected:\n---------------------------------------------------------------------\n"
		fmg_problem_output+="---------------------------------------------------------------------\n\nAll Services:\n---------------------------------------------------------------------\n"
	fi
elif [[ ${fmg_output} =~ "[WARNING]" ]]; then
	state=1
	if [[ -z "${silent}" ]]; then
		fmg_problems="One or more Problems detected:\n---------------------------------------------------------------------\n"
		fmg_problem_output+="---------------------------------------------------------------------\n\nAll Services:\n---------------------------------------------------------------------\n"
	fi
else
	state=0
	fmg_problems="All Services OK"
fi

# Replace | in human-readable text with , to avoid Nagios treating it as perfdata separator
_pp="${fmg_problem_output//|/,}"
_po="${fmg_output//|/,}"
_perf_sep="${no_perfdata:+}"
[[ -z "${no_perfdata}" && -n "${fmg_perf}" ]] && _perf_sep="|${fmg_perf}"

if [[ -z "${silent}" && -n "${fmg_problem_output}" ]]; then
	echo -e "${fmg_problems}${_pp}${_po}${_perf_sep}"
elif [[ -n "${silent}" && -n "${fmg_problem_output}" ]]; then
	echo -e "${_pp}${_perf_sep}"
elif [[ -n "${silent}" && -z "${fmg_problem_output}" ]]; then
	echo -e "${status_ok} - All Services are fine${_perf_sep}"
else
	echo -e "${_po}${_perf_sep}"
fi

exit ${state}
