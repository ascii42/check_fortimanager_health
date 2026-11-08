# check_fortimanager_health

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Shell Script](https://img.shields.io/badge/Shell-Bash-green.svg)](https://www.gnu.org/software/bash/)
[![Monitoring](https://img.shields.io/badge/Monitoring-Icinga%2FNagios-blue.svg)](https://icinga.com/)
[![Version](https://img.shields.io/badge/version-1.7.1-orange.svg)](check_fortimanager_health.sh)

A comprehensive Bash-based monitoring plugin for Fortinet FortiManager, compatible with Icinga and Nagios monitoring systems. This plugin monitors system health, managed devices, ADOMs, firmware update availability, background tasks, FortiGuard connectivity, NTP, DNS, syslog configuration, and system resources — via the FortiManager JSON-RPC API and/or SNMP.

## Features

- **JSON-RPC API**: Connects to FortiManager's `/jsonrpc` endpoint — no additional tools or cloud dependency required
- **SNMP Supplement**: SNMPv2c or SNMPv3 credentials add CPU/memory/disk resource metrics (available on VM builds where the API `/sys/performance` endpoint is not supported) and enable uptime monitoring and FortiGuard FDS connectivity checks
- **Managed Device Monitoring**: Connection state, config sync, DB sync, firmware version, HA mode, VDOM count, FortiAP/FortiSwitch/FortiExtender counts, and last-check age per device
- **ADOM Management**: ADOM list, quota utilization, enabled/disabled state
- **Firmware Catalog**: Compare managed device FortiOS versions against the FMG update catalog; alert on available Mature (M) or Fresh (F) releases
- **Task Queue**: Monitor recent background tasks (policy installs, firmware upgrades, device adds) for failures, errors, and stuck running tasks
- **FortiGuard Health**: FDS server connectivity with configurable reachability thresholds; service subscription status and expiry dates (SNMP)
- **NTP / Syslog / DNS**: System configuration checks for NTP sync status, syslog server presence, and DNS resolver configuration
- **Flexible Authentication**: API token (recommended), username/password login, or SNMP-only mode for resource/uptime checks
- **Opt-in or Opt-out**: Use `-eX` flags to run only specific checks, or `--disable-X` to suppress modules from the full set
- **Granular Thresholds**: Warning/critical thresholds for CPU, memory, disk, device states, task failures, FDS connectivity, and license/subscription expiry
- **Perfdata Output**: Full Nagios-compatible perfdata for all check modules — compatible with PNP4Nagios, Graphite, InfluxDB, etc.
- **Verbose and Silent Modes**: Tunable output verbosity for dashboards and automation

## Prerequisites

Ensure the following tools are installed on your monitoring server:

- **bash** (4.0 or higher)
- **curl** (for API communication)
- **jq** (for JSON parsing)
- **awk** (for text processing)
- **snmpget / snmpwalk** (optional — only required for SNMP-based checks, provided by net-snmp)

### Installation on Different Platforms

**Ubuntu/Debian:**
```bash
sudo apt-get install curl jq gawk snmp
```

**RHEL/CentOS/Rocky Linux:**
```bash
sudo dnf install curl jq gawk net-snmp-utils
```

**Gentoo:**
```bash
sudo emerge net-misc/curl app-misc/jq sys-apps/gawk net-analyzer/net-snmp
```

## Installation

1. **Download the script:**
   ```bash
   curl -O https://raw.githubusercontent.com/ascii42/check_fortimanager_health/main/check_fortimanager_health.sh
   ```

2. **Make it executable:**
   ```bash
   chmod +x check_fortimanager_health.sh
   ```

3. **Copy to your plugins directory:**
   ```bash
   # Icinga2
   sudo cp check_fortimanager_health.sh /usr/lib/nagios/plugins/

   # Nagios
   sudo cp check_fortimanager_health.sh /usr/local/nagios/libexec/
   ```

## FortiManager Configuration

### API Token (Recommended)

Create a dedicated REST API admin in the FortiManager GUI:

1. Navigate to **System > Admin > REST API Admin**
2. Click **Create New**
3. Set a name (e.g. `monitoring`)
4. Set **Admin Profile** to `Standard_User` (read-only is sufficient for most checks)
5. Set **JSON API Access** to `Read` (required for all API-based checks)
6. Copy the generated token

> **Note:** `-eADOMs`, `-eFirmware`, and `-eTasks` require full administrator access. A `Standard_User` profile with read-only access can run `-eSys` and `-eDevices`. For complete monitoring, use a `Super_User` profile or equivalent.

### Username / Password

Alternatively, authenticate with an existing admin account:

```bash
./check_fortimanager_health.sh -H 10.0.0.1 -U admin -P secret -A
```

The admin account must have **JSON API Access** set to `Read-Write` in FortiManager:
**System > Admin > Administrators > \<user\> > JSON API Access**

### SNMP (Supplemental)

SNMP credentials are optional and supplement the API for:

- **-eRes**: CPU, memory, disk usage via FORTINET-FORTIMANAGER-MIB (required for VM builds)
- **-eUp**: Uptime via SNMP (the only source for uptime on FortiManager)
- **-eFGD**: FortiGuard FDS server connectivity and subscription status via SNMP walk

Configure SNMP on the FortiManager: **System > Network > SNMP**

## Usage

### Basic Syntax

```bash
./check_fortimanager_health.sh -H <host> -T <token> [options]
./check_fortimanager_health.sh -H <host> -U <user> -P <pass> [options]
./check_fortimanager_health.sh -H <host> -SC <community> [options]  # SNMP supplement only
```

### Required Parameters

| Parameter | Description |
|-----------|-------------|
| `-H, --host <hostname\|IP>` | Hostname or IP address of the FortiManager |

At least one of the following authentication methods is required:

| Method | Parameters | Notes |
|--------|-----------|-------|
| API token | `-T <token>` | Recommended — long-lived token from REST API Admin |
| User/password | `-U <user> -P <pass>` | Session-based login; session is logged out on exit |
| SNMP v2c | `-SC <community>` | Supplements API for resource/uptime/FortiGuard checks |
| SNMP v3 | `--snmp-user <name> -a <authpass> -X <privpass>` | SNMPv3 mode; supplements API |

### Enable Flags (opt-in)

If any `-eX` flag is given, **only those modules** run. When no flags are given, all modules run (equivalent to `-A`).

| Flag | Long form | Description | Access Required |
|------|-----------|-------------|-----------------|
| `-eSys` | `--enable-system` | System info: hostname, platform, FortiManager version, HA mode, license status | API |
| `-eRes` | `--enable-resources` | CPU, memory, disk usage with thresholds | API or SNMP |
| `-eUp` | `--enable-uptime` | System uptime | SNMP only |
| `-eDevices` | `--enable-devices` | Managed device states: connection, config sync, DB sync, firmware, age | API |
| `-eADOMs` | `--enable-adoms` | ADOM list, state, and log quota usage | API (full-admin) |
| `-eFirmware` | `--enable-firmware` | Compare managed device FortiOS versions against FMG update catalog | API (full-admin) |
| `-eTasks` | `--enable-tasks` | Recent background tasks — alert on failed, errored, or stuck tasks | API (full-admin) |
| `-eFGD` | `--enable-fortiguard` | FortiGuard FDS server reachability + service subscription status | SNMP only |
| `-eNTP` | `--enable-ntp` | NTP sync status and configured server list | API |
| `-eSyslog` | `--enable-syslog` | Syslog server configuration | API |
| `-eDNS` | `--enable-dns` | DNS server configuration (primary/secondary/tertiary) | API (full-admin) |
| `-A` | `--enable-all` | Enable all checks (default when no `-eX` flag is given) | — |

> When running `-A` without SNMP credentials, `-eFGD` is silently skipped. When running `-A` without API credentials, `-eNTP`, `-eSyslog`, and `-eDNS` are silently skipped.

### Disable Flags (opt-out from `-A`)

Suppress individual modules when running the full check set:

```
--disable-system      --disable-resources    --disable-uptime
--disable-devices     --disable-adoms        --disable-firmware
--disable-tasks       --disable-fortiguard   --disable-ntp
--disable-syslog      --disable-dns
```

### Threshold Options

**Resource Thresholds**

| Option | Default | Description |
|--------|---------|-------------|
| `-wCPU <pct>` | 80 | WARNING threshold for CPU usage in % |
| `-cCPU <pct>` | 90 | CRITICAL threshold for CPU usage in % |
| `-wMem <pct>` | 80 | WARNING threshold for memory usage in % |
| `-cMem <pct>` | 90 | CRITICAL threshold for memory usage in % |
| `--warn-disk <pct>` | 80 | WARNING threshold for disk usage in % |
| `--crit-disk <pct>` | 90 | CRITICAL threshold for disk usage in % |

**Device Thresholds**

| Option | Default | Description |
|--------|---------|-------------|
| `--warn-devices-down <n>` | 1 | WARNING when N or more devices are disconnected |
| `--crit-devices-down <n>` | 1 | CRITICAL when N or more devices are disconnected |
| `--warn-devices-unsynced <n>` | 1 | WARNING when N or more devices are out of config sync |
| `--crit-devices-unsynced <n>` | -1 | CRITICAL when N or more devices are out of sync (-1=disabled) |
| `--warn-dev-age <minutes>` | -1 | WARNING when a device's last-check is older than N minutes (-1=disabled) |
| `--crit-dev-age <minutes>` | -1 | CRITICAL when a device's last-check is older than N minutes (-1=disabled) |

**Task Thresholds**

| Option | Default | Description |
|--------|---------|-------------|
| `--task-hours <n>` | 24 | Only check tasks started within the last N hours |
| `--warn-tasks-failed <n>` | 1 | WARNING when N or more tasks have errors |
| `--crit-tasks-failed <n>` | 1 | CRITICAL when N or more tasks have errors |
| `--task-stuck-minutes <n>` | -1 | WARNING if a running task exceeds N minutes (-1=disabled) |

**FortiGuard Thresholds**

| Option | Default | Description |
|--------|---------|-------------|
| `--warn-fds <n>` | 2 | WARNING when fewer than N FDS servers are reachable |
| `--crit-fds <n>` | 1 | CRITICAL when fewer than N FDS servers are reachable |
| `--warn-lic <days>` | 30 | WARNING when a subscription expires in less than N days |
| `--crit-lic <days>` | 15 | CRITICAL when a subscription expires in less than N days |

**Uptime Threshold**

| Option | Default | Description |
|--------|---------|-------------|
| `--warn-reboot-minutes <n>` | -1 | WARNING if uptime is below N minutes (reboot detection; -1=disabled) |

### Selection and Filter Options

| Option | Description |
|--------|-------------|
| `--blacklist-device <list>` | Comma-separated list of device names to skip entirely in -eDevices/-eFirmware |
| `--adom <name>` | Only check devices in this ADOM (affects -eDevices device endpoint) |
| `--all-adoms` | In -eADOMs, include non-FortiGate ADOMs (FortiMail, FortiProxy, etc.) |
| `--no-firmware-warn` | Suppress WARNING for available firmware updates (informational only) |
| `--firmware-all` | Include Fresh (F) release candidates in firmware update detection |

### NTP / Syslog Options

| Option | Description |
|--------|-------------|
| `--no-ntp-warn` | Suppress WARNING when NTP sync is disabled |
| `--no-syslog-warn` | Suppress WARNING when no syslog servers are configured |

### HTTPS Options

| Option | Default | Description |
|--------|---------|-------------|
| `--https-port <port>` | 443 | HTTPS/API port |

### SNMP Options

| Option | Default | Description |
|--------|---------|-------------|
| `-SC, --snmp-community <community>` | — | SNMPv2c community string |
| `-u, --snmp-user <name>` | — | SNMPv3 security name — enables SNMPv3 mode |
| `-l, --snmp-auth-proto <SHA\|MD5>` | SHA | SNMPv3 authentication protocol |
| `-a, --snmp-auth-pass <pass>` | — | SNMPv3 authentication passphrase (minimum 8 characters) |
| `-x, --snmp-priv-proto <AES\|DES>` | AES | SNMPv3 privacy protocol |
| `-X, --snmp-priv-pass <pass>` | — | SNMPv3 privacy passphrase (minimum 8 characters) |
| `-L, --snmp-sec-level <level>` | auto | noAuthNoPriv / authNoPriv / authPriv (auto-detected from credentials) |
| `--snmp-port <port>` | 161 | SNMP UDP port |

### Output Options

| Option | Description |
|--------|-------------|
| `--no-perfdata` | Suppress the perfdata section entirely (no `\|` output) |
| `-s, --silent` | Show only problem lines (suppress OK detail) |
| `-v, --verbose` | Print section headers and full per-item detail |
| `-d, --debug` | Enable bash trace output (`set -x`) |

## Examples

### Full Health Check with SNMP

Check everything — API for all checks, SNMP for resources, uptime, and FortiGuard:

```bash
./check_fortimanager_health.sh -H 10.0.0.1 -T MyApiToken \
  -u monitor -a MonitorPass1 -X MonitorPass1 -A
```

### API Token Only (VM — no SNMP)

Check everything the API exposes; resources and uptime are not available without SNMP on VM builds:

```bash
./check_fortimanager_health.sh -H 10.0.0.1 -T MyApiToken -A
```

### User/Password Authentication

```bash
./check_fortimanager_health.sh -H 10.0.0.1 -U admin -P secret -A
```

### Check Specific Modules

System info and device states only:

```bash
./check_fortimanager_health.sh -H 10.0.0.1 -T MyApiToken -eSys -eDevices -v
```

Resources and uptime via SNMP only (no API token required):

```bash
./check_fortimanager_health.sh -H 10.0.0.1 -SC monitor -eRes -eUp
```

### Device Age Threshold

Warn when a managed device has not checked in for more than 60 minutes:

```bash
./check_fortimanager_health.sh -H 10.0.0.1 -T MyApiToken -eDevices \
  --warn-dev-age 60 --crit-dev-age 180
```

### Firmware Check — Suppress Updates

Check firmware versions but do not alert on available updates:

```bash
./check_fortimanager_health.sh -H 10.0.0.1 -T MyApiToken -eFirmware --no-firmware-warn
```

### Task Queue — Extended History

Check tasks from the last 48 hours; alert if a task has been running for more than 30 minutes:

```bash
./check_fortimanager_health.sh -H 10.0.0.1 -T MyApiToken -eTasks \
  --task-hours 48 --task-stuck-minutes 30
```

### FortiGuard via SNMP (SNMPv3)

Check FDS server connectivity; warn if fewer than 3 are reachable:

```bash
./check_fortimanager_health.sh -H 10.0.0.1 -T MyApiToken \
  -u monitor -a MonitorPass1 -X MonitorPass1 \
  -eFGD --warn-fds 3 --crit-fds 1
```

### Full Check, Suppress Noisy Modules

```bash
./check_fortimanager_health.sh -H 10.0.0.1 -T MyApiToken -SC monitor -A \
  --disable-adoms --disable-firmware --no-syslog-warn
```

### Reboot Detection

Alert if the FortiManager has been up for less than 15 minutes:

```bash
./check_fortimanager_health.sh -H 10.0.0.1 -SC monitor -eUp \
  --warn-reboot-minutes 15
```

### Verbose Output

```bash
./check_fortimanager_health.sh -H 10.0.0.1 -T MyApiToken -SC monitor -A -v
```

## Sample Output

### Standard (non-verbose)

```
[OK] - System: fmg-prod FortiManager-VM64 v8.0.2-build0198 (Stand Alone)
[OK] - Resources: CPU 5%, Memory 8%, Disk 4%
[OK] - Uptime: 2d 12h 27m
[OK] - Devices: 4 total, 4 up, 0 down, 0 unsynced (managed: FAP:12 FSW:4 FEX:2)
[OK] - ADOMs: 3 total, 3 active, 0 disabled
[OK] - Firmware: 4 devices checked, 0 with available updates
[OK] - Tasks: 0 recent (last 24h), 0 failed, 0 running
[WARNING] - FortiGuard FDS: 1/5 servers connected
[OK] - FortiGuard subscriptions: 2/2 valid
[OK] - NTP: enabled, 1 server(s): ntp1.fortinet.net
[WARNING] - Syslog: no syslog servers configured
[OK] - DNS: 8.8.8.8, 8.8.4.4
| cpu=5%;80;90;0;100 mem=8%;80;90;0;100 disk=4%;80;90;0;100 dev_total=4 dev_up=4 dev_down=0 dev_unsynced=0 fap_total=12 fsw_total=4 fex_total=2 adom_total=3 adom_active=3 adom_disabled=0 fw_checked=4 fw_updates=0 task_total=0 task_failed=0 task_running=0 fgd_servers=5 fgd_connected=1 ntp_servers=1 syslog_total=0 syslog_enabled=0
```

### Verbose

```
System Info:
---------------------------------------
[OK] - System: fmg-prod FortiManager-VM64 v8.0.2-build0198 (Stand Alone)
\_ [OK] Serial:       FMG-VM64-...
\_ [OK] HA Mode:      Stand Alone
\_ [OK] License:      Valid
\_ [OK] Offline Mode: disable
---------------------------------------

System Resources:
---------------------------------------
[OK] - Resources: CPU 5%, Memory 8%, Disk 4%
\_ [OK] CPU:    5% (warn: 80%, crit: 90%)
\_ [OK] Memory: 8% 2849MB / 34453MB (warn: 80%, crit: 90%)
\_ [OK] Disk:   4% 21314MB / 502864MB (warn: 80%, crit: 90%)
---------------------------------------

Devices:
---------------------------------------
[OK] - Devices: 4 total, 4 up, 0 down, 0 unsynced (managed: FAP:12 FSW:4 FEX:2)
\_ [OK] fw-branch1 (10.1.1.1) FortiGate-60F FortiOS 7.6.2: conn=Connected / cfg=In Sync / db=In Sync / age=5m
\_ [OK] fw-branch2 (10.1.2.1) FortiGate-60F FortiOS 7.6.2: conn=Connected / cfg=In Sync / db=In Sync / age=5m
\_ [OK] fw-hq (10.1.3.1) FortiGate-200F FortiOS 7.6.2: conn=Connected / cfg=In Sync / db=In Sync / age=4m
\_ [OK] fw-dc (10.1.4.1) FortiGate-200F FortiOS 7.6.2: conn=Connected / cfg=In Sync / db=In Sync / age=4m
---------------------------------------

FortiGuard:
---------------------------------------
[WARNING] - FortiGuard FDS: 1/5 servers connected
\_ [OK] 141.109.166.60: connected
\_ [WARNING] 209.40.106.85: unreachable
\_ [WARNING] 189.25.50.40: unreachable
\_ [WARNING] 176.23.153.170: unreachable
\_ [WARNING] usfds1.fortinet.com: unreachable
[OK] - FortiGuard subscriptions: 2/2 valid
\_ [OK] AV: registered / expires 2027-06-01 / db: 1.00123
\_ [OK] IPS: registered / expires 2027-06-01 / db: 24.00456
---------------------------------------

NTP:
---------------------------------------
[OK] - NTP: enabled, 1 server(s): ntp1.fortinet.net
\_ [OK] ntp1.fortinet.net (poll:6-10s)
---------------------------------------
```

## Integration with Monitoring Systems

### Icinga2 Configuration

Create a command definition in `/etc/icinga2/conf.d/commands.conf`:

```icinga2
object CheckCommand "check_fortimanager" {
    command = [ PluginDir + "/check_fortimanager_health.sh" ]
    arguments = {
        "-H"  = "$fortimanager_host$"
        "-T"  = "$fortimanager_token$"
        "-A"  = {
            set_if = "$fortimanager_check_all$"
        }
        "-SC" = "$fortimanager_snmp_community$"
        "-u"  = "$fortimanager_snmp_user$"
        "-a"  = "$fortimanager_snmp_auth_pass$"
        "-X"  = "$fortimanager_snmp_priv_pass$"
        "-v"  = {
            set_if = "$fortimanager_verbose$"
        }
        "--warn-devices-down"    = "$fortimanager_warn_devices_down$"
        "--crit-devices-down"    = "$fortimanager_crit_devices_down$"
        "--warn-dev-age"         = "$fortimanager_warn_dev_age$"
        "--task-hours"           = "$fortimanager_task_hours$"
        "--warn-fds"             = "$fortimanager_warn_fds$"
        "--no-syslog-warn"       = {
            set_if = "$fortimanager_no_syslog_warn$"
        }
        "--no-perfdata" = {
            set_if = "$fortimanager_no_perfdata$"
        }
    }
    vars.fortimanager_check_all        = true
    vars.fortimanager_verbose          = false
    vars.fortimanager_warn_devices_down = 1
    vars.fortimanager_crit_devices_down = 1
    vars.fortimanager_warn_dev_age     = -1
    vars.fortimanager_task_hours       = 24
    vars.fortimanager_warn_fds         = 2
    vars.fortimanager_no_syslog_warn   = false
    vars.fortimanager_no_perfdata      = false
}
```

Create a service definition:

```icinga2
apply Service "FortiManager Health" {
    check_command = "check_fortimanager"
    vars.fortimanager_host             = host.vars.fortimanager_host
    vars.fortimanager_token            = host.vars.fortimanager_token
    vars.fortimanager_snmp_community   = host.vars.fortimanager_snmp_community

    assign where host.vars.fortimanager_host != ""
}
```

### Nagios Configuration

Add to `commands.cfg`:

```nagios
define command {
    command_name    check_fortimanager
    command_line    $USER1$/check_fortimanager_health.sh -H $ARG1$ -T $ARG2$ -A
}
```

Add to `services.cfg`:

```nagios
define service {
    use                 generic-service
    host_name           fmg-prod
    service_description FortiManager Health
    check_command       check_fortimanager!10.0.0.1!your-api-token-here
}
```

## Security Considerations

- **API Token**: Create a dedicated monitoring account with a read-only profile and generate an API token for it. Avoid reusing admin credentials.
- **Full-Admin Access**: For checks requiring full-admin (`-eADOMs`, `-eFirmware`, `-eTasks`, `-eDNS`), consider whether a monitoring service account with elevated privileges is acceptable in your environment. Alternatively, disable these modules with `--disable-adoms --disable-firmware --disable-tasks --disable-dns` and use a read-only profile.
- **Credential Storage**: Store API tokens and SNMP community strings in your monitoring system's secrets store (Icinga2 constants, HashiCorp Vault) — not in plain-text config files where possible.
- **Network Access**: The monitoring server requires HTTPS (port 443) access to the FortiManager management IP and SNMP UDP (port 161) for SNMP-based checks.
- **Self-Signed Certificates**: The plugin uses `--insecure` with curl to accept self-signed FortiManager certificates by default.
- **SNMP**: If using SNMP, restrict the allowed-hosts list on the FortiManager to the monitoring server IP. Use SNMPv3 with authentication and privacy where possible.

## Troubleshooting

### Common Issues

**`[UNKNOWN] - Login to <host> failed (code -22) - check credentials`:**
- Verify username and password are correct
- Confirm the account exists in FortiManager

**`[UNKNOWN] - System: cannot retrieve system status (API code -11)`:**
- The API token is invalid, expired, or the account does not have JSON API Access enabled
- Navigate to System > Admin > REST API Admin and verify the token, or for user/pass accounts: System > Admin > Administrators > \<user\> > JSON API Access: Read-Write
- Test connectivity: `curl -sk -H "Authorization: Bearer <token>" -X POST https://<host>/jsonrpc -d '{"method":"get","params":[{"url":"/sys/status"}],"id":1}'`

**`[UNKNOWN] - ADOMs: access denied (code -11) - requires full-admin access`:**
- The API token or account does not have full administrator privileges
- Either upgrade the account profile to `Super_User` or disable this check with `--disable-adoms`

**`[UNKNOWN] - Resources: /sys/performance not available on this FortiManager`:**
- The `/sys/performance` API endpoint is not available on FortiManager VM builds
- Add SNMP credentials (`-SC <community>` or `-u/-a/-X`) to enable resource collection via the FORTINET-FORTIMANAGER-MIB

**`[UNKNOWN] - FortiGuard: SNMP credentials required`:**
- `-eFGD` requires SNMP credentials because the FortiGuard FDS data is exposed only via SNMP
- Add `-SC <community>` or `-u/-a/-X` for SNMPv3

**`[UNKNOWN] - Uptime: SNMP credentials required`:**
- Uptime is only available via SNMP on FortiManager. Add SNMP credentials.

**`[UNKNOWN] - NTP: API credentials required (not available in SNMP-only mode)`:**
- NTP configuration is read via the JSON-RPC API. Add `-T <token>` or `-U/-P` credentials.

**All checks run even though only `-eSys` was given:**
- Fixed in version 1.7.1 (enable-all guard was missing `enable_up`, `enable_res`, and `enable_dns`). Update to the latest version.

**Connection Timeout:**
- Verify HTTPS (port 443) access from the monitoring server to the FortiManager management IP
- Confirm that HTTPS administrative access is enabled on the management interface

**`jq: command not found`:**
- Install jq: `apt install jq` / `dnf install jq` / `emerge app-misc/jq`

### Debug Mode

Enable full bash trace output:

```bash
./check_fortimanager_health.sh -H 10.0.0.1 -T MyApiToken -A -d 2>&1 | less
```

Or use verbose mode for readable per-module detail:

```bash
./check_fortimanager_health.sh -H 10.0.0.1 -T MyApiToken -SC monitor -A -v
```

## Contributing

Contributions are welcome! Please feel free to submit issues, feature requests, or pull requests.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-new-check`)
3. Make your changes
4. Test against a real FortiManager or a captured API JSON fixture
5. Submit a pull request

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

## Support

For support, please:
1. Review the troubleshooting section above
2. Check existing GitHub issues
3. Open a new issue with your FortiManager model, FortiManager version, and the full plugin output with `-d` (debug) enabled

## Author

**Felix Longardt**
- Email: monitoring@longardt.com
- GitHub: [@ascii42](https://github.com/ascii42)

## Acknowledgments

- Fortinet for the FortiManager JSON-RPC API and FORTINET-FORTIMANAGER-MIB documentation
- The Icinga and Nagios communities for feedback and testing

---

**Note**: This plugin is not officially supported by Fortinet, Inc. Use at your own discretion and test thoroughly in your environment before deploying to production monitoring.
