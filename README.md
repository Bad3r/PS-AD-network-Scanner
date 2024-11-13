# PS-AD-network-Scanner

## Overview

The **PS-AD-network-Scanner** is a PowerShell script designed to perform enhanced network scanning and analysis within Active Directory (AD) environments. It identifies AD services and Windows hosts, conducts port scans, performs service detection, and collects basic AD information, all without needing administrative privileges for basic scanning.

## Features

- **Subnet Scanning**: Scan local or specified subnets for hosts running Windows services and AD components.
- **Port Scanning**: Identifies open ports associated with AD and Windows services.
- **Service Detection**: Detects specific Windows and AD services and performs fingerprinting.
- **Domain Controller Identification**: Detects domain controllers and gathers related AD details.
- **Export Results**: Saves scan results to a JSON file for easy reporting and analysis.

## Requirements

- **PowerShell**: Compatible with PowerShell on Windows systems.
- **Permissions**: Basic scanning does not require elevated privileges, but certain detection features may work better with them.
- **Network Access**: Ensure explicit permission is obtained before scanning any network.

## Usage

### Parameters

- `-Subnet` : Specifies the subnet to scan. Use `"local"` for the current network or provide a subnet in CIDR notation (e.g., `"192.168.1.0/24"`). Default is `"local"`.
- `-DeepScan` : Enables additional security checks and service fingerprinting (optional).
- `-MaxConcurrentJobs` : Defines the maximum number of concurrent scanning jobs. Default is `50`.
- `-ExportResults` : Exports the scan results to a JSON file. Default is `False`.

### Examples

#### Example 1: Basic Scan of Local Network

To run a basic scan of the local network:

```powershell
./EnhancedADScan.ps1
```

#### Example 2: Deep Scan of a Specified Subnet with Results Export

To perform a detailed scan of a specific subnet and save the results:

```powershell
./EnhancedADScan.ps1 -Subnet "192.168.1.0/24" -DeepScan -ExportResults
```

## Functions

### `Get-WindowsServicePorts`

Defines common ports used by AD and Windows services and maps them to specific service names.

### `Get-ADServiceInfo`

Connects to specific ports on each host to identify open services and capture basic service banners.

### `Get-DomainInfo`

Attempts to retrieve domain information from AD using LDAP queries.

### `Get-ArpHosts`

Performs a simple ARP ping sweep to identify live hosts within the subnet.

### `./EnhancedADScan.ps1`

Main function that coordinates the scanning process, gathers network data, and organizes results.

## Output

- **Console Output**: Displays real-time scan progress and results, including identified domain controllers and other Windows hosts.
- **JSON Export** (optional): Saves detailed scan results to a timestamped JSON file.

## Important Notes

- **Non-Admin Usage**: No administrative privileges are needed for basic scanning, though some service detection might require elevated privileges.
- **Permission**: Ensure you have explicit permission to scan any network to avoid unauthorized activity.

## Note

- This script is provided "as-is" without any warranties. Use at your own risk.
- The script needs more testing.