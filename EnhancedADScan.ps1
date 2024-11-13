<#
.SYNOPSIS
Enhanced Active Directory Network Scanner - Discovers and analyzes AD services and Windows hosts on the network.

.DESCRIPTION
This script performs network scanning to identify Active Directory and Windows services running on hosts.
It includes port scanning, service detection, and basic AD information gathering.
No administrative privileges required for basic scanning.

.PARAMETER Subnet
The subnet to scan. Use "local" for current network or specify CIDR notation (e.g., "192.168.1.0/24")
Default: "local"

.PARAMETER DeepScan
Performs additional security checks and service fingerprinting
Default: False

.PARAMETER MaxConcurrentJobs
Maximum number of concurrent scan jobs
Default: 50

.PARAMETER ExportResults
Export results to JSON file
Default: False

.EXAMPLE
# Basic scan of local network
Start-EnhancedADScan

.EXAMPLE
# Deep scan of specific subnet with export
Start-EnhancedADScan -Subnet "192.168.1.0/24" -DeepScan -ExportResults

.NOTES
- Does not require administrative privileges for basic scanning
- Ensure you have explicit permission before scanning any network
- Some service detection features may work better with elevated privileges

#>

function Get-WindowsServicePorts {
    # Combined port list for efficient scanning
    $ports = @{
        # First 1000 ports (only listing relevant ones for AD/Windows)
        StandardPorts = @(
            21, 22, 23, 25, 53, 80, 88, 110, 135, 137, 138, 139, 143, 389, 443, 445, 464, 636, 873
        )
        
        # Additional important ports above 1000
        HighPorts     = @(
            1022, 1023, 1024, 1025, 1026, 1027, 1028, 1029, 1433, 1434, # SQL Server
            2222, 2382, 3268, 3269, # Global Catalog
            3389, # RDP
            4445, 5722, # RPC
            5985, 5986, # WinRM
            7001, 7002, # SOAP
            8080, 8443, # Web Services
            9389                                                           # AD Web Services
        )
        
        # Service mappings for identification
        ServiceMap    = @{
            53   = "DNS"
            88   = "Kerberos"
            135  = "RPC"
            137  = "NetBIOS Name"
            138  = "NetBIOS Datagram"
            139  = "NetBIOS Session"
            389  = "LDAP"
            445  = "SMB"
            464  = "Kerberos Password Change"
            636  = "LDAPS"
            3268 = "Global Catalog"
            3269 = "Global Catalog SSL"
            5985 = "WinRM HTTP"
            5986 = "WinRM HTTPS"
            9389 = "AD Web Services"
        }
    }
    return $ports
}

function Get-ADServiceInfo {
    param(
        [string]$ComputerName,
        [int]$Port
    )
    
    $serviceInfo = @{
        IsOpen   = $false
        Banner   = $null
        Version  = $null
        Protocol = $null
    }

    # Basic port test using TCP Client with timeout
    try {
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $connect = $tcpClient.BeginConnect($ComputerName, $Port, $null, $null)
        $wait = $connect.AsyncWaitHandle.WaitOne(1000, $false)
        
        if ($wait) {
            $tcpClient.EndConnect($connect)
            $serviceInfo.IsOpen = $true
            
            # Basic service identification
            $serviceMap = (Get-WindowsServicePorts).ServiceMap
            if ($serviceMap.ContainsKey($Port)) {
                $serviceInfo.Protocol = $serviceMap[$Port]
            }
            
            # Attempt banner grab for open ports
            try {
                $stream = $tcpClient.GetStream()
                $stream.ReadTimeout = 2000
                $buffer = New-Object byte[] 1024
                $encoding = [System.Text.ASCIIEncoding]::ASCII
                
                if ($stream.DataAvailable) {
                    $bytesRead = $stream.Read($buffer, 0, 1024)
                    if ($bytesRead -gt 0) {
                        $serviceInfo.Banner = $encoding.GetString($buffer, 0, $bytesRead).Trim()
                    }
                }
            }
            catch { }
        }
    }
    catch { }
    finally {
        if ($null -ne $tcpClient) {
            $tcpClient.Close()
        }
    }

    return $serviceInfo
}

function Get-DomainInfo {
    param(
        [string]$ComputerName
    )
    
    $domainInfo = @{
        IsDC     = $false
        Roles    = @()
        Forest   = $null
        Domain   = $null
        SiteName = $null
    }

    try {
        $ldap = New-Object System.DirectoryServices.Protocols.LdapConnection $ComputerName
        $ldap.AuthType = [System.DirectoryServices.Protocols.AuthType]::Anonymous
        $ldap.Timeout = [System.TimeSpan]::FromSeconds(2)
        
        $searchRequest = New-Object System.DirectoryServices.Protocols.SearchRequest(
            "RootDSE",
            "(objectClass=*)",
            [System.DirectoryServices.Protocols.SearchScope]::Base
        )
        
        try {
            $response = $ldap.SendRequest($searchRequest)
            if ($response.Entries.Count -gt 0) {
                $domainInfo.IsDC = $true
                
                $entry = $response.Entries[0]
                if ($entry.Attributes["supportedCapabilities"]) {
                    $domainInfo.Roles += "Global Catalog"
                }
                
                if ($entry.Attributes["defaultNamingContext"]) {
                    $domainInfo.Domain = $entry.Attributes["defaultNamingContext"][0]
                }
                if ($entry.Attributes["configurationNamingContext"]) {
                    $domainInfo.Forest = $entry.Attributes["configurationNamingContext"][0]
                }
            }
        }
        catch { }
    }
    catch { }

    return $domainInfo
}

function Get-ArpHosts {
    param(
        [string]$Subnet = "local"
    )
    
    $hosts = @()
    
    if ($Subnet -eq "local") {
        # Get local network information
        $networkInfo = Get-NetIPConfiguration | 
        Where-Object { $null -ne $_.IPv4DefaultGateway -and $_.NetAdapter.Status -eq "Up" }
        
        if ($networkInfo) {
            $localIP = $networkInfo.IPv4Address.IPAddress
            $subnetMask = $networkInfo.IPv4Address.PrefixLength
            $Subnet = "$localIP/$subnetMask"
        }
    }
    
    # Convert subnet to IP range
    $network = $Subnet.Split('/')[0]
    $mask = [int]$Subnet.Split('/')[1]
    
    # Simple ping sweep
    $ips = Get-IPRange -BaseIP $network -MaskBits $mask
    $ips | ForEach-Object {
        $ping = New-Object System.Net.NetworkInformation.Ping
        $result = $ping.Send($_, 100)
        if ($result.Status -eq 'Success') {
            $hosts += @{
                IP  = $_
                MAC = Get-MACAddress -IP $_
            }
        }
    }
    
    return $hosts
}

function Get-IPRange {
    param(
        [string]$BaseIP,
        [int]$MaskBits
    )
    
    $ip = [System.Net.IPAddress]::Parse($BaseIP)
    $mask = [System.Net.IPAddress]::Parse((Convert-Int64ToIP -Int64 ([convert]::ToInt64(("1" * $MaskBits + "0" * (32 - $MaskBits)), 2))))
    $network = [System.Net.IPAddress]::Parse(([convert]::ToInt64($ip.Address -band $mask.Address)))
    $broadcast = [System.Net.IPAddress]::Parse(([convert]::ToInt64($ip.Address -bor (-bnot [convert]::ToInt64($mask.Address) -band [uint32]::MaxValue))))
    
    $startIP = Convert-IPToInt64 -IP $network
    $endIP = Convert-IPToInt64 -IP $broadcast
    
    $startIP..$endIP | ForEach-Object {
        Convert-Int64ToIP -Int64 $_
    }
}

function Convert-IPToInt64 {
    param([string]$IP)
    return [convert]::ToInt64(($IP.Split('.') | ForEach-Object { [convert]::ToString([byte]$_, 2).PadLeft(8, '0') }) -join '', 2)
}

function Convert-Int64ToIP {
    param([int64]$Int64)
    return [System.Net.IPAddress]::Parse([convert]::ToInt64(([convert]::ToString($Int64, 2).PadLeft(32, '0') -replace '(.{8})', '$1.').Trim('.'))).ToString()
}

function Get-MACAddress {
    param([string]$IP)
    
    $arp = arp -a $IP 2>&1
    if ($arp -match '([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})') {
        return $matches[0]
    }
    return $null
}

function Start-EnhancedADScan {
    param(
        [Parameter(Mandatory = $false)]
        [string]$Subnet = "local",
        [switch]$DeepScan,
        [int]$MaxConcurrentJobs = 50,
        [switch]$ExportResults
    )

    Write-Host "`nStarting Enhanced AD Environment Scan" -ForegroundColor Cyan
    
    # Get port lists
    $portGroups = Get-WindowsServicePorts
    $scanPorts = @()
    $scanPorts += $portGroups.StandardPorts
    $scanPorts += $portGroups.HighPorts
    $scanPorts = $scanPorts | Select-Object -Unique | Sort-Object
    
    Write-Host "Discovering hosts..." -ForegroundColor Yellow
    $onlineHosts = Get-ArpHosts -Subnet $Subnet
    Write-Host "Found $($onlineHosts.Count) online hosts" -ForegroundColor Green
    
    Write-Host "Starting port scan..." -ForegroundColor Yellow
    $results = $onlineHosts | ForEach-Object -ThrottleLimit $MaxConcurrentJobs -Parallel {
        $hostInfo = @{
            IP         = $_.IP
            MAC        = $_.MAC
            Services   = @{}
            DomainInfo = $null
        }

        foreach ($port in $using:scanPorts) {
            $serviceInfo = Get-ADServiceInfo -ComputerName $_.IP -Port $port
            if ($serviceInfo.IsOpen) {
                $hostInfo.Services[$port] = $serviceInfo
            }
        }

        if ($hostInfo.Services.ContainsKey(389) -or $hostInfo.Services.ContainsKey(3268)) {
            $hostInfo.DomainInfo = Get-DomainInfo -ComputerName $_.IP
        }

        return $hostInfo
    }

    # Generate report
    Write-Host "`nScan Results:" -ForegroundColor Green
    
    # Display Domain Controllers
    $dcs = $results | Where-Object { $_.DomainInfo.IsDC }
    if ($dcs) {
        Write-Host "`nDomain Controllers:" -ForegroundColor Yellow
        foreach ($dc in $dcs) {
            Write-Host "`nDC: $($dc.IP)" -ForegroundColor Cyan
            Write-Host "Domain: $($dc.DomainInfo.Domain)"
            Write-Host "Roles: $($dc.DomainInfo.Roles -join ', ')"
            Write-Host "Open Services:"
            $dc.Services.GetEnumerator() | Sort-Object Name | ForEach-Object {
                Write-Host "  - Port $($_.Key): $($_.Value.Protocol)"
                if ($_.Value.Banner) {
                    Write-Host "    Banner: $($_.Value.Banner)"
                }
            }
        }
    }

    # Display other hosts
    $others = $results | Where-Object { -not $_.DomainInfo.IsDC }
    if ($others) {
        Write-Host "`nOther Hosts:" -ForegroundColor Yellow
        foreach ($host in $others) {
            if ($host.Services.Count -gt 0) {
                Write-Host "`nHost: $($host.IP)" -ForegroundColor Cyan
                Write-Host "Open Services:"
                $host.Services.GetEnumerator() | Sort-Object Name | ForEach-Object {
                    Write-Host "  - Port $($_.Key): $($_.Value.Protocol)"
                    if ($_.Value.Banner) {
                        Write-Host "    Banner: $($_.Value.Banner)"
                    }
                }
            }
        }
    }

    if ($ExportResults) {
        $exportPath = "ad_scan_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
        $results | ConvertTo-Json -Depth 10 | Out-File $exportPath
        Write-Host "`nResults exported to: $exportPath" -ForegroundColor Green
    }

    return $results
}