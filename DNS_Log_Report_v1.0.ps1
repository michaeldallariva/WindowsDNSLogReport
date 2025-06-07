############################################################################################################################################################################################################################################################
# Windows DNS Log Parser - Very fast generation and little resources used.
# GitHub link : https://github.com/michaeldallariva
# Version : v1.0
# Author : Michael DALLA RIVA, with the help of some AI
# Date : 7th of June 2025
#
# Purpose:
# This script reads and parses the content of a Windows DNS debug log file.
# - Please activate Windows DNS debug log before use.
# - Copy the current log file to the same location or another one.
# - It is best not to run this script on a domain controller, it runs fine, it does not use a large amount of memory or disk, but better safe than sorry. Zip your log file and move it somewhere else.
# - Specify the location of the log file in the variable at the beginning of the script.
# - After a while run this script to generate a HTML report.
# 
# - Tested a debugged on English versions of Windows Server 2016, 2019, 2022 and 2025.
#
# License :
# Feel free to use for any purpose, personal or commercial.
#
############################################################################################################################################################################################################################################################


# Change to the paths of your choice.
$LogPath    = 'C:\logs\dns2.log'
$OutputHtml = 'C:\logs\DNS_Report.html'

# Change to your own DNS servers
$PrimaryDNS = "192.168.0.171, 192.168.0.172"
$SecondaryDNS = ""

function Parse-DNSLog {
    param([string]$LogPath)
    
    try {
        $fileStream = [System.IO.File]::Open($LogPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
        $fileStream.Close()
    }
    catch [System.IO.IOException] {
        Write-Host "❌ ERROR: DNS log file is currently being used by another process!" -ForegroundColor Red
        Write-Host "   This typically happens when the DNS service is actively writing to the log." -ForegroundColor Yellow
        Write-Host "" -ForegroundColor White
        Write-Host "💡 RECOMMENDATION:" -ForegroundColor Cyan
        Write-Host "   1. Copy the DNS log file to a different location first:" -ForegroundColor White
        Write-Host "      Copy-Item '$LogPath' 'C:\Temp\dns_copy.log'" -ForegroundColor Gray
        Write-Host "   2. Then update the script to use the copied file:" -ForegroundColor White
        Write-Host "      `$LogPath = 'C:\Temp\dns_copy.log'" -ForegroundColor Gray
        Write-Host "   3. Or temporarily stop the DNS service (not recommended for production):" -ForegroundColor White
        Write-Host "      Stop-Service DNS" -ForegroundColor Gray
        Write-Host "" -ForegroundColor White
        throw "DNS log file is locked by another process. Please copy the file first and try again."
    }
    catch {
        throw "Unable to access DNS log file: $($_.Exception.Message)"
    }
    
    # Windows Server 2022/2025
    $regex2022 = [regex]::new('^(?<Date>\d{1,2}/\d{1,2}/\d{4})\s+(?<Time>\d{1,2}:\d{2}:\d{2})\s+(?<ThreadID>\w+)\s+PACKET\s+(?<MemAddr>\w+)\s+(?<Protocol>UDP|TCP)\s+(?<Direction>Rcv|Snd)\s+(?<IP>[^\s]+)\s+(?<XID>\w+)\s*(?<QR>R?)?\s*(?<Opcode>[QNU]?)?\s*\[.*?\]\s+(?<QType>SOA|IXFR|PTR|A|SRV|CNAME|AAAA|\w+)\s+(?<Domain>.+?)$', [System.Text.RegularExpressions.RegexOptions]::Compiled)

    # Windows Server 2019
    $regex2019 = [regex]::new('^(?<Date>\d{1,2}/\d{1,2}/\d{4})\s+(?<Time>\d{1,2}:\d{2}:\d{2}\s+[AP]M)\s+(?<ThreadID>\w+)\s+PACKET\s+(?<MemAddr>\w+)\s+(?<Protocol>UDP|TCP)\s+(?<Direction>Rcv|Snd)\s+(?<IP>[^\s]+)\s+(?<XID>\w+)\s*(?<QR>R?)?\s*(?<Opcode>[QNU]?)?\s*\[.*?\]\s+(?<QType>SOA|IXFR|PTR|A|SRV|CNAME|AAAA|\w+)\s+(?<Domain>.+?)$', [System.Text.RegularExpressions.RegexOptions]::Compiled)

    # Windows Server 2016
    $regex2016 = [regex]::new('^(?<Date>\d{1,2}-\d{1,2}-\d{2})\s+(?<Time>\d{1,2}:\d{2}:\d{2})\s+(?<ThreadID>\w+)\s+PACKET\s+(?<MemAddr>\w+)\s+(?<Protocol>UDP|TCP)\s+(?<Direction>Rcv|Snd)\s+(?<IP>[^\s]+)\s+(?<XID>\w+)\s*(?<QR>R?)?\s*(?<Opcode>[QNU]?)?\s*\[.*?\]\s+(?<QType>SOA|IXFR|PTR|A|SRV|CNAME|AAAA|\w+)\s+(?<Domain>.+?)$', [System.Text.RegularExpressions.RegexOptions]::Compiled)

    try {
        $reader = [System.IO.StreamReader]::new($LogPath)
    }
    catch [System.IO.IOException] {
        Write-Host "❌ ERROR: Cannot open DNS log file - it may be locked by the DNS service!" -ForegroundColor Red
        Write-Host "💡 Try copying the file first: Copy-Item '$LogPath' 'C:\Temp\dns_copy.log'" -ForegroundColor Cyan
        throw "DNS log file is currently in use. Please copy the file and try again."
    }
    catch {
        throw "Failed to open DNS log file: $($_.Exception.Message)"
    }
    
    $entries = [System.Collections.Generic.List[hashtable]]::new()
    
    $domainCleanRegex = [regex]::new("\(\d+\)", [System.Text.RegularExpressions.RegexOptions]::Compiled)
    
    $lineCount = 0
    $matchedCount = 0
    
    try {
        while (-not $reader.EndOfStream) {
            $line = $reader.ReadLine()
            $lineCount++
            
            if ($line -notlike "*PACKET*" -or $line -like "*does not match*" -or $line -like "*not match any outstanding query*" -or $line -like "*Message logging key*" -or $line.Length -lt 50 -or $line -like "*UDP question info*" -or $line -like "*Socket =*" -or $line -like "*Remote addr*" -or $line -like "*Message:*") {
                continue
            }
            

	if ($line -match "(\d+-\d+-\d+\s+\d+:\d+:\d+)\s+\S+\s+PACKET\s+(\d+-\d+-\d+\s+\d+:\d+:\d+)\s+(\S+)\s+PACKET\s+(.*)") {
		$line = "$($matches[2]) $($matches[3]) PACKET  $($matches[4])"
	} elseif ($line -match "(\d+/\d+/\d+\s+\d+:\d+:\d+\s+[AP]M)\s+\S+\s+PACKET\s+(\d+/\d+/\d+\s+\d+:\d+:\d+\s+[AP]M)\s+(\S+)\s+PACKET\s+(.*)") {
		$line = "$($matches[2]) $($matches[3]) PACKET  $($matches[4])"
	} elseif ($line -like "*does not match any outstanding query*") {
		continue
	} elseif ($line -match "(\d+/\d+/\d+\s+\d+:\d+:\d+\s+[AP]M).*(\d+/\d+/\d+\s+\d+:\d+:\d+\s+[AP]M)") {
		$cleanedLine = $line -replace "^.*?(\d+/\d+/\d+\s+\d+:\d+:\d+\s+[AP]M\s+\S+\s+PACKET\s+.*)`$", '$1'
		$line = $cleanedLine
	} elseif ($line -match "(\d+-\d+-\d+\s+\d+:\d+:\d+).*(\d+-\d+-\d+\s+\d+:\d+:\d+)") {
		$cleanedLine = $line -replace "^.*?(\d+-\d+-\d+\s+\d+:\d+:\d+\s+\S+\s+PACKET\s+.*)`$", '$1'
		$line = $cleanedLine
	}

$match = $regex2022.Match($line)
$formatType = "2022"

if (-not $match.Success) {
    $match = $regex2019.Match($line)
    $formatType = "2019"
}

if (-not $match.Success) {
    $match = $regex2016.Match($line)
    $formatType = "2016"
}

if ($match.Success) {
    $matchedCount++
    $groups = $match.Groups
    $dtString = "$($groups['Date'].Value) $($groups['Time'].Value)"
    
    try {
switch ($formatType) {
    "2016" {
        $dateParts = $groups['Date'].Value.Split('-')
        $year = "20" + $dateParts[2]  # Convert "25" to "2025"
        $month = $dateParts[1]
        $day = $dateParts[0]
        $time = $groups['Time'].Value
        
        $standardDate = "$month/$day/$year $time"
        $dateTimeObj = [DateTime]::ParseExact($standardDate, 'MM/dd/yyyy HH:mm:ss', [System.Globalization.CultureInfo]::InvariantCulture)
    }
    "2022" {
        $dateTimeObj = [DateTime]::ParseExact($dtString, 'dd/MM/yyyy HH:mm:ss', [System.Globalization.CultureInfo]::InvariantCulture)
    }
    "2019" {
        $dateTimeObj = [DateTime]::ParseExact($dtString, 'M/d/yyyy h:mm:ss tt', [System.Globalization.CultureInfo]::InvariantCulture)
    }
}

    } catch {
        Write-Warning "Failed to parse date: $dtString (Format: Win$formatType)"
        continue
    }
                
                $domain = $domainCleanRegex.Replace($groups['Domain'].Value, '.')
                $domain = $domain.Replace('..', '.').Trim('.')
                
                $qrValue = $groups['QR'].Value
                $opcodeValue = $groups['Opcode'].Value
                $queryType = $groups['QType'].Value
                
                $queryResponse = switch ($opcodeValue) {
                    'N' { 'NOTIFY' }
                    'U' { 'UPDATE' }
                    default { 
                        if ($qrValue -eq 'R') { 
                            if ($queryType -eq 'IXFR') { 'TRANSFER' } else { 'Response' }
                        } else { 
                            'Query' 
                        }
                    }
                }
                
                $entry = @{
                    Date = $groups['Date'].Value
                    Time = $groups['Time'].Value
                    Protocol = $groups['Protocol'].Value
                    Direction = $groups['Direction'].Value
                    IPAddress = $groups['IP'].Value
                    XID = $groups['XID'].Value
                    QueryResponse = $queryResponse
                    QueryType = $groups['QType'].Value
                    Domain = $domain
                    DateTime = $dateTimeObj
                }
                
                $entries.Add($entry)
            } else {
                # Debug: Show unmatched PACKET lines
                Write-Warning "Unmatched PACKET line: $line"
            }
        }
    }
    finally {
        $reader.Close()
    }
    
    Write-Host "📊 Parsing Statistics:" -ForegroundColor Cyan
    Write-Host "   Total lines processed: $lineCount" -ForegroundColor White
    Write-Host "   Matched entries: $matchedCount" -ForegroundColor Green
    Write-Host "   Final entries: $($entries.Count)" -ForegroundColor Green
    
    return $entries.ToArray()
}

function Get-DNSStatistics {
    param([array]$Entries, [string]$PrimaryDNS, [string]$SecondaryDNS)
    
    $uniqueIPsHash = @{}
    $dnsServersHash = @{}
    $clientQueries = 0
    $serverOperations = 0
    $notifyCount = 0
    $updateCount = 0
    $responseCount = 0
    $transferCount = 0
    
    $allDNSServers = @()
    if ($PrimaryDNS) {
        $allDNSServers += $PrimaryDNS.Split(',').Trim()
    }
    if ($SecondaryDNS) {
        $allDNSServers += $SecondaryDNS.Split(',').Trim()
    }
    
    foreach ($entry in $Entries) {
        $uniqueIPsHash[$entry.IPAddress] = $true
        
        switch ($entry.QueryResponse) {
            'Query' { $clientQueries++ }
            'Response' { 
                $serverOperations++
                $responseCount++
            }
            'NOTIFY' { 
                $serverOperations++
                $notifyCount++
            }
            'UPDATE' { 
                $serverOperations++
                $updateCount++
            }
            'TRANSFER' { 
                $serverOperations++
                $transferCount++
            }
        }
        
        if ($entry.IPAddress -in $allDNSServers) {
            $dnsServersHash[$entry.IPAddress] = $true
        }
    }
    
    return @{
        UniqueIPs = $uniqueIPsHash.Count
        ClientQueries = $clientQueries
        ServerOperations = $serverOperations
        DNSServers = $dnsServersHash.Count
        NotifyCount = $notifyCount
        UpdateCount = $updateCount
        ResponseCount = $responseCount
        TransferCount = $transferCount
    }
}

function Get-DNSServerStats {
    param([array]$Entries, [string]$PrimaryDNS, [string]$SecondaryDNS)
    
    $primaryServers = @()
    $secondaryServers = @()
    
    if ($PrimaryDNS) {
        $primaryServers = $PrimaryDNS.Split(',').Trim()
    }
    if ($SecondaryDNS) {
        $secondaryServers = $SecondaryDNS.Split(',').Trim()
    }
    
    $allDNSServers = $primaryServers + $secondaryServers
    
    $dnsServerStats = @{}
    
    foreach ($server in $allDNSServers) {
        $dnsServerStats[$server] = @{
            ServerIP = $server
            ServerType = if ($server -in $primaryServers) { "Primary" } else { "Secondary" }
            TotalQueries = 0
            QueryTypes = @{}
            SourceIPs = @{}
            DestinationIPs = @{}
            LastSeen = [DateTime]::MinValue
        }
    }
    
foreach ($entry in $Entries) {
    $ip = $entry.IPAddress
    
    if ($ip -in $allDNSServers) {
        $stats = $dnsServerStats[$ip]
        $stats.TotalQueries++
        
        if ($entry.DateTime -gt $stats.LastSeen) {
            $stats.LastSeen = $entry.DateTime
        }
        
        $queryType = $entry.QueryType
        if ($stats.QueryTypes.ContainsKey($queryType)) {
            $stats.QueryTypes[$queryType]++
        } else {
            $stats.QueryTypes[$queryType] = 1
        }
        
    if ($entry.Direction -eq "Rcv") {
        if (!$stats.SourceIPs.ContainsKey("Received")) { $stats.SourceIPs["Received"] = 0 }
        $stats.SourceIPs["Received"]++
    } else {
        if (!$stats.DestinationIPs.ContainsKey("Sent")) { $stats.DestinationIPs["Sent"] = 0 }
        $stats.DestinationIPs["Sent"]++
    }
    }
}
    
    $result = @()
    foreach ($serverIP in $dnsServerStats.Keys) {
        $stats = $dnsServerStats[$serverIP]
        
        $topQueryTypes = $stats.QueryTypes.GetEnumerator() | 
            Sort-Object Value -Descending | 
            Select-Object -First 3 | 
            ForEach-Object { "$($_.Name) ($($_.Value))" }
        
$hostname = "-"
try {
    $dnsResult = [System.Net.Dns]::GetHostEntry($serverIP)
    $hostname = $dnsResult.HostName
} catch {
}

$result += [PSCustomObject]@{
    ServerIP = $serverIP
    ServerType = $stats.ServerType
    HostName = $hostname
    TotalQueries = $stats.TotalQueries
    TopQueryTypes = ($topQueryTypes -join ", ")
    LastSeen = if ($stats.LastSeen -ne [DateTime]::MinValue) { $stats.LastSeen.ToString("MM/dd/yyyy HH:mm:ss") } else { "Never" }
}
    }
    
    return $result | Sort-Object TotalQueries -Descending | Select-Object -First 10
}

function Generate-HTMLReport {
    param([array]$Entries, [hashtable]$Stats, [string]$PrimaryDNS, [string]$SecondaryDNS)
    
    $dnsServerStats = Get-DNSServerStats -Entries $Entries -PrimaryDNS $PrimaryDNS -SecondaryDNS $SecondaryDNS
    
    $sb = [System.Text.StringBuilder]::new()
    
    [void]$sb.AppendLine(@"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Windows DNS Server Log Analysis Report</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f5f7fa; }
        
        .header {
            background: linear-gradient(135deg, #2c3e50 0%, #3498db 100%);
            color: white;
            padding: 20px;
            text-align: center;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        
        .header h1 {
            font-size: 2rem;
            font-weight: 300;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 10px;
        }
        
        .container { max-width: 95%; margin: 0 auto; padding: 20px; }
        
        .metrics-grid {
            display: grid;
            grid-template-columns: repeat(7, 1fr);
            gap: 12px;
            margin-bottom: 30px;
        }

        @media (max-width: 1400px) {
            .metrics-grid {
                grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
                gap: 15px;
            }
        }
        
        .metric-card {
            background: linear-gradient(135deg, #34495e 0%, #2c3e50 100%);
            color: white;
            padding: 25px;
            border-radius: 12px;
            box-shadow: 0 4px 15px rgba(52, 73, 94, 0.2);
            transition: transform 0.3s ease;
        }
        
        .metric-card:hover { transform: translateY(-2px); }
        
        .metric-value {
            font-size: 2.5rem;
            font-weight: bold;
            margin-bottom: 5px;
        }
        
        .metric-label {
            font-size: 0.9rem;
            opacity: 0.9;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        
        .analysis-section {
            background: white;
            border-radius: 12px;
            padding: 25px;
            margin-bottom: 25px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.05);
            border-left: 4px solid #4CAF50;
        }
        
        .analysis-section h3 {
            color: #2c3e50;
            margin-bottom: 15px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .legend {
            display: flex;
            flex-wrap: wrap;
            gap: 15px;
            margin: 20px 0;
        }
        
        .legend-item {
            display: flex;
            align-items: center;
            gap: 8px;
            padding: 8px 12px;
            border-radius: 20px;
            font-size: 0.85rem;
            font-weight: 500;
        }

        .inline-badge {
            display: inline;
            padding: 4px 6px;
            border-radius: 4px;
            font-size: 0.85rem;
            font-weight: 500;
            margin-right: 4px;
        }
        
        .analysis-section p {
            margin-bottom: 12px;
        }
        
        .badge-query { background: #4CAF50; color: white; }
        .badge-response { background: #2196F3; color: white; }
        .badge-notify { background: #FF9800; color: white; }
        .badge-update { background: #9C27B0; color: white; }
        .badge-transfer { background: #00BCD4; color: white; }
        .badge-debug { background: #F44336; color: white; }
        .badge-recent { background: #FFC107; color: white; }
        
        .network-visualization {
            background: white;
            border-radius: 12px;
            padding: 25px;
            margin-bottom: 25px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.05);
            border-left: 4px solid #FF6B6B;
        }
        
        .primary-dns {
            background: linear-gradient(135deg, #FF6B6B, #FF8E8E);
            border: 3px solid #FF4444;
        }
        
        .secondary-dns {
            background: linear-gradient(135deg, #4ECDC4, #6EDDD4);
            border: 3px solid #2CAA9F;
        }
        
        .client-node {
            background: linear-gradient(135deg, #95E1D3, #A8E6D8);
            border: 2px solid #6BCFC5;
        }
        
        .network-connection {
            position: absolute;
            z-index: 1;
        }
        
        .traffic-line {
            stroke-dasharray: 5,5;
            animation: dash 2s linear infinite;
        }
        
        @keyframes dash {
            to { stroke-dashoffset: -10; }
        }
        
        .node-tooltip {
            position: absolute;
            background: rgba(0,0,0,0.8);
            color: white;
            padding: 8px 12px;
            border-radius: 4px;
            font-size: 0.75rem;
            pointer-events: none;
            z-index: 100;
            display: none;
        }
        
        .network-legend {
            display: flex;
            justify-content: center;
            gap: 20px;
            margin-top: 15px;
            flex-wrap: wrap;
        }
        
        .network-legend-item {
            display: flex;
            align-items: center;
            gap: 8px;
            font-size: 0.85rem;
        }
        
        .legend-dot {
            width: 16px;
            height: 16px;
            border-radius: 50%;
        }
        
        .table-container {
            background: white;
            border-radius: 12px;
            overflow: hidden;
            box-shadow: 0 2px 10px rgba(0,0,0,0.05);
            margin-bottom: 25px;
        }
        
        .table-header {
            background: linear-gradient(135deg, #95a5a6 0%, #7f8c8d 100%);
            color: white;
            padding: 20px;
            font-size: 1.1rem;
            font-weight: 500;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.9rem;
        }
        
        th {
            background: linear-gradient(135deg, #bdc3c7 0%, #95a5a6 100%);
            color: #2c3e50;
            padding: 12px 15px;
            text-align: left;
            font-weight: 500;
            font-size: 0.85rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        td {
            padding: 12px 15px;
            border-bottom: 1px solid #ecf0f1;
            vertical-align: middle;
        }
        
        tr:hover { background: #f8f9fa; }
        
        .operation-badge {
            padding: 4px 8px;
            border-radius: 12px;
            font-size: 0.75rem;
            font-weight: 500;
            text-transform: uppercase;
        }
        
        .server-type-badge {
            padding: 4px 8px;
            border-radius: 12px;
            font-size: 0.75rem;
            font-weight: 500;
            text-transform: uppercase;
        }
        
        .query-badge { background: #4CAF50; color: white; }
        .response-badge { background: #2196F3; color: white; }
        .notify-badge { background: #FF9800; color: white; }
        .update-badge { background: #9C27B0; color: white; }
        .transfer-badge { background: #00BCD4; color: white; }
        .primary-badge { background: #E74C3C; color: white; }
        .secondary-badge { background: #3498DB; color: white; }
        
        .footer {
            text-align: center;
            padding: 20px;
            color: #7f8c8d;
            font-size: 0.85rem;
            border-top: 1px solid #ecf0f1;
            margin-top: 30px;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔍 Windows DNS Server Log Analysis Report</h1>
    </div>
    
    <div class="container">
        <div class="metrics-grid">
            <div class="metric-card">
                <div class="metric-value">$($Stats.UniqueIPs)</div>
                <div class="metric-label">📊 Unique IP Addresses</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">$($Stats.ClientQueries)</div>
                <div class="metric-label">👥 Client Queries</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">$($Stats.ResponseCount)</div>
                <div class="metric-label">📨 Responses</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">$($Stats.NotifyCount)</div>
                <div class="metric-label">🔔 NOTIFY Operations</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">$($Stats.UpdateCount)</div>
                <div class="metric-label">✏️ UPDATE Operations</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">$($Stats.TransferCount)</div>
                <div class="metric-label">🔄 TRANSFER Operations</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">$($Stats.DNSServers)</div>
                <div class="metric-label">🖥️ DNS Servers in Log</div>
            </div>
        </div>
       
        <div class="analysis-section">
            <h3>🌊 DNS Operation Flow Analysis</h3>
            <p><span class="inline-badge badge-query">QUERY</span> Legitimate DNS requests from clients to your DNS server.</p>
            <p><span class="inline-badge badge-response">RESPONSE</span> DNS responses from upstream servers or authoritative servers.</p>
            <p><span class="inline-badge badge-notify">NOTIFY</span> Zone change notifications between DNS servers for replication.</p>
            <p><span class="inline-badge badge-update">UPDATE</span> Dynamic DNS updates, typically from domain controllers or DHCP servers.</p>
            <p><span class="inline-badge badge-transfer">TRANSFER</span> Zone transfer operations including IXFR (Incremental Zone Transfer) and AXFR (Full Zone Transfer) for DNS replication between servers.</p>
        </div>
        
        <div class="table-container">
            <div class="table-header">
                🖥️ DNS Servers Activity Summary (Top 10)
            </div>
            <table>
                <thead>
                    <tr>
                        <th>Server IP</th>
                        <th>Host Name</th>
                        <th>Server Type</th>
                        <th>Total Queries</th>
                        <th>Top Query Types</th>
                        <th>Last Seen</th>
                    </tr>
                </thead>
                <tbody>
"@)

    foreach ($server in $dnsServerStats) {
        $serverTypeBadge = if ($server.ServerType -eq "Primary") { "primary-badge" } else { "secondary-badge" }
        
        [void]$sb.AppendLine(@"
                    <tr>
                        <td><strong>$($server.ServerIP)</strong></td>
                        <td>$($server.HostName)</td>
                        <td><span class="server-type-badge $serverTypeBadge">$($server.ServerType)</span></td>
                        <td>$($server.TotalQueries)</td>
                        <td>$($server.TopQueryTypes)</td>
                        <td>$($server.LastSeen)</td>
                    </tr>
"@)
    }

    [void]$sb.AppendLine(@"
                </tbody>
            </table>
        </div>
        
        <div class="table-container">
            <div class="table-header">
                📋 Detailed DNS Activity Log
            </div>
            <table>
                <thead>
                    <tr>
                        <th>IP Address</th>
                        <th>Operation Type</th>
                        <th>Host Name</th>
                        <th>Protocol</th>
                        <th>Direction</th>
                        <th>Query Count</th>
                        <th>Top Queried Domains</th>
                        <th>Last Seen</th>
                    </tr>
                </thead>
                <tbody>
"@)
    
    $ipGroups = @{}
    foreach ($entry in $Entries) {
        $ip = $entry.IPAddress
        if (-not $ipGroups.ContainsKey($ip)) {
            $ipGroups[$ip] = [System.Collections.Generic.List[hashtable]]::new()
        }
        $ipGroups[$ip].Add($entry)
    }
    
    foreach ($ip in $ipGroups.Keys) {
        $ipEntries = $ipGroups[$ip]
        $queryCount = $ipEntries.Count
        
        $lastSeen = [DateTime]::MinValue
        foreach ($entry in $ipEntries) {
            if ($entry.DateTime -gt $lastSeen) {
                $lastSeen = $entry.DateTime
            }
        }
        
        $domainCounts = @{}
        foreach ($entry in $ipEntries) {
            $domain = $entry.Domain
            if ($domainCounts.ContainsKey($domain)) {
                $domainCounts[$domain]++
            } else {
                $domainCounts[$domain] = 1
            }
        }
        
        $topDomains = $domainCounts.GetEnumerator() | 
            Sort-Object Value -Descending | 
            Select-Object -First 3 -ExpandProperty Name
        $topDomainsStr = ($topDomains -join ", ")
        if ($topDomainsStr.Length -gt 50) {
            $topDomainsStr = $topDomainsStr.Substring(0, 47) + "..."
        }
        
        $operationCounts = @{}
        $protocolSet = @{}
        $directionSet = @{}
        
        foreach ($entry in $ipEntries) {
            $operation = $entry.QueryResponse
            if ($operationCounts.ContainsKey($operation)) {
                $operationCounts[$operation]++
            } else {
                $operationCounts[$operation] = 1
            }
            $protocolSet[$entry.Protocol] = $true
            $directionSet[$entry.Direction] = $true
        }
        
        $primaryOp = ($operationCounts.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 1).Name
        $badgeClass = switch ($primaryOp) {
            'Query' { 'query-badge' }
            'Response' { 'response-badge' }
            'NOTIFY' { 'notify-badge' }
            'UPDATE' { 'update-badge' }
            'TRANSFER' { 'transfer-badge' }
            default { 'query-badge' }
        }
        
        $protocols = ($protocolSet.Keys -join "/")
        $directions = ($directionSet.Keys -join "/")
        
        $hostname = "-"
        try {
            $dnsResult = [System.Net.Dns]::GetHostEntry($ip)
            $hostname = $dnsResult.HostName
        } catch {
        }
        
        [void]$sb.AppendLine(@"
                    <tr>
                        <td>$ip</td>
                        <td><span class="operation-badge $badgeClass">$primaryOp</span></td>
                        <td>$hostname</td>
                        <td>$protocols</td>
                        <td>$directions</td>
                        <td>$queryCount</td>
                        <td title="$($topDomains -join ', ')">$topDomainsStr</td>
                        <td>$($lastSeen.ToString("MM/dd/yyyy HH:mm:ss"))</td>
                    </tr>
"@)
    }
    

    [void]$sb.AppendLine(@"
                </tbody>
            </table>
        </div>
        
        <div class="footer">
            <p>Report Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | Total Entries Processed: $($Entries.Count)</p>
        </div>
    </div>

<script>

    </script>
    </body>
</html>
"@)

    return $sb.ToString()
}

# Main
try {
    Write-Host "🔍 Windows DNS Server Log Analysis Report Generator" -ForegroundColor Cyan
    Write-Host "================================================" -ForegroundColor Cyan
    
    if (-not (Test-Path $LogPath)) {
        Write-Host "❌ ERROR: DNS log file not found at: $LogPath" -ForegroundColor Red
        Write-Host "💡 Please check the path and ensure the file exists." -ForegroundColor Cyan
        exit 1
    }
    
    $fileSize = (Get-Item $LogPath).Length
    $fileSizeMB = [math]::Round($fileSize / 1MB, 2)
    Write-Host "📁 DNS log file size: $fileSizeMB MB" -ForegroundColor White
    
    if ($fileSizeMB -gt 100) {
        Write-Host "⚠️  WARNING: Large log file detected. Processing may take several minutes..." -ForegroundColor Yellow
    }
    
    Write-Host "📖 Reading and parsing DNS log file..." -ForegroundColor Yellow
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    
    $entries = Parse-DNSLog -LogPath $LogPath
    
    Write-Host "   Parsed $($entries.Count) entries in $($stopwatch.Elapsed.TotalSeconds.ToString('F2')) seconds" -ForegroundColor Green
    
    Write-Host "📊 Calculating statistics..." -ForegroundColor Yellow
    $stats = Get-DNSStatistics -Entries $entries -PrimaryDNS $PrimaryDNS -SecondaryDNS $SecondaryDNS
    
    Write-Host "🎨 Generating HTML report..." -ForegroundColor Yellow
    $htmlReport = Generate-HTMLReport -Entries $entries -Stats $stats -PrimaryDNS $PrimaryDNS -SecondaryDNS $SecondaryDNS
    
    Write-Host "💾 Saving report to: $OutputHtml" -ForegroundColor Yellow
    [System.IO.File]::WriteAllText($OutputHtml, $htmlReport, [System.Text.Encoding]::UTF8)
    
    $stopwatch.Stop()
    
    Write-Host "✅ Report generated successfully in $($stopwatch.Elapsed.TotalSeconds.ToString('F2')) seconds!" -ForegroundColor Green
    Write-Host "📈 Statistics:" -ForegroundColor Cyan
    Write-Host "   Unique IP Addresses: $($stats.UniqueIPs)" -ForegroundColor White
    Write-Host "   Client Queries: $($stats.ClientQueries)" -ForegroundColor White
    Write-Host "   Responses: $($stats.ResponseCount)" -ForegroundColor White
    Write-Host "   NOTIFY Operations: $($stats.NotifyCount)" -ForegroundColor White
    Write-Host "   UPDATE Operations: $($stats.UpdateCount)" -ForegroundColor White
    Write-Host "   TRANSFER Operations: $($stats.TransferCount)" -ForegroundColor White
    Write-Host "   DNS Servers: $($stats.DNSServers)" -ForegroundColor White
    
    Write-Host "`n🌐 Opening report in default browser..." -ForegroundColor Cyan
    Start-Process $OutputHtml
    
} catch [System.IO.IOException] {
    Write-Host "❌ FILE ACCESS ERROR:" -ForegroundColor Red
    Write-Host "   $($_.Exception.Message)" -ForegroundColor White
    Write-Host "" -ForegroundColor White
    Write-Host "💡 SOLUTION:" -ForegroundColor Cyan
    Write-Host "   The DNS log file is being used by the DNS service. Please:" -ForegroundColor White
    Write-Host "   1. Copy the DNS log file to a safe location:" -ForegroundColor Yellow
    Write-Host "      Copy-Item '$LogPath' 'C:\Temp\dns_analysis.log'" -ForegroundColor Gray
    Write-Host "   2. Update the script to use the copied file:" -ForegroundColor Yellow
    Write-Host "      Change: `$LogPath = 'C:\Temp\dns_analysis.log'" -ForegroundColor Gray
    Write-Host "   3. Run the script again" -ForegroundColor Yellow
    exit 1
} catch {
    Write-Host "❌ UNEXPECTED ERROR:" -ForegroundColor Red
    Write-Host "   $($_.Exception.Message)" -ForegroundColor White
    Write-Host "" -ForegroundColor White
    Write-Host "🔍 TROUBLESHOOTING:" -ForegroundColor Cyan
    Write-Host "   • Check if the DNS log file path is correct" -ForegroundColor White
    Write-Host "   • Ensure you have read permissions on the file" -ForegroundColor White
    Write-Host "   • Try running PowerShell as Administrator" -ForegroundColor White
    Write-Host "   • Check if the DNS logging is enabled" -ForegroundColor White
    exit 1
}