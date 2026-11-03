# Task 3: Count requests per IP and sort from most to least.
# Run from the folder that contains the access log.

$file = ".\fa25.access.log.full"

$ips = @()
foreach ($line in Get-Content $file) {

    $current_line = $line.Split(" ")
    $ip = $current_line[0]
    $current_line[3] -match '\[([0-9]{2})\/([A-Za-z]{3})\/([0-9]{4}):'
    $date = $Matches[1] + "-" + $Matches[2] + "-" + $Matches[3]

    $ips += $ip
}

$sort = $ips | Group-Object | Sort-Object Count -Descending

$output = @()
foreach( $i in $sort)
{
    $output += ("{0} {1}" -f $i.Name, $i.Count)
}

Set-Content -Path "ipAccessLogs.txt" -Value $output
