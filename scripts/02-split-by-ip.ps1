# Task 2: Organize the access log by IP, then by date.
# Run from the folder that contains the access log.

$file = ".\fa25.access.log.full"
foreach ($line in Get-Content $file) {

    $current_line = $line.Split(" ")
    $ip = $current_line[0]
    $current_line[3] -match '\[([0-9]{2})\/([A-Za-z]{3})\/([0-9]{4}):';
    $date = $Matches[1] + "-" + $Matches[2] + "-" + $Matches[3]

    if (!(Test-Path "logsIP/$ip"))
    {
        New-Item -Path "logsIP" -Name $ip -ItemType "directory";
    }

    if (!(Test-Path "logsIP/$ip/$date"))
    {
        New-Item -Path "logsIP/$ip" -Name $date -ItemType "file";
    }

    Add-Content -Path "logsIP/$ip/$date" -Value $line
}
