# Task 1: Organize the access log by date, then by IP.
# Run from the folder that contains the access log.

$file = ".\fa25.access.log.full"
foreach($line in Get-Content $file){
    $current_line=$line.split(" ");
    $ip = $current_line[0];
    $current_line[3] -match '\[([0-9]{2})\/([A-Za-z]{3})\/([0-9]{4}):';
    $date = $Matches[1] + "-" + $Matches[2] + "-" + $Matches[3];
    if(!(Test-Path "logs/$date"))
    {
        New-Item -Path "logs" -Name $date -ItemType "directory";
    }
    if(!(Test-Path "logs/$date/$ip"))
    {
        New-Item -Path "logs/$date" -Name $ip -ItemType "file";
    }
    Add-Content -Path "logs/$date/$ip" -value $line;
}
