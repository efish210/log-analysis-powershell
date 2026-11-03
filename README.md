# Web Server Log Analysis with Powershell
**Course:** CS 3523 (UTSA), Fall 2025 **Tools:** Powershell (Windows) **Skills:** log parsing, regex, data triage, threat hunting, attack patterns

## Objective 

Given a raw web server access log, use PowerShell to:

1. Split the log into per-day folders, with one file per IP address.
2. Split the log into per-IP folders, with one file per day.
3. Count requests per IP and rank the top talkers.
4. Use the results to identify and justify malicious IP addressses.

## Dataset
| Metric | Value |
|:-|:-|
| Format | Combined Log Format |
| Total Requests | 100,000 |
| Unique source IPs | 2,050 |
| Date Range | 02 Nov 2025 to 19 Nov 2025 |
| IP's with only 1 request | 930 |
| IP's with 100+ requests | 14 |

```
188.166.235.119 - - [02/Nov/2025:03:13:16 -0600] "POST /xmlrpc.php HTTP/1.1" 200 413 "-" "Mozilla/5.0 ..."
 └── [0] client IP     └── [3] timestamp          └── request                 │   │   │      └── user agent
                                                                              │   │   └── referrer
                                                                      status ─┘   └── response bytes
``` 

Using regex to segment the log and splitting on spaces puts the IP at index `0` and the timestamp at index `3`. A regex pulls the day, month, and year out of the timestamp:

```powershell
'\[([0-9]{2})\/([A-Za-z]{3})\/([0-9]{4}):'
```

### Task 1: Organize by date, then IP
 
`scripts/01-split-by-date.ps1`
 
```powershell
$file = ".\fa25.access.log.full"
foreach ($line in Get-Content $file) {
    $current_line = $line.Split(" ")
    $ip = $current_line[0]
    $current_line[3] -match '\[([0-9]{2})\/([A-Za-z]{3})\/([0-9]{4}):'
    $date = $Matches[1] + "-" + $Matches[2] + "-" + $Matches[3]
 
    if (!(Test-Path "logs/$date")) {
        New-Item -Path "logs" -Name $date -ItemType "directory"
    }
    if (!(Test-Path "logs/$date/$ip")) {
        New-Item -Path "logs/$date" -Name $ip -ItemType "file"
    }
    Add-Content -Path "logs/$date/$ip" -Value $line
}
```

Result: folders of each date `logs/02-Nov-2025/` through `logs/19-Nov-2025/`, each holding one file per IP seen that day. This view answers "what happened on a given day?"

### Task 2: Organize by IP, then date
 
`scripts/02-split-by-ip.ps1`
 
Same parsing, with the folder hierarchy flipped to `logsIP/<ip>/<date>`. This view answers "what did this one host do, and when?", which is the view you want once a suspicious IP has been identified.
 
### Task 3: Rank IPs by request count
 
`scripts/03-count-requests-per-ip.ps1`
 
```powershell
$file = ".\fa25.access.log.full"
$ips = @()
foreach ($line in Get-Content $file) {
    $ips += $line.Split(" ")[0]
}
 
$sort = $ips | Group-Object | Sort-Object Count -Descending
$output = foreach ($i in $sort) { "{0} {1}" -f $i.Name, $i.Count }
Set-Content -Path "ipAccessLogs.txt" -Value $output
```
 
Full output: [`output/ipAccessLogs.txt`](output/ipAccessLogs.txt)

## Results: top talkers
 
| Rank | IP | Requests | Share of all traffic |
|:-|:-|:-|:-|
| 1 | 188.166.235.119 | 84,759 | 84.8% |
| 2 | 208.84.101.66 | 2,008 | 2.0% |
| 3 | 196.251.69.182 | 1,666 | 1.7% |
| 4 | 141.98.11.169 | 1,255 | 1.3% |
| 5 | 192.168.1.254 | 932 | 0.9% |
| 6 | 140.245.45.122 | 781 | 0.8% |
| 7 | 91.208.184.23 | 512 | 0.5% |

One IP produced about 85% of all web server requests, and the top three together produced 88%. Normal visitor traffic doesn't look like this.

## Findings

All three top IPs are running the same playbook against a WordPress site: fingerprint, enumerate usernames, then brute-force logins through `xmlrpc.php`.


### 1. 188.166.235.119: XML-RPC brute force (84,759 requests)
 
```
188.166.235.119 - - [02/Nov/2025:03:13:16 -0600] "POST /xmlrpc.php HTTP/1.1" 200 413 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ... Chrome/95.0.4638.69 Safari/537.36"
```

Every request from this IP is a `POST` to `/xmlrpc.php`. That file is WordPress's XML-RPC API, it's being abused because it accepts a username and password on every call bypassing the login page's usual defenses. The client sending 87,759 POST requests to the server is a credential brute force attack.

### 2. 208.84.101.66: fingerprinting plus brute force (2,008 requests)
 
```
208.84.101.66 - - [18/Nov/2025:20:04:29 -0600] "GET /wp-includes/wlwmanifest.xml HTTP/1.1" 200 1045 ...
208.84.101.66 - - [18/Nov/2025:20:05:10 -0600] "POST /xmlrpc.php HTTP/1.1" 200 413 ...
```

`wlwmanifest.xml` is a Windows Live Writer manifest that WordPress exposes. Scanners request it to confirm that the site runs WordPress. Forty seconds later the same IP switches to the XML-RPC brute force.

### 3. 196.251.69.182: full attack chain (1,666 requests)
 
```
10:46:40  GET  /wp-includes/wlwmanifest.xml   200  - confirm WordPress
10:46:50  GET  /wp-login.php                  200  - locate login page
10:47:00  GET  /?author=1                     301  - valid user found
10:47:11  GET  /?author=2                     404
10:47:21  GET  /?author=3                     404
10:48:13  POST /xmlrpc.php                    200  - brute force begins
10:48:23  POST /xmlrpc.php                    200
10:48:33  POST /xmlrpc.php                    200
```

This IP shows the whole sequence in order:

- **Fingerprinting:** requests `wlwmanifest.xml` to confirm WordPress.
- **Username enumeration:** `/?author=N` makes WordPress redirect to `/author/<username>/` when the ID exists. Author 1 returned a `301` meaning user exists, username leaked in the redirect. Authors 2 and 3 returned `404`, telling the attacker there is a likely only one account to target.
- **Brute Force:** with a username identified, it sends a password attempt to `xmlrpc.php` every 10 seconds. Steady intervals is typical of tooling designed to stay under rate limits.



































