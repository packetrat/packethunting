# Packet Mining for Privacy Leakage

Packet captures & commands for DEFCON 2018 Packet Hunting Workshop:
https://defcon.org/html/defcon-26/dc-26-workshops.html#porcello

### Getting started
Install mining tools:
```
# apt install ngrep tcpflow ssldump dsniff tshark p0f pads html2markdown
```
Set a variable for your capture file name:
```
# CAPFILE=CaptureFile.pcap
```
### Tcpdump basics
Basic local capture:
```
# tcpdump -vvv -nn -i eth0 -w output.cap
```
Reading a capture:
```
# tcpdump -vvv -nn -r output.cap
```
Remote capture through ssh (Capture on remote host's eth0):
```
# ssh dave@10.0.0.10 'sudo tcpdump -vUnni eth0 -w -' > output.cap
```
Show HTTP traffic on port 80:
```
# tcpdump -vvvAnn -i eth0 port 80
```
Show SMTP/POP3 traffic for specific host:
```
# tcpdump -vvvAnn -i eth0 'host 10.0.0.10 and port (25 or 110)'
```
Save filtered traffic to a new file (Example: Save only DNS traffic to a new file):
```
# tcpdump -r $CAPFILE -w dns-only.cap port 53
```
### Ngrep basics
Print live web traffic to console:
```
# ngrep -d eth0 -W byline -q -t port 80
```
Grep live network traffic for "password"
```
# ngrep -d eth0 -q -t -i 'password'
```
Grep for HTTP GET/POST requests:
```
# ngrep -d eth0 -W byline -q -t '^(GET|POST)' port 80
```
### Tcpflow basics
Print ASCII packet data to console:
```
# tcpflow -c -s -r $CAPFILE
```
Extract all flows, objects, & files to output folder:
```
# mkdir tcpflow
# tcpflow -a -r $CAPFILE -o tcpflow/
```
### Passive OS/app profiling
Show host OS/apps via p0f:
```
# p0f -r $CAPFILE
```
Show host OS/apps via PADS:
```
# pads -r $CAPFILE
# cat assets.csv
```
### Connection stats
Top 10 source IPs:
```
# tcpdump -nn -r $CAPFILE |grep " IP " | awk '{print$3}' |cut -d. -f -4 |sort |uniq -c |sort -nr |head
```
Top 10 destination IPs:
```
# tcpdump -nn -r $CAPFILE |grep " IP " | awk '{print$5}' |cut -d. -f -4 |sort |uniq -c |sort -nr |head
```
Top connection pairs:
```
# tcpdump -nn -r $CAPFILE |grep " IP " | awk '{print$3,$4,$5}' |sort |uniq -c |sort -nr |head
```
Top IP protocols:
```
# tcpdump -nn -v -r $CAPFILE |grep " IP " |awk -F, '{print$6}' |sort |uniq -c |sort -nr
```
Top 10 destination ports:
```
# tcpdump -nn -r $CAPFILE |grep " IP " | awk '{print$5}' |cut -d. -f 5- |sort |uniq -c |sort -nr |head
```
### DNS digging
Top domains:
```
# tcpdump -nn -r $CAPFILE port 53 | egrep " A\? " | awk '{print$8}' | egrep -io "[a-z0-9]*\.[a-z]*\.$" | sort | uniq -ic | sort -nr | head
```
Top subdomains:
```
# tcpdump -nn -r $CAPFILE port 53 | egrep " A\? " | awk '{print$8}' |sort |uniq -c |sort -nr |head
```
### Private IP/MAC address leakage
Grep for private IPs in packet data:
```
# ngrep -q -t -W byline -I $CAPFILE '10\.([0-9]{1,3}\.){2}[0-9]{1,3}|192\.168\.[0-9]{1,3}\.[0-9]{1,3}|172\.([0-9]{1,3}\.){2}[0-9]{1,3}'
```
Grep for MACs in packet data:
```
# ngrep -q -t -W byline -I $CAPFILE '([0-9a-fA-F][0-9a-fA-F]:){5}([0-9a-fA-F][0-9a-fA-F])'
```
### Profiling HTTP traffic
Top 10 websites:
```
# ngrep -I $CAPFILE -W byline -q -t '^(GET|POST)' port 80 | grep "^Host:" | sort |uniq -ic |sort -nr |head
```
Top 10 referrers:
```
# ngrep -I $CAPFILE -W byline -q -t '^(GET|POST)' port 80 | egrep "^Referer: " |sort |uniq -ic | sort -nr |head
```
Top 10 GET requests (URLs):
```
# ngrep -I $CAPFILE -W byline -q -t '^(GET )' port 80 | grep "^GET " | sort |uniq -ic | sort -nr |head
```
HTTP POSTs & POST data:
```
# ngrep -I $CAPFILE -W byline -q -t '^(POST )' port 80 | egrep "^POST|^<|^[a-z]"
```
URL log with timestamps:
```
# ngrep -I $CAPFILE -W byline -q -t '^(GET|POST)' port 80 |egrep "^T |^(GET|POST)|^Host:|^$"
```
Unique cookies:
```
# tcpflow -r $CAPFILE -c -s port 80 | grep -v "\.\." | grep "^Set-Cookie" | sort |uniq
```
Unique session IDs/UUIDs:
```
# tcpflow -r $CAPFILE -c -s port 80 | grep -v "\.\." | egrep -i "session.id|sessionid|session.token|SESSID|UUID|oauth|Authorization:"    ### Add some --color if needed!
```
User-Agent profiling:
```
# ngrep -I $CAPFILE -W byline -q -t port 80 | egrep "^User-Agent: " |sort |uniq -ic | sort -nr
```
### Extracting objects/files
Extract all objects/files & decode HTML:
```
# tcpflow -a -r $CAPFILE -o tcpflow/
```
Breakdown by file type:
```
# find tcpflow/ |egrep -o "\.[a-zA-Z]*$" |sort |uniq -ic |sort -nr
```
### Content profiling
Search engine queries:
```
# ngrep -I $CAPFILE -W byline -q -t port 80 | egrep 'GET \/search\?q=' |sort |uniq
```
URL "keyword" strings:
```
# ngrep -I $CAPFILE -W byline -q -t '^(GET|POST)' port 80 | egrep "^GET |^POST |^Referer: " | egrep -o "[a-z-]*" | egrep "[a-z-]*-[a-z-]*-" | egrep -v "(^-|-$)" |sort | uniq -ic |sort -nr |head
```
Top words from HTML content:
```
# cat tcpflow/*.html |html2markdown | egrep -o '\w{4,}' |sort |uniq -c |sort -nr |head -n25
```
### Personal contact info
Email addresses with common TLDs:
```
# tcpflow -r $CAPFILE  -c -s | egrep -i --color '\w+@[a-zA-Z_]+?\.(com|org|net|gov|mil|edu|co|biz|info)'
```
Email addresses with *any* TLD (more false positives): 
```
# tcpflow -r $CAPFILE  -c -s | egrep -i --color '\w+@[a-zA-Z_]+?\.[a-zA-Z]{2,6}'
```
"Dashed" phone numbers:
```
# tcpflow -r "$CAPFILE" -c -s port 80 | grep --color -P "\d{3}-\d{3}-\d{4}"
```
Dashed or dotted phone numbers (more false positives):
```
# tcpflow -r "$CAPFILE" -c -s port 80 | grep --color -P "\d{3}[-.]\d{3}[-.]\d{4}"
```
### Email traffic
Email senders, recipients, & email subjects:
```
# ngrep -q -t -W byline -I $CAPFILE port 25 or port 110 |egrep "^To:|^From:|^Subject"
```
Email client apps & AV scanners:
```
# tcpflow -c -s -r $CAPFILE port 25 or port 110 |egrep -A1 "^User-Agent:|X-Antivirus" |sort -u
```
Extract emails to console:
```
# tcpflow -c -s -r $CAPFILE port 25 or port 110
```
Extract emails to disk:
```
# tcpflow -a -r $CAPFILE port 25 or port 110  -o tcpflow/
```
### Password hunting
FTP, Telnet, SMTP, POP3, HTTP, etc:
```
# ngrep -I $CAPFILE -W byline -q -t | egrep --color "[Pp]assword[=:]|[Pp]ass=|[Ss]ecret=|pwd=|^PASS|^USER |^AUTH |login:|^Authorization:"
```
Decoding HTTP Basic auth, SMTP, POP3 (base64): 
```
# echo 'QWxhZGRpbjpPcGVuU2VzYW1l'  | base64 -d
```
Finding SNMP community strings:
```
# tcpdump -A -nn -r $CAPFILE port 161
```
### Digging for PII & confidential data
Credit card numbers:
```
# tcpflow -c -s -r $CAPFILE | grep -P --color '(6011|5[1-5]\d{2}|4\d{3}|3\d{3})[- ]\d{4}[- ]\d{4}[- ]\d{4}'
```
Social security numbers:
```
# tcpflow -c -s -r $CAPFILE | grep -P --color '([0-6]\d\d|7[0-256]\d|73[0-3]|77[0-2])[- ]\d{2}[- ]\d{4}'
```
DOB/License/Passport numbers:
```
# tcpflow -c -s -r $CAPFILE | grep -v Cookie |egrep --color 'DOB[:= ]|[Pp]assport[:= ]|[Ll]icense number'
```
Classified/tagged documents:
```
# tcpflow -c -s -r $CAPFILE | grep -v Cookie |egrep --color -i ' CONFIDENTIAL | PROTECTED | INTERNAL USE ONLY | TOP SECRET '
```
### Hardware/mobile device profiling
Device manufacturers/models:
```
# ngrep -I "$CAPFILE" -W byline -q -t port 80 | egrep --color "device_name=|device_type=|os_version=|dev=|X-Device-Info:|Device:|DEVICE:|deviceId=|deviceModel=" |sort |uniq
```
Cell carrier parameters:
```
# ngrep -I "$CAPFILE" -W byline -q -t port 80 | egrep --color "mcc=|mnc=|csc="
```
Decoding Apple iDevice plist files:
```
# apt install libplist-utils
# plistutil -i <plistfile>
```
Windows error reporting: Hardware vendor, model, BIOS/firmware versions, running processes, exe/dll versions, & connected USB devices:
```
# ngrep -I "$CAPFILE" -W byline -q -t '^(GET|POST)' port 80 |egrep "^T |^GET|^Host:" |egrep -B2 "watson.microsoft.com.$"
```
### Location tracking data
Via Apple default weather app, Wunderground, etc:
```
# ngrep -I "$CAPFILE" -W byline -q -t '^(GET|POST|HTTP/)' port 80 |egrep "%2Clatitude%2|maxlat=|latitude="
```
Via Windows default weather app:
```
# ngrep -I "$CAPFILE" -W byline -q -t 'weather.microsoft.com' port 80 |egrep --color "DisplayName="
```
### Amazon mobile app traffic
Kindle app traffic ("key=" indicates ASIN of each ebook)
```
# ngrep -q -t -I kindle.pcap -W byline | grep --color 'type="EBOK" key='
```
Prime video app traffic:
```
# ngrep -q -t -I kindle.pcap -W byline | grep  'Prime%20Video%22%2C%22vn'
```
### Inspecting SSL traffic
Extract SSL certificates with tcpflow:
```
# tcpflow -a -r $CAPFILE -o tcpflow/ port 443
```
Extract SSL websites via Server Name Indication (SNI):
```
# ngrep -I $CAPFILE -q -t -W byline port 443 |egrep -o "[a-z0-9]*\.[a-z0-9]*\.(com|org|net|gov|mil|edu|co|biz|info)" |sort -u
```
Sessions using weak cipher suites:
```
# ssldump -n -r $CAPFILE | grep "cipherSuite" | egrep -i "RC4|MD5|EXP|NULL|_DES|ANON|64"
```
Sessions using weak SSL protocol versions:
```
# ssldump -n -r $CAPFILE | grep Version |sort -u
```
Decrypting SSL traffic using a known private key:
```
# tshark -r SSL-decryption.pcap -q -o "ssl.keys_list:192.168.56.101,443,http,server.pem" -z "follow,ssl,ascii,2"
```
