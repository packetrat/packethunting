# Packet Mining for Privacy Leakage

Packet captures & commands for DEFCON 2018 Packet Hunting Workshop:
https://defcon.org/html/defcon-26/dc-26-workshops.html#porcello

Install mining tools:
```
# apt install ngrep tcpflow ssldump dsniff tshark p0f pads html2markdown
```

Set a variable for your capture file name:
```
# CAPFILE=CaptureFile.pcap
```

### Tcpdump basics:

Basic local capture:
```
# tcpdump -vvv -nn -i eth0 -w output.cap
```

Reading a capture:
```
# tcpdump -vvv -nn -r output.cap
```

Remote capture through ssh (Capture on remote host's eth0):
# ssh dave@10.0.0.10 'sudo tcpdump -vUnni eth0 -w -' > output.cap

Show HTTP traffic on port 80:
# tcpdump -vvvAnn -i eth0 port 80

Show SMTP/POP3 traffic for specific host:
# tcpdump -vvvAnn -i eth0 'host 10.0.0.10 and port (25 or 110)'

Save filtered traffic to a new file (Example: Save only DNS traffic to a new file):
# tcpdump -r $CAPFILE -w dns-only.cap port 53
