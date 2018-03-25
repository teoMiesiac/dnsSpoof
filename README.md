# dnsSpoof
### Simple script for MITM attack 

How to setup:

*apt-get install libnet1-dev*

*apt-get install libpcap0.8-dev*

*echo "1" > /proc/sys/net/ipv4/ip_forward*

*make*

How to run:
------
run with parameters: 
<interface> <domain_to_spoof> <ip_to_spoof> <target_ip> <gateway_ip>
  
  interface: name of your interface
  domain to spoof:  www.XYZ.com
  ip to spoof: ip where victim will be redirected e.g.  172.217.16.46  => google.com
  target ip: ip of the victim   
  gataway ip: router ip 
  
  
