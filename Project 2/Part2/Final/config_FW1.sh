#!/bin/sh
FW2_IP="172.14.5.2"
FW3_IP="172.14.6.2"
WEB_IP="172.14.6.3"
PDNS_IP="172.14.5.3"
SMTP_IP="172.14.7.2"
T_IP="172.14.3.10"
DNS_INTERNET="208.67.222.222"

# ================================== FILTER ==================================

iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT


# *** Zone 4 : Incoming rules ***

# DNS requests from anywhere
iptables -t filter -A FORWARD -m state --state NEW,ESTABLISHED -j ACCEPT -p udp -d $PDNS_IP --dport 53
iptables -t filter -A FORWARD -m state --state NEW,ESTABLISHED -j ACCEPT -p tcp -d $PDNS_IP --dport 53

# Deny otherwise
iptables -t filter -A FORWARD -m state --state NEW,ESTABLISHED -j LOG --log-prefix "[FORW - 4 in] DROP : " -d $PDNS_IP
iptables -t filter -A FORWARD -m state --state NEW,ESTABLISHED -j DROP -d $PDNS_IP

# *** Zone 4 : Outgoing rules ***

# Ask another DNS
iptables -t filter -A FORWARD -m state --state NEW,ESTABLISHED -j ACCEPT -p udp -s $PDNS_IP -d $DNS_INTERNET --dport 53
iptables -t filter -A FORWARD -m state --state NEW,ESTABLISHED -j ACCEPT -p tcp -s $PDNS_IP -d $DNS_INTERNET --dport 53

# Deny otherwise
iptables -t filter -A FORWARD -m state --state NEW,ESTABLISHED -j LOG --log-prefix "[FORW - 4 out] DROP : " -s $PDNS_IP
iptables -t filter -A FORWARD -m state --state NEW,ESTABLISHED -j DROP -s $PDNS_IP


# *** Zone 1 : Incoming rules ***

# HTTP
iptables -t filter -A FORWARD -m state --state NEW,ESTABLISHED -j ACCEPT -p tcp -d $WEB_IP --dport 80

# HTTPS
iptables -t filter -A FORWARD -m state --state NEW,ESTABLISHED -j ACCEPT -p tcp -d $WEB_IP --dport 443

# FTP (from FW2)
iptables -t filter -A FORWARD -m state --state NEW,ESTABLISHED -j ACCEPT -p tcp -s $FW2_IP -d $WEB_IP --dport 21

# FTP (from FW3)
iptables -t filter -A FORWARD -m state --state NEW,ESTABLISHED -j ACCEPT -p tcp -s $FW3_IP -d $WEB_IP --dport 21

# Deny otherwise
iptables -t filter -A FORWARD -m state --state NEW,ESTABLISHED -j LOG --log-prefix "[FORW - 1 in] DROP : " -d $WEB_IP
iptables -t filter -A FORWARD -m state --state NEW,ESTABLISHED -j DROP -d $WEB_IP

# *** Zone 1 : Outgoing rules ***

# FTP (data)
iptables -t filter -A FORWARD -m state --state NEW,ESTABLISHED -j ACCEPT -p tcp -s $WEB_IP --sport 20

# Deny otherwise
iptables -t filter -A FORWARD -m state --state NEW,ESTABLISHED -j LOG --log-prefix "[FORW - 1 out] DROP : " -s $WEB_IP
iptables -t filter -A FORWARD -m state --state NEW,ESTABLISHED -j DROP -s $WEB_IP


# *** Zone 9 : Incoming rules ***

# All from FW2
iptables -t filter -A FORWARD -m state --state NEW,ESTABLISHED -j ACCEPT -p tcp -s $FW2_IP -o eth0
iptables -t filter -A FORWARD -m state --state NEW,ESTABLISHED -j ACCEPT -p udp -s $FW2_IP -o eth0

# SMTP to Internet
iptables -t filter -A FORWARD -m state --state NEW,ESTABLISHED -j ACCEPT -p tcp -s $SMTP_IP -o eth0 --dport 25
iptables -t filter -A FORWARD -m state --state NEW,ESTABLISHED -j ACCEPT -p tcp -s $SMTP_IP -o eth0 --dport 110
iptables -t filter -A FORWARD -m state --state NEW,ESTABLISHED -j ACCEPT -p tcp -s $SMTP_IP -o eth0 --dport 995

# I2 (FW3) to Internet
iptables -t filter -A FORWARD -m state --state NEW,ESTABLISHED -j ACCEPT -p tcp -s $FW3_IP -o eth0

# Deny otherwise
iptables -t filter -A FORWARD -m state --state NEW,ESTABLISHED -j LOG --log-prefix "[FORW - 9 in] DROP : " -o eth0
iptables -t filter -A FORWARD -m state --state NEW,ESTABLISHED -j DROP -o eth0

# *** Zone 9 : Outgoing rules ***

# DNS from Internet
iptables -t filter -A FORWARD -m state --state NEW,ESTABLISHED -j ACCEPT -p tcp -i eth0 -d $PDNS_IP --dport 53
iptables -t filter -A FORWARD -m state --state NEW,ESTABLISHED -j ACCEPT -p udp -i eth0 -d $PDNS_IP --dport 53

# SSH from Internet
iptables -t filter -A FORWARD -m state --state NEW,ESTABLISHED -j ACCEPT -p tcp -i eth0 -d $FW2_IP --dport 22
iptables -t filter -A FORWARD -m state --state NEW,ESTABLISHED -j ACCEPT -p tcp -i eth0 -d $FW3_IP --dport 22

# Visit website
iptables -t filter -A FORWARD -m state --state NEW,ESTABLISHED -j ACCEPT -p tcp -i eth0 -d $WEB_IP --dport 80

# Internet to SMTP
iptables -t filter -A FORWARD -m state --state NEW,ESTABLISHED -j ACCEPT -p tcp -i eth0 -d $SMTP_IP --dport 25
iptables -t filter -A FORWARD -m state --state NEW,ESTABLISHED -j ACCEPT -p tcp -i eth0 -d $SMTP_IP --dport 110
iptables -t filter -A FORWARD -m state --state NEW,ESTABLISHED -j ACCEPT -p tcp -i eth0 -d $SMTP_IP --dport 995

# Deny otherwise
iptables -t filter -A FORWARD -m state --state NEW,ESTABLISHED -j LOG --log-prefix "[FORW - 9 out] DROP : " -i eth0
iptables -t filter -A FORWARD -m state --state NEW,ESTABLISHED -j DROP -i eth0

iptables -t filter -A FORWARD -m state --state NEW,ESTABLISHED -j LOG --log-prefix "[FORW] DROP : "
iptables -t filter -A FORWARD -m state --state NEW,ESTABLISHED -j DROP

iptables -t filter -A INPUT -j DROP
iptables -t filter -A OUTPUT -j DROP
