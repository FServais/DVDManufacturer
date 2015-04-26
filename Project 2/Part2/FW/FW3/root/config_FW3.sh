#!/bin/sh
FW2_IP="172.14.5.2"
FW3_IP="172.14.6.2"
WEB_IP="172.14.6.3"
PDNS_IP="172.14.5.3"
SMTP_IP="172.14.7.2"
I2_PRIV_IP="172.16.4.2"
T_IP="172.14.3.10"

# ================================== NAT ==================================

# Outgoing (change source)
iptables -t nat -A POSTROUTING -p tcp -s $I2_PRIV_IP -j LOG --log-prefix "[SNAT] : "
iptables -t nat -A POSTROUTING -p tcp -s $I2_PRIV_IP -j SNAT --to-source $FW3_IP

# Arriving (change dest)
iptables -t nat -A PREROUTING -p tcp -d $FW3_IP -j LOG --log-prefix "[DNAT] "
iptables -t nat -A PREROUTING -p tcp -d $FW3_IP -j DNAT --to-destination $I2_PRIV_IP

# ================================== FILTER ==================================

iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow ICMP
iptables -t filter -A FORWARD -m state --state NEW,ESTABLISHED -p icmp -j ACCEPT

# *** Zone 3 : Incoming rules ***

# SSH coming from FW2
iptables -t filter -A FORWARD -m state --state NEW,ESTABLISHED -j ACCEPT -p tcp -s $FW2_IP -d $I2_PRIV_IP --dport 22
# SSH coming from Internet
iptables -t filter -A FORWARD -m state --state NEW,ESTABLISHED -j ACCEPT -p tcp -s $T_IP -d $I2_PRIV_IP --dport 22
# FTP (data) coming from web
iptables -t filter -A FORWARD -m state --state NEW,ESTABLISHED -j ACCEPT -p tcp -s $WEB_IP --sport 20 -d $I2_PRIV_IP

iptables -t filter -A FORWARD -m state --state NEW,ESTABLISHED -j LOG --log-prefix "[FORW - 3 in] DROP : " -d $I2_PRIV_IP
iptables -t filter -A FORWARD -m state --state NEW,ESTABLISHED -j DROP -d $I2_PRIV_IP

# *** Zone 3 : Outgoing rules ***

# Allow connection to SSH
iptables -t filter -A FORWARD -m state --state NEW,ESTABLISHED -j ACCEPT -p tcp -s $I2_PRIV_IP -d $FW2_IP --dport 22

# Allow connection to HTTP
iptables -t filter -A FORWARD -m state --state NEW,ESTABLISHED -j ACCEPT -p tcp -s $I2_PRIV_IP -d $FW2_IP --dport 80 # HTTP
iptables -t filter -A FORWARD -m state --state NEW,ESTABLISHED -j ACCEPT -p tcp -s $I2_PRIV_IP -d $FW2_IP --dport 443 # HTTPS

# Allow connection to PDNS
iptables -t filter -A FORWARD -m state --state NEW,ESTABLISHED -j ACCEPT -p udp -s $I2_PRIV_IP -d $PDNS_IP --dport 53
iptables -t filter -A FORWARD -m state --state NEW,ESTABLISHED -j ACCEPT -p tcp -s $I2_PRIV_IP -d $PDNS_IP --dport 53

# Allow connection to WEB
iptables -t filter -A FORWARD -m state --state NEW,ESTABLISHED -j ACCEPT -p tcp -s $I2_PRIV_IP -d $WEB_IP --dport 80 # HTTP
iptables -t filter -A FORWARD -m state --state NEW,ESTABLISHED -j ACCEPT -p tcp -s $I2_PRIV_IP -d $WEB_IP --dport 21 # FTP

# Allow connection to SMTP
iptables -t filter -A FORWARD -m state --state NEW,ESTABLISHED -j ACCEPT -p tcp -s $I2_PRIV_IP -d $SMTP_IP --dport 25
iptables -t filter -A FORWARD -m state --state NEW,ESTABLISHED -j ACCEPT -p tcp -s $I2_PRIV_IP -d $SMTP_IP --dport 110
iptables -t filter -A FORWARD -m state --state NEW,ESTABLISHED -j ACCEPT -p tcp -s $I2_PRIV_IP -d $SMTP_IP --dport 995

# Deny otherwise
iptables -t filter -A FORWARD -m state --state NEW,ESTABLISHED -j LOG --log-prefix "[FORW - 3 out] DROP : " -s $FW3_IP
iptables -t filter -A FORWARD -m state --state NEW,ESTABLISHED -j DROP -s $I2_PRIV_IP



# *** Zone 2 : Incoming rules ***

# SMTP can receive from U2
iptables -t filter -A FORWARD -m state --state NEW,ESTABLISHED -j ACCEPT -p tcp -s $FW2_IP -d $SMTP_IP --dport 25
iptables -t filter -A FORWARD -m state --state NEW,ESTABLISHED -j ACCEPT -p tcp -s $FW2_IP -d $SMTP_IP --dport 110
iptables -t filter -A FORWARD -m state --state NEW,ESTABLISHED -j ACCEPT -p tcp -s $FW2_IP -d $SMTP_IP --dport 995

# SMTP can receive from I2
iptables -t filter -A FORWARD -m state --state NEW,ESTABLISHED -j ACCEPT -p tcp -s $I2_PRIV_IP -d $SMTP_IP --dport 25
iptables -t filter -A FORWARD -m state --state NEW,ESTABLISHED -j ACCEPT -p tcp -s $I2_PRIV_IP -d $SMTP_IP --dport 110
iptables -t filter -A FORWARD -m state --state NEW,ESTABLISHED -j ACCEPT -p tcp -s $I2_PRIV_IP -d $SMTP_IP --dport 995

# SMTP can receive from Internet
iptables -t filter -A FORWARD -m state --state NEW,ESTABLISHED -j ACCEPT -p tcp -s $T_IP -d $SMTP_IP --dport 25
iptables -t filter -A FORWARD -m state --state NEW,ESTABLISHED -j ACCEPT -p tcp -s $T_IP -d $SMTP_IP --dport 110
iptables -t filter -A FORWARD -m state --state NEW,ESTABLISHED -j ACCEPT -p tcp -s $T_IP -d $SMTP_IP --dport 995

# Deny otherwise
iptables -t filter -A FORWARD -m state --state NEW,ESTABLISHED -j LOG --log-prefix "[FORW - 2 in] DROP : " -d $SMTP_IP
iptables -t filter -A FORWARD -m state --state NEW,ESTABLISHED -j DROP -p tcp -d $SMTP_IP

# *** Zone 2 : Outgoing rules ***

# SMTP can send to U2
iptables -t filter -A FORWARD -m state --state NEW,ESTABLISHED -j ACCEPT -p tcp -s $SMTP_IP -d $FW2_IP --dport 25
iptables -t filter -A FORWARD -m state --state NEW,ESTABLISHED -j ACCEPT -p tcp -s $SMTP_IP -d $FW2_IP --dport 110
iptables -t filter -A FORWARD -m state --state NEW,ESTABLISHED -j ACCEPT -p tcp -s $SMTP_IP -d $FW2_IP --dport 995

# SMTP can send to I2
iptables -t filter -A FORWARD -m state --state NEW,ESTABLISHED -j ACCEPT -p tcp -s $SMTP_IP -d $FW3_IP --dport 25
iptables -t filter -A FORWARD -m state --state NEW,ESTABLISHED -j ACCEPT -p tcp -s $SMTP_IP -d $FW3_IP --dport 110
iptables -t filter -A FORWARD -m state --state NEW,ESTABLISHED -j ACCEPT -p tcp -s $SMTP_IP -d $FW3_IP --dport 995

# SMTP can ask to PDNS
iptables -t filter -A FORWARD -m state --state NEW,ESTABLISHED -j ACCEPT -p tcp -s $SMTP_IP -d $PDNS_IP --dport 53

# Deny otherwise
iptables -t filter -A FORWARD -m state --state NEW,ESTABLISHED -j LOG --log-prefix "[FORW - 2 out] DROP : " -s $SMTP_IP
iptables -t filter -A FORWARD -m state --state NEW,ESTABLISHED -j DROP -s $SMTP_IP



# *** Zone 1 : Incoming rules ***

# Accessible from I2 (HTTP)
iptables -t filter -A FORWARD -m state --state NEW,ESTABLISHED -j ACCEPT -p tcp -s $FW3_IP -d $WEB_IP --dport 80

# Accessible from I2 (HTTPS)
iptables -t filter -A FORWARD -m state --state NEW,ESTABLISHED -j ACCEPT -p tcp -s $FW3_IP -d $WEB_IP --dport 443

# FTP from I2
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


iptables -t filter -A FORWARD -m state --state NEW,ESTABLISHED -j LOG --log-prefix "[FORW] DROP : "
iptables -t filter -A FORWARD -m state --state NEW,ESTABLISHED -j DROP

iptables -t filter -A INPUT -j LOG --log-prefix "[IN] DROP : "
iptables -t filter -A INPUT -j DROP

iptables -t filter -A OUTPUT -j LOG --log-prefix "[OUT] DROP : "
iptables -t filter -A OUTPUT -j DROP
