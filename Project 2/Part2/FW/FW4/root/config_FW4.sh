# Statefull firewall
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

#zone 8 incoming

# the subnet may be reach by SSH
iptables -t filter -A FORWARD -p tcp -s 172.16.7.3 -d 172.16.8.0/24 --dport 22 -m state --state NEW,ESTABLISHED -j ACCEPT

# Communication between DHCP and DHCP_R1
iptables -t filter -A FORWARD -s 172.16.7.2 -d 172.16.8.2   -j ACCEPT

# Deny otherwise
iptables -t filter -A FORWARD -j LOG --log-prefix "[FORW] DROP : " -d 172.16.8.2
iptables -t filter -A FORWARD -j DROP -d 172.16.8.2

#zone 8 outgoing

# Communication between DHCP and DHCP_R1
iptables -t filter -A FORWARD -s 172.16.8.2  -d 172.16.7.2 -m state --state NEW,ESTABLISHED -j ACCEPT

# HTTP(S) proxy
iptables -t filter -A FORWARD -p tcp  -s 172.16.8.0/24 -d 172.16.7.4 --dport 3128 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -t filter -A FORWARD -p tcp  -s 172.16.8.0/24 -d 172.16.7.4 --dport 80 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -t filter -A FORWARD -p tcp -s 172.16.8.0/24 -d 172.16.7.4 --dport 443 -m state --state NEW,ESTABLISHED -j ACCEPT

# SSH connections
iptables -t filter -A FORWARD -p tcp -s 172.16.8.0/24 -d 172.16.7.3 --dport 22 -m state --state NEW,ESTABLISHED -j ACCEPT

# RSYNC Access
iptables -t filter -A FORWARD  -p tcp -s 172.16.8.0/24 -d 172.16.9.2 --dport 873 -m state --state NEW,ESTABLISHED -j ACCEPT

# LDNS
iptables -t filter -A FORWARD -s 172.16.8.0/24 -d 172.16.7.5 -m state --state NEW,ESTABLISHED -j ACCEPT


#iptables -t filter -A FORWARD -p tcp -s 172.16.8.0/24 -d 172.14.6.3 --dport 80 -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -t filter -A FORWARD -p tcp -s 172.16.8.0/24 -d 172.14.6.3 --dport 443 -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -t filter -A FORWARD -p tcp -s 172.16.8.0/24 -d 172.14.6.3 --dport 21 -m state --state NEW,ESTABLISHED -j ACCEPT

# The subnet can not access its mail
iptables -t filter -A FORWARD -p tcp -s 172.16.8.0/24 -d 172.14.7.2 -m state --state NEW,ESTABLISHED -j DENY

# Deny otherwise
iptables -t filter -A FORWARD -j LOG --log-prefix "[FORW] DROP : " -s 172.16.8.2
iptables -t filter -A FORWARD -j DROP -s 172.16.8.2
iptables -t filter -A FORWARD -j LOG --log-prefix "[FORW] DROP : " -s 172.16.8.3
iptables -t filter -A FORWARD -j DROP -s 172.16.8.3
iptables -t filter -A FORWARD -j LOG --log-prefix "[FORW] DROP : " -s 172.16.8.0/24
iptables -t filter -A FORWARD -j DROP -s 172.16.8.0/24

#zone 7 incoming
iptables -t filter -A FORWARD -p tcp -s 172.16.7.3 -d 172.16.9.2 --dport 22 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -t filter -A FORWARD -p tcp -s 172.16.8.0/24 -d 172.16.9.2 --dport 873 -m state --state NEW,ESTABLISHED -j ACCEPT

# Deny otherwise
iptables -t filter -A FORWARD -j LOG --log-prefix "[FORW] DROP : " -d 172.16.9.2
iptables -t filter -A FORWARD -j DROP

iptables -t filter -A FORWARD -j LOG --log-prefix "[FORW] DROP : "
iptables -t filter -A FORWARD -j DROP
