
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

#zone 8 incoming
iptables -t filter -A FORWARD -p tcp -s 172.16.7.3 -d 172.16.8.0/24 --dport 22 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -t filter -A FORWARD -p tcp -s 172.14.6.3 --sport 20  -m state --state NEW,ESTABLISHED, RELATED -j ACCEPT
iptables -t filter -A FORWARD -s 172.16.7.2 -d 172.16.8.2   -j ACCEPT
#zone 8 outgoing
iptables -t filter -A FORWARD -s 172.16.8.2  -d 172.16.7.2 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -t filter -A FORWARD -p tcp  -s 172.16.8.0/24 -d 172.16.7.4 --dport 3128 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -t filter -A FORWARD -p tcp  -s 172.16.8.0/24 -d 172.16.7.4 --dport 80 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -t filter -A FORWARD -p tcp -s 172.16.8.0/24 -d 172.16.7.4 --dport 443 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -t filter -A FORWARD -p tcp -s 172.16.8.0/24 -d 172.16.7.3 --dport 22 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -t filter -A FORWARD  -p tcp -s 172.16.8.0/24 -d 172.16.9.2 --dport 873 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -t filter -A FORWARD -s 172.16.8.0/24 -d 172.16.7.5 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -t filter -A FORWARD -p tcp -s 172.16.8.0/24 -d 172.14.6.3 --dport 80 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -t filter -A FORWARD -p tcp -s 172.16.8.0/24 -d 172.14.6.3 --dport 443 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -t filter -A FORWARD -p tcp -s 172.16.8.0/24 -d 172.14.6.3 --dport 21 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -t filter -A FORWARD -p tcp -s 172.16.8.0/24 -d 172.14.7.2 -m state --state NEW,ESTABLISHED -j DENY

#zone 7 incoming
iptables -t filter -A FORWARD -p tcp -s 172.16.7.3 -d 172.16.9.2 --dport 22 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -t filter -A FORWARD -p tcp -s 172.16.8.0/24 -d 172.16.9.2 --dport 873 -m state --state NEW,ESTABLISHED -j ACCEPT


iptables -t filter -A INPUT -j LOG --log-prefix "[IN] DROP : "
iptables -t filter -A INPUT -j DROP

iptables -t filter -A FORWARD -j LOG --log-prefix "[FORW] DROP : "
iptables -t filter -A FORWARD -j DROP

iptables -t filter -A OUTPUT -j LOG --log-prefix "[OUT] DROP : "
iptables -t filter -A OUTPUT -j DROP
