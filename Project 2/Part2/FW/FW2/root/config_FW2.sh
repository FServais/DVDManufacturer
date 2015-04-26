iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

iptables -t nat -A POSTROUTING -j LOG --log-prefix "[MASQ] "
iptables -t nat -A POSTROUTING -j MASQUERADE -o eth0 -s 172.16.6.0/24
iptables -t nat -A POSTROUTING -j MASQUERADE -o eth0 -s 172.16.5.0/24

iptables -t nat -A POSTROUTING -j LOG --log-prefix "[DNAT] "
iptables -t nat -A PREROUTING -j DNAT -p tcp -d 172.14.5.2 --dport 22 --to-destination 172.16.6.3
iptables -t nat -A PREROUTING -j DNAT -p tcp -d 172.14.5.2 --dport 80 --to-destination 172.16.6.4
iptables -t nat -A PREROUTING -j DNAT -p tcp -d 172.14.5.2 --dport 443 --to-destination 172.16.6.4
iptables -t nat -A PREROUTING -j DNAT -p tcp -d 172.14.5.2 --dport 53 --to-destination 172.16.6.5
iptables -t nat -A PREROUTING -j DNAT -p tcp -d 172.14.5.2 --dport 3128 --to-destination 172.16.6.4


#filter
#zone 6 incoming
iptables -t filter -A FORWARD -p udp -s 172.16.5.2 --sport 67 -d 172.16.6.2 --dport 67  -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -t filter -A FORWARD -p udp -s 172.16.5.2 --sport 68 -d 172.16.6.2 --dport 67  -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -t filter -A FORWARD -p tcp -d 172.16.6.3 --dport 22 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -t filter -A FORWARD -p tcp -s 172.16.5.0/24 -d 172.16.6.4 --dport 3128 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -t filter -A FORWARD -p tcp -s 172.16.5.0/24 -d 172.16.6.4 --dport 80 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -t filter -A FORWARD -p tcp -s 172.16.5.0/24 -d 172.16.6.4 --dport 443 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -t filter -A FORWARD -p tcp -s 172.14.6.2 -d 172.16.6.4 --dport 80 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -t filter -A FORWARD -p tcp -s 172.14.6.2 -d 172.16.6.4 --dport 443 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -t filter -A FORWARD -p udp -s 172.16.5.0/24 -d 172.16.6.5 --dport 53 -m state --state NEW,ESTABLISHED -j ACCEPT
#zone 6 outgoing
iptables -t filter -A FORWARD -p tcp -s 172.16.6.3 --dport 22 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -t filter -A FORWARD -p tcp -s 172.16.6.4 --dport 80 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -t filter -A FORWARD -p tcp -s 172.16.6.4 --dport 443 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -t filter -A FORWARD -p udp -s 172.16.6.5 -d 172.14.5.3 --dport 53 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -t filter -A FORWARD -p udp -s 172.16.6.5 -d 208.67.222.222 --dport 53 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -t filter -A FORWARD -s 172.16.6.3 -d 172.14.6.2 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -t filter -A FORWARD -s 172.16.6.4 -d 172.14.6.2 -m state --state NEW,ESTABLISHED -j ACCEPT

#zone 5 outgoing
iptables -t filter -A FORWARD -p tcp -s 172.16.5.0/24 -d 172.14.6.3 --dport 80 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -t filter -A FORWARD -p tcp -s 172.16.5.0/24 -d 172.14.6.3 --dport 443 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -t filter -A FORWARD -p tcp -s 172.16.5.0/24 -d 172.14.6.3 --dport 21 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -t filter -A FORWARD -s 172.16.5.0/24 -d 172.14.6.2 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -t filter -A FORWARD -s 172.16.5.0/24 -d 172.14.7.2 --dport 25 -m state --state NEW,ESTABLISHED -j ACCEPT


iptables -t filter -A INPUT -j LOG --log-prefix "[IN] DROP : "
iptables -t filter -A INPUT -j DROP

iptables -t filter -A FORWARD -j LOG --log-prefix "[FORW] DROP : "
iptables -t filter -A FORWARD -j DROP

iptables -t filter -A OUTPUT -j LOG --log-prefix "[OUT] DROP : "
iptables -t filter -A OUTPUT -j DROP#
