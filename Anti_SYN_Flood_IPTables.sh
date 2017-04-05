#!/bin/sh
# A simple shell to build a Firewall anti SYN Flood
# Under CentOS, Fedora and RHEL / Redhat Enterprise Linux
# servers.
# ----------------------------------------------------------------------------
# Written by LongVNIT 
# (c) 2009 lifeLinux under GNU GPL v2.0+

IPT="iptables"
MODPROBE="modprobe"
IF="eth0"
IP="192.168.1.112"
PORT="22 80 443"
CHECK_TIME=60
BAN_TIME=120
HITCOUNT=10
MOD="ip_tables ip_conntrack iptable_filter ipt_state"

# Load Module
for M in $MOD
do
	$MODPROBE $M
done

# Flush IPTables
$IPT -F
$IPT -X
$IPT -P INPUT DROP
$IPT -P OUTPUT ACCEPT
$IPT -P FORWARD DROP

# Define SYN_CHECK CHAIN
$IPT -N SYN_CHECK

# BAN IP IN 
$IPT -t mangle -A PREROUTING -p TCP -d $IP -m recent --name SYN --update --seconds $BAN_TIME --hitcount $HITCOUNT -j DROP

# DROP INVALID PACKET
$IPT -A INPUT -p TCP ! --syn -m state --state NEW -j DROP

# ACCPET ALL ESTABLISHED PACKET
$IPT -A INPUT -i $IF -m state --state ESTABLISHED -j ACCEPT

# CHECK SYN
for P in $PORT
do
	$IPT -A INPUT -i $IF -p TCP -d $IP --dport $P -m state --state NEW -j SYN_CHECK
done

# ACCEPT
for P in $PORT
do
	$IPT -A INPUT -i $IF -p TCP -d $IP --dport $P -m state --state NEW -j ACCEPT
done

# SYN_CHECK CHAIN
$IPT -A SYN_CHECK -m recent --set --name SYN
$IPT -A SYN_CHECK -m recent --name SYN --update --seconds $CHECK_TIME --hitcount $HITCOUNT -j LOG --log-level 5 --log-prefix "SYN_FLOOD"
$IPT -A SYN_CHECK -m recent --name SYN --update --seconds $CHECK_TIME --hitcount $HITCOUNT -j DROP