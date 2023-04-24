#!/bin/sh

define_chain()
{
    iptables -N white-list
    iptables -N chain-lock
    iptables -A chain-lock -j white-list
    iptables -I FORWARD 1 -j chain-lock
}

if [ $1 = "lock" ];
then
    echo "LOCK MODE..."
    define_chain

    iptables -A white-list -p udp --dport 53 -j ACCEPT
    iptables -A white-list -p udp --sport 53 -j ACCEPT

    # Lock machine from internet access
    iptables -A chain-lock -j DROP

elif [ $1 = "unlock" ];
then
    echo "UNLOCK MODE..."
    iptables -D FORWARD -j chain-lock
    iptables -D chain-lock -j white-list
    iptables -F white-list
    iptables -F chain-lock
    iptables -X white-list
    iptables -X chain-lock
fi