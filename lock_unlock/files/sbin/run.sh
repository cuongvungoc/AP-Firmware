#!/bin/sh

url="vhtont.sytes.net"

define_chain()
{
    # Create chain_lock and white_list
    iptables -N white_list
    iptables -N chain_lock
    iptables -N web_ap_block
    # Add white_list to chain_lock, chain_lock to FORWARD and web_ap_block to INPUT
    iptables -A chain_lock -j white_list
    iptables -I FORWARD 1 -j chain_lock
    iptables -I INPUT 1 -j web_ap_block
}

default_lock()
{
    # Accept udp port to get DNS query and response
    iptables -A white_list -p udp --dport 53 -j ACCEPT
    iptables -A white_list -p udp --sport 53 -j ACCEPT
    # Lock machine from internet access
    iptables -A chain_lock -j DROP
}

block_web_access()
{
    #  Get listen http in 0.0.0.0:80 [::]:80 format
    listen_http=$(uci get uhttpd.main.listen_http)
    # Get http port: 80
    http_port=${listen_http##*:} 
    iptables -A web_ap_block -p tcp --dport $http_port -j DROP
    # echo $http_port

    # Same as http
    listen_https=$(uci get uhttpd.main.listen_https)
    https_port=${listen_https##*:}
    # echo $https_port
    iptables -A web_ap_block -p tcp --dport $https_port -j DROP
}

flush_rules()
{
    iptables -D FORWARD -j chain_lock
    iptables -D chain_lock -j white_list
    iptables -D INPUT -j web_ap_block
    iptables -F white_list
    iptables -F chain_lock
    iptables -F web_ap_block
    iptables -X white_list
    iptables -X chain_lock
    iptables -X web_ap_block
}

if [ $1 = "lock" ];
then
    echo "LOCK MODE..."
    define_chain
    default_lock
    block_web_access
    # Start DNS parser daemon
    lock_unlock &   
    # nslookup $url > /dev/null 2>&1
elif [ $1 = "unlock" ];
then
    echo "UNLOCK MODE..."
    flush_rules
    # Kill DNS parser daemon
    killall lock_unlock     
fi