#!/usr/bin/env python
#
# Author: St0rn (fabien.dromas@synetis.com)
# Organisation: Synetis
# Description:
#

from os import system
from scapy.all import *
from netfilterqueue import NetfilterQueue

# Set scapy verbose to 0
conf.verbose=0

# Global
bind=list()
i=1


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



################## Misci function ##################

# Get hackable network flow informations
# Evol:
# Lancer une attaque pour chaques types de flux reseau
#

def get_network_informations(p):
        # Find LLMNR flow
        if p.haslayer("LLMNRQuery"):
                print "LLMNR Query is present! Try to use responder :)"
        if p.haslayer("LLMNRResponse"):
                print "LLMNR Response is present! Try to use responder :)"
        # Find Spanning tree flow
        if p.haslayer("STP"):
                print "Spanning Tree Protocol is present! Try to STP Mangling is you can :)"
        # Find TCP flow
        if p.haslayer("TCP"):
                if p[TCP].dport==23:
                        print "%s is a Telnet Server! you can hijack this or steal credential :)"
                if p[TCP].dport==21:
                        print "%s is a FTP Server! you can hijack this or steal credential :)"
        # Find ICMP flow
        if p.haslayer("ICMP"):
                print "ICMP is used in this network! Try to use ICMP Redirect :)"

################## Bridge attack Func ##################

# Set iptable rule to use nfqueue

def set_table(chain, proto, bind):
        table="/sbin/iptables -I "+chain+" -p "+proto+" -j NFQUEUE --queue-num "+i
        system(table)
		return bind

# Bridge function to modify network flow

def bridge(func, chain, proto):
        queue=NetfilterQueue()
        queue.bind(set_table(chain, proto), func)
        try:
                print "[*] Attack in progress [*]\n"
                queue.run()
        except KeyboardInterrupt:
                pass

def exit():
 print "exit"

################## Define Bridge Func ##################


################ End define Bridge Func ################

if __name__ == "__main__":
        print "Let me talk about that"
