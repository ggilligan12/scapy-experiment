from scapy.all import *
from pprint import pprint

# Briefly trying to mess around with using scapy to sniff 802.11 frames
# Proved difficult. Needs to be in monitor mode, easy enough, however on
# my host this gets immediately turned back to managed mode. Unsure what
# I was fighting against. One to look into more another day.

def GrabWLANPkts(pkt):
  if pkt.haslayer('Dot11'):
    print(pkt.summary())

# The following has proved a pretty handy resource:
# http://bowdennetworks.co.uk/downloads/Scapy%20802.11%20Cheat%20Sheet%20v0.1.pdf
def sniffing():
  pkts = sniff(iface='wlp0s20f3',
               count=1000,
               monitor=True,
               prn=GrabWLANPkts)