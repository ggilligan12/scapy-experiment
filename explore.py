from scapy.all import *
from pprint import pprint

# PCAP of some traffic on my home WLAN
file = rdpcap("scapy.pcapng")

# Print the first packet
print(len(file))
# Summarise packet
print(file[0].summary())
# Exploring available attributes and methods
pprint(dir(file[0].layers()[1]))
pprint(file[0].layers()[1].src.fld.__str__())