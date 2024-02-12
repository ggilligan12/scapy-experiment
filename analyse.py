from scapy.all import *

file = rdpcap("scapy.pcapng")

# Print the first packet
print(file[0])