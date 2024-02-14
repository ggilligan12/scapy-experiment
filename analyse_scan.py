from scapy.all import *
from pprint import pprint

# Went and grabbed a pcap file to play with from https://www.netresec.com/?page=PcapFiles
# as you might guess it was an nmap Xmas tree scan.
# Most obvious thing to was to get frequencies of source and destination IPs and ports,
# since this is what confirms beyond all shadow of a doubt what the contents of the PCAP are
file = rdpcap("SCAN_nmap_XMAS_TREE_SCAN_EvilFingers.pcap")

def getSourceIPs(file):
  IPs = [pkt['IP'].src for pkt in file if pkt.haslayer('IP')]
  return {ip : IPs.count(ip) for ip in IPs}

def getDestIPs(file):
  IPs = [pkt['IP'].dst for pkt in file if pkt.haslayer('IP')]
  return {ip : IPs.count(ip) for ip in IPs}

def getSourcePorts(file):
  ports = [pkt['TCP'].sport for pkt in file if pkt.haslayer('TCP')]
  return {port : ports.count(port) for port in ports}

def getDestPorts(file):
  ports = [pkt['TCP'].dport for pkt in file if pkt.haslayer('TCP')]
  return {port : ports.count(port) for port in ports}

def summariseFirstTen(file):
  for i in range(40):
    print(file[i].summary())


pprint(getSourceIPs(file))
pprint(getDestIPs(file))
pprint(getSourcePorts(file))
pprint(getDestPorts(file))
summariseFirstTen(file)