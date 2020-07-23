import sys
import random
from scapy.all import *
from scapy.config import conf
conf.use_pcap = True

version = 0.2

def determineIPAddress():
  localIPs = [get_if_addr(i) for i in get_if_list()]
  # Assume the last one is the IP to send from.
  return localIPs[-1]

def spoofSYNACK(pkt):
  # Spoof the SYN ACK with a small window
  if (pkt[IP].src in answered and answered[pkt[IP].src] == pkt[IP].dport):
    return
  response = IP()/TCP()
  response[IP].src = pkt[IP].dst  # Since IP also has a .src, we have to qualify
  response[IP].dst = pkt[IP].src
  response[TCP].sport = pkt[TCP].dport
  response[TCP].dport = pkt[TCP].sport
  response[TCP].seq = random.randint(1,2400000000)
  response[TCP].ack = pkt[TCP].seq + 1
  response[TCP].window = random.randint(1,100)
  response[TCP].flags = 0x12
  send(response, verbose = 0)
  answered[response[IP].dst] = response[TCP].sport
  print("SYNACK spoofing TCP {0} to {1}".format(pkt[TCP].dport,pkt[IP].src))

def spoofACK(pkt):
  # ACK anything that gets sent back with a zero window
  response = IP()/TCP()
  response[IP].src = pkt[IP].dst
  response[IP].dst = pkt[IP].src
  response[TCP].sport = pkt[TCP].dport
  response[TCP].dport = pkt[TCP].sport
  response[TCP].seq = pkt[TCP].ack
  response[TCP].ack = pkt[TCP].seq
  if Raw in pkt:
    if(len(pkt[Raw].load) > 1):  # The window probe is 1 byte
      response[TCP].ack = pkt[TCP].seq + len(pkt[Raw].load)
  response[TCP].window = 0
  response[TCP].flags = 0x10
  send(response, verbose = 0)
  print("ACK spoofing TCP {0} to {1}".format(pkt[TCP].dport,pkt[IP].src))

def packet_received(pkt):
  #pkt.show()
  if IP in pkt:
    if pkt[IP].src != sourceIP:
      if TCP in pkt and (pkt[TCP].flags & 0x3f) == 0x02:
        spoofSYNACK(pkt)
      if TCP in pkt and (pkt[TCP].flags & 0x12) == 0x10:
        spoofACK(pkt)

answered = dict()
sourceIP = determineIPAddress()
print("Scapified LaBrea Modified to Honeypot")
print("Version {0} - Modified Copyright Grant Priewe & Tyler Viles".format(version))
print("Original Copyright David Hoelzer / Enclave Forensics, Inc.")
print("Using {0} as the source IP.  If this is wrong, edit the code.".format(sourceIP))
sniff(prn=packet_received, store=0)