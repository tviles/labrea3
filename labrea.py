import random, mysql.connector, datetime
from scapy.all import *

version = 0.3

dbini = {}
with open("labrea.ini") as ini:
  for line in ini:
    (k, v) = line.rstrip().split("=")
    dbini[k] = v

mydb = mysql.connector.connect(
  host=dbini["host"],
  user=dbini["user"],
  password=dbini["password"],
  database=dbini["database"]
  )

mycursor = mydb.cursor()


def determineIPAddress():
  localIPs = [get_if_addr(i) for i in get_if_list()]
  interface = 'eth0'

  if (sys.platform == 'darwin'):
      interface = 'en0'
  if(sys.platform == 'linux'):
      interface = 'eth0'
  # Assume the last one is the IP to send from.
  return localIPs[get_if_list().index(interface)]


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
  logging(pkt)


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
  logging(pkt)


def logging(pkt):
  if Raw in pkt:
    sql = "INSERT INTO packets (`timestamp`, `ether.dst`, `ether.src`, \
    `ether.type`, `ip.version`, `ip.ihl`, `ip.tos`, `ip.len`, `ip.id`, `ip.flags`, \
    `ip.frag`, `ip.ttl`, `ip.proto`, `ip.chksum`, `ip.src`, `ip.dst`, `ip.options`, \
    `tcp.sport`, `tcp.dport`, `tcp.seq`, `tcp.ack`, `tcp.dataofs`, `tcp.reserved`, \
    `tcp.flags`, `tcp.window`, `tcp.chksum`, `tcp.urgptr`, `tcp.options`, \
    `raw.load`) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, \
    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
    val = (datetime.now().strftime('%Y-%m-%d %H:%M:%S'), pkt[Ether].dst, 
    pkt[Ether].src, pkt[Ether].type, pkt[IP].version, pkt[IP].ihl, pkt[IP].tos, 
    pkt[IP].len, pkt[IP].id, str(pkt[IP].flags), pkt[IP].frag, pkt[IP].ttl, 
    pkt[IP].proto, pkt[IP].chksum, pkt[IP].src, pkt[IP].dst, str(pkt[IP].options), 
    pkt[TCP].sport, pkt[TCP].dport, pkt[TCP].seq, pkt[TCP].ack, pkt[TCP].dataofs, 
    pkt[TCP].reserved, str(pkt[TCP].flags), pkt[TCP].window, pkt[TCP].chksum, 
    pkt[TCP].urgptr, str(pkt[TCP].options), str(pkt[Raw].load))
  else:
    sql = "INSERT INTO packets (`timestamp`, `ether.dst`, `ether.src`, \
    `ether.type`, `ip.version`, `ip.ihl`, `ip.tos`, `ip.len`, `ip.id`, `ip.flags`, \
    `ip.frag`, `ip.ttl`, `ip.proto`, `ip.chksum`, `ip.src`, `ip.dst`, `ip.options`, \
    `tcp.sport`, `tcp.dport`, `tcp.seq`, `tcp.ack`, `tcp.dataofs`, `tcp.reserved`, \
    `tcp.flags`, `tcp.window`, `tcp.chksum`, `tcp.urgptr`, `tcp.options`) VALUES \
    (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, \
    %s, %s, %s, %s, %s, %s, %s, %s, %s)"
    val = (datetime.now().strftime('%Y-%m-%d %H:%M:%S'), pkt[Ether].dst, 
    pkt[Ether].src, pkt[Ether].type, pkt[IP].version, pkt[IP].ihl, pkt[IP].tos, 
    pkt[IP].len, pkt[IP].id, str(pkt[IP].flags), pkt[IP].frag, pkt[IP].ttl, 
    pkt[IP].proto, pkt[IP].chksum, pkt[IP].src, pkt[IP].dst, str(pkt[IP].options), 
    pkt[TCP].sport, pkt[TCP].dport, pkt[TCP].seq, pkt[TCP].ack, pkt[TCP].dataofs, 
    pkt[TCP].reserved, str(pkt[TCP].flags), pkt[TCP].window, pkt[TCP].chksum, 
    pkt[TCP].urgptr, str(pkt[TCP].options))
  mycursor.execute(sql, val)
  mydb.commit()


def packet_received(pkt):
  #pkt.show()
  if IP in pkt:
    if pkt[IP].src != sourceIP and pkt[IP].src != dbini["host"]:
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
