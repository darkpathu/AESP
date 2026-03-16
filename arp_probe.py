from scapy.all import ARP, Ether, sendp
import ipaddress
import time

def arp_scan(iface="enp0s3", subnet="192.168.29.0/24"):
    for ip in ipaddress.IPv4Network(subnet):
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(ip))
        sendp(pkt, iface=iface, verbose=False)
        time.sleep(0.01)
