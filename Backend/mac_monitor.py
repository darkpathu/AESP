# mac_monitor.py
from scapy.all import sniff, ARP, Ether, srp
from threading import Thread
import time
import os

INTERFACE = "enp0s8"
NETWORK = "192.168.29.0/24"   # adjust if needed

mac_table = {}  # ip -> {mac, last_seen}

def update(ip, mac):
    mac_table[ip] = {
        "mac": mac,
        "last_seen": int(time.time())
    }

# ---------------------------
# Passive ARP sniffer
# ---------------------------
def arp_handler(pkt):
    if pkt.haslayer(ARP):
        if pkt[ARP].psrc and pkt[ARP].hwsrc:
            update(pkt[ARP].psrc, pkt[ARP].hwsrc)

def start_arp_sniffer():
    sniff(
        iface=INTERFACE,
        filter="arp",
        prn=arp_handler,
        store=False
    )

# ---------------------------
# Active ARP discovery (FORCE MAC VISIBILITY)
# ---------------------------
def arp_scan():
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=NETWORK)
    ans, _ = srp(pkt, iface=INTERFACE, timeout=2, verbose=False)

    for _, rcv in ans:
        update(rcv.psrc, rcv.hwsrc)

# ---------------------------
# Public start function
# ---------------------------
def start():
    print("[MAC] Running initial ARP scan")
    arp_scan()

    print("[MAC] Starting ARP sniffer")
    t = Thread(target=start_arp_sniffer, daemon=True)
    t.start()
