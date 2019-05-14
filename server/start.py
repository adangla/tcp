from scapy.all import *

SYN = 0x02

if __name__ == "__main__":
    r = sniff(filter="dst port 5555", count=1)
    if r[0][TCP].flags == SYN:
        print("TODO:\tHandle client connexion")
