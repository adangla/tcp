from scapy.all import *
import random
from shared import constant

def start():
    r = sniff(filter="dst port 5555", count=1, iface="lo")
    if r[0][TCP].flags == constant.SYN:
        print("TODO:\tHandle client connexion")
        reply = IP()/TCP()
       
        reply[TCP].sport = r[0].dport
        reply[TCP].dport = r[0].sport
        reply[TCP].seq = random.randint(1, 255)
        reply[TCP].ack = r[0].seq + 1
        reply[TCP].flags = 'SA'
       
        answer = sr1(reply, iface = "lo", timeout = 10)
        if answer is None:
            print('TODO:\thandle error\n\tDid not receive the ACK for finish the connexion')
        elif answer[TCP].flags == constant.ACK:
            print("TODO:\tCheck ack and seq value")
            print('TODO:\tConnexion established')

