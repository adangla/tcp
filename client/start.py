from scapy.all import sr1, IP, TCP
from shared import constant 

SYNACK = constant.SYN | constant.ACK

def client_connect(host, port):
    packet = IP()/TCP()
    
    packet[IP].dst      = host
    packet[TCP].sport   = 2222
    packet[TCP].dport   = port
    packet[TCP].seq     = 1000
    packet[TCP].flags   = 'S'
    
    res = sr1(packet, iface = 'lo', timeout = 10)

    if res is None:
        print('TODO:\thandle error\n\tCannot reach host {host} on port {port}'.format(host = host, port = port))
    elif res[TCP].flags == SYNACK:
        print('TODO:\tManage connexion\n\tConnexion success')
    else:
        print('TODO:\tClose connexion')
