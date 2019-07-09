from scapy.all import sr1, IP, TCP

SYN = 0x02
ACK = 0x10
SYNACK = SYN | ACK

def client_connect(host, port):
    packet = IP(dst = host)/TCP(dport = port, flags = 'S')
    res = sr1(packet, timeout = 1)

    if res is None:
        print('TODO:\thandle error\n\tCannot reach host {host} on port {port}'.format(host = host, port = port))
    elif res[TCP].flags == SYNACK:
        print('TODO:\tManage connexion\n\tConnexion success')
    else:
        print('TODO:\tClose connexion')
