from scapy.all import sr1, IP, TCP

SYN = 0x02
ACK = 0x10
SYNACK = SYN | ACK

def client_connect(host, port):
    packet = IP(dst = host)/TCP(dport = port, flags = 'S')
    res = sr1(packet, timeout = 1)

    if res is None:
        print(f'TODO: handle error\nCannot reach host {host} on port {port}')
    elif res[TCP].flags == SYNACK:
        print('TODO: Manage connexion\nConnexion success')
    else:
        print('TODO: Close connexion')
