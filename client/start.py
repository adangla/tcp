from scapy.all import send, sr1, IP, TCP
from shared import constant, colors 


# TODO: manage iface (interface) for the moment I use lo

SYNACK = constant.SYN | constant.ACK

def client_connect(host, port):
    print(colors.OKGREEN + '[*]\tSYN_SENT' + colors.ENDC)
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
        print(colors.OKGREEN + '[*]\tESTABLISHED' + colors.ENDC)
        reply = IP()/TCP()

        reply[TCP].sport    = res[TCP].dport
        reply[TCP].dport    = res[TCP].sport
        reply[TCP].seq      = res[TCP].ack + 1
        reply[TCP].ack      = res[TCP].seq + 1
        reply[TCP].flags    = 'A'
        
        send(reply, iface = 'lo')
        print('TODO:\tManage send information')

    else:
        print('TODO:\tClose connexion')
