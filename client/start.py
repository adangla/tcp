from scapy.all import *
from shared import constant, colors 
import random

# TODO: manage iface (interface) for the moment I use lo

SYNACK = constant.SYN | constant.ACK

def client_connect(host, port):
    print(colors.OKGREEN + '[*]\tSYN_SENT' + colors.ENDC)
    packet = IP()/TCP()
    
    packet[IP].dst      = host
    packet[TCP].sport   = 2222
    packet[TCP].dport   = port
    packet[TCP].seq     = random.randint(1, 2048) # TODO: Check RFC
    packet[TCP].flags   = 'S'
    
    res = sr1(packet, iface = 'lo', timeout = 10)

    if res is None:
        # TODO: handle error
        print('Cannot reach host {host} on port {port}'.format(host = host, port = port))
    elif res[TCP].flags == SYNACK:
        # TODO: Manage connexion - Connexion success
        print(colors.OKGREEN + '[*]\tESTABLISHED' + colors.ENDC)
        reply = IP()/TCP()

        reply[TCP].sport    = res[TCP].dport
        reply[TCP].dport    = res[TCP].sport
        reply[TCP].seq      = res[TCP].ack + 1
        reply[TCP].ack      = res[TCP].seq + 1
        reply[TCP].flags    = 'A'
        # TODO: Check seq and ack 
        send(reply, iface = 'lo')
        # TODO: Manage send information
        try:
            while True:
                message = raw_input('Put the message you want to send: ')
                com = IP()/TCP()/Raw(message)
                com[TCP].sport    = reply[TCP].sport
                com[TCP].dport    = reply[TCP].dport
                com[TCP].seq      = reply[TCP].seq + 1 
                com[TCP].ack      = reply[TCP].ack  
                com[TCP].flags    = 'PA'
                
                ack = sr1(com, iface='lo', timeout=10)
                if ack is None:
                    # TODO: Handle error
                    print('Did not received ack for data')
                elif ack[TCP].flags == constant.ACK and ack[TCP].ack == (com[TCP].seq + len(message)):
                    print(colors.OKBLUE + '...\tMessage received' + colors.ENDC)
        except KeyboardInterrupt:
            # TODO: Close connexion
            print('Close')
    else:
        # TODO: Close connexion
        print('Close')
