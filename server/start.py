from scapy.all import *
import random
from shared import constant, colors

def start():
    r = sniff(filter="dst port 5555", count=1, iface="lo")
    if r[0][TCP].flags == constant.SYN:
        print(colors.OKGREEN + '[*]\tSYN_RCVD' + colors.ENDC)
        # TODO: Handle client connexion
        reply = IP()/TCP()
       
        reply[TCP].sport = r[0].dport
        reply[TCP].dport = r[0].sport
        reply[TCP].seq = random.randint(1, 2048)
        reply[TCP].ack = r[0].seq + 1
        reply[TCP].flags = 'SA'
       
        answer = sr1(reply, iface = "lo", timeout = 10)
        if answer is None:
            # TODO: handle error 
            print('Did not receive the ACK for finish the connexion')
        elif answer[TCP].flags == constant.ACK:
            print(colors.OKGREEN + '[*]\tESTABLISHED' + colors.ENDC)
            # TODO: Check ack and seq value
            # TODO: Connexion established
            try:
                print(colors.OKBLUE + '...\tMESSAGE RECEIVED' + colors.ENDC)
                nb_msg = 0
                while True:
                    # TODO: Check ack/seq and flags and reply a ACK
                    r = sniff(filter='dst port 5555', count=1, iface="lo")
                    if r and Raw in r[0] and r[0][TCP].flags == constant.PSH | constant.ACK:
                        nb_msg += 1
                        print('[' + str(nb_msg) + ']: ' + r[0][Raw].load)
            except KeyboardInterrupt:
                print('Total number of message receive: ' + str(nb_msg))
                # TODO: Close connexion
