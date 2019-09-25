from scapy.all import *
from shared import constant, colors, pprint
import random


# TODO: manage iface (interface) for the moment I use lo
class Client:
    def __init__(self):
        self.state = 'CLOSED'
        pprint.state(self.state)

        self.packet             = IP()/TCP()
        self.packet[TCP].sport  = 2222
        self.packet[TCP].seq    = random.randint(1, 2048) # TODO: Check RFC

    def connection(self, host, port):
        self.state = 'SYN_SENT'
        pprint.state(self.state)
        
        # Send SYN
        self.packet[IP].dst     = host
        self.packet[TCP].dport  = port
        self.packet[TCP].flags  = 'S'
        res = sr1(self.packet, iface='lo', timeout=10)
    
        if res is None:
            # TODO: handle error
            pprint.error('Cannot reach host {host} on port {port}'.format(host = self.packet[IP].dst, port = self.packet[TCP].dport))
        elif res[TCP].flags == constant.SYN | constant.ACK:
            # TODO: Check ACK value
            
            # Send ACK
            self.packet[TCP].seq    = res[TCP].ack
            self.packet[TCP].ack    = res[TCP].seq + 1
            self.packet[TCP].flags  = 'A'
            send(self.packet, iface='lo' )

            # Start communication
            self.communication()

        else:
            # TODO: Deconnection
            print('Close')


    def communication(self):
        self.state = 'ESTABLISHED'
        pprint.state(self.state)
        try:
            while True:
                message = raw_input('Put the message you want to send: ')
                self.packet[TCP].flags    = 'PA'

                ack = sr1(self.packet/Raw(message), iface='lo', timeout=10)
                if len(ack) <= 0:
                    # TODO: Handle error
                     pprint.error('Did not received ack for data')
                elif ack[TCP].flags == constant.ACK and ack[TCP].ack == (self.packet[TCP].seq + len(message)):
                    self.packet[TCP].seq = ack[TCP].ack
                    pprint.information('Message received')
        except KeyboardInterrupt:
            self.packet[TCP].flags  = 'F'
            fin = sr1(self.packet, iface='lo', timeout=10)
            if len(ack) <= 0:
                pprint.error('Did not received ack for data')
            elif ack[TCP].flags == constant.ACK | constant.SYN:
                pprint.information('ack and syn received')
                data = sniff(filter='dst port 2222', count=1, iface="lo", timeout=10)
                if data and data[0][TCP].flags == constant.FIN:
                    pprint.information('fin received')
                    data = sniff(filter='dst port 2222', count=1, iface="lo", timeout=10)
                    data[0][TCP].ack    = data[0][TCP].seq + 1
                    data[0][TCP].flags  = 'A'
                    send(data[0], iface='lo')
            # TODO: Close connexion
            print('Close')

