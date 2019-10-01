from scapy.all import *
from shared import constant, colors, pprint
import random, time
import os

# TODO: manage iface (interface) for the moment I use lo
class Client:
    def __init__(self):
        self.state = 'CLOSED'
        pprint.state(self.state)
        os.system('iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP')
        self.packet             = IP()/TCP()
        self.packet[TCP].sport  = 2222
        self.packet[TCP].seq    = random.randint(1, 2048) # TODO: Check RFC

    def connection(self, host, port, iface):
        conf.iface = iface
        self.state = 'SYN_SENT'
        pprint.state(self.state)
        
        # Send SYN
        self.packet[IP].dst     = host
        self.packet[TCP].dport  = port
        self.packet[TCP].flags  = 'S'
        res = sr1(self.packet, timeout=10)
    
        if res is None:
            # TODO: handle error
            pprint.error('Cannot reach host {host} on port {port}'.format(host = self.packet[IP].dst, port = self.packet[TCP].dport))
        elif res[TCP].flags == constant.SYN | constant.ACK:
            self.checkAckValue(self.packet[TCP].seq + 1, res[TCP].ack)
            # Send ACK
            self.packet[TCP].seq    = res[TCP].ack
            self.packet[TCP].ack    = res[TCP].seq + 1
            self.packet[TCP].flags  = 'A'
            send(self.packet )

            # Start communication
            self.communication()

        else:
            self.deconnection()
            self.state = 'CLOSED'
            pprint.state(self.state)


    def communication(self):
        self.state = 'ESTABLISHED'
        pprint.state(self.state)
        try:
            while True:
                message = raw_input('Put the message you want to send: ')
                self.packet[TCP].flags    = 'PA'

                ack = sr1(self.packet/Raw(message), timeout=10)
                if len(ack) <= 0:
                    # TODO: Handle error
                     pprint.error('Did not received ack for data')
                elif self.checkAck(ack, message):
                    self.checkAckValue(ack[TCP].ack, self.packet[TCP].seq + len(message))
                    self.packet[TCP].seq = ack[TCP].ack
                    pprint.information('Message received')
        except KeyboardInterrupt:
            self.deconnection()
            self.state = 'CLOSED'
            pprint.state(self.state)

    def checkAck(self, ack, message):
        return(ack[TCP].flags == constant.ACK and ack[TCP].ack == (self.packet[TCP].seq + len(message)))

    def checkAckValue(self, ack_number, ack_expected):
        if (ack_number != ack_expected):
            pprint.error('This frame is suspicious : bad ACK number received')
            exit()
        return


    def deconnection(self):
        self.packet[TCP].flags  = 'F'
        fin = send(self.packet)
        self.state = 'FIN_WAIT_1'
        pprint.state(self.state)
        self.state = 'FIN_WAIT_2'
        pprint.state(self.state)
        data = sniff(count=2, timeout=10)
        self.packet[TCP].seq    = data[1][TCP].ack
        self.packet[TCP].ack    = data[1][TCP].seq + 1
        self.packet[TCP].flags  = 'A'
        time.sleep(2)
        send(self.packet)
        pprint.state(self.state)
        self.state = 'TIME_WAIT'
