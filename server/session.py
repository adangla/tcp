import random
from scapy.all import *

from shared import constant, colors, pprint

class Session:
    def __init__(self, iface, request):
        self.state  = ''
        self.iface  = iface
        self.port   = request[TCP].dport
        
        self.packet             = IP()/TCP()
        self.packet[IP].src     = request[IP].dst
        self.packet[IP].dst     = request[IP].src
        self.packet[TCP].sport  = request[TCP].dport
        self.packet[TCP].dport  = request[TCP].sport
        self.packet[TCP].seq    = random.randint(1, 2048) # TODO: Check RFC

    def getInterface(self):
        return self.iface

    def getState(self):
        return self.state

    def sendACK(self, data, ack):
        self.packet[TCP].seq    = data[TCP].ack
        self.packet[TCP].ack    = ack
        self.packet[TCP].flags  = 'A'

        send(self.packet, iface=self.iface)

    def connection(self, request):
        self.state = 'SYN_RCVD'
        pprint.state(self.state)
    
        self.packet[TCP].ack      = request[0].seq + 1
        self.packet[TCP].flags    = 'SA'
    
        answer = sr1(self.packet, iface=self.iface, retry=5, timeout = 10)
        if answer is None:
            # TODO: handle error 
            pprint.error('Did not receive the ACK for finish the connexion')
        elif answer[TCP].flags == constant.ACK:
            self.communication() 

    def communication(self):
        self.state = 'ESTABLISHED'
        pprint.state(self.state)

        # TODO: Check ack and seq value
        # TODO: Connexion established
        try:
            nb_msg = 0
            while True:
                data = None
                # TODO: Check ack/seq and flags and reply a ACK
                data = sniff(filter='tcp and dst port ' + str(self.port), count=1, iface=self.iface)
                if data and len(data) <= 0:
                    # TODO: Handle timeout
                    print(colors.FAIL + '[!]\tTIMEOUT' + colors.ENDC)
                    # TODO: Close connexion
                    break
                if self.isFin(data):
                    self.sendACK(data[0], data[0][TCP].seq + 1)
                    self.deconnection(data)
                    break
                elif self.containsMessage(data):
                    nb_msg += 1
                    print(colors.BOLD + colors.WARNING + '[' + str(nb_msg) + ']: ' + data[0][Raw].load + colors.ENDC)

                    # Send ACK
                    ackvalue = data[0][TCP].seq + len(data[0][Raw].load)
                    self.sendACK(data[0], ackvalue)
        except KeyboardInterrupt:
            print('Total number of message receive: ' + str(nb_msg))
              # TODO: Close connexion

    def isFin(self, data):
        return (data and data[0][TCP].flags == constant.FIN)

    def isAck(self, data):
        return (data and data[0][TCP].flags == constant.ACK)

    def containsMessage(self, data):
        return (data and Raw in data[0] and data[0][TCP].flags == constant.PSH | constant.ACK)

    def checkAckValue(self, ack_number, ack_expected):
        if (ack_number != ack_expected):
            pprint.error('This frame is suspicious : bad ACK number received')
            exit()
        return

    def deconnection(self, data):
        self.state = 'CLOSE_WAIT'
        pprint.state(self.state)


        self.packet[TCP].seq    = data[0][TCP].ack
        self.packet[TCP].ack    = data[0][TCP].seq + 1
        self.packet[TCP].flags  = 'F'

        ackreceived = sr1(self.packet, timeout=10, iface=self.iface)
        if self.isAck(ackreceived):
            self.checkAckValue(ackreceived[TCP].ack, self.packet[TCP].seq + 1)
            self.state = 'LAST_ACK'
            pprint.state(self.state)
        else:
            pprint.error('Did not receive the ACK for finish the deconnection')
        self.state = 'CLOSED'
        pprint.state(self.state)
