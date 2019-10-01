import netifaces
import os
import random
import threading

from scapy.all import *

from shared import constant, colors, pprint

# TODO: Change IP SRC/DST currently -> use default location 127... (lo)
class Server(threading.Thread):
    def __init__(self, port):
        threading.Thread.__init__(self)
        self.state = 'CLOSED'
        pprint.state(self.state)
        self.port = port
        os.system('iptables -t raw -A PREROUTING -p tcp --dport ' + str(self.port) + ' -j DROP')

    def run(self):
        self.state = 'LISTEN'
        pprint.state(self.state)

        filter_options = 'tcp and dst port ' + str(self.port) + ' and tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn'
        for iface in netifaces.interfaces():
            r = sniff(filter=filter_options, prn=self.connection(iface), count=1, iface=iface, timeout=10)
#            if r is not None and len(r) > 0:
#                self.connection(r, iface)

    def sendACK(self, data, ack):
        ackdata             = IP()/TCP()
        ackdata[TCP].sport  = self.port
        ackdata[TCP].dport  = data[TCP].sport
        ackdata[TCP].seq    = data[TCP].ack
        ackdata[TCP].ack    = ack
        ackdata[TCP].flags  = 'A'

        send(ackdata)

    def connection(self, iface):
       def connection_packet(request):
            conf.iface = iface
            self.state = 'SYN_RCVD'
            pprint.state(self.state)
        
            reply               = IP()/TCP()
            reply[TCP].sport    = self.port
            reply[TCP].dport    = request[0].sport
            reply[TCP].seq      = random.randint(1, 2048) # TODO: Check RFC
            reply[TCP].ack      = request[0].seq + 1
            reply[TCP].flags    = 'SA'

            answer = sr1(reply, timeout = 10)
            if answer is None:
                # TODO: handle error 
                print('Did not receive the ACK for finish the connexion')
            elif answer[TCP].flags == constant.ACK:
                self.communication() 
       return connection_packet

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
                # TODO: Create conf file with timeout option
                data = sniff(filter='tcp and dst port ' + str(self.port), count=1)
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

    def deconnection(self, data):
        self.state = 'CLOSE_WAIT'
        pprint.state(self.state)

       
        fin_pkt             = IP()/TCP()
        fin_pkt[TCP].sport  = self.port
        fin_pkt[TCP].dport  = data[0][TCP].sport
        fin_pkt[TCP].seq    = data[0][TCP].ack
        fin_pkt[TCP].ack    = data[0][TCP].seq + 1
        fin_pkt[TCP].flags  = 'F'

        ackreceived = sr1(fin_pkt, timeout=10)
        if self.isAck(ackreceived):
            self.state = 'LAST_ACK'
            pprint.state(self.state)
        else:
            pprint.error('Did not receive the ACK for finish the deconnection')
        self.state = 'CLOSED'
        pprint.state(self.state)
