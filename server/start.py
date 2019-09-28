from scapy.all import *
import random
from shared import constant, colors, pprint

# TODO: Change IP SRC/DST currently -> use default location 127... (lo)
class Server:
    def __init__(self, port):
        self.state = 'CLOSED'
        pprint.state(self.state)
        self.port = port

    def start(self):
        self.state = 'LISTEN'
        pprint.state(self.state)

        r = sniff(filter="dst port " + str(self.port), count=1, iface="lo")
        if r[0][TCP].flags == constant.SYN:
            self.connection(r)

    def sendACK(self, data, ack):
        ackdata             = IP()/TCP()
        ackdata[TCP].sport  = self.port
        ackdata[TCP].dport  = data[TCP].sport
        ackdata[TCP].seq    = data[TCP].ack
        ackdata[TCP].ack    = ack
        ackdata[TCP].flags  = 'A'

        send(ackdata, iface='lo')

    def connection(self, request):
        self.state = 'SYN_RCVD'
        pprint.state(self.state)

        reply               = IP()/TCP()
        reply[TCP].sport    = self.port
        reply[TCP].dport    = request[0].sport
        reply[TCP].seq      = random.randint(1, 2048) # TODO: Check RFC
        reply[TCP].ack      = request[0].seq + 1
        reply[TCP].flags    = 'SA'

        answer = sr1(reply, iface = "lo", timeout = 10)
        if answer is None:
            # TODO: handle error 
            print('Did not receive the ACK for finish the connexion')
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
                # TODO: Create conf file with timeout option
                data = sniff(filter='dst port 5555', count=1, iface="lo", timeout=10)
                if len(data) <= 0:
                    # TODO: Handle timeout
                    print(colors.FAIL + '[!]\tTIMEOUT' + colors.ENDC)
                    # TODO: Close connexion
                    break
                if self.getFin(data):
                    self.sendACK(data[0], data[0][TCP].seq + 1)
                    self.deconnection(data)
                    break
                elif self.checkData(data):
                    nb_msg += 1
                    print(colors.BOLD + colors.WARNING + '[' + str(nb_msg) + ']: ' + data[0][Raw].load + colors.ENDC)

                    # Send ACK
                    ackvalue = data[0][TCP].seq + len(data[0][Raw].load)
                    self.sendACK(data[0], ackvalue)
        except KeyboardInterrupt:
           print('Total number of message receive: ' + str(nb_msg))
              # TODO: Close connexion

    def getFin(self, data):
        return (data and data[0][TCP].flags == constant.FIN)

    def checkAck(self, data):
        return (data and data[0][TCP].flags == constant.ACK)

    def checkData(self, data):
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

        ackreceived = sr1(fin_pkt, iface='lo', timeout=10)
        if self.checkAck(ackreceived):
            self.state = 'LAST_ACK'
            pprint.state(self.state)
        else:
            pprint.error('Did not receive the ACK for finish the deconnection')
        self.state = 'CLOSED'
        pprint.state(self.state)
