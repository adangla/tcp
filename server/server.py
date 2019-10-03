import netifaces
import os
import random
import time

from scapy.all import *

from session import Session
from shared import constant, colors, pprint

class Server:
    def __init__(self, port):
        self.state = 'CLOSED'
        pprint.state(self.state)
        self.port = port
        self.sniffers = []
        self.sessions = []
        os.system('iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP')
    
    def start(self):
        self.state = 'LISTEN'
        pprint.state(self.state)

        try :
            filter_options = 'tcp and dst port ' + str(self.port) + ' and tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn'
            for iface in netifaces.interfaces():
                sniffer = AsyncSniffer(filter=filter_options, prn=self.newSession(iface), count=1, iface=iface)
                sniffer.start()
                self.sniffers.append(sniffer)
                pprint.information('sniffing on ' + iface)

            while len(self.sessions) <= 0:
                time.sleep(1)

            while True:
                for session in self.sessions:
                    if session.getState() == 'ESTABLISHED':
                        session_iface = session.getInterface()
                        sniffer = AsyncSniffer(filter=filter_options, prn=self.newSession(session_iface), count=1, iface=session_iface)
                        sniffer.start()
                        pprint.information('sniffing on ' + session_iface)
                        self.sniffers.append(sniffer)
                        self.sessions.remove(session)

        except KeyboardInterrupt:
            for sniffer in self.sniffers:
                sniffer.stop()

    def newSession(self, iface):
        def addSession(request):
            new_s = Session(iface=iface, request=request)
            self.sessions.append(new_s)
            pprint.information('Openning session with ' + request[IP].src)
            new_s.connection(request)
        return addSession

