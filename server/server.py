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

        filter_options = 'tcp and dst port ' + str(self.port) + ' and tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn'
        for iface in netifaces.interfaces():
            pprint.information('sniffing on ' + iface)
            self.sniffers.append(AsyncSniffer(filter=filter_options, prn=self.newSession(iface), count=1, iface=iface, timeout=10))

        for sniffer in self.sniffers:
            sniffer.start()
        time.sleep(2000)

    def newSession(self, iface):
        def addSession(request):
            new_s = Session(iface=iface, request=request)
            new_s.connection(request)
            self.sessions.append(new_s)
        return addSession

