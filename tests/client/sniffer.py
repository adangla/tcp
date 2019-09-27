from scapy.all import *
from threading import Thread, Event
from time import sleep

class Sniffer(Thread):
    def  __init__(self, interface="lo"):
        super(Sniffer, self).__init__()

        self.interface = interface
        self.stop_sniffer = Event()
        
    # TODO : Find a way to return the sniffed packet.
    def run(self):
        sniff(iface=self.interface, filter="ip", prn=self.print_packet, stop_filter=self.should_stop_sniffer, count=1)

    def join(self, timeout=None):
        self.stop_sniffer.set()
        super().join(timeout)

    def should_stop_sniffer(self, packet):
        return self.stop_sniffer.isSet()

    def print_packet(self, packet):
        ip_layer = packet.getlayer(IP)
        print("[!] New Packet: {src} -> {dst}".format(src=ip_layer.src, dst=ip_layer.dst))
