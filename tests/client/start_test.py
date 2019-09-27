from client.start import Client
from server.start import Server
from scapy.all import *
from multiprocessing import Process
from tests.client.sniffer import Sniffer
import pytest

def test_client_init_parameters_test_shall_pass():
    c = Client()
    assert c.state == "CLOSED"
    assert type(c.packet) == type(IP()/TCP())
    assert c.packet[TCP].sport == 2222
    assert c.packet[TCP].seq in range(1, 2048)


def test_send_syn_from_client_test_shall_pass():
    host = "127.0.0.1"
    port = 8888
    c = Client()
    s = Sniffer()
#    pytest.set_trace()
    s.start()
    res = c.send_syn(host, port)
    print(res)
    r = s.join()
    print(r)
    # p.join()
