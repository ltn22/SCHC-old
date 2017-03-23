'''
Created on 2 mar. 2017

@author: Philippe Clavier
'''

# Import Clases
from messages_classes import CBOR
from messages_classes import coap_message
from messages_classes import udp_header
from messages_classes import ipv6_header

# Definitions
POST = 2
NON = 1


class packet_generation:
    """
    Packet generator
    """

    def __init__(self):
        self.buffer = []
        self.measure = 0
        self.decrease = 0
        self.alea = 0

    def generate_packet(self):
        self.measure += 1
        self.decrease -= 7
        self.alea = 0

        c_measure = CBOR(self.measure)
        c_alea = CBOR(self.alea)
        c_decrease = CBOR(self.decrease)

        c = CBOR([c_measure, c_alea, c_decrease])

        m = coap_message()
        # Fist 32 bits
        m.new_header(coap_type=NON,  code=POST,  token=10)
        # Payload Marker - only present if there is a payload
        m.end_option()    # Payload
        m.add_value(c)
        #print("CoAP Message")
        # print(m.buffer)

        uc = udp_header()
        uc.add_header(m.buffer)
        #print("UDP/CoAP Message")
        # print(uc.buffer)

        self.buffer = ipv6_header()
        self.buffer.add_header(uc.buffer)
        self.buffer = self.buffer.buffer
        #print("IPv6/UDP/CoAP Message")
        # print(self.buffer.buffer)
        # print()
