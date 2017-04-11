'''
Created on 6 mar. 2017

@author: pclavier
'''

import pycom
import time
import socket
import binascii
from network import LoRa
from Parser import Parser
from Compressor import Compressor
from packet_generator import packet_generation

# The rules to be used are defined

# print("\n\t## Rules definition ###")

rule0 = {
    "IP_version": {
        "targetValue": b"6",
        "matchingOperator": "equal",
        "compDecompFct": "not-sent"
    },
    "IP_trafficClass": {
        "targetValue": b"00",
        "matchingOperator": "equal",
        "compDecompFct": "not-sent"
    },
    "IP_flowLabel": {
        "targetValue": b"00000",
        "matchingOperator": "equal",
        "compDecompFct": "not-sent"
    },
    "IP_payloadLength": {
        "targetValue": '',
        "matchingOperator": "ignore",
        "compDecompFct": "compute-IPv6-length"
    },
    "IP_nextHeader": {
        "targetValue": b"11",
        "matchingOperator": "equal",
        "compDecompFct": "not-sent"
    },
    "IP_hopLimit": {
        "targetValue": b"40",
        "matchingOperator": "equal",
        "compDecompFct": "not-sent"
    },
    "IP_prefixES": {
        "targetValue": b"20010db80a0b12f0",
        "matchingOperator": "ignore",
        "compDecompFct": "not-sent"
    },
    "IP_iidES": {
        "targetValue": b"",
        "matchingOperator": "ignore",
        "compDecompFct": "ESiid-DID"
    },
    "IP_prefixLA": {
        "targetValue": b"2d513de80a0b4df0",
        "matchingOperator": "equal",
        "compDecompFct": "not-sent"
    },
    "IP_iidLA": {
        "targetValue": b"",
        "matchingOperator": "ignore",
        "compDecompFct": "LAiid-DID"
    },
    "UDP_PortES": {
        "targetValue": b"1f90",
        "matchingOperator": "equal",
        "compDecompFct": "not-sent"
    },
    "UDP_PortLA": {
        "targetValue": b"2382",
        "matchingOperator": "equal",
        "compDecompFct": "not-sent"
    },
    "UDP_length": {
        "targetValue": '',
        "matchingOperator": "ignore",
        "compDecompFct": "compute-UDP-length"
    },
    "UDP_checksum": {
        "targetValue": '',
        "matchingOperator": "ignore",
        "compDecompFct": "compute-UDP-checksum"
    },
    "CoAP_version": {
        "targetValue": b"1",
        "matchingOperator": "equal",
        "compDecompFct": "not-sent"
    },
    "CoAP_type": {
        "targetValue": b"1",
        "matchingOperator": "equal",
        "compDecompFct": "not-sent"
    },
    "CoAP_tokenLength": {
        "targetValue": b"1",
        "matchingOperator": "equal",
        "compDecompFct": "not-sent"
    },
    "CoAP_code": {
        "targetValue": b"02",
        "matchingOperator": "equal",
        "compDecompFct": "not-sent"
    },
    "CoAP_messageID": {
        "targetValue": b"000",
        "matchingOperator": "MSB(12)",
        "compDecompFct": "LSB(4)"
    },
    "CoAP_token": {
        "targetValue": '',
        "matchingOperator": "ignore",
        "compDecompFct": "value-sent"
    }
}

rule1 = {
    "IP_version": {
        "targetValue": b"6",
        "matchingOperator": "equal",
        "compDecompFct": "not-sent"
    },
    "IP_trafficClass": {
        "targetValue": b"00",
        "matchingOperator": "equal",
        "compDecompFct": "not-sent"
    },
    "IP_flowLabel": {
        "targetValue": b"00000",
        "matchingOperator": "equal",
        "compDecompFct": "not-sent"
    },
    "IP_payloadLength": {
        "targetValue": "",
        "matchingOperator": "ignore",
        "compDecompFct": "compute-IPv6-length"
    },
    "IP_nextHeader": {
        "targetValue": b"11",
        "matchingOperator": "equal",
        "compDecompFct": "not-sent"
    },
    "IP_hopLimit": {
        "targetValue": b"40",
        "matchingOperator": "equal",
        "compDecompFct": "not-sent"
    },
    "IP_prefixES": {
        "targetValue": {
            b"1": b"20010db80a0b12f0",
            b"2": b"2d513de80a0b4df0",
        },
        "matchingOperator": "match-mapping",
        "compDecompFct": "mapping-sent(4)"
    },
    "IP_iidES": {
        "targetValue": b"",
        "matchingOperator": "ignore",
        "compDecompFct": "ESiid-DID"
    },
    "IP_prefixLA": {
        "targetValue": {
            b"1": b"20010db80a0b12f0",
            b"2": b"2d513de80a0b4df0",
        },
        "matchingOperator": "match-mapping",
        "compDecompFct": "mapping-sent(4)"
    },
    "IP_iidLA": {
        "targetValue": b"",
        "matchingOperator": "ignore",
        "compDecompFct": "LAiid-DID"
    },
    "UDP_PortES": {
        "targetValue": b"1f90",
        "matchingOperator": "equal",
        "compDecompFct": "not-sent"
    },
    "UDP_PortLA": {
        "targetValue": b"2382",
        "matchingOperator": "equal",
        "compDecompFct": "not-sent"
    },
    "UDP_length": {
        "targetValue": "",
        "matchingOperator": "ignore",
        "compDecompFct": "compute-UDP-length"
    },
    "UDP_checksum": {
        "targetValue": "",
        "matchingOperator": "ignore",
        "compDecompFct": "compute-UDP-checksum"
    },
    "CoAP_version": {
        "targetValue": b"1",
        "matchingOperator": "equal",
        "compDecompFct": "not-sent"
    },
    "CoAP_type": {
        "targetValue": b"1",
        "matchingOperator": "equal",
        "compDecompFct": "not-sent"
    },
    "CoAP_tokenLength": {
        "targetValue": b"1",
        "matchingOperator": "equal",
        "compDecompFct": "not-sent"
    },
    "CoAP_code": {
        "targetValue": b"02",
        "matchingOperator": "equal",
        "compDecompFct": "not-sent"
    },
    "CoAP_messageID": {
        "targetValue": b"000",
        "matchingOperator": "MSB(12)",
        "compDecompFct": "LSB(4)"
    },
    "CoAP_token": {
        "targetValue": "",
        "matchingOperator": "ignore",
        "compDecompFct": "value-sent"
    },
    "CoAP_Uri-Path 1": {
        "targetValue": b"666f6f",  # "foo"
        "matchingOperator": "equal",
        "compDecompFct": "not-sent"
    },
    "CoAP_Uri-Path 2": {
        "targetValue": "",
        "matchingOperator": "ignore",
        "compDecompFct": "value-sent"
    }
}

# Elements instantiation

# print("\n\t## Elements instantiation ###")

compressor = Compressor()
#print("\t\t Compressor (LC) A instantiated.")

# Rules are loaded to the Compressor

compressor.addRule(rule0)
compressor.addRule(rule1)

# The packet generator is initialized
packet = packet_generation()

# Initialize LoRa in LORAWAN mode.
lora = LoRa(mode=LoRa.LORAWAN)

# create an OTAA authentication parameters
app_eui = binascii.unhexlify('AD A4 DA E3 AC 12 67 6B'.replace(' ', ''))
app_key = binascii.unhexlify(
    '12 34 56 78 12 34 56 78 01 23 45 67 01 23 45 67'.replace(' ', ''))

# join a network using OTAA (Over the Air Activation)
lora.join(activation=LoRa.OTAA, auth=(app_eui, app_key), timeout=0)

# wait until the module has joined the network
while not lora.has_joined():
    time.sleep(2.5)
    print('Not yet joined...')

# create a LoRa socket
s = socket.socket(socket.AF_LORA, socket.SOCK_RAW)

# set the LoRaWAN data rate
s.setsockopt(socket.SOL_LORA, socket.SO_DR, 5)

s.bind(1)
pycom.heartbeat(False)

##############################################################
# Main program starts here

lora_buffer = []

while True:
    # A IPv6/UDP/CoAP packet is generated
    packet.generate_packet()

    print("\n\t## IPv6/UDP/CoAP Message to be sent")
    print("\t\t", packet.buffer)

    # PARSING THE MESSAGE TO BE SENT

    # Parsing the packet to be analysed by the Compressor
    # print("\n\t## Beginning of parsing ##")
    parser = Parser()
    parser.parser(packet.buffer)

    # COMPRESSION

    # Load the parsed header fields and the payload to the compressor
    compressor.loadFromParser(
        parser.header_fields, parser.coap_header_options, parser.payload)

    # Search of matching rule in the context
    print("\t## Searching matching rule in context ##")
    compressor.analyzePacketToSend()

    # Compression of the packet to send
    # print("\t## Compression of the packet to send ##")
    compressor.compressPacket()

    # Sending compressed packet
    print("\t## Sending compressed packet ##")
    compressor.appendCompressedPacket()
    print("\t\t", compressor.compressed_packet)
    lora_buffer = binascii.unhexlify(compressor.compressed_packet)
    print("\t##############################")

    s.setblocking(True)
    pycom.rgbled(0x00FF00)
    s.send(bytes(lora_buffer))
    s.setblocking(False)
    data = s.recv(64)
    print(data)
    pycom.rgbled(0x000000)
    time.sleep(20)
