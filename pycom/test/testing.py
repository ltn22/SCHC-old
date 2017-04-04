'''
Created on 6 mar. 2017

@author: Philippe Clavier

Made for testing, cleaning and debugging 
'''

import time
from packet_generator import packet_generation
from Parser import Parser
from Compressor import Compressor

# The rules to be used are defined

print("\n\t## Rules definition ###")

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
    }
}

# Elements instantiation

print("\n\t## Elements instantiation ###")

compressor = Compressor()
print("\t\t Compressor (LC) A instantiated.")

parser = Parser()

# Rules are loaded to the Compressor

compressor.addRule(rule0)

print("\n\t Rules created.")
print("\t Contexts filled.\n")
compressor.printContext()

# The packet generator is initialized
packet = packet_generation()

while True:
    # A IPv6/UDP/CoAP packet is generated
    packet.generate_packet()

    print("\n\t## IPv6/UDP/CoAP Message to be sent")
    print("\t\t", packet.buffer)

    # PARSING

    # Parsing the packet to be analysed by the Compressor
    print("\n\t## Beginning of parsing ##")
    parser.parser(packet.buffer)

    # COMPRESSION

    # Load the parsed header fields and the payload to the compressor
    compressor.loadFromParser(parser.header_fields, parser.payload)

    # Search of matching rule in the context
    print("\t## Searching matching rule in context ##")
    compressor.analyzePacketToSend()

    # Compression of the packet to send
    print("\t## Compression of the packet to send ##")
    compressor.compressPacket()

    # Append the compressed header fields into a packet to be sent
    print("\t## Appending the compressed header fields ##")
    compressor.appendCompressedPacket()
    print("\t\t", compressor.compressed_packet)
    print("\t##############################")

    time.sleep(5)
