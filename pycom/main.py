'''
Created on 6 mar. 2017

@author: pclavier
'''

from Compressor import Compressor
from Decompressor import Decompressor
from Parser import Parser
from binascii import hexlify
import binascii
import time
from network import LoRa
import pycom
import socket

# The rules to be used are defined

# print("\n\t## Rules definition ###")

rule0 = {
    "IP_version": {
        "targetValue": b"6",
        "matchingOperator": "equal",
        "compDecompFct": "not-sent",
        "direction": "bi"
    },
    "IP_trafficClass": {
        "targetValue": b"00",
        "matchingOperator": "equal",
        "compDecompFct": "not-sent",
        "direction": "bi"
    },
    "IP_flowLabel": {
        "targetValue": b"00000",
        "matchingOperator": "equal",
        "compDecompFct": "not-sent",
        "direction": "bi"
    },
    "IP_payloadLength": {
        "targetValue": "",
        "matchingOperator": "ignore",
        "compDecompFct": "compute-IPv6-length",
        "direction": "bi"
    },
    "IP_nextHeader": {
        "targetValue": b"11",
        "matchingOperator": "equal",
        "compDecompFct": "not-sent",
        "direction": "bi"
    },
    "IP_hopLimit": {
        "targetValue": b"40",
        "matchingOperator": "equal",
        "compDecompFct": "not-sent",
        "direction": "bi"
    },
    "IP_prefixES": {
        "targetValue": {
            b"1": b"20010db80a0b12f0",
            b"2": b"2d513de80a0b4df0",
        },
        "matchingOperator": "match-mapping",
        "compDecompFct": "mapping-sent(4)",
        "direction": "bi"
    },
    "IP_iidES": {
        "targetValue": b"",
        "matchingOperator": "ignore",
        "compDecompFct": "ESiid-DID",
        "direction": "bi"
    },
    "IP_prefixLA": {
        "targetValue": {
            b"1": b"20010db80a0b12f0",
            b"2": b"2d513de80a0b4df0",
        },
        "matchingOperator": "match-mapping",
        "compDecompFct": "mapping-sent(4)",
        "direction": "bi"
    },
    "IP_iidLA": {
        "targetValue": b"",
        "matchingOperator": "ignore",
        "compDecompFct": "LAiid-DID",
        "direction": "bi"
    },
    "UDP_PortES": {
        "targetValue": b"1f90",
        "matchingOperator": "equal",
        "compDecompFct": "not-sent",
        "direction": "bi"
    },
    "UDP_PortLA": {
        "targetValue": b"2382",
        "matchingOperator": "equal",
        "compDecompFct": "not-sent",
        "direction": "bi"
    },
    "UDP_length": {
        "targetValue": "",
        "matchingOperator": "ignore",
        "compDecompFct": "compute-UDP-length",
        "direction": "bi"
    },
    "UDP_checksum": {
        "targetValue": "",
        "matchingOperator": "ignore",
        "compDecompFct": "compute-UDP-checksum",
        "direction": "bi"
    },
    "CoAP_version": {
        "targetValue": b"1",
        "matchingOperator": "equal",
        "compDecompFct": "not-sent",
        "direction": "bi"
    },
    "CoAP_type": {
        "targetValue": b"1",
        "matchingOperator": "equal",
        "compDecompFct": "not-sent",
        "direction": "bi"
    },
    "CoAP_tokenLength": {
        "targetValue": b"1",
        "matchingOperator": "equal",
        "compDecompFct": "not-sent",
        "direction": "bi"
    },
    "CoAP_code": {
        "targetValue": b"02",
        "matchingOperator": "equal",
        "compDecompFct": "not-sent",
        "direction": "bi"
    },
    "CoAP_messageID": {
        "targetValue": "000000000000",  # ESTO TIENE QUE ESTAR EN BITS
        "matchingOperator": "MSB(12)",
        "compDecompFct": "LSB(4)",
        "direction": "bi"
    },
    "CoAP_token": {
        "targetValue": "",
        "matchingOperator": "ignore",
        "compDecompFct": "value-sent",
        "direction": "bi"
    },
    "CoAP_Uri-Path 1": {
        "targetValue": b"b3666f6f",  # "foo"
        "matchingOperator": "equal",
        "compDecompFct": "not-sent",
        "direction": "bi"
    },
    "CoAP_Uri-Path 2": {
        "targetValue": "",
        "matchingOperator": "ignore",
        "compDecompFct": "value-sent",
        "direction": "bi"
    }
}

# Elements instantiation

# print("\n\t## Elements instantiation ###")
compressor = Compressor()
decompressor = Decompressor()

#print("\t\t Compressor_nibbles (LC) A instantiated.")

# Rules are loaded to the Compressor_nibbles

compressor.addRule(rule0)
decompressor.addRule(rule0)

#print("\n\t Rules created.")
#print("\t Contexts filled.\n")
#compressor.printContext()

# The packet generator is initialized
packet = {}

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

#print("apres setsock")
# make the socket blocking
# (waits for the data to be sent and for the 2 receive windows to expire)

s.bind(1)

# send some data
pycom.heartbeat(False)

##############################################################
# Main program starts here

lora_buffer = []

packet = {}
packet_header = b'60000000001a114020010db80a0b12f070b3d549925aa6192d513de80a0b4df0ada4dae3ac12676b1f902382001a0a94510200010ab3666f6f03626172ff'
packet_payload = 1

while True:
    # A IPv6/UDP/CoAP packet is generated
    if packet_payload < 255:
        packet_payload += 1
    else:
        packet_payload = 1

    packet_buffer = b"".join([packet_header, hexlify(bytes([packet_payload]))])

    print("\n\t## IPv6/UDP/CoAP Message to be sent")
    print("\t\t", packet_buffer)

    # PARSING THE MESSAGE TO BE SENT

    # Parsing the packet to be analysed by the Compressor_nibbles
    # print("\n\t## Beginning of parsing ##")
    parser = Parser()
    parser.parser(packet_buffer)

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
    time.sleep(10)
    
    pycom.rgbled(0xFF0000)
    data = s.recv(64)
    print("\t\t", data)
    
    # DECOMPRESSION
    # Decompress packet
    if data != b"":
        decompressor.parseCompressedPacket(data)
        decompressor.loadIIDs(b"70b3d549925aa619", b"ada4dae3ac12676b")
        decompressor.decompressHeader()
    
    pycom.rgbled(0x000000)
    time.sleep(10)
