'''
Created on 2 mar. 2017

@author: Philippe Clavier
'''

import math
from re import search
from binascii import hexlify, unhexlify
from builtins import enumerate


class Decompressor:

    def __init__(self):

        self.context = []
        self.received_payload = b""
        self.field_size = {
            "IP_version": 4,
            "IP_trafficClass": 8,
            "IP_flowLabel": 20,
            "IP_payloadLength": 16,
            "IP_nextHeader": 8,
            "IP_hopLimit": 8,
            "IP_prefixES": 64,
            "IP_iidES": 64,
            "IP_prefixLA": 64,
            "IP_iidLA": 64,
            "UDP_PortES": 16,
            "UDP_PortLA": 16,
            "UDP_length": 16,
            "UDP_checksum": 16,
            "CoAP_version": 2,
            "CoAP_type": 2,
            "CoAP_tokenLength": 4,
            "CoAP_code": 8,
            "CoAP_messageID": 16,
            "CoAP_token": 8
        }
        # Auxiliarys to order the options for every rule
        self.options_order = {}
        self.repeatable_options = 3
        self.options_index = ["CoAP_If-Match", "CoAP_Uri-Host", "CoAP_ETag", "CoAP_If-None-Match", "CoAP_Uri-Port",
                              "CoAP_Location-Path", "CoAP_Uri-Path", "CoAP_Content-Format", "CoAP_Max-Age", "CoAP_Uri-Query",
                              "CoAP_Accept", "CoAP_Location-Query", "CoAP_Proxy-Uri", "CoAP_Proxy-Scheme", "CoAP_Sizel"]

    def addRule(self, rule):
        index = len(self.context)
        self.context.append(rule)
        self.options_order[index] = obtain_options_order(
            rule, self.options_index, self.repeatable_options)

#########################################################################
##############   Here Starts The Decompression Functions   ##############
#########################################################################

    def parseCompressedPacket(self, received_compressed_packet):
        self.reiniteDecompressor()
        rule = received_compressed_packet[0:2]
        rule = int(rule, 16)
        self.decompression_rule = rule
        index = 8  # In bits

        # if self.options_order[rule]:
        self.header_order = self.header_order + self.options_order[rule]

        for order in range(0, len(self.header_order), 1):
            if self.header_order[order] == "CoAP_token":
                self.field_size[self.header_order[order]] = int(
                    self.context[rule]["CoAP_tokenLength"]["targetValue"]) * 8
            if(self.context[rule][self.header_order[order]]["compDecompFct"] == "value-sent"):
                # After the header number 20 the options start
                # CoAP option length is sent first
                if order >= 20:
                    # Fist 4 bits delta and 4 bits of length (CoAP)
                    option_length = obtain_compressed_field(
                        index + 4, 4, received_compressed_packet)
                    length_bits = int(option_length) * 8 + 8
                else:
                    length_bits = self.field_size[self.header_order[order]]
                field_data = obtain_compressed_field(
                    index, length_bits, received_compressed_packet)
                self.decompressed_header[self.header_order[order]] = complete_field_zeros(
                    field_data, length_bits)
                index += length_bits
            reg = search('mapping-sent\((.*)\)',
                         self.context[rule][self.header_order[order]]["compDecompFct"])
            if (reg):
                length_bits = int(reg.group(1))
                field_data = obtain_compressed_field(
                    index, length_bits, received_compressed_packet)
                self.decompressed_header[self.header_order[order]] = complete_field_zeros(
                    field_data, length_bits)
                index += length_bits
            reg = search(
                'LSB\((.*)\)', self.context[self.decompression_rule][self.header_order[order]]["compDecompFct"])
            if (reg):
                # The number of LSB to be used is obtained from the "CDF" of
                # the rule
                length_bits = int(reg.group(1))
                field_data = obtain_compressed_field(
                    index, length_bits, received_compressed_packet)
                self.decompressed_header[self.header_order[order]] = field_data
                # self.decompressed_header[self.header_order[order]] = complete_field_zeros(
                #    field_data, self.field_size[self.header_order[order]])
                index += length_bits
        packet_start = math.ceil(index / 4)
        # The LoPy sends bytes, if the extra bits are 4 or more then they
        # should be skipped
        if packet_start % 2 != 0:
            packet_start += 1
        self.received_payload = received_compressed_packet[
            packet_start:]

    def decompressHeader(self):
        decompression_rule = self.decompression_rule
        print("\n\t\tStart decompressing packet with the rule " +
              str(decompression_rule) + " ...\n")
        # for field_name, field_content in self.decompressed_header.items()
        for order in range(0, len(self.header_order), 1):
            # for item in self.header_order:
            # order = int(item)
            print("\t\t\tfield " + self.header_order[order] + " :")
            # It checks if the CDF for that field is "not-sent" according to
            # the rule received
            if (self.context[decompression_rule][self.header_order[order]]["compDecompFct"] == "not-sent"):
                # If it is the decompressed value of the field will be the
                # "tagetValue" from that field of the rule received
                self.decompressed_header[self.header_order[order]] = self.context[
                    self.decompression_rule][self.header_order[order]]["targetValue"]
                print("\t\t\t\tdecompressed " + self.header_order[
                      order] + " is %s (retrieved from the context)" % self.decompressed_header[self.header_order[order]])
            # It checks if the CDF for that field is "value-sent" according to
            # the rule received
            elif (self.context[decompression_rule][self.header_order[order]]["compDecompFct"] == "value-sent"):
                # If it is the decompressed value of the field will be the same
                # as the compressed value (which has not been compressed)
                print("\t\t\t\tdecompressed " + self.header_order[
                      order] + " is %s (retrieved from the link)" % self.decompressed_header[self.header_order[order]])
            # ESiid and LAiid must be obtained correctly from L2 but for now it
            # will be used the TV
            elif (self.context[decompression_rule][self.header_order[order]]["compDecompFct"] == "ESiid-DID"):
                self.decompressed_header[self.header_order[order]] = self.ESiid
                print("\t\t\t\tdecompressed " + self.header_order[
                      order] + " is %s (retrieved from L2)" % self.decompressed_header[self.header_order[order]])
            elif (self.context[decompression_rule][self.header_order[order]]["compDecompFct"] == "LAiid-DID"):
                self.decompressed_header[self.header_order[order]] = self.LAiid
                print("\t\t\t\tdecompressed " + self.header_order[
                      order] + " is %s (retrieved from L2)" % self.decompressed_header[self.header_order[order]])
            reg = search('mapping-sent\((.*)\)',
                         self.context[decompression_rule][self.header_order[order]]["compDecompFct"])
            if (reg):
                # The received field is the key in the Target Value for the
                # true value
                key = self.decompressed_header[self.header_order[order]]
                self.decompressed_header[self.header_order[order]] = self.context[
                    decompression_rule][self.header_order[order]]["targetValue"][key]

                print("\t\t\t\tdecompressed " + self.header_order[
                      order] + " is %s (retrieved from the mapping-sent)" % self.decompressed_header[self.header_order[order]])

            # It checks if the CDF for that field is "LSB" according to the
            # rule received
            reg = search(
                'LSB\((.*)\)', self.context[decompression_rule][self.header_order[order]]["compDecompFct"])
            if (reg):
                # The number of LSB to be used is obtained from the rule
                lsb = int(reg.group(1))
                # The MSBs value is obtained from the "targetValue" of the
                # field from that rule
                msb_value = int(
                    self.context[decompression_rule][self.header_order[order]]["targetValue"], 16)
                # The received LSBs value
                lsb_value = int(
                    self.decompressed_header[self.header_order[order]], 16)
                # The MSB and LSB are merged with an OR to obtain the final
                # value
                field_value = (msb_value << lsb) | lsb_value
                # The final value is expressed in hexa string
                field_value = long_to_bytes(field_value, 'big')
                self.decompressed_header[self.header_order[order]] = complete_field_zeros(
                    field_value, self.field_size[self.header_order[order]])
                msb = self.field_size[self.header_order[order]] - lsb
                print('\t\t\t\tdecompressed %s is %s (retrieved from the context (%d MSB) and from the link (%d LSB))' % (self.header_order[
                      order], self.decompressed_header[self.header_order[order]], msb, lsb))
        # Now the fields with the compute-* function must be obtained
        print()
        if (self.context[decompression_rule]["UDP_length"]["compDecompFct"] == "compute-UDP-length"):
            aux = (int(self.decompressed_header["CoAP_version"], 16) << 6) | (int(self.decompressed_header[
                "CoAP_type"], 16) << 4) | int(self.decompressed_header["CoAP_tokenLength"], 16)
            aux = hexlify(bytes([aux]))
            coap_h = b""
            for index, field_name in enumerate(self.header_order):
                if (index >= 17):   # and index < 20):
                    coap_h = b"".join(
                        [coap_h, self.decompressed_header[field_name]])
            coap_h = b"".join([aux, coap_h, b"ff"])
            coap_packet = b"".join([coap_h, self.received_payload])
            udp_length = int(len(coap_packet) / 2) + 8

            if (udp_length > 255):
                lsb = udp_length & 0x00ff
                msb = udp_length >> 8
            else:
                lsb = udp_length
                msb = 0
            udp_length = hexlify(bytes([msb, lsb]))
            self.decompressed_header[
                "UDP_length"] = complete_field_zeros(udp_length, 16)
            print("\t\t\t\tUDP Length computed: %s (%d bytes)" % (self.decompressed_header[
                  "UDP_length"], int(self.decompressed_header["UDP_length"], 16)))
            # 16 bits zeros checksum until it is computed
            self.decompressed_header["UDP_checksum"] = b"0000"
            udp_h = b"".join([self.decompressed_header["UDP_PortES"], self.decompressed_header[
                             "UDP_PortLA"], self.decompressed_header["UDP_length"], self.decompressed_header["UDP_checksum"]])
            udp_packet = b"".join([udp_h, coap_packet])
        if (self.context[decompression_rule]["UDP_checksum"]["compDecompFct"] == "compute-UDP-checksum"):
            udp_pseudo_header = b"".join([self.decompressed_header["IP_prefixES"], self.decompressed_header["IP_iidES"], self.decompressed_header[
                                         "IP_prefixLA"], self.decompressed_header["IP_iidLA"], self.decompressed_header["UDP_length"], b"00", self.decompressed_header["IP_nextHeader"]])
            checksum_packet = b"".join([udp_pseudo_header, udp_packet])
            checksum_packet = bytesArray_to_intArray(checksum_packet)
            chksm = checksum(checksum_packet)
            if (chksm > 255):
                lsb = chksm & 0x00FF
                msb = chksm >> 8
            else:
                lsb = chksm
                msb = 0
            chksm = hexlify(bytes([msb, lsb]))
            self.decompressed_header[
                "UDP_checksum"] = complete_field_zeros(chksm, 16)
            print("\t\t\t\tUDP_Checksum computed: ",
                  self.decompressed_header["UDP_checksum"])
        if (self.context[decompression_rule]["IP_payloadLength"]["compDecompFct"] == "compute-IPv6-length"):
            ip_payloadlength = int(len(udp_packet) / 2)
            if (ip_payloadlength > 255):
                lsb = ip_payloadlength & 0x00ff
                msb = ip_payloadlength >> 8
            else:
                lsb = ip_payloadlength
                msb = 0
            ip_payloadlength = hexlify(bytes([msb, lsb]))
            self.decompressed_header[
                "IP_payloadLength"] = complete_field_zeros(ip_payloadlength, 16)
            print("\t\t\t\tIP Payload Length computed: %s (%d bytes)" % (self.decompressed_header[
                  "IP_payloadLength"], int(self.decompressed_header["IP_payloadLength"], 16)))
        print()
        print("\t\t\t Payload: %s (%d bytes) " %
              (self.received_payload, len(self.received_payload) / 2))

        for index in self.header_order:
            if (index != "CoAP_version" and index != "CoAP_type"):
                self.decompressed_packet = self.decompressed_packet + \
                    self.decompressed_header[index]
            elif index == "CoAP_version":
                aux = (int(self.decompressed_header["CoAP_version"], 16) << 2) | (
                    int(self.decompressed_header["CoAP_type"], 16))
                aux = hexlify(bytes([aux]))[1:]
                self.decompressed_packet = self.decompressed_packet + aux
        if (self.received_payload):
            self.decompressed_packet += b"ff" + self.received_payload

    def reiniteDecompressor(self):
        # Received payload for the decompression stage
        self.received_payload = b""

        # Received packet decompressed
        self.decompressed_packet = b""

        # Rule For Decompression
        self.decompression_rule = 0xff

        # ESiid obtained from L2
        self.ESiid = b""

        # LAiid obtained from L2
        self.LAiid = b""

        # Auxiliary list to order the dictionary fields
        self.header_order = ["IP_version", "IP_trafficClass", "IP_flowLabel",
                             "IP_payloadLength", "IP_nextHeader", "IP_hopLimit", "IP_prefixES", "IP_iidES",
                             "IP_prefixLA", "IP_iidLA", "UDP_PortES", "UDP_PortLA",
                             "UDP_length", "UDP_checksum", "CoAP_version", "CoAP_type", "CoAP_tokenLength",
                             "CoAP_code", "CoAP_messageID", "CoAP_token"]

        # Values to be filled after the decompression of the packet received
        self.decompressed_header = {
            "IP_version": "",
            "IP_trafficClass": "",
            "IP_flowLabel": "",
            "IP_payloadLength": "",
            "IP_nextHeader": "",
            "IP_hopLimit": "",
            "IP_prefixES": "",
            "IP_iidES": "",
            "IP_prefixLA": "",
            "IP_iidLA": "",
            "UDP_PortES": "",
            "UDP_PortLA": "",
            "UDP_length": "",
            "UDP_checksum": "",
            "CoAP_version": "",
            "CoAP_type": "",
            "CoAP_tokenLength": "",
            "CoAP_code": "",
            "CoAP_messageID": "",
            "CoAP_token": ""
        }

    def loadIIDs(self, ESiid, LAiid):
        self.ESiid = ESiid
        self.LAiid = LAiid

#########################################################################
##############             Auxiliary Functions             ##############
#########################################################################


def checksum(msg):
    # Computes the UDP checksum for the decompressor
    # msg includes the pseudo-header for UDP, the UDP header and the UDP payload.
    # If the length of msg is not even a zero byte is added
    if len(msg) % 2 == 1:
        msg += [0]
    s = 0
    w = 0
    # Loop taking 2 bytes at a time (16 bits)
    for i in range(0, len(msg), 2):
        w = msg[i + 1] + (msg[i] << 8)  # Primer bit es el mas grande
        s = s + w
    while s > 0xffff:
        s = (s >> 16) + (s & 0xffff)
    # Complement and mask to 2 bytes (dont know for what is this last part)
    s = ~s & 0xffff
    return s

# Completes the field with zeros up to its size


def complete_field_zeros(field, field_length):
    nibbles = int(field_length / 4)
    while(len(field) < nibbles):
        field = b"".join([b"0", field])
    while(len(field) > nibbles):
        field = field[1:]
    return field


def obtain_compressed_field(index, length_bits, compPacket):
    nibble_index = math.floor(index / 4)
    nibble_end = math.ceil((index + length_bits) / 4)
    diffe = nibble_end * 4 - (length_bits + index)
    field_data = int(compPacket[nibble_index:nibble_end], 16)
    field_data = field_data >> diffe  # Shift
    field_data = field_data & int(2**length_bits - 1)  # Mask
    field_data = long_to_bytes(field_data, 'big')
    return field_data


def obtain_options_order(rule, options_index, repeatable_options):
    options_order = []
    for field_name in rule:
        for k in range(0, len(options_index), 1):
            re = options_index[k] + "\\s(\\d*)"  # ,"\\s\(\\d*\)"
            reg = search(re, field_name)
            if (reg):
                options_order.append(
                    [field_name, k * repeatable_options + int(reg.group(1)) - 1])
    # options_order.sort(function(a, b){return a[1]-b[1]});
    sorted(options_order, key=itemgetter(1))
    for k in range(0, len(options_order), 1):
        options_order[k] = options_order[k][0]
    return options_order


def long_to_bytes(val, endianness='big'):
    '''
    Use :ref:`string formatting` and :func:`~binascii.unhexlify` to
    convert ``val``, a :func:`long`, to a byte :func:`str`.

    :param long val: The value to pack

    :param str endianness: The endianness of the result. ``'big'`` for
      big-endian, ``'little'`` for little-endian.

    If you want byte- and word-ordering to differ, you're on your own.

    Using :ref:`string formatting` lets us use Python's C innards.
    '''

    # one (1) hex digit per four (4) bits
    width = bit_length(val)

    # unhexlify wants an even multiple of eight (8) bits, but we don't
    # want more digits than we need (hence the ternary-ish 'or')
    width += 8 - ((width % 8) or 8)

    # format width specifier: four (4) bits per hex digit
    fmt = '%%0%dx' % (width // 4)

    # prepend zero (0) to the width, to zero-pad the output
    s = unhexlify(fmt % val)

    if endianness == 'little':
        # see http://stackoverflow.com/a/931095/309233
        s = s[::-1]

    '''
    length = (bit_length(val) + 7) // 8
    s = val.to_bytes(length, 'big') or b'\0'
    '''
    return hexlify(s)


def bytesArray_to_intArray(bytesArray):
    intArray = []
    for k in range(0, len(bytesArray), 2):
        intArray.append(int(bytesArray[k:k + 2], 16))
    return intArray


def bit_length(s):
    s = bin(s)       # binary representation:  bin(-37) --> '-0b100101'
    s = s.lstrip('-0b')  # remove leading zeros and minus sign
    return len(s)


def itemgetter(*items):
    if len(items) == 1:
        item = items[0]

        def g(obj):
            return obj[item]
    else:
        def g(obj):
            return tuple(obj[item] for item in items)
    return g
