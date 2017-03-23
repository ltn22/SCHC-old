'''
Created on 2 mar. 2017

@author: Philippe Clavier
'''

from re import search
from binascii import hexlify
from binascii import unhexlify


class Compressor:

    def __init__(self):

        # The context will store the rules that can be used for a compression
        self.context = []

        # Header received from the EndSystem
        self.parsedHeaderFields = {}

        # Received compressed packet for the decompression stage
        self.received_compressed_packet = {}

        # Received payload for the decompression stage
        self.received_payload = b""

        # Received CoAP packet
        self.coap_packet = b""

        # Received UDP packet
        self.udp_packet = b""

        # Received UDP packet
        self.udp_h = b""

        # Compressed packet ready to be send
        self.compressed_packet_to_send = {
            "rule": "",
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

        # Auxiliar list to order the dictionary
        self.header_order = ["rule", "IP_version", "IP_trafficClass", "IP_flowLabel",
                             "IP_payloadLength", "IP_nextHeader", "IP_hopLimit", "IP_prefixES", "IP_iidES",
                             "IP_prefixLA", "IP_iidLA", "UDP_PortES", "UDP_PortLA",
                             "UDP_length", "UDP_checksum", "CoAP_version", "CoAP_type", "CoAP_tokenLength",
                             "CoAP_code", "CoAP_messageID", "CoAP_token"]

        # Values to be filled after the decompression of the packet received
        self.decompressed_packet = {
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

        # Fields sizes in bits
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
    # Tokens and Options are not being taken into account for now

    def addRule(self, rule):
        self.context.append(rule)

    def analyzePacketToSend(self, parsedHeaderFields):
        self.parsedHeaderFields = parsedHeaderFields
        # The first thing will be to compare every rule from the context with
        # the packet to be analysed, and check if it is possible to use any
        # compression rule for this packet
        self.rule_found = False
        self.rule_found_id = 0
        i = 0

        for rule in self.context:
            '''print("\n\t\tAnalyzing rule %d..." % i)'''
            matched = False

            # Each field in the rule will be analysed
            for field_name, field_content in rule.items():
                '''print("\t\t\tfield %s :" % field_name)'''

                # It is checked which is the "matchingOperator" for that field
                # Possible "matchingOperators" are: equal | ignore | MSB(*)
                # |(match-mapping is not considered yet)
                if field_content["matchingOperator"] == "equal":
                    '''print("\t\t\t\t%s context value is %s and received value is %s..." % (
                        field_name, field_content["targetValue"], self.parsedHeaderFields[field_name]))'''

                    # If the "matchingOperator" is "equal" the "targetValue" of
                    # the rule is compared to the received packet field value
                    # and check if there is a match
                    if field_content["targetValue"] == self.parsedHeaderFields[field_name]:
                        '''print("\t\t\t\t\t...it is a match.")'''
                        matched = True
                    else:
                        matched = False
                        break
                if field_content["matchingOperator"] == "ignore":

                    # If the "matchingOperator" is "ignore" this fields value
                    # is ignored
                    '''print("\t\t\t\t%s context value is %s and received value is %s..." % (
                        field_name, field_content["targetValue"], self.parsedHeaderFields[field_name]))'''
                    '''print("\t\t\t\t\t...but they are ignored.")'''
                    matched = True

                # serach() function makes a comparison between the field
                # "matchingOperator" and "MSB" if it matches it gives back a
                # True value
                reg = search(
                    'MSB\((.*)\)', field_content["matchingOperator"])

                # If the "matchingOperator" is "MSB" then it should proceed
                # with the compression
                if reg:
                    msb = int(reg.group(1))
                    '''print("\t\t\t\t%s context value is %s and received value is %s..." % (
                        field_name, field_content["targetValue"], self.parsedHeaderFields[field_name]))'''

                    # ctx_bin will have the "targetValue" of the rule field in
                    # binary representation
                    ctx_bin = bin(int(field_content["targetValue"], 16))[2:]

                    # rcv_bin will have the value of the recieved packet field
                    # in binary representation
                    rcv_bin = bin(
                        int(self.parsedHeaderFields[field_name], 16))[2:]

                    # ctx_nbz will be the size of the field name minus the
                    # length of the "tagetValue"
                    ctx_nbz = self.field_size[field_name] - len(ctx_bin)
                    # ctx_bin is filled with zeros for the diference in size
                    ctx_bin = self.zfill(ctx_bin, ctx_nbz)

                    # rcv_nbz will be the size of the field name minus the
                    # length of the received field value
                    rcv_nbz = self.field_size[field_name] - len(rcv_bin)
                    # rcv_bin is filled with zeros for the diference in size
                    rcv_bin = self.zfill(rcv_bin, rcv_nbz)

                    # Here it is checked if the MSB of the "targetValue" and
                    # the value of the recieved packet field are the same
                    if ctx_bin[0:msb] == rcv_bin[0:msb]:
                        '''print(
                            "\t\t\t\t\t...it is a match on the first %d bits." % msb)'''
                        matched = True
                    else:
                        matched = False
                        break

            # Finally if the rule has matched it finishes, if not it keeps
            # comparing with the other rules of the list
            if matched:
                print("\t\tRule %d matched!" % i)
                self.rule_found = True
                self.rule_found_id = i
                break
            else:
                print("\t\tRule %d do not match." % i)
            i += 1

    def compressPacket(self):
        # If a rule is found the packet is compressed according to the selected
        # rule
        if self.rule_found:
            '''print("\n\t\tStart compressing packet with the rule %d...\n" %
                  self.rule_found_id)'''

            # In this iterations the "compDecompFct" is analysed for each field
            # of the selected rule
            for field_name, field_content in self.context[self.rule_found_id].items():
                '''print("\t\t\tfield %s :" % field_name)'''

                # It is checked if the "compDecompFct" of the field contains
                # "LSB"
                reg = search('LSB\((.*)\)', field_content["compDecompFct"])
                if reg:

                    # group(1) returns the first parenthesized subgroup
                    lsb = int(reg.group(1))

                    # The field value from the received packet is expressed in
                    # binary
                    rcv_bin = bin(
                        int(self.parsedHeaderFields[field_name], 16))[2:]

                    # rcv_nbz calculates the difference in length between the
                    # field size and the received field value
                    rcv_nbz = self.field_size[
                        field_name] - len((rcv_bin))

                    # rcv_bin is then completed with rcv_nbz zeros
                    rcv_bin = self.zfill(rcv_bin, rcv_nbz)

                    # The LSB bits from rcv_bin to be send are separeted
                    # The rcv_bin bits are selected from (field_size - lsb) to
                    # field_size
                    rcv_bin = rcv_bin[
                        self.field_size[field_name] - lsb:self.field_size[field_name]]

                    # Binary to byte format
                    lsb_value = int(rcv_bin)
                    lsb_value = hexlify(bytes([lsb_value]))
                    self.compressed_packet_to_send[
                        field_name] = self.complete_field_zeros(lsb_value, lsb)
                    '''print("\t\t\t\t%d lsb of %s are sent to the server, value is %s" % (
                        lsb, field_name, self.compressed_packet_to_send[field_name]))'''

                # It is checked if the "compDecompFct" of the field contains
                # "value-sent"
                elif field_content["compDecompFct"] == "value-sent":
                    self.compressed_packet_to_send[
                        field_name] = self.parsedHeaderFields[field_name]
                    '''print("\t\t\t\tfield content of %s is sent to the server, value is %s" % (
                        field_name, self.compressed_packet_to_send[field_name]))'''

                # In any other case the field is omitted
                # All fields with compute-* are not sent
                else:
                    '''print("\t\t\t\tfield elided.")'''

            # The selected ruled is also sent in the packet
            self.compressed_packet_to_send["rule"] = hexlify(
                bytes([self.rule_found_id]))

        # If no rule is found the packet should be fragmented to be sent
        else:
            print("\t\tNo rule found, the packet is dropped.")

    def sendPacketToLA(self):
        return self.compressed_packet_to_send

    def receiveCompressedPacket(self, received_compressed_packet, payload):
        self.received_compressed_packet = received_compressed_packet
        self.received_payload = payload

    def decompressPacket(self):
        # Checks if the received rule is valid
        if(self.received_compressed_packet["rule"] == ""):
            return False
        decompression_rule = int(
            self.received_compressed_packet["rule"])
        '''print("\n\t\tStart decompressing packet with the rule %d...\n" %
              decompression_rule)'''

        #
        for field_name, field_content in self.decompressed_packet.items():
            print("\t\t\tfield %s :" % field_name)

            # It checks if the CDF for that field is "not-sent" according to
            # the rule received
            if self.context[decompression_rule][field_name]["compDecompFct"] == "not-sent":

                # If it is the decompressed value of the field will be the
                # "tagetValue" from that field of the rule received
                self.decompressed_packet[field_name] = self.context[
                    decompression_rule][field_name]["targetValue"]
                '''print("\t\t\t\tdecompressed %s is %s (retrieved from the context)" % (
                    field_name, self.decompressed_packet[field_name]))'''

            # It checks if the CDF for that field is "value-sent" according to
            # the rule received
            elif self.context[decompression_rule][field_name]["compDecompFct"] == "value-sent":

                # If it is the decompressed value of the field will be the same
                # as the compressed value (which has not been compressed)
                self.decompressed_packet[
                    field_name] = self.received_compressed_packet[field_name]
                '''print("\t\t\t\tdecompressed %s is %s (retrieved from the link)" % (
                    field_name, self.decompressed_packet[field_name]))'''

            elif self.context[decompression_rule][field_name]["compDecompFct"] == "remapping":

                # For the moment the field will be remapped by using only LSBs
                # Then the original value is obtained adding two zeros at the
                # MSBs
                self.decompressed_packet[field_name] = b"".join(
                    [b"00", self.received_compressed_packet[field_name]])
                '''print("\t\t\t\tdecompressed %s is %s (retrieved from the link)" % (
                    field_name, self.decompressed_packet[field_name]))'''

            # ESiid and LAiid must be obtained correctly from L2 but for now it
            # will be used the TV
            elif self.context[decompression_rule][field_name]["compDecompFct"] == "ESiid-DID":
                self.decompressed_packet[field_name] = self.context[
                    decompression_rule][field_name]["targetValue"]
                '''print("\t\t\t\tdecompressed %s is %s (retrieved from L2)" % (
                    field_name, self.decompressed_packet[field_name]))'''

            elif self.context[decompression_rule][field_name]["compDecompFct"] == "LAiid-DID":
                self.decompressed_packet[field_name] = self.context[
                    decompression_rule][field_name]["targetValue"]
                '''print("\t\t\t\tdecompressed %s is %s (retrieved from L2)" % (
                    field_name, self.decompressed_packet[field_name]))'''

            # It checks if the CDF for that field is "LSB" according to the
            # rule received
            reg = search(
                'LSB\((.*)\)', self.context[decompression_rule][field_name]["compDecompFct"])
            if reg:
                # The number of LSB to be used is obtained from the rule
                lsb = int(reg.group(1))

                # The MSB are obtained from the "targetValue" of the field from
                # that rule
                ctx_bin = int(self.context[decompression_rule][
                              field_name]["targetValue"], 16)

                # The received value is expressed in binary representation
                rcv_bin = int(self.received_compressed_packet[field_name], 16)

                # The MSB and LSB are mershed with an OR to obtain the final
                # value
                res_or = ctx_bin | rcv_bin

                # The final value is expressed in hexa
                res_or = hexlify(
                    res_or.to_bytes((res_or.bit_length() + 7) // 8, byteorder="big"))
                self.decompressed_packet[field_name] = res_or
                msb = self.field_size[field_name] - lsb
                '''print("\t\t\t\tdecompressed %s is %s (retrieved from the context (%d MSB) and from the link (%d LSB))" % (
                    field_name, self.decompressed_packet[field_name], msb, lsb))'''

        # Now the compute-* fields must be computed

        if self.context[decompression_rule]["UDP_length"]["compDecompFct"] == "compute-UDP-length":
            # Length of the payload plus 8 bytes of the header
            coap_h = b"".join([self.decompressed_packet["CoAP_version"], self.decompressed_packet["CoAP_tokenLength"], self.decompressed_packet[
                "CoAP_code"], self.decompressed_packet["CoAP_messageID"], self.decompressed_packet["CoAP_token"], b"ff"])
            self.coap_packet = b"".join([coap_h, self.received_payload])
            udp_length = int(len(self.coap_packet) / 2) + 8
            if udp_length > 255:
                lsb = udp_length & 0x00FF
                msb = udp_length >> 8
            else:
                lsb = udp_length
                msb = 0
            self.decompressed_packet[
                "UDP_length"] = hexlify(bytes([msb, lsb]))
            '''print("\t\t\t\tUDP Length computed: ",
                  self.decompressed_packet["UDP_length"])'''
            # 16 bits zeros checksum until it is computed
            self.decompressed_packet["UDP_checksum"] = b"0000"
            self.udp_h = b"".join([self.decompressed_packet["UDP_PortES"], self.decompressed_packet["UDP_PortLA"], self.decompressed_packet[
                "UDP_length"], self.decompressed_packet["UDP_checksum"]])
            self.udp_packet = b"".join([self.udp_h, self.coap_packet])

        if self.context[decompression_rule]["UDP_checksum"]["compDecompFct"] == "compute-UDP-checksum":
            udp_pseudo_header = b"".join([self.decompressed_packet["IP_prefixES"],
                                          self.decompressed_packet["IP_iidES"],
                                          self.decompressed_packet[
                                              "IP_prefixLA"],
                                          self.decompressed_packet["IP_iidLA"],
                                          self.decompressed_packet[
                                              "UDP_length"], b"00",
                                          self.decompressed_packet["IP_nextHeader"]])
            checksum_packet = b"".join([udp_pseudo_header, self.udp_packet])
            hex_data = unhexlify(checksum_packet)
            checksum_list = list(hex_data)
            chksm = self.checksum(checksum_list)
            if chksm > 255:
                lsb = chksm & 0x00FF
                msb = chksm >> 8
            else:
                lsb = chksm
                msb = 0
            checksum = bytes([msb, lsb])
            self.decompressed_packet["UDP_checksum"] = hexlify(checksum)
            '''print("\t\t\t\tUDP_Checksum computed: ",
                  self.decompressed_packet["UDP_checksum"])'''

        if self.context[decompression_rule]["IP_payloadLength"]["compDecompFct"] == "compute-IPv6-length":
            ip_payloadlength = int(len(self.udp_packet) / 2)
            if ip_payloadlength > 255:
                lsb = ip_payloadlength & 0x00FF
                msb = ip_payloadlength >> 8
            else:
                lsb = ip_payloadlength
                msb = 0
            self.decompressed_packet[
                "IP_payloadLength"] = hexlify(bytes([msb, lsb]))
            '''print("\t\t\t\tIP Payload Length computed: ",
                  self.decompressed_packet["IP_payloadLength"])'''

    def sendDecompressedPacketToLA(self):
        return self.decompressed_packet

    def printContext(self):
        i = 0
        for rule in self.context:
            print("\t\trule %d :" % i)
            i += 1
            for field_name, field_content in rule.items():
                print("\t\t\tfield %s :" % field_name)
                for field_desc_name, field_desc_content in field_content.items():
                    print("\t\t\t\t %s : %s" %
                          (field_desc_name, field_desc_content))

    def printReceivedPacket(self):
        for field_name, field_content in self.parsedHeaderFields.items():
            '''print("\t\t\t%s : %s" % (field_name, field_content))'''

    def printSentPacket(self):
        for field_name, field_content in self.compressed_packet_to_send.items():
            self.compressed_packet_to_send.items()

    # For now minimum size for each field is a nibble (should be changed)
    # Values should be stored in binary to then join the string -> int -> byte
    def returnCompressedPacket(self, payload):
        compressed_packet = b""
        # self.header_order is used to assure the header packet is formed in
        # the right order since the dictionaries order is not fixed
        for field_name in self.header_order:
            if type(self.compressed_packet_to_send[field_name]) == bytes:
                compressed_packet = b"".join(
                    [compressed_packet, self.compressed_packet_to_send[field_name]])
        compressed_packet = b"".join([compressed_packet, payload])
        return compressed_packet

    # Computes the UDP checksum for the decompressor
    def checksum(self, msg):
        # msg includes the pseudo-header for UDP, the UDP header and the UDP
        # payload.

        # If the length of msg is not even a zero byte is added
        if len(msg) % 2 == 1:
            msg += [0]
        s = 0
        # Loop taking 2 bytes at a time (16 bits)
        for i in range(0, len(msg), 2):
            #w = msg[i] + (msg[i + 1] << 8)
            w = msg[i + 1] + (msg[i] << 8)  # Primer bit es el mas grande
            s = s + w
        while s > 0xffff:
            s = (s >> 16) + (s & 0xffff)
        # Complement and mask to 2 bytes (dont know for what is this last part)
        s = ~s & 0xffff
        return s

    # This function fills strtofill with nbz zeros at the the MSBs
    def zfill(self, strtofill, nbz):
        filledstr = strtofill
        for i in range(nbz):
            filledstr = "0" + filledstr
        return filledstr

    # Completes the field with zeros up to its size
    def complete_field_zeros(self, field, field_length):
        nibbles = int(field_length / 4)
        while(len(field) < nibbles):
            field = b"".join([b"0", field])
        return field
