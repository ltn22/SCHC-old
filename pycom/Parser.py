'''
Created on 2 mar. 2017

@author: Philippe Clavier
'''

from binascii import hexlify, unhexlify

option_names = {
    1: "CoAP_If-Match",
    3: "CoAP_Uri-Host",
    4: "CoAP_ETag",
    5: "CoAP_If-None-Match",
    6: "CoAP_Observe",
    7: "CoAP_Uri-Port",
    8: "CoAP_Location-Path",
    11: "CoAP_Uri-Path",
    12: "CoAP_Content-Format",
    14: "CoAP_Max-Age",
    15: "CoAP_Uri-Query",
    17: "CoAP_Accept",
    20: "CoAP_Location-Query",
    23: "CoAP_Block2",
    27: "CoAP_Block1",
    28: "CoAP_Size2",
    35: "CoAP_Proxy-Uri",
    39: "CoAP_Proxy-Scheme",
    60: "CoAP_Sizel",
    258: "CoAP_No-Response"
}


class Parser:

    def __init__(self):
        self.header_fields = {}
        self.payload = b""

    def parser(self, packet):
        self.sepacketHexaContent = packet

        # The complete trame content in printed
        '''print("\n\t\tTrame content (hexa): %s" % self.sepacketHexaContent)'''

        # The "IP_version" field is pulled apart
        self.header_fields["IP_version"] = self.sepacketHexaContent[0:1]
        '''print("\n\t\t\tIP version (decimal): %d" %
              int(self.header_fields["IP_version"], 16))'''

        # The "IP_trafficClass" field is pulled apart
        self.header_fields["IP_trafficClass"] = self.sepacketHexaContent[1:3]
        '''print("\t\t\tIP Traffic Class (hexa): %s" %
              self.header_fields["IP_trafficClass"])'''

        # The "IP_flowLabel" field is pulled apart
        self.header_fields["IP_flowLabel"] = self.sepacketHexaContent[3:8]
        '''print("\t\t\tIP Flow Label (hexa): %s" %
              self.header_fields["IP_flowLabel"])'''

        # The "IP_payloadLength" field is pulled apart
        self.header_fields["IP_payloadLength"] = self.sepacketHexaContent[8:12]
        '''print("\t\t\tIP Payload Length (decimal): %d" %
              int(self.header_fields["IP_payloadLength"], 16))'''

        # The "IP_nextHeader" field is pulled apart
        self.header_fields["IP_nextHeader"] = self.sepacketHexaContent[12:14]
        '''print("\t\t\tIP Next Header (decimal): %d" %
              int(self.header_fields["IP_nextHeader"], 16))'''

        # The "IP_hopLimit" field is pulled apart
        self.header_fields["IP_hopLimit"] = self.sepacketHexaContent[14:16]
        '''print("\t\t\tIP Hop Limit (decimal): %d" %
              int(self.header_fields["IP_hopLimit"], 16))'''

        # The "IP_prefixES" field is pulled apart
        self.header_fields[
            "IP_prefixES"] = self.sepacketHexaContent[16:32]
        '''print("\t\t\tIP ES Prefix (hexa): %s" %
              self.header_fields["IP_prefixES"])'''

        # The "IP_iidES" field is pulled apart
        self.header_fields[
            "IP_iidES"] = self.sepacketHexaContent[32:48]
        '''print("\t\t\tIP ED IID (hexa): %s" %
              self.header_fields["IP_iidES"])'''

        # The "IP_prefixLA" field is pulled apart
        self.header_fields[
            "IP_prefixLA"] = self.sepacketHexaContent[48:64]
        '''print("\t\t\tIP LA Prefix (hexa): %s" %
              self.header_fields["IP_prefixLA"])'''

        # The "IP_iidLA" field is pulled apart
        self.header_fields[
            "IP_iidLA"] = self.sepacketHexaContent[64:80]
        '''print("\t\t\tIP LA IID (hexa): %s" %
              self.header_fields["IP_iidLA"])'''

        # The "UDP_PortES" field is pulled apart
        self.header_fields["UDP_PortES"] = self.sepacketHexaContent[80:84]
        '''print("\t\t\tUDP ES Port (decimal): %d" %
              int(self.header_fields["UDP_PortES"], 16))'''

        # The "UDP_PortLA" field is pulled apart
        self.header_fields[
            "UDP_PortLA"] = self.sepacketHexaContent[84:88]
        '''print("\t\t\tUDP LA Port (decimal): %d" %
              int(self.header_fields["UDP_PortLA"], 16))'''

        # The "UDP_length" field is pulled apart
        self.header_fields["UDP_length"] = self.sepacketHexaContent[88:92]
        '''print("\t\t\tUDP Length (decimal): %d" %
              int(self.header_fields["UDP_length"], 16))'''

        # The "UDP_checksum" field is pulled apart
        self.header_fields["UDP_checksum"] = self.sepacketHexaContent[92:96]
        '''print("\t\t\tUDP Checksum (hexa): %s" %
              self.header_fields["UDP_checksum"])'''

        coap_version_type = self.sepacketHexaContent[96:97]

        self.header_fields["CoAP_version"] = hexlify(bytes(
            [int(coap_version_type, 16) >> 2]))[1:]
        '''print("\t\t\tCoAP version (decimal): %d" %
              int(self.header_fields["CoAP_version_bin"], 2))'''

        self.header_fields["CoAP_type"] = hexlify(
            (bytes([int(coap_version_type) & 3])))[1:]
        '''print("\t\t\tCoAP Type (decimal): %d" %
              int(self.header_fields["CoAP_type_bin"], 2))'''

        self.header_fields[
            "CoAP_tokenLength"] = self.sepacketHexaContent[97:98]
        '''print("\t\t\tCoAP Token Length (decimal): %d" %
              int(self.header_fields["CoAP_tokenLength"], 16))'''

        self.header_fields["CoAP_code"] = self.sepacketHexaContent[98:100]
        '''print("\t\t\tCoAP Code (decimal): %d" %
              int(self.header_fields["CoAP_code"], 16))'''

        self.header_fields[
            "CoAP_messageID"] = self.sepacketHexaContent[100:104]
        '''print("\t\t\tCoAP MessageID (decimal): %d" %
              int(self.header_fields["CoAP_messageID"], 16))'''

        self.header_fields[
            "CoAP_token"] = self.sepacketHexaContent[104:106]
        '''print("\t\t\tCoAP Token (decimal): %d" %
              int(self.header_fields["CoAP_token"], 16))'''

        start = 106
        end = 107
        option_number = 0
        self.coap_header_options = []

        while(self.sepacketHexaContent[start:end + 1] != b"ff"):
            #print("Here options should be parsed in the appropriate way")
            if option_number > 60:
                print("error when parsing coap options")
                break
            option_position = 1
            option_delta = int(self.sepacketHexaContent[start:end], 16)
            option_number += option_delta
            start += 1
            end += 1
            option_length = int(self.sepacketHexaContent[start:end], 16)
            if option_length != 0:
                start += 1
                end += option_length * 2
                option_value = self.sepacketHexaContent[start:end]
                if option_delta == 0:
                    option_position += 1
                option_name = option_names[
                    option_number] + " " + str(option_position)
                self.header_fields[option_name] = option_value
                self.coap_header_options.append(option_name)
                start += option_length * 2
                end += 1
            else:
                start += 1
                end += 1
        else:
            self.payload = self.sepacketHexaContent[end + 1:]
