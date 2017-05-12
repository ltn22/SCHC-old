'''
Created on 2 mar. 2017

@author: Philippe Clavier
'''

from binascii import hexlify

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
        print("\n\t\tInitializing Parser")

    def parser(self, packet):
        self.sepacketHexaContent = packet
        self.coap_header_options = []
        self.header_fields = {}

        self.header_fields["IP_version"] = self.sepacketHexaContent[0:1]
        self.header_fields["IP_trafficClass"] = self.sepacketHexaContent[1:3]
        self.header_fields["IP_flowLabel"] = self.sepacketHexaContent[3:8]
        self.header_fields["IP_payloadLength"] = self.sepacketHexaContent[8:12]
        self.header_fields["IP_nextHeader"] = self.sepacketHexaContent[12:14]
        self.header_fields["IP_hopLimit"] = self.sepacketHexaContent[14:16]
        self.header_fields["IP_prefixES"] = self.sepacketHexaContent[16:32]
        self.header_fields["IP_iidES"] = self.sepacketHexaContent[32:48]
        self.header_fields["IP_prefixLA"] = self.sepacketHexaContent[48:64]
        self.header_fields["IP_iidLA"] = self.sepacketHexaContent[64:80]
        self.header_fields["UDP_PortES"] = self.sepacketHexaContent[80:84]
        self.header_fields["UDP_PortLA"] = self.sepacketHexaContent[84:88]
        self.header_fields["UDP_length"] = self.sepacketHexaContent[88:92]
        self.header_fields["UDP_checksum"] = self.sepacketHexaContent[92:96]
        coap_version_type = self.sepacketHexaContent[96:97]
        self.header_fields["CoAP_version"] = hexlify(bytes(
            [int(coap_version_type, 16) >> 2]))[1:]
        self.header_fields["CoAP_type"] = hexlify(
            (bytes([int(coap_version_type) & 3])))[1:]
        self.header_fields[
            "CoAP_tokenLength"] = self.sepacketHexaContent[97:98]
        token_length = int(self.sepacketHexaContent[97:98])
        self.header_fields["CoAP_code"] = self.sepacketHexaContent[98:100]
        self.header_fields[
            "CoAP_messageID"] = self.sepacketHexaContent[100:104]
        self.header_fields["CoAP_token"] = self.sepacketHexaContent[
            104:104 + token_length * 2]

        start = 104 + token_length * 2
        end = start + 1
        option_number = 0

        while(self.sepacketHexaContent[start:end + 1] != b"ff" and end <= len(self.sepacketHexaContent)):
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
                option_value = self.sepacketHexaContent[
                    start - 2:end]  # Include delta+length (-2) # ALL OPTION SENT
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

        del self.sepacketHexaContent
        del token_length, coap_version_type, start, end, option_number, option_position, option_name, option_value, option_delta, option_length
