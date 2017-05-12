'''
Created on 2 mar. 2017

@author: Philippe Clavier
'''

from re import search
from binascii import hexlify
from builtins import enumerate


class Compressor:

    def __init__(self):

        self.context = []
        self.parsedHeaderFields = {}
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
##############    Here Starts The Compression Functions    ##############
#########################################################################

    def loadFromParser(self, parsedHeaderFields, coap_header_options, payload):
        self.parsedHeaderFields = parsedHeaderFields
        self.coap_header_options = coap_header_options
        self.payload = payload

        # Reset initial values
        self.compressed_header_fields = {
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
        self.header_order = ["IP_version", "IP_trafficClass", "IP_flowLabel",
                             "IP_payloadLength", "IP_nextHeader", "IP_hopLimit", "IP_prefixES", "IP_iidES",
                             "IP_prefixLA", "IP_iidLA", "UDP_PortES", "UDP_PortLA",
                             "UDP_length", "UDP_checksum", "CoAP_version", "CoAP_type", "CoAP_tokenLength",
                             "CoAP_code", "CoAP_messageID", "CoAP_token"]

    def analyzePacketToSend(self):
        # The first thing will be to compare every rule from the context with
        # the packet to be analysed, and check if it is possible to use any
        # compression rule for this packet
        self.rule_found = False
        self.rule_found_id = 0
        i = 0

        # I add this to know every field received has a match
        fieldsMatchCheck = self.parsedHeaderFields.copy()

        for rule in self.context:
            '''print("\n\t\tAnalyzing rule %d..." % i)'''

            # Each field in the rule will be analysed
            for field_name, field_content in rule.items():
                '''print("\t\t\tfield %s :" % field_name)'''

                matched = False

                if field_content["direction"] == "dw":
                    break

                # It is checked which is the "matchingOperator" for that field

                if field_content["matchingOperator"] == "equal":
                    '''print("\t\t\t\t%s context value is %s and received value is %s..." % (
                        field_name, field_content["targetValue"], self.parsedHeaderFields[field_name]))'''

                    # If the "matchingOperator" is "equal" the "targetValue" of
                    # the rule is compared to the received packet field value
                    # and check if there is a match
                    if field_content["targetValue"] == self.parsedHeaderFields[field_name]:
                        '''print("\t\t\t\t\t...it is a match.")'''
                        fieldsMatchCheck[field_name] = True
                        matched = True

                if field_content["matchingOperator"] == "ignore":

                    # If the "matchingOperator" is "ignore" this fields value
                    # is ignored
                    '''print("\t\t\t\t%s context value is %s and received value is %s..." % (
                        field_name, field_content["targetValue"], self.parsedHeaderFields[field_name]))'''
                    '''print("\t\t\t\t\t...but they are ignored.")'''
                    fieldsMatchCheck[field_name] = True
                    matched = True

                if field_content["matchingOperator"] == "match-mapping":
                    # Every item in the target value should be checked for a
                    # matching

                    for mapping_id, mapping_value in field_content["targetValue"].items():
                        if mapping_value == self.parsedHeaderFields[field_name]:
                            fieldsMatchCheck[field_name] = True
                            matched = True
                            break

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

                    ctx_bin = field_content["targetValue"]
                    #ctx_bin = bin(int(field_content["targetValue"], 16))[2:]

                    # rcv_bin will have the value of the recieved packet field
                    # in binary representation
                    rcv_bin = bin(
                        int(self.parsedHeaderFields[field_name], 16))[2:]

                    # ctx_nbz will be the size of the field name minus the
                    # length of the "tagetValue"
                    ctx_nbz = self.field_size[field_name] - len(ctx_bin)
                    # ctx_bin is filled with zeros for the diference in size
                    ctx_bin = zfill(ctx_bin, ctx_nbz)

                    # rcv_nbz will be the size of the field name minus the
                    # length of the received field value
                    rcv_nbz = self.field_size[field_name] - len(rcv_bin)
                    # rcv_bin is filled with zeros for the diference in size
                    rcv_bin = zfill(rcv_bin, rcv_nbz)

                    # Here it is checked if the MSB of the "targetValue" and
                    # the value of the recieved packet field are the same
                    if ctx_bin[0:msb] == rcv_bin[0:msb]:
                        '''print(
                            "\t\t\t\t\t...it is a match on the first %d bits." % msb)'''
                        fieldsMatchCheck[field_name] = True
                        matched = True

                if matched == False:
                    break

            # It is checked that every field received has an appropriate
            # compression
            for field_name, field_value in fieldsMatchCheck.items():
                if field_value != True:
                    # print(
                    #    "\n\t\tNo compression for", field_name, "field in this rule.")
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
                self.rule_found = False
            i += 1

    def compressPacket(self):
        # If a rule is found the packet is compressed according to the selected
        # rule
        if self.rule_found:
            '''print("\n\t\tStart compressing packet with the rule %d...\n" %
                  self.rule_found_id)'''

            self.header_order = self.header_order + self.coap_header_options

            # In this iterations the "compDecompFct" is analysed for each field
            # of the selected rule
            for order, field_name in enumerate(self.header_order):
                '''print("\t\t\tfield %s :" % field_name)'''

                # It is checked if the "compDecompFct" of the field contains
                # "LSB"
                reg = search(
                    'LSB\((.*)\)', self.context[self.rule_found_id][field_name]["compDecompFct"])
                if reg:
                    # group(1) returns the first parenthesized subgroup
                    lsb = int(reg.group(1))

                    # The field value from the received packet is expressed in
                    # binary
                    rcv_bin = bin(
                        int(self.parsedHeaderFields[field_name], 16))[2:]

                    # rcv_nbz calculates the difference between the
                    # field size and the received value length (in bits)
                    rcv_nbz = self.field_size[
                        field_name] - len((rcv_bin))

                    # rcv_bin is then completed with rcv_nbz zeros
                    rcv_bin = zfill(rcv_bin, rcv_nbz)

                    # The LSB bits from rcv_bin to be send are separeted
                    # The rcv_bin bits are selected from (field_size - lsb) to
                    # field_size
                    rcv_bin = rcv_bin[
                        self.field_size[field_name] - lsb:self.field_size[field_name]]

                    # Save it as binary, so that it can be then appended in a
                    # compressed packet
                    self.compressed_header_fields[field_name] = rcv_bin

                reg = search(
                    'mapping-sent\((.*)\)', self.context[self.rule_found_id][field_name]["compDecompFct"])
                if reg:
                    # The value matched is searched and the mapping ID is saved

                    for mapping_id, mapping_value in self.context[self.rule_found_id][field_name]["targetValue"].items():
                        if mapping_value == self.parsedHeaderFields[field_name]:
                            # Save it as binary
                            rcv_bin = bin(int(mapping_id, 16))[2:]
                            rcv_nbz = lsb = int(reg.group(1)) - len(rcv_bin)
                            rcv_bin = zfill(rcv_bin, rcv_nbz)
                            self.compressed_header_fields[field_name] = rcv_bin
                            break

                # It is checked if the "compDecompFct" of the field contains
                # "value-sent"
                elif self.context[self.rule_found_id][field_name]["compDecompFct"] == "value-sent":

                    # If an option_value is sent, the length is added as a
                    # first byte to the data
                    data = self.parsedHeaderFields[field_name]
                    # ALL OPTION SENT
                    # Order is the field order number
                    if(order >= 20):
                        option_length = int(
                            len(self.parsedHeaderFields[field_name]) / 2)

                        # Save it as binary (options)
                        rcv_bin = bin(int(data, 16))[2:]
                        rcv_nbz = option_length * 8 - len(rcv_bin)

                    else:
                        # Save it as binary (not-option)
                        rcv_bin = bin(int(data, 16))[2:]
                        rcv_nbz = self.field_size[field_name] - len(rcv_bin)

                    rcv_bin = zfill(rcv_bin, rcv_nbz)
                    self.compressed_header_fields[field_name] = rcv_bin

                    '''print("\t\t\t\tfield content of %s is sent to the server, value is %s" % (
                        field_name, self.compressed_header_fields[field_name]))'''

                # In any other case the field is omitted
                # All fields with compute-* are not sent
                else:
                    '''print("\t\t\t\tfield elided.")'''
                    if(order >= 20):
                        # If not when appending the packet it wont find the
                        # field and show an error
                        self.compressed_header_fields[field_name] = ""

            # The selected ruled is also sent in the packet
            self.compressed_header_fields["rule"] = hexlify(
                bytes([self.rule_found_id]))

        # If no rule is found the packet should be fragmented to be sent
        else:
            print("\t\tNo rule found, the packet is dropped.")

    # For now minimum size for each field is a nibble (should be changed)
    def appendCompressedPacket(self):
        self.compressed_packet = self.compressed_header_fields["rule"]
        auxBuffer = ""

        # self.header_order is used to assure the header packet is formed in
        # the right order since the dictionaries order is not fixed
        for field_name in self.header_order:
            # ACA juntar string binaria -> pasar a bytes -> unir regla con
            # header fields y payload
            tipo = type(self.compressed_header_fields[field_name])
            if tipo != bytes:
                auxBuffer = auxBuffer + \
                    self.compressed_header_fields[field_name]

        # Data is arranged to be sent in nibbles
        while len(auxBuffer) >= 4:
            one_nibble = auxBuffer[0:4]
            one_nibble = int(one_nibble, 2)
            one_nibble = hexlify(bytes([one_nibble]))[1:]
            self.compressed_packet = b"".join(
                [self.compressed_packet, one_nibble])
            auxBuffer = auxBuffer[4:]

        if len(auxBuffer) > 0:
            one_nibble = zfill(auxBuffer, 4 - len(auxBuffer))
            one_nibble = int(one_nibble, 2)
            one_nibble = hexlify(bytes([one_nibble]))[1:]
            self.compressed_packet = b"".join(
                [self.compressed_packet, one_nibble])

        # Data is sent in bytes, so there should be an even quantity of nibbles
        # An extra zero is added if necessary
        if len(self.compressed_packet) % 2 != 0:
            self.compressed_packet = b"".join(
                [self.compressed_packet, b"0"])

        self.compressed_packet = b"".join(
            [self.compressed_packet, self.payload])

#########################################################################
##############             Auxiliary Functions             ##############
#########################################################################

# This function fills strtofill with nbz zeros at the the MSBs


def zfill(strtofill, nbz):
    filledstr = strtofill
    for i in range(nbz):
        filledstr = "0" + filledstr
    return filledstr


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


def itemgetter(*items):
    if len(items) == 1:
        item = items[0]

        def g(obj):
            return obj[item]
    else:
        def g(obj):
            return tuple(obj[item] for item in items)
    return g
