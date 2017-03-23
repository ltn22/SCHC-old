'''
Created on 2 mar. 2017

@author: Philippe Clavier
'''

import binascii
#from pip._vendor.pkg_resources import msg

# Class CoAP to be moved into a module (based on txThings)
# https://github.com/mwasilak/txThings/blob/master/txthings/coap.py

CON = 0
"""Confirmable message type."""

NON = 1
"""Non-confirmable message type."""

ACK = 2
"""Acknowledgement message type."""

RST = 3
"""Reset message type"""

types = {0: 'CON',
         1: 'NON',
         2: 'ACK',
         3: 'RST'}

EMPTY = 0
GET = 1
POST = 2
PUT = 3
DELETE = 4
CREATED = 65
DELETED = 66
VALID = 67
CHANGED = 68
CONTENT = 69
CONTINUE = 95
BAD_REQUEST = 128
UNAUTHORIZED = 129
BAD_OPTION = 130
FORBIDDEN = 131
NOT_FOUND = 132
METHOD_NOT_ALLOWED = 133
NOT_ACCEPTABLE = 134
REQUEST_ENTITY_INCOMPLETE = 136
PRECONDITION_FAILED = 140
REQUEST_ENTITY_TOO_LARGE = 141
UNSUPPORTED_CONTENT_FORMAT = 143
INTERNAL_SERVER_ERROR = 160
NOT_IMPLEMENTED = 161
BAD_GATEWAY = 162
SERVICE_UNAVAILABLE = 163
GATEWAY_TIMEOUT = 164
PROXYING_NOT_SUPPORTED = 165

requests = {1: 'GET',
            2: 'POST',
            3: 'PUT',
            4: 'DELETE'}

requests_rev = {v: k for k, v in requests.items()}

IF_MATCH = 1
URI_HOST = 3
ETAG = 4
IF_NONE_MATCH = 5
OBSERVE = 6
URI_PORT = 7
LOCATION_PATH = 8
URI_PATH = 11
CONTENT_FORMAT = 12
MAX_AGE = 14
URI_QUERY = 15
ACCEPT = 17
LOCATION_QUERY = 20
BLOCK2 = 23
BLOCK1 = 27
SIZE2 = 28
PROXY_URI = 35
PROXY_SCHEME = 39
SIZE1 = 60

options = {1: 'If-Match',
           3: 'Uri-Host',
           4: 'ETag',
           5: 'If-None-Match',
           6: 'Observe',
           7: 'Uri-Port',
           8: 'Location-Path',
           11: 'Uri-Path',
           12: 'Content-Format',
           14: 'Max-Age',
           15: 'Uri-Query',
           17: 'Accept',
           20: 'Location-Query',
           23: 'Block2',
           27: 'Block1',
           28: 'Size2',
           35: 'Proxy-Uri',
           39: 'Proxy-Scheme',
           60: 'Size1'}

options_rev = {v: k for k, v in options.items()}


class coap_message:
    """
    class CoAP for client and server
    """

    def __init__(self):
        self.buffer = []
        self.mid = 1
        self.option = 0
        '''print('Class CoAP created')'''

    def __dump_buffer(self):
        for octets in self.buffer:
            print(hex(octets), end='-')

    def new_header(self, coap_type=NON, code=POST, token=0x12):
        self.buffer = []

        # First 32 bit word
        # Version | Type | Token Length
        byte = (1 << 6) | (coap_type << 4) | 0x01
        self.buffer.append(byte)
        self.buffer.append(code)           # Code
        self.buffer.append(self.mid >> 8)  # Message ID
        self.buffer.append(self.mid & 0x00FF)
        self.mid += 1
        # Token (1 Byte)
        self.buffer.append(token)

    # T - option value, L - length
    def __add_option_TL(self, T, L):
        # Find the diferential value (delta) with the previous option
        delta = T - self.option
        # Save the new option
        self.option = T
        # The option delta and the option length can not be greater than 12
        if (delta < 13) and (L < 13) is True:
            # The option delta and the option length are added to the buffer
            self.buffer.append((delta << 4) | L)
        else:
            print('Not Done')

    def add_option_path(self, path=''):
        # The option is 'Uri-Path' (11) and its the path length has to be
        # passed
        self.__add_option_TL(11,  len(path))
        # The path is added to the buffer
        for char in path:
            self.buffer.append(ord(char))

        '''print('add option ')'''

    # Payload Marker to signal the end of options and the start of the payload
    def end_option(self):
        self.buffer.append(0xFF)

    def add_value(self,  m=''):
        '''print('Type = ', type(m))'''

        if (type(m)) == type(str()):
            '''print("we have a string")'''
            # Add the value to the buffer converting every char to int
            for char in m:
                self.buffer.append(ord(char))
        elif (type(m) == CBOR):
            '''print('du CBOR')'''
            # Add the value to the buffer
            for char in m.buffer:
                self.buffer.append(char)

        '''self.__dump_buffer()'''

    def to_coap(self):
        return self.buffer


class udp_header:
    """
    udp header
    """

    def __init__(self):
        self.buffer = []
        '''print('Class UDP created')'''

    def add_header(self, coap=[]):
        self.buffer = []

        source_port = 8080
        destination_port = 9090
        length = len(coap)
        self.add_two_bytes_field(source_port)
        self.add_two_bytes_field(destination_port)
        self.add_two_bytes_field(length)
        coap_checksum = self.checksum(coap)
        self.add_two_bytes_field(coap_checksum)
        self.buffer = self.buffer + coap

    def add_two_bytes_field(self, value):
        if value > 255:
            lsb = value & 0x00FF
            msb = value >> 8
        else:
            lsb = value
            msb = 0
        self.buffer = self.buffer + [msb, lsb]

    def checksum(self, msg):
        # Here needs to be included the pseudo-header for UDP and the UDP
        # header
        if len(msg) % 2 == 1:
            '''print("need to add 0")'''
            msg += [0]
        s = 0
        # loop taking 2 characters at a time
        for i in range(0, len(msg), 2):
            if type(msg[i]) == int:
                if type(msg[i + 1]) == int:
                    w = msg[i + 1] + (msg[i] << 8)
                else:
                    w = msg[i + 1] + (ord(msg[i]) << 8)
            else:
                if type(msg[i + 1]) == int:
                    w = ord(msg[i + 1]) + (msg[i] << 8)
                else:
                    w = ord(msg[i + 1]) + (ord(msg[i]) << 8)
            s = s + w
        while s > 0xffff:
            s = (s >> 16) + (s & 0xffff)
        # complement and mask to 4 byte short
        s = ~s & 0xffff
        #    print "the results is " + str(s)
        return s


class ipv6_header:
    """
    ipv6 header
    """

    def __init__(self):
        self.buffer = []
        '''print('Class IPv6 created')'''

    def add_header(self, msg=[]):
        self.buffer = []
        udp_coap = b""
        version = b"6"
        traffic_class = b"00"
        flow_label = b"00000"
        payload_length = binascii.hexlify(bytes([len(msg)]))
        payload_length = self.complete_field_zeros(payload_length, 16)
        next_header = b"11"
        hop_limit = b"40"
        source_address = b"20010db80a0b12f00000000000000001"
        destination_adress = b"2d513de80a0b4df00000000000000001"
        for item in msg:
            udp_coap = b"".join([udp_coap, binascii.hexlify(bytes([item]))])
        self.buffer = b"".join([version, traffic_class, flow_label, payload_length, next_header,
                                hop_limit, source_address, destination_adress, udp_coap])

    # The function receives the length of the field in bits and completes de
    # byte type with zeros in the MSBs
    def complete_field_zeros(self, field, field_length):
        nibbles = int(field_length / 4)
        while(len(field) != nibbles):
            field = b"".join([b"0", field])
        return field

# Class CBOR

CBOR_POSITIVE = 0x00
CBOR_NEGATIVE = 0x20

# The Class CBOR initializes a buffer where the value passed is encoded in CBOR


class CBOR:

    def __init__(self,  value):
        self.buffer = []

        '''print("TYPE de CBOR = ",  type(value))'''

        # if the value is an int
        if type(value) is int:
            # Check if the value is positive or negative
            if (value >= 0):
                self.buffer.append(CBOR_POSITIVE)
            else:
                self.buffer.append(CBOR_NEGATIVE)
                value = -1 * value
                value = value + 1

            # Check if the value is less than 24
            if (value < 24):
                self.buffer[0] |= value
                return
            else:
                # if its greater it
                # finds the size in bits (first bit to the left != 0)
                for i in range(31,  0,  -1):
                    if ((0x01 << i) & value):
                        break

                '''print('i=',  i)'''

                # depending on the number of bits... (CBOR)
                if (i < 7):
                    self.buffer[0] |= 24  # "bitwise or"
                    nb_byte = 1
                elif (i < 15):
                    self.buffer[0] |= 25
                    nb_byte = 2
                elif (i < 31):
                    self.buffer[0] |= 26
                    nb_byte = 4
                elif (i < 63):
                    self.buffer[0] |= 27
                    nb_byte = 8
                else:
                    print('Too big number')
                    return

                '''print('size =',  nb_byte)'''

                for k in range(nb_byte,  0,  -1):
                    msk = 0xFF << 8 * (k - 1)   # the MSB is a mask (0xFF)
                    result = (value & msk) >> 8 * (k - 1)
                    '''print('====', k, ':', hex(msk),  '==',  hex(result))'''
                    self.buffer.append(result)

            return  # end of Int

        # if value is a list
        if type(value) is list:
            l = len(value)
            if (l < 23):
                self.buffer.append(0x80 | l)
            else:
                print('Too much elements')
                return
            '''print(value)'''
            for elm in value:
                # All values in the list are summed up
                self.buffer += elm.buffer

    def dump(self):
        if ((self.buffer[0] & CBOR_POSITIVE) == CBOR_POSITIVE):
            print('POSITIVE ',  hex(self.buffer[0]))
