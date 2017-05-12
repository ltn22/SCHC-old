/**
 * Created by Philippe Clavier on 20/03/2017.
 */

// Rules Definitions

var rule0 = {
    "IP_version": {
        "targetValue": "6",
        "matchingOperator": "equal",
        "compDecompFct": "not-sent",
        "direction": "bi"
    },
    "IP_trafficClass": {
        "targetValue": "00",
        "matchingOperator": "equal",
        "compDecompFct": "not-sent",
        "direction": "bi"
    },
    "IP_flowLabel": {
        "targetValue": "00000",
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
        "targetValue": "11",
        "matchingOperator": "equal",
        "compDecompFct": "not-sent",
        "direction": "bi"
    },
    "IP_hopLimit": {
        "targetValue": "40",
        "matchingOperator": "equal",
        "compDecompFct": "not-sent",
        "direction": "bi"
    },
    "IP_prefixES": {
        "targetValue": "20010db80a0b12f0",
        "matchingOperator": "equal",
        "compDecompFct": "not-sent",
        "direction": "bi"
    },
    "IP_iidES": {
        "targetValue": "",
        "matchingOperator": "ignore",
        "compDecompFct": "ESiid-DID",
        "direction": "bi"
    },
    "IP_prefixLA": {
        "targetValue": "2d513de80a0b4df0",
        "matchingOperator": "equal",
        "compDecompFct": "not-sent",
        "direction": "bi"
    },
    "IP_iidLA": {
        "targetValue": "",
        "matchingOperator": "ignore",
        "compDecompFct": "LAiid-DID",
        "direction": "bi"
    },
    "UDP_PortES": {
        "targetValue": "1f90",
        "matchingOperator": "equal",
        "compDecompFct": "not-sent",
        "direction": "bi"
    },
    "UDP_PortLA": {
        "targetValue": "2382",
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
        "targetValue": "1",
        "matchingOperator": "equal",
        "compDecompFct": "not-sent",
        "direction": "bi"
    },
    "CoAP_type": {
        "targetValue": "1",
        "matchingOperator": "equal",
        "compDecompFct": "not-sent",
        "direction": "bi"
    },
    "CoAP_tokenLength": {
        "targetValue": "1",
        "matchingOperator": "equal",
        "compDecompFct": "not-sent",
        "direction": "bi"
    },
    "CoAP_code": {
        "targetValue": "02",
        "matchingOperator": "equal",
        "compDecompFct": "not-sent",
        "direction": "bi"
    },
    "CoAP_messageID": {
        "targetValue": "000000000000",
        "matchingOperator": "MSB(12)",
        "compDecompFct": "LSB(4)",
        "direction": "bi"
    },
    "CoAP_token": {
        "targetValue": "",
        "matchingOperator": "ignore",
        "compDecompFct": "value-sent",
        "direction": "bi"
    }
};

var rule1 = {
    "IP_version": {
        "targetValue": "6",
        "matchingOperator": "equal",
        "compDecompFct": "not-sent",
        "direction": "bi"
    },
    "IP_trafficClass": {
        "targetValue": "00",
        "matchingOperator": "equal",
        "compDecompFct": "not-sent",
        "direction": "bi"
    },
    "IP_flowLabel": {
        "targetValue": "00000",
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
        "targetValue": "11",
        "matchingOperator": "equal",
        "compDecompFct": "not-sent",
        "direction": "bi"
    },
    "IP_hopLimit": {
        "targetValue": "40",
        "matchingOperator": "equal",
        "compDecompFct": "not-sent",
        "direction": "bi"
    },
    "IP_prefixES": {
        "targetValue": {
            "1": "20010db80a0b12f0",
            "2": "2d513de80a0b4df0"
        },
        "matchingOperator": "match-mapping",
        "compDecompFct": "mapping-sent(4)",
        "direction": "bi"
    },
    "IP_iidES": {
        "targetValue": "",
        "matchingOperator": "ignore",
        "compDecompFct": "ESiid-DID",
        "direction": "bi"
    },
    "IP_prefixLA": {
        "targetValue": {
            "1": "20010db80a0b12f0",
            "2": "2d513de80a0b4df0",
        },
        "matchingOperator": "match-mapping",
        "compDecompFct": "mapping-sent(4)",
        "direction": "bi"
    },
    "IP_iidLA": {
        "targetValue": "",
        "matchingOperator": "ignore",
        "compDecompFct": "LAiid-DID",
        "direction": "bi"
    },
    "UDP_PortES": {
        "targetValue": "1f90",
        "matchingOperator": "equal",
        "compDecompFct": "not-sent",
        "direction": "bi"
    },
    "UDP_PortLA": {
        "targetValue": "2382",
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
        "targetValue": "1",
        "matchingOperator": "equal",
        "compDecompFct": "not-sent",
        "direction": "bi"
    },
    "CoAP_type": {
        "targetValue": "1",
        "matchingOperator": "equal",
        "compDecompFct": "not-sent",
        "direction": "bi"
    },
    "CoAP_tokenLength": {
        "targetValue": "1",
        "matchingOperator": "equal",
        "compDecompFct": "not-sent",
        "direction": "bi"
    },
    "CoAP_code": {
        "targetValue": "02",
        "matchingOperator": "equal",
        "compDecompFct": "not-sent",
        "direction": "bi"
    },
    "CoAP_messageID": {
        "targetValue": "000000000000",
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
        "targetValue": "b3666f6f",  // "foo"
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
};

// Importing the module
var Compressor_Decompressor = require('../lib/schc_cd');
// Importing parser module
var Parser = require('../lib/parser');

// Creating new (empty) Compressor_Decompressor
var CD = new Compressor_Decompressor();
// Creating new Parser
var parser = new Parser();

// Initializing the Compressor/Decompressor
CD.initializeCD();

// Adding a rule to the CDF context (for the moment must be added in order)
CD.addCompressionRule(rule0);
CD.addCompressionRule(rule1);

// PARSING
// Parsing the CoAP/UDP/IPv6 packet packet to be analysed by the Compressor
console.log("\n\t## Beginning of parsing ##");
parser.parse("60000000001a114020010db80a0b12f070b3d549925aa6192d513de80a0b4df0ada4dae3ac12676b1f902382001a0a94510200010ab3666f6f03626172ff01");
console.log(parser.header_fields);

// COMPRESSION
// Load the parsed header fields and the payload to the compressor
CD.loadFromParser(parser.header_fields, parser.coap_header_options, parser.payload);

// Search of matching rule in the context
console.log("\t## Searching matching rule in context ##");
CD.analyzePacketToSend();

// Compression of the packet to send
if (CD.rule_found){
    console.log("\t## Compression of the packet to send ##");
    CD.compressPacket();
    // Append the compressed header fields into a packet to be sent
    console.log("\t## Appending the compressed header fields and message ##");
    CD.appendCompressedPacket();
    console.log("\t\t", CD.compressed_packet);
}

// DECOMPRESSION
// Parsing the compressed packet received
CD.parseCompressedPacket(CD.compressed_packet); // Example message compressed message with rule 1
// Load IIDs obtained from L2 (ESiid, LAiid)
CD.loadIIDs("70b3d549925aa619","ada4dae3ac12676b"); // Examples of IIDs
// Decompression of the header according to the rule
CD.decompressHeader();

// The decompressed_packet from de CD is only the header, adding the payload the complete packet is obtained
CD.decompressed_packet = CD.decompressed_packet + CD.received_payload;
