/**
 * Created by Philippe Clavier on 20/03/2017.
 */

// Rules Definitions

var rule0 = {
    "IP_version": {
        "targetValue": "6",
        "matchingOperator": "equal",
        "compDecompFct": "not-sent",
    },
    "IP_trafficClass": {
        "targetValue": "00",
        "matchingOperator": "equal",
        "compDecompFct": "not-sent",
    },
    "IP_flowLabel": {
        "targetValue": "00000",
        "matchingOperator": "equal",
        "compDecompFct": "not-sent",
    },
    "IP_payloadLength": {
        "targetValue": '',
        "matchingOperator": "ignore",
        "compDecompFct": "compute-IPv6-length",
    },
    "IP_nextHeader": {
        "targetValue": "11",
        "matchingOperator": "equal",
        "compDecompFct": "not-sent",
    },
    "IP_hopLimit": {
        "targetValue": "40",
        "matchingOperator": "equal",
        "compDecompFct": "not-sent",
    },
    "IP_prefixES": {
        "targetValue": "20010db80a0b12f0",
        "matchingOperator": "ignore",
        "compDecompFct": "not-sent",
    },
    "IP_iidES": {
        "targetValue": "",
        "matchingOperator": "equal",
        "compDecompFct": "ESiid-DID",
    },
    "IP_prefixLA": {
        "targetValue": "2d513de80a0b4df0",
        "matchingOperator": "equal",
        "compDecompFct": "not-sent",
    },
    "IP_iidLA": {
        "targetValue": "",
        "matchingOperator": "ignore",
        "compDecompFct": "LAiid-DID",
    },
    "UDP_PortES": {
        "targetValue": "1f90",
        "matchingOperator": "equal",
        "compDecompFct": "not-sent",
    },
    "UDP_PortLA": {
        "targetValue": "2382",
        "matchingOperator": "equal",
        "compDecompFct": "not-sent",
    },
    "UDP_length": {
        "targetValue": '',
        "matchingOperator": "ignore",
        "compDecompFct": "compute-UDP-length",
    },
    "UDP_checksum": {
        "targetValue": '',
        "matchingOperator": "ignore",
        "compDecompFct": "compute-UDP-checksum",
    },
    "CoAP_version": {
        "targetValue": "5",
        "matchingOperator": "equal",
        "compDecompFct": "not-sent",
    },
    "CoAP_type": {
        "targetValue": "5",
        "matchingOperator": "equal",
        "compDecompFct": "not-sent",
    },
    "CoAP_tokenLength": {
        "targetValue": "1",
        "matchingOperator": "equal",
        "compDecompFct": "not-sent",
    },
    "CoAP_code": {
        "targetValue": "02",
        "matchingOperator": "equal",
        "compDecompFct": "not-sent",
    },
    "CoAP_messageID": {
        "targetValue": "00",
        "matchingOperator": "MSB(8)",
        "compDecompFct": "LSB(8)",
    },
     "CoAP_token": {
        "targetValue": '',
        "matchingOperator": "ignore",
        "compDecompFct": "value-sent",
    }
};

// Importing the module
var Compressor_Decompressor = require('../lib/schc_cd');

// Creating new (empty) Compressor_Decompressor
var CD = new Compressor_Decompressor();

// Initializing the Compressor/Decompressor
CD.initializeCD();

// Adding a rule to the CDF context (for the moment must be added in order)
CD.addCompressionRule(rule0);

// Load IIDs obtained from L2 (ESiid, LAiid)
CD.loadIIDs("70b3d549925aa619","ada4dae3ac12676b"); // Examples of IIDs

// Parsing the compressed packet received
CD.parseCompressedPacket("00010a83190089003903c0"); // Example of a compressed message with rule0

// Decompression of the header according to the rule
CD.decompressHeader();
