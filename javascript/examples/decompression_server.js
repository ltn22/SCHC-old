/**
 * Created by Philippe Clavier on 16/03/2017.
 */

var path = require('path');
var express = require('express');

var comp_decomp = require('../lib/schc_cd'); // IMPORTING CD MODULE

// --------------------------------------------------------------
// RULES DEFINITIONS
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
        "targetValue": "",
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
        "targetValue": {
            "1": "20010db80a0b12f0",
            "2": "2d513de80a0b4df0"
        },
        "matchingOperator": "match-mapping",
        "compDecompFct": "mapping-sent(4)"
    },
    "IP_iidES": {
        "targetValue": "",
        "matchingOperator": "equal",
        "compDecompFct": "ESiid-DID",
    },
    "IP_prefixLA": {
        "targetValue": {
            "1": "20010db80a0b12f0",
            "2": "2d513de80a0b4df0"
            },
        "matchingOperator": "match-mapping",
        "compDecompFct": "mapping-sent(4)"
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
        "targetValue": "",
        "matchingOperator": "ignore",
        "compDecompFct": "compute-UDP-length",
    },
    "UDP_checksum": {
        "targetValue": "",
        "matchingOperator": "ignore",
        "compDecompFct": "compute-UDP-checksum",
    },
    "CoAP_version": {
        "targetValue": "1",
        "matchingOperator": "equal",
        "compDecompFct": "not-sent",
    },
    "CoAP_type": {
        "targetValue": "1",
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
        "targetValue": "000",
        "matchingOperator": "MSB(12)",
        "compDecompFct": "LSB(4)",
    },
     "CoAP_token": {
        "targetValue": "",
        "matchingOperator": "ignore",
        "compDecompFct": "value-sent",
    }
};
// --------------------------------------------------------------

// HTTP server
var httpServer = express();

// Route for POST /lopy
httpServer.post('/lopy/*', function(req, res){
    var buff = '';
    var CD = new comp_decomp(); // NEW (EMPTY) Compressor Decompressor Function
    CD.initializeCD();  // COMPRESSOR-DECOMPRESSOR INITIALIZED
    CD.addCompressionRule(rule0); // COMPRESSION RULE ADDED TO THE CD

    req.on('data',function(data){
        buff = data;
    });
    req.on('end',function(){
        console.log ('\nhttp receives on APP '+"["+buff.toString()+"]\n")
        var http_data = JSON.parse(buff.toString());
        var ESiid = http_data.devEUI;
        var LAiid = http_data.appEUI;
        var message = http_data.data;

        // Message is passed from base64 to hex
        message = new Buffer(message, 'base64');
        message = message.toString('hex');

        CD.loadIIDs(ESiid,LAiid); // Load IIDs obtained from L2 (ESiid, LAiid)
        CD.parseCompressedPacket(message); // Parsing compressed packet received
        CD.decompressHeader(); // Decompression of packet received
    });
});

httpServer.listen(3333);
console.log('Listening on port 3333');
