/**
 * Created by Philippe Clavier on 16/03/2017.
 */

var path = require('path');
var express = require('express');

var comp_decomp = require('./schc_cd'); // IMPORTING CD MODULE
// Importing parser module
var Parser = require('./parser');

// --------------------------------------------------------------
// RULES DEFINITIONS
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

// --------------------------------------------------------------

// HTTP server
var httpServer = express();

// Route for POST /lopy
httpServer.post('/lopy/*', function(req, res){
    var buff = '';
    var CD = new comp_decomp(); // NEW (EMPTY) Compressor Decompressor Function
    // Creating new Parser
    var parser = new Parser();
    CD.initializeCD();  // COMPRESSOR-DECOMPRESSOR INITIALIZED
    CD.addCompressionRule(rule0); // COMPRESSION RULES ADDED TO THE CD

    req.on('data',function(data){
        buff = data;
    });
    req.on('end',function(){
        console.log ('\nhttp receives on APP '+"["+buff.toString()+"]\n");
        var http_data = JSON.parse(buff.toString());
        var ESiid = http_data.devEUI;
        var LAiid = http_data.appEUI;
        var message = http_data.data;

        // Message is passed from base64 to hex
        message = new Buffer(message, 'base64');
        message = message.toString('hex');

        CD.parseCompressedPacket(message); // Parsing compressed packet received
        CD.loadIIDs(ESiid,LAiid); // Load IIDs obtained from L2 (ESiid, LAiid)
        CD.decompressHeader(); // Decompression of packet received

        aux = parseInt(CD.received_payload,16);
        if (aux < 255) {
            aux += 1;
        }
        else {
            aux = 1;
        }
        aux = aux.toString(16);
        if (aux.length < 2 ){
            aux = "0" + aux;
        }
        var decompressed_response_packet = CD.decompressed_packet + aux;

        parser.parse(decompressed_response_packet);
        CD.loadFromParser(parser.header_fields, parser.coap_header_options, parser.payload);
        CD.analyzePacketToSend();

        if (CD.rule_found){
            CD.compressPacket();
            CD.appendCompressedPacket();

            var compressed_response_packet = CD.compressed_packet;
        }

        console.log("Paquete a enviar->",compressed_response_packet);

        var responseStruct = {
            'fport' : 2,
            'data' : new Buffer(compressed_response_packet).toString("base64"),
            'devEUI' : http_data.devEUI
        };
        console.log("\nSending response",responseStruct);

        res.writeHead(200);
        res.end(JSON.stringify(responseStruct));
    });
});

httpServer.listen(3333);
console.log('Listening on port 3333');
