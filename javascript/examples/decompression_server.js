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
        var ESiid = separate_ESiid(buff.toString());
        var LAiid = separate_LAiid(buff.toString());
        var data = separate_data(buff.toString());

        CD.loadIIDs(ESiid,LAiid); // Load IIDs obtained from L2 (ESiid, LAiid)
        CD.parseCompressedPacket(data); // Parsing compressed packet received
        CD.decompressHeader(); // Decompression of packet received
    });
});

httpServer.listen(3333);
console.log('Listening on port 3333');

// AUXILIARY FUNCTIONS

// OBTAINING THE RECIEVED DATA FROM THE HTTP APP
// Searches "data" in the http message and returns it
function separate_data(full_string){
    var initial_position = full_string.search('data');
    initial_position += 7;
    var final_position = full_string.search('loRaSNR');
    final_position -= 3;
    var data_string = full_string.slice(initial_position, final_position);
    console.log ( "\tData (base64): " + data_string);
    var b = new Buffer(data_string, 'base64');
    var hex_data = b.toString('hex');
    console.log ( "\tData (hex): %s (%d bytes)", hex_data, hex_data.length/2);
    return hex_data;
}

// Searches ""devEUI"" in the http message and returns it
function separate_ESiid(full_string){
    initial_position = full_string.search('devEUI');
    initial_position += 9;
    final_position = full_string.search('appEUI');
    final_position -= 3;
    data_string = full_string.slice(initial_position, final_position);
    console.log ( "\tdevEUI (hex): " + data_string);
    return data_string;
}

// Searches "appEUI" in the http message and returns it
function separate_LAiid(full_string){
    initial_position = full_string.search('appEUI');
    initial_position += 9;
    final_position = full_string.search('fPort');
    final_position -= 3;
    data_string = full_string.slice(initial_position, final_position);
    console.log ( "\tappEUI (hex): " + data_string);
    return data_string;
}
