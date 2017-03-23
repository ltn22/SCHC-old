/**
 * Created by Philippe Clavier on 20/03/2017.
 */

//------------------------------------------
//
//    SCHC Compressor-Decompressor MODULE
//
//------------------------------------------

var cdf = function(array){
    this.array = array;
};

cdf.prototype.initializeCD = function(){

    // The context will store the rules that can be used for a compression
    this.context = [];

    // Received payload for the decompression stage
    this.received_payload = "";

    // Rule For Decompression
    this.decompression_rule = 0xff;

    // ESiid obtained from L2
    this.ESiid = "";

    // LAiid obtained from L2
    this.LAiid = "";

    // Auxiliary list to order the dictionary fields
    this.header_order = ["IP_version", "IP_trafficClass", "IP_flowLabel",
        "IP_payloadLength", "IP_nextHeader", "IP_hopLimit", "IP_prefixES", "IP_iidES",
        "IP_prefixLA", "IP_iidLA", "UDP_PortES", "UDP_PortLA",
        "UDP_length", "UDP_checksum", "CoAP_version", "CoAP_type", "CoAP_tokenLength",
        "CoAP_code", "CoAP_messageID", "CoAP_token"];

    // Values to be filled after the decompression of the packet received
    this.decompressed_header = {
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
    };

    // Decompressed fields sizes in bits
    this.field_size = {
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
    };
};

cdf.prototype.addCompressionRule = function(rule){
    this.context[this.context.length] = rule;
};

cdf.prototype.loadIIDs = function(ESiid,LAiid){
    this.ESiid = ESiid;
    this.LAiid = LAiid;
};

cdf.prototype.parseCompressedPacket = function(received_compressed_packet){
    var rule = received_compressed_packet.slice(0,2);
    rule = parseInt(rule,16);
    this.decompression_rule = rule;
    var index = 8; // In bits

    for(var item in this.header_order){
        var order = parseInt(item);
        if(this.header_order[order] === "CoAP_token"){
            this.field_size[this.header_order[order]] = parseInt(this.context[rule]["CoAP_tokenLength"]["targetValue"])*8;
        }
        if(this.context[rule][this.header_order[order]]["compDecompFct"] === "value-sent"){
            var length_bits = this.field_size[this.header_order[order]];
            var field_data = obtain_compressed_field(index, length_bits,received_compressed_packet);
            this.decompressed_header[this.header_order[order]] = complete_field_zeros(field_data,length_bits);
            index += length_bits;
        }
        var condition = /LSB\((.*)\)/.test(this.context[rule][this.header_order[order]]["compDecompFct"]);
        if (condition){
            // The number of LSB to be used is obtained from the "CDF" of the rule
            var reg = /LSB\((.*)\)/.exec(this.context[rule][this.header_order[order]]["compDecompFct"]);
            var length_bits = parseInt(reg[1]);
            var field_data = obtain_compressed_field(index, length_bits,received_compressed_packet);
            this.decompressed_header[this.header_order[order]] = complete_field_zeros(field_data,this.field_size[this.header_order[order]]);
            index += length_bits;
        }
    }
    this.received_payload = received_compressed_packet.slice(index/4,received_compressed_packet.length);
};

cdf.prototype.decompressHeader = function(){
    var decompression_rule = this.decompression_rule;
    console.log("\n\t\tStart decompressing packet with the rule " + decompression_rule + " ...\n");
    // for field_name, field_content in self.decompressed_header.items()
    for(var field_name in this.decompressed_header) {
        console.log("\t\t\tfield " + field_name + " :");
        // It checks if the CDF for that field is "not-sent" according to the rule received
        if (this.context[decompression_rule][field_name]["compDecompFct"] === "not-sent") {
            // If it is the decompressed value of the field will be the "tagetValue" from that field of the rule received
            this.decompressed_header[field_name] = this.context[decompression_rule][field_name]["targetValue"];
            // This is PROVISIONAL as the whole nibble is checked for the matach and so is how the rule is defined
            if(field_name === "CoAP_version"){
                this.decompressed_header[field_name] = (12 & this.decompressed_header[field_name]) >>> 2;
            }
            else if(field_name === "CoAP_type"){
                this.decompressed_header[field_name] = 3 & this.decompressed_header[field_name] ;
            }
            console.log("\t\t\t\tdecompressed " + field_name + " is " + this.decompressed_header[field_name] +
                " (retrieved from the context)");
        }
        // It checks if the CDF for that field is "value-sent" according to the rule received
        else if (this.context[decompression_rule][field_name]["compDecompFct"] === "value-sent") {
            // If it is the decompressed value of the field will be the same
            // as the compressed value (which has not been compressed)
            console.log("\t\t\t\tdecompressed " + field_name + " is " + this.decompressed_header[field_name] +
                " (retrieved from the link)");
        }
        else if (this.context[decompression_rule][field_name]["compDecompFct"] === "remapping") {
            // For the moment the field will be remapped by using only LSBs
            // Then the original value is obtained adding two zeros at the MSBs
            console.log("\t\t\t\tdecompressed " + field_name + " is " + this.decompressed_header[field_name] +
                " (retrieved from the link)");
        }
        // ESiid and LAiid must be obtained correctly from L2 but for now it will be used the TV
        else if (this.context[decompression_rule][field_name]["compDecompFct"] === "ESiid-DID") {
            this.decompressed_header[field_name] = this.ESiid;
            console.log("\t\t\t\tdecompressed " + field_name + " is " + this.decompressed_header[field_name] +
                " (retrieved from L2)");
        }
        else if (this.context[decompression_rule][field_name]["compDecompFct"] === "LAiid-DID") {
            this.decompressed_header[field_name] = this.LAiid;
            console.log("\t\t\t\tdecompressed " + field_name + " is " + this.decompressed_header[field_name] +
                " (retrieved from L2)");
        }
        // It checks if the CDF for that field is "LSB" according to the rule received
        var condition = /LSB\((.*)\)/.test(this.context[decompression_rule][field_name]["compDecompFct"]);
        if (condition){
            // The number of LSB to be used is obtained from the rule
            var reg = this.context[decompression_rule][field_name]["compDecompFct"].match(/LSB\((.*)\)/);
            var lsb = parseInt(reg[1]);
            // The MSBs value is obtained from the "targetValue" of the field from that rule
            var msb_value = parseInt(this.context[decompression_rule][field_name]["targetValue"], 16);
            // The received LSBs value
            var lsb_value = parseInt(this.decompressed_header[field_name], 16);
            // The MSB and LSB are merged with an OR to obtain the final value
            var field_value = (msb_value << lsb) | lsb_value;
            // The final value is expressed in hexa string
            field_value = field_value.toString(16);
            this.decompressed_header[field_name] = complete_field_zeros(field_value,this.field_size[field_name]);
            msb = this.field_size[field_name] - lsb;
            console.log('\t\t\t\tdecompressed %s is %s (retrieved from the context (%d MSB) and from the link (%d LSB))'
                , field_name, this.decompressed_header[field_name], msb, lsb);
        }
    }
    // Now the fields with the compute-* function must be obtained
    console.log();
    var lsb;
    var msb;
    if (this.context[decompression_rule]["UDP_length"]["compDecompFct"] === "compute-UDP-length"){
        // Length of the payload plus 8 bytes of the header
        var coap_h = this.decompressed_header["CoAP_version"] +
            this.decompressed_header["CoAP_tokenLength"] +
            this.decompressed_header["CoAP_code"] +
            this.decompressed_header["CoAP_messageID"] +
            this.decompressed_header["CoAP_token"] + "ff";
        var coap_packet = coap_h + this.received_payload;
        var udp_length = parseInt(coap_packet.length / 2) + 8;
        if (udp_length > 255){
            lsb = udp_length & 0x00ff;
            msb = udp_length >> 8;
        }
        else {
            lsb = udp_length;
            msb = 0;
        }
        udp_length = msb.toString(16) + lsb.toString(16);
        this.decompressed_header["UDP_length"] = complete_field_zeros(udp_length,16);
        console.log("\t\t\t\tUDP Length computed: %s (%d bytes)", this.decompressed_header["UDP_length"],parseInt(this.decompressed_header["UDP_length"],16));
        this.decompressed_header["UDP_checksum"] = "0000"; // 16 bits zeros checksum until it is computed
        var udp_h = this.decompressed_header["UDP_PortES"] + this.decompressed_header["UDP_PortLA"] +
            this.decompressed_header["UDP_length"] + this.decompressed_header["UDP_checksum"];
        var udp_packet = udp_h + coap_packet;
    }
    if (this.context[decompression_rule]["UDP_checksum"]["compDecompFct"] === "compute-UDP-checksum"){
        var udp_pseudo_header = this.decompressed_header["IP_prefixES"] + this.decompressed_header["IP_iidES"] +
            this.decompressed_header["IP_prefixLA"] + this.decompressed_header["IP_iidLA"] +
            this.decompressed_header["UDP_length"] + "00" + this.decompressed_header["IP_nextHeader"];
        var checksum_packet = udp_pseudo_header + udp_packet;
        var checksum_buffer = new Buffer(checksum_packet, 'hex');
        var chksm = checksum(checksum_buffer);
        if (chksm > 255){
            lsb = chksm & 0x00FF;
            msb = chksm >> 8;
        }
        else {
            lsb = chksm;
            msb = 0;
        }
        chksm = msb.toString(16) + lsb.toString(16);
        this.decompressed_header["UDP_checksum"] = complete_field_zeros(chksm,16);
        console.log("\t\t\t\tUDP_Checksum computed: ", this.decompressed_header["UDP_checksum"]);
    }
    if (this.context[decompression_rule]["IP_payloadLength"]["compDecompFct"] === "compute-IPv6-length") {
        var ip_payloadlength = parseInt(udp_packet.length / 2);
        if (ip_payloadlength > 255) {
            lsb = ip_payloadlength & 0x00ff;
            msb = ip_payloadlength >> 8;
        }
        else {
            lsb = ip_payloadlength;
            msb = 0;
        }
        ip_payloadlength = msb.toString(16) + lsb.toString(16);
        this.decompressed_header["IP_payloadLength"] = complete_field_zeros(ip_payloadlength,16);
        console.log("\t\t\t\tIP Payload Length computed: %s (%d bytes)" ,this.decompressed_header["IP_payloadLength"], parseInt(this.decompressed_header["IP_payloadLength"],16));
    }
    console.log();
    console.log("\t\t\t Payload: %s (%d bytes) ", this.received_payload, this.received_payload.length/2);
};

module.exports = exports = cdf;

// AUXILIARY FUNCTIONS

function checksum(msg){
    // Computes the UDP checksum for the decompressor
    // msg includes the pseudo-header for UDP, the UDP header and the UDP payload.
    // If the length of msg is not even a zero byte is added
    if (msg.length % 2 === 1){
        var zero = Buffer.alloc(1);
        msg = Buffer.concat([msg, zero]);
    }
    var s = 0;
    var w = 0;
    // Loop taking 2 bytes at a time (16 bits)
    for(i=0; i +2 <= msg.length ; i+=2){
        w = msg[i+1] + (msg[i] << 8);
        s = s + w;
    }
    while (s > 0xffff){
        s = (s >> 16) + (s & 0xffff);
    }
    // Complement and mask to 2 bytes (dont know for what is this last part)
    s = ~s & 0xffff;
    return s;
};

function complete_field_zeros(field, field_length){
    // The function receives the length of the field in bits and completes de
    // byte type with zeros in the MSBs
    var nibbles = parseInt(field_length / 4);
    while(field.length < nibbles){
        field = "0" + field ;
    }
    return field;
};

function obtain_compressed_field(index, length_bits,compPacket){
    var nibble_index = Math.floor(index/4);
    var nibble_end = Math.ceil((index+length_bits)/4);
    var diffe = nibble_end*4 - (length_bits + index);
    var field_data = parseInt(compPacket.slice(nibble_index, nibble_end),16);
    field_data = field_data >>> diffe; // Shift
    field_data = field_data & (Math.pow(2, length_bits)-1); // Mask
    field_data = field_data.toString(16);
    return field_data;
}
