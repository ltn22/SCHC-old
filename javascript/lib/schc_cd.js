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
    // Header received from the EndSystem
    this.parsedHeaderFields = {};
    // Received payload for the decompression stage
    this.received_payload = "";
    // Auxiliarys to order the options for every rule
    this.options_order = {};
    this.repeatable_options = 10; // Number of posible repetitions for options
    this.options_index = ["CoAP_If-Match", "CoAP_Uri-Host", "CoAP_ETag", "CoAP_If-None-Match", "CoAP_Uri-Port",
        "CoAP_Location-Path", "CoAP_Uri-Path", "CoAP_Content-Format", "CoAP_Max-Age", "CoAP_Uri-Query",
        "CoAP_Accept", "CoAP_Location-Query", "CoAP_Proxy-Uri", "CoAP_Proxy-Scheme", "CoAP_Sizel"];
    // Fields sizes in bits
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

//------------------------------------------
//
//              Compression
//
//------------------------------------------

cdf.prototype.loadFromParser = function(parsedHeaderFields, coap_header_options, payload) {
    this.parsedHeaderFields = parsedHeaderFields;
    this.coap_header_options = coap_header_options;
    this.payload = payload;
    // Reset initial values
    this.compressed_header_fields = {
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
    };
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
    // Rule For Decompression
    this.decompression_rule = 0xff;
    // Auxiliar list to order the dictionary
    this.header_order = ["IP_version", "IP_trafficClass", "IP_flowLabel",
        "IP_payloadLength", "IP_nextHeader", "IP_hopLimit", "IP_prefixES", "IP_iidES",
        "IP_prefixLA", "IP_iidLA", "UDP_PortES", "UDP_PortLA",
        "UDP_length", "UDP_checksum", "CoAP_version", "CoAP_type", "CoAP_tokenLength",
        "CoAP_code", "CoAP_messageID", "CoAP_token"];
};

cdf.prototype.analyzePacketToSend = function(){
    // The first thing will be to compare every rule from the context with
    // the packet to be analysed, and check if it is possible to use any
    // compression rule for this packet
    this.rule_found = false;
    this.rule_found_id = 0;
    var i = 0;

    // I add this to know every field received has a match
    var fieldsMatchCheck = JSON.parse(JSON.stringify(this.parsedHeaderFields));

    for (var rule_id in this.context) {
        //console.log("\n\t\tAnalyzing rule %d..." , i);
        var rule = this.context[rule_id];
        // Each field in the rule will be analysed
        for (var field_name in rule) {
            //console.log("\t\t\tfield %s :" , field_name);

            var matched = false;

            if (rule[field_name]["direction"] === "dw") {
                break;
            }

            // It is checked which is the "matchingOperator" for that field

            if (rule[field_name]["matchingOperator"] === "equal") {
                /*console.log("\t\t\t\t%s context value is %s and received value is %s..." % (
                 field_name, field_content["targetValue"], this.parsedHeaderFields[field_name]))*/

                // If the "matchingOperator" is "equal" the "targetValue" of
                // the rule is compared to the received packet field value
                // and check if there is a match
                if (rule[field_name]["targetValue"] === this.parsedHeaderFields[field_name]) {
                    /*console.log("\t\t\t\t\t...it is a match.")*/
                    fieldsMatchCheck[field_name] = true;
                    matched = true;
                }
            }
            if (rule[field_name]["matchingOperator"] === "ignore") {
                // If the "matchingOperator" is "ignore" this fields value
                // is ignored

                /*console.log("\t\t\t\t%s context value is %s and received value is %s..." % (
                 field_name, field_content["targetValue"], this.parsedHeaderFields[field_name]))*/
                /*console.log("\t\t\t\t\t...but they are ignored.")*/
                fieldsMatchCheck[field_name] = true;
                matched = true;
            }
            if (rule[field_name]["matchingOperator"] === "match-mapping") {
                // Every item in the target value should be checked for a
                // matching
                for(var mapping_id in rule[field_name]["targetValue"]){
                    if (rule[field_name]["targetValue"][mapping_id] === this.parsedHeaderFields[field_name]){
                        fieldsMatchCheck[field_name] = true;
                        matched = true;
                        break;
                    }
                }
            }
            // serach() function makes a comparison between the field
            // "matchingOperator" and "MSB" if it matches it gives back a
            // true value
            var condition = /MSB\((.*)\)/.test(rule[field_name]["matchingOperator"]);
            // If the "matchingOperator" is "MSB" then it should proceed
            // with the compression
            if (condition) {
                var reg = /MSB\((.*)\)/.exec(rule[field_name]["matchingOperator"]);
                var msb = parseInt(reg[1]);
                /*console.log("\t\t\t\t%s context value is %s and received value is %s..." % (
                 field_name, field_content["targetValue"], this.parsedHeaderFields[field_name]))*/

                // ctx_bin will have the "targetValue" of the rule field in
                // binary representation
                var ctx_bin = rule[field_name]["targetValue"];
                //ctx_bin = bin(parseInt(field_content["targetValue"], 16))[2:]
                // rcv_bin will have the value of the recieved packet field
                // in binary representation
                var rcv_bin = (parseInt(this.parsedHeaderFields[field_name], 16).toString(2)); // Le saque el slice()
                // ctx_nbz will be the size of the field name minus the
                // length of the "tagetValue"
                var ctx_nbz = this.field_size[field_name] - ctx_bin.length;
                // ctx_bin is filled with zeros for the diference in size
                ctx_bin = zfill(ctx_bin, ctx_nbz);
                // rcv_nbz will be the size of the field name minus the
                // length of the received field value
                var rcv_nbz = this.field_size[field_name] - rcv_bin.length;
                // rcv_bin is filled with zeros for the diference in size
                rcv_bin = zfill(rcv_bin, rcv_nbz);
                // Here it is checked if the MSB of the "targetValue" and
                // the value of the recieved packet field are the same
                if (ctx_bin.slice(0, msb) === rcv_bin.slice(0, msb)) {
                    /*console.log(
                     "\t\t\t\t\t...it is a match on the first %d bits." % msb)*/
                    fieldsMatchCheck[field_name] = true;
                    matched = true;
                }
            }
            if (matched === false) {
                break;
            }
        }
        // It is checked that every field received has an appropriate
        // compression
        for (var field_name in fieldsMatchCheck) {
            if (fieldsMatchCheck[field_name] !== true){
                // console.log(
                //    "\n\t\tNo compression for", field_name, "field in this rule.")
                matched = false;
                break;
            }
        }
        // Finally if the rule has matched it finishes, if not it keeps
        // comparing with the other rules of the list
        if (matched) {
            console.log("\t\tRule %d matched!", i);
            this.rule_found = true;
            this.rule_found_id = i;
            break;
        }
        else {
            console.log("\t\tRule %d do not match.", i);
            this.rule_found = false;
            i += 1;
        }
    }
};

cdf.prototype.compressPacket = function(){
    // If a rule is found the packet is compressed according to the selected
    // rule
    if (this.rule_found){
        /*console.log("\n\t\tStart compressing packet with the rule %d...\n" %
         this.rule_found_id)*/

        this.header_order = this.header_order.concat(this.coap_header_options);
        // In this iterations the "compDecompFct" is analysed for each field
        // of the selected rule
        for (order in this.header_order) {
            /*console.log("\t\t\tfield %s :" % field_name)*/

            // It is checked if the "compDecompFct" of the field contains "LSB"
            var condition = /LSB\((.*)\)/.test(this.context[this.rule_found_id][this.header_order[order]]["compDecompFct"]);
            if (condition) {
                var reg = /LSB\((.*)\)/.exec(this.context[this.rule_found_id][this.header_order[order]]["compDecompFct"]);
                var lsb = parseInt(reg[1]);

                // The field value from the received packet is expressed in
                // binary
                rcv_bin = (parseInt(this.parsedHeaderFields[this.header_order[order]], 16).toString(2));
                // rcv_nbz calculates the difference between the
                // field size and the received value length (in bits)
                rcv_nbz = this.field_size[this.header_order[order]] - rcv_bin.length;
                // rcv_bin is then completed with rcv_nbz zeros
                rcv_bin = zfill(rcv_bin, rcv_nbz);
                // The LSB bits from rcv_bin to be send are separeted
                // The rcv_bin bits are selected from (field_size - lsb) to
                // field_size
                rcv_bin = rcv_bin.slice(this.field_size[this.header_order[order]] - lsb, this.field_size[this.header_order[order]]);
                // Save it as binary, so that it can be then appended in a
                // compressed packet
                this.compressed_header_fields[this.header_order[order]] = rcv_bin;
            }
            var condition = /mapping-sent\((.*)\)/.test(this.context[this.rule_found_id][this.header_order[order]]["compDecompFct"]);
            if (condition) {
                // The value matched is searched and the mapping ID is saved
                for (mapping_id in this.context[this.rule_found_id][this.header_order[order]]["targetValue"]) {
                    var mapping_value = this.context[this.rule_found_id][this.header_order[order]]["targetValue"][mapping_id];
                    if (mapping_value === this.parsedHeaderFields[this.header_order[order]]) {
                        // Save it as binary
                        reg = /mapping-sent\((.*)\)/.exec(this.context[this.rule_found_id][this.header_order[order]]["compDecompFct"]);
                        rcv_bin = (parseInt(mapping_id, 16).toString(2));
                        rcv_nbz = lsb = parseInt(reg[1]) - rcv_bin.length;
                        rcv_bin = zfill(rcv_bin, rcv_nbz);
                        this.compressed_header_fields[this.header_order[order]] = rcv_bin;
                        break;
                    }
                }
            }
            // It is checked if the "compDecompFct" of the field contains
            // "value-sent"
            else if (this.context[this.rule_found_id][this.header_order[order]]["compDecompFct"] === "value-sent") {
                // If an option_value is sent, the length is added as a
                // first byte to the data
                data = this.parsedHeaderFields[this.header_order[order]];
                // Order is the field order number
                if (order >= 20) {
                    option_length = parseInt((this.parsedHeaderFields[this.header_order[order]]).length / 2);
                    //data = option_length.toString(16).slice(1) + data;
                    // Save it as binary (options)
                    //rcv_bin = (parseInt(data, 16).slice(2)).toString(2);
                    //rcv_nbz = option_length * 8 + 4 - rcv_bin.length;
                    rcv_bin = (parseInt(data, 16).toString(2));
                    rcv_nbz = option_length * 8 - rcv_bin.length;
                }
                else {
                    // Save it as binary (not-option)
                    rcv_bin = (parseInt(data, 16).toString(2));
                    rcv_nbz = this.field_size[this.header_order[order]] - rcv_bin.length;
                }
                rcv_bin = zfill(rcv_bin, rcv_nbz);
                this.compressed_header_fields[this.header_order[order]] = rcv_bin;
                /*console.log("\t\t\t\tfield content of %s is sent to the server, value is %s" % (
                 field_name, this.compressed_header_fields[field_name]))*/
            }
            // In any other case the field is omitted
            // All fields with compute-* are not sent
            else {
                /*console.log("\t\t\t\tfield elided.")*/
                if (order >= 20) {
                    // If not when appending the packet it wont find the
                    // field and show an error
                    this.compressed_header_fields[this.header_order[order]] = "";
                }
            }
        }
        // The selected ruled is also sent in the packet
        this.compressed_header_fields["rule"] = (this.rule_found_id).toString(16);
    }
    // If no rule is found the packet should be fragmented to be sent
    else{
        console.log("\t\tNo rule found, the packet is dropped.");
    }
};

// For now minimum size for each field is a nibble (should be changed)
cdf.prototype.appendCompressedPacket = function(){
    this.compressed_packet = this.compressed_header_fields["rule"];
    this.compressed_packet = complete_field_zeros(this.compressed_packet,8);
    auxBuffer = "";
    // this.header_order is used to assure the header packet is sent in
    // the right order since the dictionaries order is not fixed
    for (var index in this.header_order){
        var field_name = this.header_order[index];
        auxBuffer = auxBuffer + this.compressed_header_fields[field_name];
    }
    // Data is arranged to be sent in nibbles
    while (auxBuffer.length >= 4){
        one_nibble = auxBuffer.slice(0, 4);
        one_nibble = parseInt(one_nibble, 2);
        one_nibble = (one_nibble.toString(16));
        this.compressed_packet = this.compressed_packet + one_nibble;
        auxBuffer = auxBuffer.slice(4);
    }
    if (auxBuffer.length > 0){
        one_nibble = zfill(auxBuffer, 4 - auxBuffer.length);
        one_nibble = parseInt(one_nibble, 2);
        one_nibble = (one_nibble.toString(16)).slice(1);
        this.compressed_packet = this.compressed_packet + one_nibble;
    }
    // Data is sent in bytes, so there should be an even quantity of nibbles
    // An extra zero is added if necessary

    if ((this.compressed_packet).length % 2 !== 0){
        this.compressed_packet = this.compressed_packet + "0";
    }
    this.compressed_packet = this.compressed_packet + this.payload;
};

//------------------------------------------
//
//              Decompression
//
//------------------------------------------

cdf.prototype.reiniteDecompressor = function() {
    // Received payload for the decompression stage
    this.received_payload = "";
    // Complete CoAP/UDP/IPv6 Packet
    this.decompressed_packet = "";
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
};

cdf.prototype.addCompressionRule = function(rule){
    var index = this.context.length;
    this.context[index] = rule;
    this.options_order[index] = obtain_options_order(rule, this.options_index, this.repeatable_options)
};

cdf.prototype.loadIIDs = function(ESiid,LAiid){
    this.ESiid = ESiid;
    this.LAiid = LAiid;
};

cdf.prototype.parseCompressedPacket = function(received_compressed_packet){
    this.reiniteDecompressor();
    var rule = received_compressed_packet.slice(0,2);
    rule = parseInt(rule,16);
    this.decompression_rule = rule;
    var index = 8; // In bits

    this.header_order = this.header_order.concat(this.options_order[rule]);

    for(var item in this.header_order){
        var order = parseInt(item);

        if(this.header_order[order] === "CoAP_token"){
            this.field_size[this.header_order[order]] = parseInt(this.context[rule]["CoAP_tokenLength"]["targetValue"])*8;
        }
        if(this.context[rule][this.header_order[order]]["compDecompFct"] === "value-sent"){
            // After the header number 20 the options start
            // CoAP option length is sent first
            if (order >= 20){
                var option_length = obtain_compressed_field(index + 4 , 4,received_compressed_packet);
                var length_bits = parseInt(option_length)*8 + 8;
                // index += 4;
            }
            else{
                var length_bits = this.field_size[this.header_order[order]];
            }
            var field_data = obtain_compressed_field(index, length_bits,received_compressed_packet);
            this.decompressed_header[this.header_order[order]] = complete_field_zeros(field_data,length_bits);
            index += length_bits;
        }
        var condition = /mapping-sent\((.*)\)/.test(this.context[rule][this.header_order[order]]["compDecompFct"]);
        if (condition){
            var reg = /mapping-sent\((.*)\)/.exec(this.context[rule][this.header_order[order]]["compDecompFct"]);
            var length_bits = parseInt(reg[1]);
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
    var packet_start = Math.ceil(index/4);
    // The LoPy sends bytes, if the extra bits are 4 or more then they should be skipped
    if (packet_start % 2 != 0){
        packet_start += 1;
    }
    this.received_payload = received_compressed_packet.slice(packet_start,received_compressed_packet.length);
};
cdf.prototype.decompressHeader = function(){
    var decompression_rule = this.decompression_rule;
    console.log("\n\t\tStart decompressing packet with the rule " + decompression_rule + " ...\n");
    // for field_name, field_content in this.decompressed_header.items()
    for(var item in this.header_order){
        var order = parseInt(item);
        console.log("\t\t\tfield " + this.header_order[order] + " :");
        // It checks if the CDF for that field is "not-sent" according to the rule received
        if (this.context[decompression_rule][this.header_order[order]]["compDecompFct"] === "not-sent") {
            // If it is the decompressed value of the field will be the "tagetValue" from that field of the rule received
            this.decompressed_header[this.header_order[order]] = this.context[decompression_rule][this.header_order[order]]["targetValue"];
            // This is PROVISIONAL as the whole nibble is checked for the matach and so is how the rule is defined
            /*
             if(this.header_order[order] === "CoAP_version"){
             this.decompressed_header[this.header_order[order]] = (12 & this.decompressed_header[this.header_order[order]]) >>> 2;
             }
             else if(this.header_order[order] === "CoAP_type"){
             this.decompressed_header[this.header_order[order]] = 3 & this.decompressed_header[this.header_order[order]] ;
             }
             */
            console.log("\t\t\t\tdecompressed " + this.header_order[order] + " is " + this.decompressed_header[this.header_order[order]] +
                " (retrieved from the context)");
        }
        // It checks if the CDF for that field is "value-sent" according to the rule received
        else if (this.context[decompression_rule][this.header_order[order]]["compDecompFct"] === "value-sent") {
            // If it is the decompressed value of the field will be the same
            // as the compressed value (which has not been compressed)
            console.log("\t\t\t\tdecompressed " + this.header_order[order] + " is " + this.decompressed_header[this.header_order[order]] +
                " (retrieved from the link)");
        }
        // ESiid and LAiid must be obtained correctly from L2 but for now it will be used the TV
        else if (this.context[decompression_rule][this.header_order[order]]["compDecompFct"] === "ESiid-DID") {
            this.decompressed_header[this.header_order[order]] = this.ESiid;
            console.log("\t\t\t\tdecompressed " + this.header_order[order] + " is " + this.decompressed_header[this.header_order[order]] +
                " (retrieved from L2)");
        }
        else if (this.context[decompression_rule][this.header_order[order]]["compDecompFct"] === "LAiid-DID") {
            this.decompressed_header[this.header_order[order]] = this.LAiid;
            console.log("\t\t\t\tdecompressed " + this.header_order[order] + " is " + this.decompressed_header[this.header_order[order]] +
                " (retrieved from L2)");
        }
        var condition = /mapping-sent\((.*)\)/.test(this.context[decompression_rule][this.header_order[order]]["compDecompFct"]);
        if (condition){
            // The received field is the key in the Target Value for the true value
            var key = this.decompressed_header[this.header_order[order]];
            this.decompressed_header[this.header_order[order]] = this.context[decompression_rule][this.header_order[order]]["targetValue"][key];

            console.log("\t\t\t\tdecompressed " + this.header_order[order] + " is " + this.decompressed_header[this.header_order[order]] +
                " (retrieved from the mapping-sent)");
        }
        // It checks if the CDF for that field is "LSB" according to the rule received
        var condition = /LSB\((.*)\)/.test(this.context[decompression_rule][this.header_order[order]]["compDecompFct"]);
        if (condition){
            // The number of LSB to be used is obtained from the rule
            var reg = this.context[decompression_rule][this.header_order[order]]["compDecompFct"].match(/LSB\((.*)\)/);
            var lsb = parseInt(reg[1]);
            // The MSBs value is obtained from the "targetValue" of the field from that rule
            var msb_value = parseInt(this.context[decompression_rule][this.header_order[order]]["targetValue"], 16);
            // The received LSBs value
            var lsb_value = parseInt(this.decompressed_header[this.header_order[order]], 16);
            // The MSB and LSB are merged with an OR to obtain the final value
            var field_value = (msb_value << lsb) | lsb_value;
            // The final value is expressed in hexa string
            field_value = field_value.toString(16);
            this.decompressed_header[this.header_order[order]] = complete_field_zeros(field_value,this.field_size[this.header_order[order]]);
            msb = this.field_size[this.header_order[order]] - lsb;
            console.log('\t\t\t\tdecompressed %s is %s (retrieved from the context (%d MSB) and from the link (%d LSB))'
                , this.header_order[order], this.decompressed_header[this.header_order[order]], msb, lsb);
        }
    }
    // Now the fields with the compute-* function must be obtained
    console.log();
    var lsb;
    var msb;
    if (this.context[decompression_rule]["UDP_length"]["compDecompFct"] === "compute-UDP-length"){
        // Length of the payload plus 8 bytes of the header
        var aux =  (parseInt(this.decompressed_header["CoAP_version"],16) << 6) |
            (parseInt(this.decompressed_header["CoAP_type"],16) << 4) |
            parseInt(this.decompressed_header["CoAP_tokenLength"],16);
        aux = aux.toString(16);
        var coap_h = "";
        for(var item in this.header_order){
            var index = parseInt(item);
            if (index >= 17) {
                coap_h += this.decompressed_header[this.header_order[index]];
            }
        }
        coap_h = aux + coap_h + "ff";
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
        var checksum_buffer = new Buffer(checksum_packet,'hex');
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
    for (var index in this.header_order){
        if (index != "14" & index != "15"){
            this.decompressed_packet = this.decompressed_packet + this.decompressed_header[this.header_order[index]];
        }
        else if (index === "14"){
            var aux = (parseInt(this.decompressed_header["CoAP_version"],16) << 2) |
                (parseInt(this.decompressed_header["CoAP_type"],16));
            aux = aux.toString(16);
            this.decompressed_packet = this.decompressed_packet + aux;
        }


    }
    if (this.received_payload){
        this.decompressed_packet += "ff";
    }
};

module.exports = exports = cdf;

//------------------------------------------
//
//              AUXILIARY FUNCTIONS
//
//------------------------------------------

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
}

function complete_field_zeros(field, field_length){
    // The function receives the length of the field in bits and completes de
    // byte type with zeros in the MSBs
    var nibbles = parseInt(field_length / 4);
    while(field.length < nibbles){
        field = "0" + field ;
    }
    return field;
}

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

function obtain_options_order(rule, options_index, repeatable_options){
    var options_order = [];

    for (var field_name in rule){
        for (var k in options_index){
            var re = new RegExp(options_index[k]+"\\s(\\d*)"); //  ,"\\s\(\\d*\)"
            var condition = re.test(field_name);
            if (condition){
                var reg = re.exec(field_name);
                options_order.push([field_name, k * repeatable_options + parseInt(reg[1]) -1]);
            }
        }
    }
    options_order.sort(function(a, b){return a[1]-b[1]});
    for (var k in options_order){
        options_order[k] = options_order[k][0];
    }
    return options_order
}

function zfill(strtofill, nbz){
    filledstr = strtofill;
    for (i = 0; i < nbz; i++){
        filledstr = "0" + filledstr;
    }
    return filledstr;
}
