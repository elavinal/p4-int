#include "headers.p4"
#include "int_headers.p4"

control SwitchEgress(inout headers hdr,
                     inout metadata meta,
                     inout standard_metadata_t standard_metadata) {

    /********************  R E G I S T E R S ********************/
    register<bit<32>>(10) RegSampling; //used as a table, contain flow id and its counter  
    register<bit<32>>(1) tmpFrequency; //used a variable 
    register<bit<32>>(1) tmpID; // same


    /********************  A C T I O N S ***********************/

    action increment(bit<32> id, bit<32> sampling){ 
        bit<32> tmp;
        RegSampling.read(tmp,id); //we go the the counter associated with id
        tmp = tmp +1; //increment the counter
        RegSampling.write(id,tmp); // write it
        tmpFrequency.write(0,sampling); //stock the max frequency in a register 
        tmpID.write(0,id); //stock the id in a register
        meta.flow_id = id;
    }

    action setup_int(int_instruction_t instructionBitmap) {
       
        // initiate the int_shim header
        hdr.int_md_shim.setValid();
        hdr.int_md_shim.type = TYPE_INT_MD;
        hdr.int_md_shim.nextProtocol = 0;
        hdr.int_md_shim.rsv = 0;
        hdr.int_md_shim.len = 3; // init with MD header size (3*32bits)
        hdr.int_md_shim.nptDependentField = (bit<16>) hdr.ipv4.dscp;

        // initiate the int_md header
        hdr.int_md_header.setValid();
        hdr.int_md_header.version = VERSION_INT_MD;
        hdr.int_md_header.flags = 0b000;
        hdr.int_md_header.rsv = 0x000;
        hdr.int_md_header.hopMetaLength = 0;
        hdr.int_md_header.remainingHopCount = MAX_MD;
        hdr.int_md_header.instructionBitmap = instructionBitmap;
        hdr.int_md_header.domainSpecificFlags = 0;
        hdr.int_md_header.domainSpecificInstructions = 0;

        if (instructionBitmap & NODE_ID != 0)
            hdr.int_md_header.hopMetaLength = hdr.int_md_header.hopMetaLength + 1;
        if ((instructionBitmap & LVL1_IF_ID) != 0)
            hdr.int_md_header.hopMetaLength = hdr.int_md_header.hopMetaLength + 1;
        if ((instructionBitmap  & HOP_LATENCY) != 0)
            hdr.int_md_header.hopMetaLength = hdr.int_md_header.hopMetaLength + 1;
        if (instructionBitmap  & QUEUE_ID_OCCUPANCY != 0)
            hdr.int_md_header.hopMetaLength = hdr.int_md_header.hopMetaLength + 1;
        if (instructionBitmap  & INGRESS_TIMESTAMP != 0)
            hdr.int_md_header.hopMetaLength = hdr.int_md_header.hopMetaLength + 1;
        if (instructionBitmap  & EGRESS_TIMESTAMP != 0)
            hdr.int_md_header.hopMetaLength = hdr.int_md_header.hopMetaLength + 1;
        if (instructionBitmap  & LVL2_IF_ID != 0)
            hdr.int_md_header.hopMetaLength = hdr.int_md_header.hopMetaLength + 1;
        if (instructionBitmap & EG_IF_TX_UTIL != 0)
            hdr.int_md_header.hopMetaLength = hdr.int_md_header.hopMetaLength + 1;
        if (instructionBitmap & BUFFER_ID_OCCUPANCY != 0)
            hdr.int_md_header.hopMetaLength = hdr.int_md_header.hopMetaLength + 1;

        // not spec intended but we write the flowID in int headers
        // (for reports in the sink)
        bit<32> d ;
        tmpID.read(d,0);
        hdr.int_md_header.domainSpecificId = (bit<16>) d;

        hdr.ipv4.dscp = CONTAINS_INT;
        hdr.ipv4.totalLen = hdr.ipv4.totalLen + 16;
        if(hdr.udp.isValid()) {
            hdr.udp.len = hdr.udp.len + 16;
        }
        
    }

    // Creates the node_id header with matching metadata
    action add_node_id(switchID_t switch_id) {
        hdr.node_id.setValid();
        hdr.node_id.node_id = switch_id;
        hdr.int_md_shim.len = hdr.int_md_shim.len + 1;
        hdr.ipv4.totalLen = hdr.ipv4.totalLen + 4;

    }

    // Creates Level 1 Ingress and Egress interface IDs header
    action add_lv1_if_id() {
        // v1model does not handle it
        hdr.lv1_if_id.setValid();
        hdr.lv1_if_id.ingress_if_id = 0;
        hdr.lv1_if_id.egress_if_id = 0;
        hdr.int_md_shim.len = hdr.int_md_shim.len + 1;
        hdr.ipv4.totalLen = hdr.ipv4.totalLen + 4;

    }

    // Creates the hop_latency header
    action add_hop_latency() {
        // WARNING: might cause problems as we cast 48 bits into 32..
        hdr.hop_latency.setValid();
        hdr.hop_latency.hop_latency = 
            (bit<32>) (standard_metadata.egress_global_timestamp - standard_metadata.ingress_global_timestamp);
        hdr.int_md_shim.len = hdr.int_md_shim.len + 1;
        hdr.ipv4.totalLen = hdr.ipv4.totalLen + 4;

    }

    // Creates queue_id_occupancy header
    action add_queue_id_occupancy() {
        // NOTE: Using enq_qdepth but also works with deq_qdepth
        hdr.queue_id_occupancy.setValid();
        hdr.queue_id_occupancy.queue_id = 0; // not part of the std meta in v1model
        hdr.queue_id_occupancy.queue_occupancy = (qdepth_t)standard_metadata.deq_qdepth;
        hdr.int_md_shim.len = hdr.int_md_shim.len + 1;
        hdr.ipv4.totalLen = hdr.ipv4.totalLen + 4;
    }

    // Creates ingress_timestamp header
    action add_ingress_timestamp() {
        hdr.ingress_timestamp.setValid();
        hdr.ingress_timestamp.ingress_timestamp = 
            (bit<64>) standard_metadata.ingress_global_timestamp;
        hdr.int_md_shim.len = hdr.int_md_shim.len + 1;
        hdr.ipv4.totalLen = hdr.ipv4.totalLen + 4;
    }

    // Creates egress_timestamp header
    action add_egress_timestamp() {
        hdr.egress_timestamp.setValid();
        hdr.egress_timestamp.egress_timestamp =
            (bit<64>) standard_metadata.egress_global_timestamp;
        hdr.int_md_shim.len = hdr.int_md_shim.len + 1;
        hdr.ipv4.totalLen = hdr.ipv4.totalLen + 4;
    }

    // Creates Level 2 Ingress and Egress Interface ID
    action add_lv2_if_id() {
        //v1model does not handle it
        hdr.lv2_if_id.setValid();
        hdr.lv2_if_id.ingress_if_id = 0;
        hdr.lv2_if_id.egress_if_id = 0;
        hdr.int_md_shim.len = hdr.int_md_shim.len + 1;
        hdr.ipv4.totalLen = hdr.ipv4.totalLen + 4;
    }

    // Creates Egress Interface Tx utilization (????)
    action add_eg_if_tx_util() {
        hdr.eg_if_tx_util.setValid();
        hdr.eg_if_tx_util.eg_if_tx_util = 0;
        hdr.int_md_shim.len = hdr.int_md_shim.len + 1;
        hdr.ipv4.totalLen = hdr.ipv4.totalLen + 4;
    }

    // Creates buffer_id_occupancy header
    // WARNING: not implemented, will require byte counter
    action add_buffer_id_occupancy() {
        hdr.buffer_id_occupancy.setValid();
        hdr.buffer_id_occupancy.buffer_id = 0;
        hdr.buffer_id_occupancy.buffer_occupancy = 0;
        hdr.int_md_shim.len = hdr.int_md_shim.len + 1;
        hdr.ipv4.totalLen = hdr.ipv4.totalLen + 4;
    }


    action source_action() {

    }
    action transit_action() {

    }

    action update_int_headers() {
        if(hdr.int_md_header.remainingHopCount > 0) {
            hdr.int_md_header.remainingHopCount = hdr.int_md_header.remainingHopCount - 1;
            hdr.ipv4.totalLen = hdr.ipv4.totalLen + (bit<16>) (hdr.int_md_header.hopMetaLength << 2);
        } else {
            hdr.int_md_header.flags = hdr.int_md_header.flags | HOP_COUNT_EXCEEDED;
        }
    }

    


    /******************* T A B L E S ************************/

    table add_int_hdr {
        key = {
            meta.flow_id : exact;
        }
        actions = {
            setup_int;
            NoAction;
        }
        default_action = NoAction;
    }

    table add_node_id_hdr {
        
        actions = {
            add_node_id;
        }
    }

    table sample_int {
        key = {
            hdr.ipv4.dstAddr  : exact;
            hdr.ipv4.protocol : exact;
            hdr.ipv4.srcAddr  : ternary;
            hdr.udp.dstPort   : ternary;
            hdr.tcp.dstPort   : ternary; 
        }
        actions = {
            increment;
            NoAction;
        }
        default_action = NoAction();
    }

    table switch_roles {
        key = {
            hdr.ipv4.dstAddr : ternary;
        }
        actions = {
            source_action;
            transit_action;
        }
    }

    apply {
        switch (switch_roles.apply().action_run) {
            source_action: {

                sample_int.apply();

                bit<32> a;
                bit<32> b;
                bit<32> c;

                tmpID.read(a,0); // a = tmp ID we just change in sampleTCP/UDP
                tmpFrequency.read(b,0); // same for b 
                RegSampling.read(c,a); // we check the counter with tmpID 
        
                if(1 == c){ //if the max frequency fixed is equal to the counter
                    add_int_hdr.apply(); //we add int headers to the paquet
                }
                if(b == c){
                    RegSampling.write(a,0); //reset the counter
                }
            }

            transit_action: {
                update_int_headers();
                
            }
        }
                
        // Adding all the required headers according to instruction bitmap
        if (hdr.int_md_shim.isValid() && hdr.int_md_header.isValid()) {

            int_instruction_t instructions = hdr.int_md_header.instructionBitmap;

            if (instructions & NODE_ID != 0)
                add_node_id_hdr.apply();
            if ((instructions & LVL1_IF_ID) != 0)
                add_lv1_if_id();
            if ((instructions & HOP_LATENCY) != 0)
                add_hop_latency();
            if (instructions & QUEUE_ID_OCCUPANCY != 0)
                add_queue_id_occupancy();
            if (instructions & INGRESS_TIMESTAMP != 0)
                add_ingress_timestamp();
            if (instructions & EGRESS_TIMESTAMP != 0)
                add_egress_timestamp();
            if (instructions & LVL2_IF_ID != 0)
                add_lv2_if_id();
            if (instructions & EG_IF_TX_UTIL != 0)
                add_eg_if_tx_util();
            if (instructions & BUFFER_ID_OCCUPANCY != 0)
                add_buffer_id_occupancy();

            if (hdr.udp.isValid()) {
                hdr.udp.len = hdr.udp.len + ((bit<16>) hdr.int_md_header.hopMetaLength << 2);
            }
        }
    }
}
