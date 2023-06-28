#include "headers.p4"
#include "int_headers.p4"

control SwitchEgress(inout headers hdr,
                     inout metadata meta,
                     inout standard_metadata_t standard_metadata) {

    /********************  R E G I S T E R S ********************/
    register<bit<32>>(10) sampling; //used as a table, contain flow id and its counter  
    register<bit<32>>(1) tmpFrequency; //used a variable 
    register<bit<32>>(1) tmpID; // same


    /********************  A C T I O N S ***********************/


    action increment(bit<32> id, bit<32> frequency){ 
         bit<32> tmp;
         sampling.read(tmp,id); //we go the the counter associated with id
         tmp = tmp +1; //increment the counter
         sampling.write(id,tmp); // write it
         tmpFrequency.write(0,frequency); //stock the max frequency in a register 
         tmpID.write(0,id); //stock the id in a register
    }

    action setup_int(int_instruction_t instructionBitmap) {
       
        
         //initiate the int_shim headaer
        hdr.int_md_shim.setValid();
        hdr.int_md_shim.type = TYPE_INT_MD;
        hdr.int_md_shim.nextProtocol = 0;
        hdr.int_md_shim.rsv = 0;
        //length initialized with md header size (3*32bits)
        hdr.int_md_shim.len = 3;
        hdr.int_md_shim.nptDependentField = (bit<16>) hdr.ipv4.dscp;

        hdr.int_md_header.setValid();
        hdr.int_md_header.version = VERSION_INT_MD;
        hdr.int_md_header.flags = 0b000;
        hdr.int_md_header.rsv = 0x000;
        //initiate the int_md headaer
        hdr.int_md_header.hopMetaLength = 0;
        hdr.int_md_header.remainingHopCount = MAX_MD;
        hdr.int_md_header.instructionBitmap = instructionBitmap;
        hdr.int_md_header.domainSpecificFlags = 0;
        hdr.int_md_header.domainSpecificInstructions = 0;

        //not spec intended but we write the flowID in int headers
        bit<32> d ;
        tmpID.read(d,0);
        hdr.int_md_header.domainSpecificId = (bit<16>) d;

        hdr.ipv4.dscp = CONTAINS_INT;
        hdr.ipv4.totalLen = hdr.ipv4.totalLen + 16;
        if(hdr.udp.isValid()) {
            hdr.udp.len = hdr.udp.len + 16;
        }
        
    }

    //Creates the node_id header with matching metadata
    action add_node_id(switchID_t switch_id) {
        hdr.node_id.setValid();
        hdr.node_id.node_id = switch_id;
        hdr.ipv4.totalLen = hdr.ipv4.totalLen + 4;
        hdr.int_md_shim.len = hdr.int_md_shim.len + 1;
        hdr.int_md_header.hopMetaLength = hdr.int_md_header.hopMetaLength + 1;
    }

    //Creates Level 1 Ingress and Egress interface IDs header
    action add_lv1_if_id() {
        //v1model does not handle it
        hdr.lv1_if_id.setValid();
        hdr.lv1_if_id.ingress_if_id = 0;
        hdr.lv1_if_id.egress_if_id = 0;
        hdr.ipv4.totalLen = hdr.ipv4.totalLen + 4;
        hdr.int_md_shim.len = hdr.int_md_shim.len + 1;
        hdr.int_md_header.hopMetaLength = hdr.int_md_header.hopMetaLength + 1;
    }

    //Creates the hop_latency header
    action add_hop_latency() {
        // WARNING : Might cause problems as we cast 48 bits into 32..
        hdr.hop_latency.setValid();
        hdr.hop_latency.hop_latency = 
            (bit<32>) (standard_metadata.egress_global_timestamp - standard_metadata.ingress_global_timestamp);
        hdr.int_md_shim.len = hdr.int_md_shim.len + 1;
        hdr.ipv4.totalLen = hdr.ipv4.totalLen + 4;
        hdr.int_md_header.hopMetaLength = hdr.int_md_header.hopMetaLength + 1;
    }

    //creates queue_id_occupancy header
    action add_queue_id_occupancy() {
        //NOTE : Using enq_qdepth but also works with deq_qdepth
        hdr.queue_id_occupancy.setValid();
        hdr.queue_id_occupancy.queue_id = 0; //not part of the std meta in v1model
        hdr.queue_id_occupancy.queue_occupancy = (qdepth_t)standard_metadata.deq_qdepth;
        hdr.int_md_shim.len = hdr.int_md_shim.len + 1;
        hdr.ipv4.totalLen = hdr.ipv4.totalLen + 4;
        hdr.int_md_header.hopMetaLength = hdr.int_md_header.hopMetaLength + 1;
    }

    //creates ingress_timestamp header
    action add_ingress_timestamp() {
        hdr.ingress_timestamp.setValid();
        hdr.ingress_timestamp.ingress_timestamp = 
            (bit<64>) standard_metadata.ingress_global_timestamp;
        hdr.int_md_shim.len = hdr.int_md_shim.len + 2;
        hdr.ipv4.totalLen = hdr.ipv4.totalLen + 8;
        hdr.int_md_header.hopMetaLength = hdr.int_md_header.hopMetaLength + 2;
    }

    //creates egress_timestamp header
    action add_egress_timestamp() {
        hdr.egress_timestamp.setValid();
        hdr.egress_timestamp.egress_timestamp =
            (bit<64>) standard_metadata.egress_global_timestamp;
        hdr.int_md_shim.len = hdr.int_md_shim.len + 2;
        hdr.ipv4.totalLen = hdr.ipv4.totalLen + 8;
        hdr.int_md_header.hopMetaLength = hdr.int_md_header.hopMetaLength + 2;
    }

    //creates Level 2 Ingress and Egress Interface ID
    action add_lv2_if_id() {
        //v1model does not handle it
        hdr.lv2_if_id.setValid();
        hdr.lv2_if_id.ingress_if_id = 0;
        hdr.lv2_if_id.egress_if_id = 0;
        hdr.int_md_shim.len = hdr.int_md_shim.len + 2;
        hdr.ipv4.totalLen = hdr.ipv4.totalLen + 8;
        hdr.int_md_header.hopMetaLength = hdr.int_md_header.hopMetaLength + 2;
    }

    //creates Egress Interface Tx utilization (????)
    action add_eg_if_tx_util() {
        hdr.eg_if_tx_util.setValid();
        hdr.eg_if_tx_util.eg_if_tx_util = 0;
        hdr.int_md_shim.len = hdr.int_md_shim.len + 1;
        hdr.ipv4.totalLen = hdr.ipv4.totalLen + 4;
        hdr.int_md_header.hopMetaLength = hdr.int_md_header.hopMetaLength + 1;
    }

    //creates buffer_id_occupancy header
    //WARNING : not implemented, will require byte counter
    action add_buffer_id_occupancy() {
        hdr.buffer_id_occupancy.setValid();
        hdr.buffer_id_occupancy.buffer_id = 0;
        hdr.buffer_id_occupancy.buffer_occupancy = 0;
        hdr.int_md_shim.len = hdr.int_md_shim.len + 1;
        hdr.ipv4.totalLen = hdr.ipv4.totalLen + 4;
        hdr.int_md_header.hopMetaLength = hdr.int_md_header.hopMetaLength + 1;
    }

    /******************* T A B L E S ************************/

table add_int_hdr_udp {
        key = {
            hdr.ipv4.dstAddr : lpm;
            hdr.ipv4.srcAddr : exact;
            hdr.udp.dstPort  : exact;
        }
        actions = {
            setup_int;
            NoAction;
        }
        default_action = NoAction();
    }

table add_int_hdr_tcp {
        key = {
            hdr.ipv4.dstAddr : lpm;
            hdr.ipv4.srcAddr : exact;
            hdr.tcp.dstPort  : exact;
        }
        actions = {
            setup_int;
            NoAction;
        }
        default_action = NoAction();
    }


    table add_node_id_hdr {
        
        actions = {
            add_node_id;
        }
    }

    table add_lv1_if_id_hdr {
        
        actions = {
            add_lv1_if_id;
        }
    }

    table add_hop_latency_hdr {
        
        actions = {
            add_hop_latency;
            
        }
    }

    table add_queue_id_occupancy_hdr {
        
        actions = {
            add_queue_id_occupancy;
        }
    }

    table add_ingress_timestamp_hdr {
       
        actions = {
            add_ingress_timestamp;
        }
    }

    table add_egress_timestamp_hdr {
        
        actions = {
            add_egress_timestamp;
        }
    }

    table add_lv2_if_id_hdr {
       
        actions = {
            add_lv2_if_id;
        }
    }

    table add_eg_if_tx_util_hdr {
        
        actions = {
            add_eg_if_tx_util;
        }
    }

    table add_buffer_id_occupancy_hdr {
        
        actions = {
            add_buffer_id_occupancy;
        }
    }

table sampleUDP {
        key = {
            hdr.ipv4.dstAddr : lpm;
            hdr.ipv4.srcAddr : exact;
            hdr.udp.dstPort  : exact;
        }
        actions = {
            increment;
            NoAction;
        }
        default_action = NoAction();
    }
table sampleTCP {
        key = {
            hdr.ipv4.dstAddr : lpm;
            hdr.ipv4.srcAddr : exact;
            hdr.tcp.dstPort  : exact;
        }
        actions = {
            increment;
            NoAction;
        }
        default_action = NoAction();
    }

    apply {
         if(hdr.tcp.isValid()) {
                sampleTCP.apply();
            }
            if(hdr.udp.isValid()) {
                sampleUDP.apply();
            }
        

        bit<32> a;
        bit<32> b;
        bit<32> c;

        tmpID.read(a,0); // a = tmp ID we just change in sampleTCP/UDP
        tmpFrequency.read(b,0); // same for b 
        sampling.read(c,a); // we check the counter with tmpID 
        
        if(1 == c){ //if the max frequency fixed is equal to the counter
            //we add int headers to the paquet
            if(hdr.tcp.isValid()) {
                add_int_hdr_tcp.apply();
            }
            if(hdr.udp.isValid()) {
                add_int_hdr_udp.apply();
            }
            
        }
        if(b == c){
            sampling.write(a,0); //reset the counter
        }
        //Adding all the required headers according to instruction bitmap
        if(hdr.int_md_shim.isValid() && hdr.int_md_header.isValid()) {
            int_instruction_t instructions = hdr.int_md_header.instructionBitmap;
            if(instructions & NODE_ID != 0)
                add_node_id_hdr.apply();
            if((instructions & LVL1_IF_ID) != 0)
                add_lv1_if_id_hdr.apply();
            if((instructions & HOP_LATENCY) != 0)
                add_hop_latency_hdr.apply();
            if(instructions & QUEUE_ID_OCCUPANCY != 0)
                add_queue_id_occupancy_hdr.apply();
            if(instructions & INGRESS_TIMESTAMP != 0)
                add_ingress_timestamp_hdr.apply();
            if(instructions & EGRESS_TIMESTAMP != 0)
                add_egress_timestamp_hdr.apply();
            if(instructions & LVL2_IF_ID != 0)
                add_lv2_if_id_hdr.apply();
            if(instructions & EG_IF_TX_UTIL != 0)
                add_eg_if_tx_util_hdr.apply();
            if(instructions & BUFFER_ID_OCCUPANCY != 0)
                add_buffer_id_occupancy_hdr.apply();
            if(hdr.udp.isValid()) {
                hdr.udp.len = hdr.udp.len + ((bit<16>) hdr.int_md_header.hopMetaLength << 2);
            }
        }
    }
}
