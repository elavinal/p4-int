#include "headers.p4"
#include "int_headers.p4"

control SwitchEgress(inout headers hdr,
                      inout metadata meta,
                      inout standard_metadata_t standard_metadata) {

    /********************** A C T I O N S **********************/

    //Creates the node_id header
    action add_node_id(switchID_t switch_id) {
        hdr.node_id.setValid();
        hdr.node_id.node_id = switch_id;
    }

    //Creates Level 1 Ingress and Egress Interface IDs header
    action add_lv1_if_id() {
        //v1model does not handle it
        hdr.lv1_if_id.setValid();
        hdr.lv1_if_id.ingress_if_id = 0;
        hdr.lv1_if_id.egress_if_id = 0;
    }

    //Creates the hop_latency header
    action add_hop_latency() {
        // WARNING : Might cause problems as it casts 48 bits to 32
        hdr.hop_latency.setValid();
        hdr.hop_latency.hop_latency =            
            (bit<32>) (standard_metadata.egress_global_timestamp - standard_metadata.ingress_global_timestamp);
    }

    //Creates queue_id_occupancy header
    action add_queue_id_occupancy() {
        hdr.queue_id_occupancy.setValid();
        hdr.queue_id_occupancy.queue_id = 0;//not in v1model std meta
        hdr.queue_id_occupancy.queue_occupancy = (qdepth_t)standard_metadata.enq_qdepth;
    }

    //Creates ingress_timestamp header
    action add_ingress_timestamp() {
        hdr.ingress_timestamp.setValid();
        hdr.ingress_timestamp.ingress_timestamp =
            (bit<64>) standard_metadata.ingress_global_timestamp;
    }
    
    //Creates egress_timestamp header
    action add_egress_timestamp() {
        hdr.egress_timestamp.setValid();
        hdr.egress_timestamp.egress_timestamp =
            (bit<64>) standard_metadata.egress_global_timestamp;
    }

    //Creates Level 2 Ingress and Egress Interface ID
    action add_lv2_if_id() {
        //v1model does not handle it
        hdr.lv2_if_id.setValid();
        hdr.lv2_if_id.ingress_if_id = 0;
        hdr.lv2_if_id.egress_if_id = 0;
    }

    //Creates Egress Interface Tx utilization
    action add_eg_if_tx_util() {
        hdr.eg_if_tx_util.setValid();
        hdr.eg_if_tx_util.eg_if_tx_util = 0;
    }

    //Creates buffer_id_occupancy header
    //WARNING : not implemeted, will require byte counter
    action add_buffer_id_occupancy() {
        hdr.buffer_id_occupancy.setValid();
        hdr.buffer_id_occupancy.buffer_id = 0;
        hdr.buffer_id_occupancy.buffer_occupancy = 0;
    }

    //Updates the length of metadata
    action update_int_headers() {
        if(hdr.int_md_header.remainingHopCount > 0) {
            hdr.int_md_shim.len = hdr.int_md_shim.len + (bit<8>) hdr.int_md_header.hopMetaLength;
            hdr.int_md_header.remainingHopCount = hdr.int_md_header.remainingHopCount - 1;
        hdr.ipv4.totalLen = hdr.ipv4.totalLen + (bit<16>) (hdr.int_md_header.hopMetaLength * 4);
        } else {
            hdr.int_md_header.flags = hdr.int_md_header.flags | HOP_COUNT_EXCEEDED;
        }
    }

    action restore_original() {
        //Restoring IPv4 header
        hdr.ipv4.tos = (bit<8>) hdr.int_md_shim.nptDependentField;
        hdr.ipv4.totalLen = hdr.ipv4.totalLen - ((bit<16>) hdr.int_md_shim.len << 2);
        //Deleting INT from the client's packet
        hdr.int_md_shim.setInvalid();
        hdr.int_md_header.setInvalid();
        hdr.node_id.setInvalid();
        hdr.lv1_if_id.setInvalid();
        hdr.hop_latency.setInvalid();
        hdr.queue_id_occupancy.setInvalid();
        hdr.ingress_timestamp.setInvalid();
        hdr.egress_timestamp.setInvalid();
        hdr.lv2_if_id.setInvalid();
        hdr.eg_if_tx_util.setInvalid();
        hdr.buffer_id_occupancy.setInvalid();
    }

    /******************* T A B L E S ************************/


    table add_node_id_hdr {
        key = {
            hdr.ipv4.dstAddr : lpm;
        }
        actions = {
            add_node_id;
            NoAction;
        }
        default_action = NoAction();
    }

    table add_lv1_if_id_hdr {
        key = {
            hdr.ipv4.dstAddr : lpm;
        }
        actions = {
            add_lv1_if_id;
            NoAction;
        }
        default_action = NoAction();
    }

    table add_hop_latency_hdr {
        key = {
            hdr.ipv4.dstAddr : lpm;
        }
        actions = {
            add_hop_latency;
            NoAction;
        }
        default_action = NoAction();
    }

    table add_queue_id_occupancy_hdr {
        key = {
            hdr.ipv4.dstAddr : lpm;
        }
        actions = {
            add_queue_id_occupancy;
            NoAction;
        }
        default_action = NoAction();
    }

    table add_ingress_timestamp_hdr {
        key = {
            hdr.ipv4.dstAddr : lpm;
        }
        actions = {
            add_ingress_timestamp;
            NoAction;
        }
        default_action = NoAction();
    }

    table add_egress_timestamp_hdr {
        key = {
            hdr.ipv4.dstAddr : lpm;
        }
        actions = {
            add_egress_timestamp;
            NoAction;
        }
        default_action = NoAction();
    }

    table add_lv2_if_id_hdr {
        key = {
            hdr.ipv4.dstAddr : lpm;
        }
        actions = {
            add_lv2_if_id;
            NoAction;
        }
        default_action = NoAction();
    }

    table add_eg_if_tx_util_hdr {
        key = {
            hdr.ipv4.dstAddr : lpm;
        }
        actions = {
            add_eg_if_tx_util;
            NoAction;
        }
        default_action = NoAction();
    }

    table add_buffer_id_occupancy_hdr {
        key = {
            hdr.ipv4.dstAddr : lpm;
        }
        actions = {
            add_buffer_id_occupancy;
            NoAction;
        }
        default_action = NoAction();
    }

    table update_int_hdrs {
        key = {
            hdr.ipv4.dstAddr : lpm;
        }
        actions = {
            update_int_headers;
            NoAction;
        }
        default_action = NoAction();
    }

    table clear_int {
        actions = {
            restore_original;
        }
    }

    apply {
        if(hdr.int_md_shim.isValid() 
           && hdr.int_md_header.isValid()
           && (hdr.int_md_header.flags & HOP_COUNT_EXCEEDED == 0b000)) {
            
            update_int_hdrs.apply();
            int_instruction_t instructions = hdr.int_md_header.instructionBitmap;
            if(instructions & NODE_ID != 0)
                add_node_id_hdr.apply();
            if(instructions & LVL1_IF_ID != 0)
                add_lv1_if_id_hdr.apply();
            if(instructions & HOP_LATENCY != 0)
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
        }
        if (standard_metadata.instance_type == PKT_INSTANCE_TYPE_INGRESS_CLONE) {
            clear_int.apply();
        }
    }
}
