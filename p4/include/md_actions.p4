#include "headers.p4"
#include "int_headers.p4"
#include "types.p4"
#include "defines.p4"

//Creates the node_id header with matching metadata
action add_node_id(switchID_t switch_id, headers hdr) {
    hdr.node_id.setValid();
    hdr.node_id.node_id = switch_id;
    hdr.ipv4.totalLen = hdr.ipv4.totalLen + 4;
    hdr.int_md_shim.len = hdr.int_md_shim.len + 1;
    hdr.int_md_header.hopMetaLength = hdr.int_md_header.hopMetaLength + 1;
}

//Creates Level 1 Ingress and Egress interface IDs header
action add_lv1_if_id(headers hdr) {
    //v1model does not handle it
    hdr.lv1_if_id.setValid();
    hdr.lv1_if_id.ingress_if_id = 0;
    hdr.lv1_if_id.egress_if_id = 0;
    hdr.ipv4.totalLen = hdr.ipv4.totalLen + 4;
    hdr.int_md_shim.len = hdr.int_md_shim.len + 1;
    hdr.int_md_header.hopMetaLength = hdr.int_md_header.hopMetaLength + 1;
}

//Creates the hop_latency header
action add_hop_latency(headers hdr, standard_metadata_t standard_metadata) {
    // WARNING : Might cause problems as we cast 48 bits into 32..
    hdr.hop_latency.setValid();
    hdr.hop_latency.hop_latency = 
        (bit<32>) (standard_metadata.egress_global_timestamp - standard_metadata.ingress_global_timestamp);
    hdr.int_md_shim.len = hdr.int_md_shim.len + 1;
    hdr.ipv4.totalLen = hdr.ipv4.totalLen + 4;
    hdr.int_md_header.hopMetaLength = hdr.int_md_header.hopMetaLength + 1;
}

//creates queue_id_occupancy header
action add_queue_id_occupancy(headers hdr, standard_metadata_t standard_metadata) {
    //NOTE : Using enq_qdepth but also works with deq_qdepth
    hdr.queue_id_occupancy.setValid();
    hdr.queue_id_occupancy.queue_id = 0; //not part of the std meta in v1model
    hdr.queue_id_occupancy.queue_occupancy = (qdepth_t)standard_metadata.enq_qdepth;
    hdr.int_md_shim.len = hdr.int_md_shim.len + 1;
    hdr.ipv4.totalLen = hdr.ipv4.totalLen + 4;
    hdr.int_md_header.hopMetaLength = hdr.int_md_header.hopMetaLength + 1;
}

//creates ingress_timestamp header
action add_ingress_timestamp(headers hdr, standard_metadata_t standard_metadata) {
    hdr.ingress_timestamp.setValid();
    hdr.ingress_timestamp.ingress_timestamp = 
        (bit<64>) standard_metadata.ingress_global_timestamp;
    hdr.int_md_shim.len = hdr.int_md_shim.len + 2;
    hdr.ipv4.totalLen = hdr.ipv4.totalLen + 8;
    hdr.int_md_header.hopMetaLength = hdr.int_md_header.hopMetaLength + 2;
}

//creates egress_timestamp header
action add_egress_timestamp(headers hdr, standard_metadata_t standard_metadata) {
    hdr.egress_timestamp.setValid();
    hdr.egress_timestamp.egress_timestamp =
        (bit<64>) standard_metadata.egress_global_timestamp;
    hdr.int_md_shim.len = hdr.int_md_shim.len + 2;
    hdr.ipv4.totalLen = hdr.ipv4.totalLen + 8;
    hdr.int_md_header.hopMetaLength = hdr.int_md_header.hopMetaLength + 2;
}

//creates Level 2 Ingress and Egress Interface ID
action add_lv2_if_id(headers hdr, standard_metadata_t standard_metadata) {
    //v1model does not handle it
    hdr.lv2_if_id.setValid();
    hdr.lv2_if_id.ingress_if_id = 0;
    hdr.lv2_if_id.egress_if_id = 0;
    hdr.int_md_shim.len = hdr.int_md_shim.len + 2;
    hdr.ipv4.totalLen = hdr.ipv4.totalLen + 8;
    hdr.int_md_header.hopMetaLength = hdr.int_md_header.hopMetaLength + 2;
}

//creates Egress Interface Tx utilization (????)
action add_eg_if_tx_util(headers hdr, standard_metadata_t standard_metadata) {
    hdr.eg_if_tx_util.setValid();
    hdr.eg_if_tx_util.eg_if_tx_util = 0;
    hdr.int_md_shim.len = hdr.int_md_shim.len + 1;
    hdr.ipv4.totalLen = hdr.ipv4.totalLen + 4;
    hdr.int_md_header.hopMetaLength = hdr.int_md_header.hopMetaLength + 1;
}

//creates buffer_id_occupancy header
//WARNING : not implemented, will require byte counter
action add_buffer_id_occupancy(headers hdr, standard_metadata_t standard_metadata) {
    hdr.buffer_id_occupancy.setValid();
    hdr.buffer_id_occupancy.buffer_id = 0;
    hdr.buffer_id_occupancy.buffer_occupancy = 0;
    hdr.int_md_shim.len = hdr.int_md_shim.len + 1;
    hdr.ipv4.totalLen = hdr.ipv4.totalLen + 4;
    hdr.int_md_header.hopMetaLength = hdr.int_md_header.hopMetaLength + 1;
}