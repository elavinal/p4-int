#include "headers.p4"

#ifndef __INT_HEADERS__
#define __INT_HEADERS__


struct resubmit_meta_t {
    @field_list(1)
    bit<8> index;
}
header int_md_shim_t {
    bit<4>  type;
    bit<2>  nextProtocol;
    bit<2>  rsv;
    bit<8>  len;
    bit<16> nptDependentField;
}

header int_md_header_t {
    bit<4>            version;
    bit<3>            flags; //discard|hopCountExceeded|mtuExceeded
    bit<12>           rsv;
    bit<5>            hopMetaLength;
    bit<8>            remainingHopCount;
    int_instruction_t instructionBitmap;
    bit<16>           domainSpecificFlags;
    int_instruction_t domainSpecificInstructions;
    bit<16>           domainSpecificId;
}

header tel_rep_group_header_t {
    bit<4>  version; // This spec defines 2
    bit<6>  hw_id; // to identify NIC
    bit<22> seq_number; // to be stored in a register and incremented 
    switchID_t node_id;
}

/* INT specific metadata headers */

header node_id_t {
    switchID_t node_id;
}

header lv1_if_id_t {
    bit<16> ingress_if_id;
    bit<16> egress_if_id;
}

header hop_latency_t {
    bit<32> hop_latency;
}

header queue_id_occupancy_t {
    bit<8>  queue_id;
    bit<24> queue_occupancy;
}

header ingress_timestamp_t {
    bit<64> ingress_timestamp;
}

header egress_timestamp_t {
    bit<64> egress_timestamp;
}

header lv2_if_id_t {
    bit<32> ingress_if_id;
    bit<32> egress_if_id;
}

header eg_if_tx_util_t {
    bit<32> eg_if_tx_util;
}

header buffer_id_occupancy_t {
    bit<8>  buffer_id;
    bit<24> buffer_occupancy;
}

header metadata_extractor_t {
    md_word_t md_word;
}

struct int_metadata_t {
    md_word_t int_metadata;
}

// TODO rename int_report_t
struct int_headers_t { 
    // tel_rep_group_header_ta tel_rep_group_header;

    // Report Group Header
    bit<4>  version; // This spec defines 2
    bit<6>  hw_id; // to identify NIC
    bit<22> seq_number; // to be stored in a register and incremented 
    switchID_t node_idE;

    // Individual Report Header
    bit<4>  RepType;
    bit<4>  InType;
    bit<8>  ReportLenght;
    bit<8>  MDlength;
    bit<4>  flags;
    bit<4>  RSV;

    // Individual Report Main Contents
    bit<16> RepMDBits;
    bit<16> DomainSpecificId;
    bit<16> DSMdBits;
    bit<16> DSMdStatus;
}

struct metadata {
    parser_metadata_t parser_metadata;
    int_headers_t int_headers;  // TODO rename int_headers --> int_report 
    int_metadata_t int_metadata;
    resubmit_meta_t resubmit_meta;
}

struct headers {
    ethernet_t                           ethernet;
    ipv4_t                               ipv4;
    tcp_t                                tcp;
    udp_t                                udp;
    tel_rep_group_header_t               tel_rep_group_header;
    int_md_shim_t                        int_md_shim;
    int_md_header_t                      int_md_header;
    node_id_t                            node_id;
    lv1_if_id_t                          lv1_if_id;
    hop_latency_t                        hop_latency;
    queue_id_occupancy_t                 queue_id_occupancy;
    ingress_timestamp_t                  ingress_timestamp;
    egress_timestamp_t                   egress_timestamp;
    lv2_if_id_t                          lv2_if_id;
    eg_if_tx_util_t                      eg_if_tx_util;
    buffer_id_occupancy_t                buffer_id_occupancy;
    metadata_extractor_t[MAX_MD_WORDS]   metadata_extractor;
}

#endif