#include "headers.p4"
#include "int_headers.p4"

control SwitchDeparser(packet_out packet, in headers hdr) {
    apply {            
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
        packet.emit(hdr.tel_rep_group_header);
        packet.emit(hdr.int_md_shim);
        packet.emit(hdr.int_md_header);
        packet.emit(hdr.node_id);
        packet.emit(hdr.lv1_if_id);
        packet.emit(hdr.hop_latency);
        packet.emit(hdr.queue_id_occupancy);
        packet.emit(hdr.ingress_timestamp);
        packet.emit(hdr.egress_timestamp);
        packet.emit(hdr.lv2_if_id);
        packet.emit(hdr.eg_if_tx_util);
        packet.emit(hdr.buffer_id_occupancy);
        packet.emit(hdr.metadata_extractor);
    }
}
