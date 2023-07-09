#include "defines.p4"
#include "headers.p4"
#include "int_headers.p4"
#include "types.p4"

parser SwitchParser(packet_in packet,
                    out headers hdr,
                    inout metadata meta,
                    inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4 : parse_ipv4;
            default   : accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.ihl) {
            5       : check_l4_proto;
            default : accept;
        }
    }

    state check_l4_proto {
        transition select(hdr.ipv4.protocol) {
            TYPE_TCP : parse_tcp;
            TYPE_UDP : parse_udp;
            default  : accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition check_int;
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition check_int;
    }

    state check_int {
        transition select(hdr.ipv4.dscp) {
            CONTAINS_INT : parse_int_md_shim;
            default      : accept;
        }
    }

    state parse_int_md_shim {
        packet.extract(hdr.int_md_shim);
        transition parse_int_md_header;
    }

    state parse_int_md_header {
        packet.extract(hdr.int_md_header);
        meta.parser_metadata.remaining = hdr.int_md_shim.len;
        transition select(meta.parser_metadata.remaining) {
            3       : accept;
            default : parse_metadata;
        }
    }

    state parse_metadata {
        packet.extract(hdr.metadata_extractor.next);
        meta.parser_metadata.remaining = meta.parser_metadata.remaining - 1;
        transition select(meta.parser_metadata.remaining) {
            3       : accept;
            default : parse_metadata;
        }
    }
}
