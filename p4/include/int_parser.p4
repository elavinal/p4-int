#include "defines.p4"
#include "headers.p4"
#include "int_headers.p4"

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
            5       : check_tcp;
            default : accept;
        }
    }

    state check_tcp {
        transition select(hdr.ipv4.protoType) {
            TYPE_TCP : parse_tcp;
            default  : accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition select(hdr.ipv4.tos) {
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
        transition accept;
    }
}
