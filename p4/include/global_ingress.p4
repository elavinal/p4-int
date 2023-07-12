#include "headers.p4"

control SwitchIngress(inout headers hdr,
                       inout metadata meta,
                       inout standard_metadata_t standard_metadata) {

    action drop(){
        mark_to_drop(standard_metadata);
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action set_int_role(bit<8> role){
        meta.role = role;
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr : lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }

    table switch_roles {
        actions = {
            set_int_role();
        }
    }
    

    apply {
        switch_roles.apply();

        if(hdr.ipv4.isValid())
            ipv4_lpm.apply();
    }
}

