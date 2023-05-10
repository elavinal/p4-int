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
    }

    action clone_packet() {
        clone(CloneType.I2E, REPORT_MIRROR_SESSION_ID);
    }
/* -- Outdated --  
    action reroute_int(ipv4Addr_t mon_addr) {
        hdr.ipv4.dstAddr = mon_addr;
    }

    table report_int {
        actions = {
            reroute_int;
            drop;
            NoAction;
        }
        default_action = drop();
    }
 */
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

    apply {
        if(hdr.ipv4.isValid()){
          if(hdr.int_md_shim.isValid() 
           && hdr.int_md_header.isValid()
           && (hdr.int_md_header.flags & HOP_COUNT_EXCEEDED == 0b000)
        ) {
            
             int_instruction_t instructions = hdr.int_md_header.instructionBitmap;
            if(instructions & NODE_ID != 0){
                digest<switchID_t>(1,hdr.node_id.node_id);
            }
              
        
        }
        ipv4_lpm.apply();
    }
}
                       }