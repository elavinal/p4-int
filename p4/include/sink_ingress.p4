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

                meta.int_headers.version = hdr.tel_rep_group_header.version;
                meta.int_headers.hw_id = hdr.tel_rep_group_header.hw_id;
                meta.int_headers.seq_number = hdr.tel_rep_group_header.seq_number;
                meta.int_headers.node_idE = hdr.tel_rep_group_header.node_id;  

                meta.int_headers.type = hdr.int_md_shim.type;
                meta.int_headers.nextProtocol = hdr.int_md_shim.nextProtocol;
                meta.int_headers.rsv = hdr.int_md_shim.rsv;
                meta.int_headers.len = hdr.int_md_shim.len;
                meta.int_headers.nptDependentField = hdr.int_md_shim.nptDependentField;
                meta.int_headers.node_idS = hdr.node_id.node_id;
                
                digest<int_headers_t>(1,meta.int_headers);
            }
              
        
        }
        ipv4_lpm.apply();
    }
}
                       }