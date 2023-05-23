#include "headers.p4"

control SwitchIngress(inout headers hdr,
                       inout metadata meta,
    
                       inout standard_metadata_t standard_metadata) {

    register<bit<22>>(1) seq_number;

    action drop(){
        mark_to_drop(standard_metadata);
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
    }
    action trgh_digest(switchID_t switch_id){
            meta.int_headers.version = 0b0010;
            meta.int_headers.hw_id = 0;

            bit<22> tmp;
            seq_number.read(tmp,0);
            meta.int_headers.seq_number = tmp;
            tmp = tmp + 1;
            seq_number.write(0,tmp);

            meta.int_headers.node_idE = switch_id;

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
    table trgh {
        actions ={
            trgh_digest;
        }
    }

  

    apply {
        if(hdr.ipv4.isValid()){
          if(hdr.int_md_shim.isValid() 
           && hdr.int_md_header.isValid()
           && (hdr.int_md_header.flags & HOP_COUNT_EXCEEDED == 0b000)
        ) { 
            trgh.apply();

            meta.int_headers.type = hdr.int_md_shim.type;
            meta.int_headers.nextProtocol = hdr.int_md_shim.nextProtocol;
            meta.int_headers.rsv = hdr.int_md_shim.rsv;
            meta.int_headers.len = hdr.int_md_shim.len;
            meta.int_headers.nptDependentField = hdr.int_md_shim.nptDependentField;
                
            digest<int_headers_t>(1,meta.int_headers);            
            
             int_instruction_t instructions = hdr.int_md_header.instructionBitmap;
            if(instructions & NODE_ID != 0){

            }
              
        
        }
        ipv4_lpm.apply();
    }
}
                       }