#include "headers.p4"

control SwitchIngress(inout headers hdr,
                       inout metadata meta,
    
                       inout standard_metadata_t standard_metadata) {

    register<bit<22>>(1) seq_number;
    register<bit<8>>(1) clone_number;

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
            if (standard_metadata.instance_type == 0) {
            trgh.apply();

            meta.int_headers.RepType = hdr.int_md_shim.type;
            meta.int_headers.InType = 0b0000;
            meta.int_headers.ReportLenght = hdr.int_md_shim.len;
            meta.int_headers.MDlength = (bit<8>)hdr.int_md_header.hopMetaLength;
            meta.int_headers.flags = 0b0000;
            meta.int_headers.RSV = 0b0000;

            meta.int_headers.RepMDBits = (bit<16>)hdr.int_md_header.instructionBitmap;
            meta.int_headers.DomainSpecificId = 0;
            meta.int_headers.DSMdBits = 0;
            meta.int_headers.DSMdStatus = 0;

                
            digest<int_headers_t>(1,meta.int_headers);

            bit<8> init;
            init = 0;
            clone_number.write(0,init);  


            resubmit_preserving_field_list((bit<8>)1);
            }
            else{

            bit<8> nbcl;
            clone_number.read(nbcl,0);
            if (nbcl == hdr.int_md_shim.len - 3){
                drop();
            }
            else{
            meta.int_metadata.int_metadata = hdr.metadata_extractor[nbcl].md_word;

            digest<int_metadata_t>(1, meta.int_metadata);

            bit<8> tempor;
            clone_number.read(tempor,0);
            tempor = tempor + 1;
            clone_number.write(0,tempor);

            
            resubmit_preserving_field_list((bit<8>)1);
    }
            drop();  
            }
            
        }
        ipv4_lpm.apply();
    }
}
}
                       