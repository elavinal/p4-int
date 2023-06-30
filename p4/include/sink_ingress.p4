#include "headers.p4"

control SwitchIngress(inout headers hdr,
                       inout metadata meta,
    
                       inout standard_metadata_t standard_metadata) {

    // TODO array of registers? according to flow_id?
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
            meta.int_report.version = 0b0010;
            meta.int_report.hw_id = 0;

            bit<22> tmp;
            seq_number.read(tmp,0);
            meta.int_report.seq_number = tmp;
            tmp = tmp + 1;
            seq_number.write(0,tmp);

            meta.int_report.node_idE = switch_id;

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
        // if the paquet contains an INT header
        if  (hdr.int_md_shim.isValid() && hdr.int_md_header.isValid() &&
            (hdr.int_md_header.flags & HOP_COUNT_EXCEEDED == 0b000)) /* What is this for? */ {

            // if the paquet is an original and not cloned in any way  
            if (standard_metadata.instance_type == 0) {
                // instantiate Telemetry Group Header  
                trgh.apply();

                // fill int header with paquet information, the report format is similar to what we had to the paquet 
                meta.int_report.RepType = hdr.int_md_shim.type;
                meta.int_report.InType = 0b0000;
                meta.int_report.ReportLenght = hdr.int_md_shim.len;
                meta.int_report.MDlength = (bit<8>)hdr.int_md_header.hopMetaLength;
                meta.int_report.flags = 0b0000;
                meta.int_report.RSV = 0b0000;

                meta.int_report.RepMDBits = (bit<16>)hdr.int_md_header.instructionBitmap;
                meta.int_report.DomainSpecificId = hdr.int_md_header.domainSpecificId;
                meta.int_report.DSMdBits = 0;
                meta.int_report.DSMdStatus = 0;

                // send to the collector the static/main part of the report
                digest<int_report_t>(1, meta.int_report);

                // initiate the counter of clone made at 0 
                bit<8> init;
                init = 0;
                clone_number.write(0,init);  

                // resubmit the paquet to Ingress
                resubmit_preserving_field_list((bit<8>)1);
            }
            else {
                // if the paquet is a clone 
                bit<8> nbcl;
                clone_number.read(nbcl,0);
                // we read the number of clone made so far 
                if (nbcl == hdr.int_md_shim.len - 3) {
                    // if all clone needed were made, we drop the paquet and no more clone will be created
                    drop();
                }
                else {
                    // otherwise we read the metadata at the clone Index
                    meta.int_metadata.int_metadata = hdr.metadata_extractor[nbcl].md_word;
                    // and send it to the collector
                    digest<int_metadata_t>(1, meta.int_metadata);

                    // increase the clone counter
                    bit<8> tempor;
                    clone_number.read(tempor,0);
                    tempor = tempor + 1;
                    clone_number.write(0,tempor);

                    // resubmit the paquet again in Ingress
                    resubmit_preserving_field_list((bit<8>)1);
                }
                // drop any clone 
                drop();  
            }
        }
        if (hdr.ipv4.isValid())
            ipv4_lpm.apply();
    }
}
                       