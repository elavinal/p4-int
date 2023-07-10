#include "headers.p4"

control SwitchIngress(inout headers hdr,
                       inout metadata meta,
    
                       inout standard_metadata_t standard_metadata) {

    // TODO array of registers? according to flow_id?
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


                meta.int_report.metadata0 = hdr.metadata_extractor[0].md_word;
                meta.int_report.metadata1 = hdr.metadata_extractor[1].md_word;
                meta.int_report.metadata2 = hdr.metadata_extractor[2].md_word;
                meta.int_report.metadata3 = hdr.metadata_extractor[3].md_word;
                meta.int_report.metadata4 = hdr.metadata_extractor[4].md_word;
                meta.int_report.metadata5 = hdr.metadata_extractor[5].md_word;
                meta.int_report.metadata6 = hdr.metadata_extractor[6].md_word;
                meta.int_report.metadata7 = hdr.metadata_extractor[7].md_word;
                meta.int_report.metadata8 = hdr.metadata_extractor[8].md_word;
                meta.int_report.metadata9 = hdr.metadata_extractor[9].md_word;
                meta.int_report.metadata10 = hdr.metadata_extractor[10].md_word;
                meta.int_report.metadata11 = hdr.metadata_extractor[11].md_word;
                meta.int_report.metadata12 = hdr.metadata_extractor[12].md_word;
                meta.int_report.metadata13 = hdr.metadata_extractor[13].md_word;
                meta.int_report.metadata14 = hdr.metadata_extractor[14].md_word;
                meta.int_report.metadata15 = hdr.metadata_extractor[15].md_word;
                // send to the collector the report
                digest<int_report_t>(1, meta.int_report);

                hdr.ipv4.dscp = (bit<6>) hdr.int_md_shim.nptDependentField;
                hdr.ipv4.totalLen = hdr.ipv4.totalLen - ((bit<16>) hdr.int_md_shim.len << 2) - 4; // Because INT shim header isn't counted for length
                if(hdr.udp.isValid()) {
                    hdr.udp.len = hdr.udp.len 
                        - ((bit<16>) hdr.int_md_shim.len << 2)
                        - ((bit<16>) hdr.int_md_header.hopMetaLength << 2)
                        - 4; //Because INT shim header isn't counted for length
                }
                //Deleting INT from the client's packet
                hdr.int_md_shim.setInvalid();
                hdr.int_md_header.setInvalid();
                hdr.tel_rep_group_header.setInvalid();
                hdr.node_id.setInvalid();
                hdr.lv1_if_id.setInvalid();
                hdr.hop_latency.setInvalid();
                hdr.queue_id_occupancy.setInvalid();
                hdr.ingress_timestamp.setInvalid();
                hdr.egress_timestamp.setInvalid();
                hdr.lv2_if_id.setInvalid();
                hdr.eg_if_tx_util.setInvalid();
                hdr.buffer_id_occupancy.setInvalid();
                hdr.metadata_extractor.pop_front(MAX_MD_WORDS);
            }
        }
        if (hdr.ipv4.isValid())
            ipv4_lpm.apply();
    }
}
                       