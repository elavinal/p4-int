#include "headers.p4"
#include "int_headers.p4"

control SwitchVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}

control SwitchComputeChecksum(inout headers hdr, inout metadata meta){
    apply{
        update_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.dscp,
              hdr.ipv4.ecn,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.checksum,
            HashAlgorithm.csum16
        );
    }
}