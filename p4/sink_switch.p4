/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>
#include "include/types.p4"
#include "include/defines.p4"
#include "include/headers.p4"
#include "include/int_headers.p4"
#include "include/sink_parser.p4"
#include "include/sink_ingress.p4"
#include "include/sink_egress.p4"
#include "include/deparser.p4"
#include "include/checksum.p4"

V1Switch(
    SwitchParser(),
    SwitchVerifyChecksum(),
    SwitchIngress(),
    SwitchEgress(),
    SwitchComputeChecksum(),
    SwitchDeparser()
) main;