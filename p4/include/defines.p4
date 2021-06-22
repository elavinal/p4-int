#include "types.p4"

#ifndef __DEFINES__
#define __DEFINES__

#define PKT_INSTANCE_TYPE_NORMAL 0
#define PKT_INSTANCE_TYPE_INGRESS_CLONE 1
#define PKT_INSTANCE_TYPE_EGRESS_CLONE 2
#define PKT_INSTANCE_TYPE_COALESCED 3
#define PKT_INSTANCE_TYPE_INGRESS_RECIRC 4
#define PKT_INSTANCE_TYPE_REPLICATION 5
#define PKT_INSTANCE_TYPE_RESUBMIT 6

#define MAX_MD 9

const bit<16> TYPE_IPV4      = 0x800;
const bit<8>  TYPE_TCP       = 0x06;
const bit<4>  TYPE_INT_MD    = 0x1;
const bit<4>  VERSION_INT_MD = 0x2;
const bit<6>  CONTAINS_INT   = 0x17;
const bit<3>  HOP_COUNT_EXCEEDED = 0b010;
const bit<32> REPORT_MIRROR_SESSION_ID = 500;
/* The following declarations are flags for the INT infos to add */
const int_instruction_t NODE_ID             = 0b1;
const int_instruction_t LVL1_IF_ID          = 0b10;      //ingress&egress
const int_instruction_t HOP_LATENCY         = 0b100;
const int_instruction_t QUEUE_ID_OCCUPANCY  = 0b1000;
const int_instruction_t INGRESS_TIMESTAMP   = 0b10000;
const int_instruction_t EGRESS_TIMESTAMP    = 0b100000;
const int_instruction_t LVL2_IF_ID          = 0b1000000; //ingress&egress
const int_instruction_t EG_IF_TX_UTIL       = 0b10000000;
const int_instruction_t BUFFER_ID_OCCUPANCY = 0b100000000;

#endif