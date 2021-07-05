#include "defines.p4"

#ifndef __HEADERS__
#define __HEADERS__

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16> etherType;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<6>  dscp;
    bit<2>  ecn;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protoType;
    bit<16> checksum;
    ipv4Addr_t srcAddr;
    ipv4Addr_t dstAddr;
}

header tcp_t {
    portNumber_t srcPort;
    portNumber_t dstPort;
    bit<32>      seqNumber;
    bit<32>      ackNumber;
    bit<4>       hdrLen;
    bit<3>       rsv;
    bit<9>       flags;
    bit<16>      winSize;
    bit<16>      checksum;
    bit<16>      urgentPtr;
}

header udp_t {
    portNumber_t srcPort;
    portNumber_t dstPort;
    bit<16>      len;
    bit<16>      checksum;
}

#endif