#ifndef __TYPES__
#define __TYPES__

typedef bit<48> macAddr_t;
typedef bit<32> ipv4Addr_t;
typedef bit<16> portNumber_t;
typedef bit<16> int_instruction_t;
typedef bit<9>  egressSpec_t;
typedef bit<32> switchID_t;
typedef bit<24> qdepth_t;

struct parser_metadata_t {
    bit<8> remaining;
}

#endif