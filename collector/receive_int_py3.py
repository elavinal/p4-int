#!/usr/bin/env python3
import sys
import struct
import os

import csv
import argparse
from datetime import datetime
from scapy.all import sniff, sendp, hexdump, get_if_list, get_if_hwaddr
from scapy.all import Packet, IPOption
from scapy.all import ByteField, PacketListField, ShortField, IntField, LongField, BitField, FieldListField, FieldLenField
from scapy.all import IP, TCP, UDP, Raw
from scapy.layers.inet import TCP, bind_layers

NODE_ID             = 0b1
LVL1_IF_ID          = 0b10
HOP_LATENCY         = 0b100
QUEUE_ID_OCCUPANCY  = 0b1000
INGRESS_TIMESTAMP   = 0b10000
EGRESS_TIMESTAMP    = 0b100000
LVL2_IF_ID          = 0b1000000
EG_IF_TX_UTIL       = 0b10000000
BUFFER_ID_OCCUPANCY = 0b100000000

def get_if():
    ifs=get_if_list()
    iface=None
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface

class INTMD(Packet):
    name = "INT-MD_Header"
    fields_desc =  [BitField("version", 0, 4),
                    BitField("flags", 0, 3),
                    BitField("reserved", 0, 12),
                    BitField("HopMetaLength", 0, 5),
                    BitField("RemainingHopCount", 0, 8),
                    ShortField("Instructions", 0),
                    ShortField("DomainFlags", 0),
                    ShortField("DomainInstructions", 0),
                    ShortField("DomainID", 0)]

class INTShim(Packet):
    name = "INT Shim header"
    fields_desc = [BitField("type", 0, 4),
                   BitField("next_protocol", 0, 2),
                   BitField("reserved", 0, 2),
                   BitField("int_length", 0, 8),
                   ShortField("NPT_Dependent_Field", 0)]

def extract_metadata(metadata, bytes, index):
    value = 0
    while bytes > 0:
            multiplier = 2**(8*(bytes - 1))
            value += ord(metadata[index])*multiplier
            bytes -= 1
            index += 1
    return value

def parse_metadata(pkt, instructions, metadata, meta_size, hop_meta_length, writer):
    char_index = 0
    meta_index = 0
    data_row = ['N/A','N/A','N/A','N/A','N/A','N/A','N/A', 'N/A',
                'N/A','N/A','N/A','N/A','N/A','N/A', 'N/A']
    while meta_size > 0:
        data_row[0]=datetime.now().strftime("%d/%m/%Y %H:%M:%S")
        meta_index += 1
        print("\n------ Metadata %d ------" % meta_index)
        if(instructions & NODE_ID):
            data = extract_metadata(metadata, 4, char_index)
            print(f"node id : {data}")
            data_row[1] = data
            char_index += 4
        if(instructions & LVL1_IF_ID):
            data = extract_metadata(metadata, 2, char_index)
            char_index += 2
            print("lv1 ingress interface id : %d" % data)
            data_row[2] = data
            data = extract_metadata(metadata, 2, char_index)
            char_index += 2       
            print("lv1 egress interface id : %d" % data)
            data_row[3] = data
        if(instructions & HOP_LATENCY):
            data = extract_metadata(metadata, 4, char_index)
            char_index += 4
            print("hop latency : %d microsec" % data)
            data_row[4] = data
        if(instructions & QUEUE_ID_OCCUPANCY):
            data = extract_metadata(metadata, 1, char_index)
            char_index += 1
            print("queue id : %d" %data)
            data_row[5] = data
            data = extract_metadata(metadata, 3, char_index)
            char_index += 3
            print("queue occupancy : %d packet(s)" % data)
            data_row[6] = data
        if(instructions & INGRESS_TIMESTAMP):
            data = extract_metadata(metadata, 8, char_index)
            char_index += 8
            print("ingress timestamp : %d " % data)
            data_row[7] = data
            print(datetime.fromtimestamp(data))
            print(data)
        if(instructions & EGRESS_TIMESTAMP):
            data = extract_metadata(metadata, 8, char_index)
            char_index += 8
            print("egress timestamp : %d" % data)
            data_row[8] = data
        if(instructions & LVL2_IF_ID):
            data = extract_metadata(metadata, 4, char_index)
            char_index += 4
            print("lv2 ingress interface id : %d" % data)
            data_row[9] = data
            data = extract_metadata(metadata, 4, char_index)
            char_index += 4
            print("lv2 egress interface id : %d" % data)
            data_row[10] = data
        if(instructions & EG_IF_TX_UTIL):
            data = extract_metadata(metadata, 4, char_index)
            char_index += 4
            print("egress interface TX utilization : %d" % data)
            data_row[11] = data
        if(instructions & BUFFER_ID_OCCUPANCY):
            data = extract_metadata(metadata, 1, char_index)
            char_index += 1
            print("buffer id : %d" % data)
            data_row[12] = data
            data = extract_metadata(metadata, 3, char_index)
            char_index += 3
            print("buffer occupancy : %d" % data)
            data_row[13] = data
        meta_size -= hop_meta_length
        print("TCP port : %d" % pkt[TCP].dport)
        data_row[14] = pkt[TCP].dport
        writer.writerow(data_row)


#bind_layers(IP, INTShim, tos=0x17)



def handle_pkt(pkt, writer):

    if TCP in pkt and pkt[IP].tos == 0x5C:
        print("\n\n********* Receiving Telemtry Report ********")
        parse_metadata(pkt,
                       int(pkt[INTMD].Instructions), 
                       #pkt[Raw].load.decode('cp1250'),
                       str(pkt[Raw].load[:(pkt[INTShim].int_length-3)*4], 'utf-8', 'ignore'), 
                       int(pkt[INTShim].int_length-3)*4, 
                       int(pkt[INTMD].HopMetaLength)*4, writer)
        print(pkt[Raw].load[:(pkt[INTShim].int_length-3)*4])
        pkt.show()
    #    print int(pkt[Metadata])
    #    hexdump(pkt)

def main(output):
    bind_layers(TCP, INTShim)
    bind_layers(INTShim, INTMD, type=1)
    headers = ['date', 'node_id', 'lv1_in_if_id', 'lv1_eg_if_id', 
               'hop_latency', 'queue_id', 'queue_occupancy', 
               'ingress_timestamp','egress_timestamp',
               'lv2_in_if_id', 'lv2_eg_if_id', 'eg_if_tx_util', 
               'buffer_id', 'buffer_occupancy', 'tcp_port']
    write_headers = 1
    if os.path.exists(output):
        write_headers = 0
    with open(output, 'a') as file:
        writer = csv.writer(file)
        if write_headers:
            writer.writerow(headers)
        ifaces = filter(lambda i: 'eth' in i, os.listdir('/sys/class/net/'))
        print(ifaces)
        iface = 'eth0'
        print("sniffing on %s" % iface)
        sys.stdout.flush()
        sniff(iface = iface,
            prn = lambda x: handle_pkt(x, writer))

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='CSV outputfile')
    parser.add_argument('--o', help='output CSV file name',
                        type=str, action="store", required=False,
                        default=os.devnull)
    args = parser.parse_args()
    if args.o != os.devnull:
        args.o = "../data/%s.csv" % args.o
    main(args.o)
