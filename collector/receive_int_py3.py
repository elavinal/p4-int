#!/usr/bin/env python3

import sys
import struct
import os
import json
import csv
import argparse


from datetime import datetime
import grpc
# sys.path.append(
#     os.path.join(os.path.dirname(os.path.abspath(__file__)),
#     'utils/'))
# Import P4Runtime lib from current dir
sys.path.append('.')
import p4runtime_lib.bmv2
from p4runtime_lib.error_utils import printGrpcError
from p4runtime_lib.switch import ShutdownAllSwitchConnections
import p4runtime_lib.helper
import p4runtime_lib.simple_controller as p4controller
import yaml
from p4runtime_lib.convert import decodeNum


NODE_ID             = 0b1
LVL1_IF_ID          = 0b10
HOP_LATENCY         = 0b100
QUEUE_ID_OCCUPANCY  = 0b1000
INGRESS_TIMESTAMP   = 0b10000
EGRESS_TIMESTAMP    = 0b100000
LVL2_IF_ID          = 0b1000000
EG_IF_TX_UTIL       = 0b10000000
BUFFER_ID_OCCUPANCY = 0b100000000

def hexToBitMap(Hex):
    scale = 16 # equals to hexadecimal
    num_of_bits = 16
    return bin(int(Hex, scale))[2:].zfill(num_of_bits)



def handleStatic(digest_list,sw):
    index = 0
    data = digest_list.data[index]

    print("\n *** Parsing Telemetry report Group ***")
    version = data.struct.members[index].bitstring
    print("Version :" + version.hex())
    index+=1 
    hw_id = data.struct.members[index].bitstring
    print("hw_id :" + hw_id.hex()) 
    index+=1 
    Sequence_number = data.struct.members[index].bitstring
    print("Sequence number :" + Sequence_number.hex())
    index+=1  
    switchEmission = data.struct.members[index].bitstring
    print("IDSwitchEmission :" + switchEmission.hex()) 
    index+=1 

    print("\n *** Parsing Individual Report Header ***")
    IntType = data.struct.members[index].bitstring
    print("ReportType :" + IntType.hex() + " // 01 = INT")
    index+=1 
    InnerType = data.struct.members[index].bitstring
    print("InnerType :" + InnerType.hex() + " // 00 = No tunned Report")
    index+=1 
    ReportLenght = data.struct.members[index].bitstring
    print("Report Lenght :" + ReportLenght.hex())
    nbMD = int(ReportLenght.hex(),16)
    nbMD = nbMD -3 #on enlève la taille int shim + int header
    index+=1 
    MDLenght = data.struct.members[index].bitstring
    print("Metadata Lenght :" + MDLenght.hex())
    nbMD = int(MDLenght.hex(),16)
    index+=1 
    Flags = data.struct.members[index].bitstring
    print("Flags :" + Flags.hex() + " // (D)Dropped , (Q)Congested, (F)Tracked, (I) Intermediate")
    index+=1 
    RSV = data.struct.members[index].bitstring
    print("reserved :" + RSV.hex() + " // must be 0")
    index+=1 

    print("\n *** Individual Report Main Content ***")
    RepMDBits = data.struct.members[index].bitstring
    bitmap = hexToBitMap(RepMDBits.hex())
    print("BITMAP :" + bitmap)
    index+=1 
    DomainSpecID = data.struct.members[index].bitstring
    print("DomainSpecID :" + DomainSpecID.hex())
    index+=1 
    DSMdBits = data.struct.members[index].bitstring
    print("DomainSpec BITMAP :" + DSMdBits.hex())
    index+=1 
    DSMdStatus = data.struct.members[index].bitstring
    print("DomainSpecMD status  :" + DSMdStatus.hex())
    index+=1 

    handleDynamic(bitmap,nbMD,MDLenght,sw)

def BitmapToStringTab(bitmap):
    tab[String]
    if(bitmap & NODE_ID):
        tab.append("node_id")
    if(bitmap & LVL1_IF_ID):
        tab.append("LVL1_IF_ID")
    if(bitmap & HOP_LATENCY):
        tab.append("HOP_LATENCY")
    if(bitmap & QUEUE_ID_OCCUPANCY):
        tab.append("QUEUE_ID_OCCUPANCY")
    if(bitmap & INGRESS_TIMESTAMP):
        tab.append("INGRESS_TIMESTAMP")
    if(bitmap & EGRESS_TIMESTAMP):
        tab.append("EGRESS_TIMESTAMP")
    if(bitmap & LVL2_IF_ID):
        tab.append("LVL2_IF_ID")
    if(bitmap & EGRESS_TIMESTAMP):
        tab.append("EG_IF_TX_UTIL")
    if(bitmap & EGRESS_TIMESTAMP):
        tab.append("BUFFER_ID_OCCUPANCY")
    return tab



def handleDynamic(bitmap,nbMD,MDLenght,sw):
    print(bitmap)
    print(nbMD)

    for j in range(2):
        index = 0
        print("\n *** LECTURE METADATA  ***")
        for i in range(2):
            print("attente packet")
            stream_msg_resp = sw.StreamMessageIn()
            print("packet reçu")
            if stream_msg_resp.WhichOneof('update') == 'digest':
                print("Received Digest")
                digest_list = stream_msg_resp.digest
                byteValue = digest_list.data[0].struct.members[index].bitstring
                print(byteValue.hex())
                index += 1
    

    

def main():
    
    try:
        sw = p4runtime_lib.bmv2.Bmv2SwitchConnection(
                name='s4',
                address='127.0.0.1:50054',
                device_id=3,
                proto_dump_file='logs/s4-p4runtime-stream.txt')
        sw.MasterArbitrationUpdate()


        print("connexion au switch effectué")
        while True:
            print("Attente packet")
            stream_msg_resp = sw.StreamMessageIn()
            print("packet reçu")
            if stream_msg_resp.WhichOneof('update') == 'digest':
                print("Received Digest")
                digest_list = stream_msg_resp.digest
                
                handleStatic(digest_list,sw)

    
    except grpc.RpcError as e:
        printGrpcError(e)


if __name__ == '__main__':
    main()