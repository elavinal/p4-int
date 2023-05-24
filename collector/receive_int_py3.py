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




def handle(digest_list):
    index = 0
    data = digest_list.data[index]
    print(type(data))
    print(type(data.struct))
    print(type(data.struct.members))
    print(data.struct.members)

    print("*** Parsing Telemetry report Group ***")
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

    print("*** Parsing INT MD SHIM ***")
    IntType = data.struct.members[index].bitstring
    print("ReportType :" + IntType.hex() + " // 01 = INT")
    index+=1 
    InnerType = data.struct.members[index].bitstring
    print("InnerType :" + InnerType.hex() + " // 00 = No tunned Report")
    index+=1 
    ReportLenght = data.struct.members[index].bitstring
    print("Report Lenght :" + ReportLenght.hex())
    index+=1 
    MDLenght = data.struct.members[index].bitstring
    print("Metadata Lenght :" + MDLenght.hex())
    index+=1 
    Flags = data.struct.members[index].bitstring
    print("Flags :" + Flags.hex() + " // (D)Dropped , (Q)Congested, (F)Tracked, (I) Intermediate")
    index+=1 
    RSV = data.struct.members[index].bitstring
    print("reserved :" + RSV.hex() + " // must be 0")
    index+=1 

    print("*** Individual Report Main Content ***")
    RepMDBits = data.struct.members[index].bitstring
    print("BITMAP :" + RepMDBits.hex())
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
                handle(digest_list)

    
    except grpc.RpcError as e:
        printGrpcError(e)


if __name__ == '__main__':
    main()