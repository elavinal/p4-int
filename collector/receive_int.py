#!/usr/bin/env python3
from multiprocessing import Process, Queue
import sys
import struct
import os
import json
import csv
import argparse
import time

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

StaticID = 392481334

def hexToBitMap(Hex): 
    scale = 16 # equals to hexadecimal
    num_of_bits = 16 #lLength of the desired bitmap output
    return bin(int(Hex, scale))[2:].zfill(num_of_bits)


# https://p4.org/p4-spec/docs/telemetry_report_v2_0.pdf
#

# handle a digest with the static part of the report  
def handleStatic(digest_list, sw, t0):

    index = 0 # will help us naviguate in the data 
    data = digest_list.data[index]

    # Telemetry Report Group Header (Ver 2.0)
    # 0                                                               31
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |  Ver  |   hw_id   |           Sequence Number                 |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |                            Node ID                            |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    print("\n *** Parsing Telemetry Report Group Header ***")
    version = data.struct.members[index].bitstring
    print("Version: " + version.hex())
    index += 1
    hw_id = data.struct.members[index].bitstring
    print("hw_id: " + hw_id.hex())
    index += 1
    Sequence_number = data.struct.members[index].bitstring
    print("Sequence number: " + Sequence_number.hex())
    index += 1
    switchEmission = data.struct.members[index].bitstring
    print("Node ID: " + switchEmission.hex())
    index += 1
    
    # Individual Report Header (Ver 2.0)
    # 0                                                               31
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |RepType| InType| Report Length |   MD Length   |D|Q|F|I|  Rsvd |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+<--+
    # |                                                               |   |
    # |                 Individual Report Main Contents               |   |
    # |                  (varies depending on RepType)                |   |
    # |                                                               |   |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ Report
    # |                                                               | Length
    # |                 Individual Report Inner Contents              |   |
    # |         (Truncated Packet or Additional DS Extension Data     |   |
    # |              or TLV depending on InType)                      |   |
    # |                                                               |   |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+<--+
    print("\n *** Parsing Individual Report Header ***")
    RepType = data.struct.members[index].bitstring
    print("Report Type: " + RepType.hex() + " // 01 = INT")
    index += 1
    InType = data.struct.members[index].bitstring
    print("Inner Type: " + InType.hex() + " // 00 = None")
    index += 1
    ReportLength = data.struct.members[index].bitstring
    print("Report Length: " + ReportLength.hex())
    nbMD = int(ReportLength.hex(), 16)
    nbMD = nbMD - 3 # minus the length of int shim + int header
    index += 1
    MDLength = data.struct.members[index].bitstring
    print("Metadata Length: " + MDLength.hex())
    LengthMD = int(MDLength.hex(),16)
    index += 1
    Flags = data.struct.members[index].bitstring
    print("Flags: " + Flags.hex() + " // (D)Dropped , (Q)Congested, (F)Tracked, (I)Intermediate")
    index += 1
    RSV = data.struct.members[index].bitstring
    print("Reserved: " + RSV.hex() + " // must be 0")
    index += 1

    # Individual Report Main Contents for RepType 1 (INT)
    # 0                                                               31
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |            RepMdBits          |      Domain Specific ID       |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |            DSMdBits           |          DSMdstatus           |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+<--+
    # |              Variable Optional Baseline Metadata              |   |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ MD Length
    # |           Variable Optional Domain Specific Metadata          |   |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+<--+
    print("\n *** Individual Report Main Contents ***")
    RepMDBits = data.struct.members[index].bitstring
    bitmap = hexToBitMap(RepMDBits.hex())
    print("BITMAP: " + bitmap)
    index += 1
    DomainSpecID = data.struct.members[index].bitstring
    print("DomainSpecID: " + DomainSpecID.hex())
    index += 1
    DSMdBits = data.struct.members[index].bitstring
    print("DomainSpec BITMAP: " + DSMdBits.hex())
    index += 1
    DSMdStatus = data.struct.members[index].bitstring
    print("DomainSpec MD status: " + DSMdStatus.hex())
    index += 1

    #write in export file
    with open('./collector/export.csv', 'a', newline='') as csvfile:
        fieldnames = ['Time', 'Version', 'hw_id', 'Sequence_Number', 'NodeID', # Telemetry Report Group Header
                      'RepType', 'InType', 'RepLength', 'MDLength', 'Flags', 'Reserved', # Individual Report Header
                      'Bitmap', 'DomainSpecID', 'DomainSpecBitmap', 'DomainSpecStatus'] # Individual Report Main Contents
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writerow(
            {'Time': str(time.thread_time_ns()-t0),
             'Version': version.hex(), 'hw_id': hw_id.hex(), 'Sequence_Number': Sequence_number.hex(), 'NodeID': switchEmission.hex(),
             'RepType': RepType.hex(), 'InType': InType.hex(), 'RepLength': ReportLength.hex(), 'MDLength': MDLength.hex(), 'Flags': Flags.hex() , 'Reserved': RSV.hex(),
             'Bitmap': str(bitmap), 'DomainSpecID': DomainSpecID.hex(), 'DomainSpecBitmap': DSMdBits.hex(), 'DomainSpecStatus': DSMdStatus.hex()})


    #parsing metadata
    tab = BitmapToStringTab(bitmap)

    nbloop = int(nbMD/LengthMD) #nbloop = number of switch crossed
    for i in range(nbloop): # for each switch crossed 
        print("Switch n°"  + str(i))
        for k in range(LengthMD): #for each metadata collected by switch     
            byteValue = data.struct.members[index].bitstring #we extract the data from the correct digest
            
            with open('./collector/export.csv', 'a', newline='') as csvfile:
                writer = csv.writer(csvfile, delimiter=',',quotechar='|', quoting=csv.QUOTE_MINIMAL)
                string  = byteValue.hex()
                alt = int(string,16)
                
                writer.writerow([str(time.thread_time_ns()-t0),tab[k],str(alt)])
            index += 1 # increment the currentID




# return a tab with all the attributes contained in the report by order 
def BitmapToStringTab(bitmap):
    tab = []
    if(bitmap[15] == '1'):
        tab.append("node_id")
    if(bitmap[14] == '1'):
        tab.append("LVL1_IF_ID")
    if(bitmap[13] == '1'):
        tab.append("HOP_LATENCY")
    if(bitmap[12] == '1'):
        tab.append("QUEUE_ID_OCCUPANCY")
    if(bitmap[11] == '1'):
        tab.append("INGRESS_TIMESTAMP")
    if(bitmap[10] == '1'):
        tab.append("EGRESS_TIMESTAMP")
    if(bitmap[9] == '1'):
        tab.append("LVL2_IF_ID")
    if(bitmap[8] == '1'):
        tab.append("EG_IF_TX_UTIL")
    if(bitmap[7] == '1'):
        tab.append("BUFFER_ID_OCCUPANCY")
    return tab




def main(s):
    
    try:
        idSwitch = int(s)-1 
        # instantiate switch connection
        sw = p4runtime_lib.bmv2.Bmv2SwitchConnection(
                name='s%s' % s,
                address='127.0.0.1:5005%s' % s,
                device_id=idSwitch, 
                proto_dump_file='logs/s%s-p4runtime-stream.txt' % s) 
        sw.MasterArbitrationUpdate()

        print("Connected to switch %s" % s)
        # instantiate buffer and global indexes
        t0 = time.thread_time_ns()

        with open('./collector/export.csv', 'w', newline='') as csvfile:
            fieldnames = ['Time', 'Version', 'hw_id', 'Sequence_Number', 'NodeID', # Telemetry Report Group Header
                          'RepType', 'InType', 'RepLength', 'MDLength', 'Flags', 'Reserved', # Individual Report Header
                          'Bitmap', 'DomainSpecID', 'DomainSpecBitmap', 'DomainSpecStatus'] # Individual Report Main Contents
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
        # main loop 
        while True:
                print("Attente packet")
                stream_msg_resp = sw.StreamMessageIn() #listen()
                print("packet reçu")
                if stream_msg_resp.WhichOneof('update') == 'digest': #if message is a digest
                    print("Received Digest")
                    print(stream_msg_resp)
                    digest_list = stream_msg_resp.digest
                    if (digest_list.digest_id == StaticID): # if it's a static part digest
                        handleStatic(digest_list, sw, t0) # we proceed it
    except grpc.RpcError as e:
        printGrpcError(e)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='id of the sink switch to connect to, exemple: --s 3 to connect to s3')
    parser.add_argument('--s', help='number of the sink switch to connect to, exemple: --s 3 to connect to s3',
                        type=str, action="store", required=True)
    args = parser.parse_args()
    main(args.s)