#!/usr/bin/env python3
from multiprocessing import Process, Queue
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


def hexToBitMap(Hex): 
    scale = 16 # equals to hexadecimal
    num_of_bits = 16 #llenght of the desired bitmap output
    return bin(int(Hex, scale))[2:].zfill(num_of_bits)


# handle a digest with the static part of the report  
def handleStatic(digest_list,sw,bufferSub,bufferMain,currentID):
    index = 0 # will help us naviguate in the data 
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
    nbMD = nbMD -3 #minus the lenght of int shim + int header
    index+=1 
    MDLenght = data.struct.members[index].bitstring
    print("Metadata Lenght :" + MDLenght.hex())
    lenghtMD = int(MDLenght.hex(),16)
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


    with open('./collector/export.csv', 'a', newline='') as csvfile:
        fieldnames = ['Version', 'hw_id', 'Sequence_Number', 'IDEmission', 'ReportType', 'InnerType', 'Report_Lenght', 'Meta_Lenght', 'Flags', 'Reserved', 'Bitmap', 'DomainSpecID', 'DomainSpecBitmap', 'DomainSpecStatus']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writerow({'Version': version.hex(), 'hw_id': hw_id.hex(), 'Sequence_Number': Sequence_number.hex(), 'IDEmission': switchEmission.hex(), 'ReportType': IntType.hex(), 'InnerType': InnerType.hex(), 'Report_Lenght': ReportLenght.hex(), 'Meta_Lenght': MDLenght.hex(), 'Flags': Flags.hex() , 'Reserved': RSV.hex(), 'Bitmap': str(bitmap), 'DomainSpecID': DomainSpecID.hex(), 'DomainSpecBitmap': DSMdBits.hex(), 'DomainSpecStatus': DSMdStatus.hex()})


    SavedID = handleDynamic(bitmap,nbMD,lenghtMD,digest_list.list_id,sw,bufferSub,bufferMain,currentID)
    #SavedID store the last used digest_id from flexible digest
    #it will be stocked later, in the main loop in currentID to be used here. 

    return SavedID

#return a tab with all the attributes contain in the report by order 
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


# handle all flexible part digests associated with the static part of the report  
def handleDynamic(bitmap,nbMD,MDLenght,digest_id,sw,bufferSub,bufferMain,currentID):
    print(bitmap)
    print(nbMD)
    tab = BitmapToStringTab(bitmap)

    nbloop = int(nbMD/MDLenght) #nbloop = number of switch crossed
    for i in range(nbloop): # for each switch crossed 
        print("Switch n°"  + str(i))
        for k in range(MDLenght): #for each metadata collected by switch
            f = 0 
            #print("Metadata "+ tab[k-1])
            for j in bufferSub: # we try to see if the digest with CurrentID is in our bufferSub
                if (j.list_id == currentID): 
                    f = 1 # if found , we dont need to listen and skip to the end of the loop 
                    info = j # the correct digest is stocked 
                    bufferSub.remove(j) # we remoove it from the buffer

            if (f == 0): #if the currentID digest wasn't in the buffer 
                q = 0 # exit boolean 
                while(q == 0):
                    print("Packet " + str(currentID) + " pas encore reçu, Attente")
                    stream_msg_resp = sw.StreamMessageIn() #  listen to the sink connection
                    print("packet reçu")
                    if stream_msg_resp.WhichOneof('update') == 'digest': # if the message received is a digest 
                        digest_list = stream_msg_resp.digest
                        if (digest_list.digest_id == 399285173): #if the digest contain a static part
                            bufferMain.append(digest_list) # it's stored in the bufferMain
                        else:
                            if(digest_list.list_id == currentID): #if the digest is the one with the currendID
                                info = digest_list # the correct digest is stocked 
                                q = 1 #we don't have to search for the currentID digest no more 
                            else:
                                print('paquet n°'+ str(digest_list.list_id)+ 'recu')
                                bufferSub.append(digest_list) #otherwise it's stored in bufferSub
                    
            

            byteValue = info.data[0].struct.members[0].bitstring #we extract the data from the correct digest
            print(byteValue.hex()) 
            with open('./collector/export.csv', 'a', newline='') as csvfile:
                writer = csv.writer(csvfile, delimiter=' ',quotechar='|', quoting=csv.QUOTE_MINIMAL)
                writer.writerow([tab[k],byteValue.hex()])
            currentID = currentID + 1 # increment the currentID

    SavedID = currentID #once all loops end, we send back the last currentID used.
    return SavedID

    

    

def main():
    
    try:
        # instantiate swicth connection
        sw = p4runtime_lib.bmv2.Bmv2SwitchConnection(
                name='s4',
                address='127.0.0.1:50054',
                device_id=3,
                proto_dump_file='logs/s4-p4runtime-stream.txt')
        sw.MasterArbitrationUpdate()

        print("connexion au switch effectué")
        #instantiate buffer and global indexs
        bufferSub = [] # buffer which contain static part digests
        bufferMain = [] # buffer which contain metadata digests 
        currentID = 1 
        SavedID = 1

        with open('./collector/export.csv', 'w', newline='') as csvfile:
            fieldnames = ['Version', 'hw_id', 'Sequence_Number', 'IDEmission', 'ReportType', 'InnerType', 'Report_Lenght', 'Meta_Lenght', 'Flags', 'Reserved', 'Bitmap', 'DomainSpecID', 'DomainSpecBitmap', 'DomainSpecStatus']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

            writer.writeheader()
        #main loop 
        while True:
            currentID = SavedID # currentID = the last currentID 
            if(len(bufferMain) == 0): # if bufferMain is empty
                print("Attente packet")
                stream_msg_resp = sw.StreamMessageIn() #listen()
                print("packet reçu")
                if stream_msg_resp.WhichOneof('update') == 'digest': #if message is a digest
                    print("Received Digest")
                    print(stream_msg_resp)
                    digest_list = stream_msg_resp.digest
                    if (digest_list.digest_id == 399285173): #if it's a static part digest
                        SavedID = handleStatic(digest_list,sw,bufferSub,bufferMain,currentID) #we proceed it
                    else : 
                        bufferSub.append(digest_list) #otherwise we stock it in the bufferSub
            else: #if the bufferMain is not empty
                digestlist = bufferMain[0] # we pop the first one
                SavedID = handleStatic(digest_list,sw,bufferSub,bufferMain,currentID) #and proceed it 
                bufferMain.remove(0)


    
    except grpc.RpcError as e:
        printGrpcError(e)


if __name__ == '__main__':
    main()