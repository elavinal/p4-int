#!/usr/bin/env python3

import argparse
import os, sys, json, subprocess, re, argparse
import grpc
# Import P4Runtime lib from current dir
sys.path.append('.')
import p4runtime_lib.bmv2
from p4runtime_lib.error_utils import printGrpcError
from p4runtime_lib.switch import ShutdownAllSwitchConnections
import p4runtime_lib.helper
import p4runtime_lib.simple_controller as p4controller
import yaml

SOURCE = 0
TRANSIT = 1
SINK = 2

TCP = 6
UDP = 17

# TODO: add argument?
WATCHLIST = 'watchlist.yaml'

def push_rules(sw_runtime_file, switch, p4info_helper):
    sw_conf_file = open(sw_runtime_file, 'r')
    sw_conf = p4controller.json_load_byteified(sw_conf_file)
    if 'table_entries' in sw_conf:
        table_entries = sw_conf['table_entries']
        # p4controller.info("Inserting table entries...")
        for entry in table_entries:
            p4controller.insertTableEntry(switch, entry, p4info_helper)

def setup_source_instructions(switch, config, p4info_helper):

    for dest in config['flows']:
        dstAddr = dest['ipv4_dst']
        if dest['l4_proto'] == 'udp':
            l4Proto = UDP
        elif dest['l4_proto'] == 'tcp':
            l4Proto = TCP
        else:
            print('Error on transport protocol')
        srcAddr = dest['ipv4_src']
        dstPort = dest['port_dst']
        flowId = dest['id']
        sampling = dest['sampling']
        instruction = 0
        for instruct in dest['instructions']:
            if instruct == 'node_id':
                instruction |= 0b1
            if instruct == 'lv1_if_id':
                instruction |= 0b10
            if instruct == 'hop_latency':
                instruction |= 0b100
            if instruct == 'queue_id_occupancy':
                instruction |= 0b1000
            if instruct == 'ingress_timestamp':
                instruction |= 0b10000
            if instruct == 'egress_timestamp':
                instruction |= 0b100000
            if instruct == 'lv2_if_id':
                instruction |= 0b1000000
            if instruct == 'eg_if_tx_util':
                instruction |= 0b10000000
            if instruct == 'buffer_id_occupancy':
                instruction |= 0b100000000

        # Build key (for sampling table)
        match_fields = {
            'hdr.ipv4.dstAddr': dstAddr,
            'hdr.ipv4.protocol': l4Proto   
        }
        # Set low priority when no ternary matches
        # (priority is a P4Runtime table entry field)
        priority = 1
        if (srcAddr != 'wildcard'):
            match_fields.update({'hdr.ipv4.srcAddr': (srcAddr, 0xFFFFFFFF)})
            priority += 10
        if (dstPort != 'wildcard'):
            if (l4Proto == TCP):
                match_fields.update({'hdr.tcp.dstPort': (dstPort, 0xFFFF)})
                priority += 10
            elif (l4Proto == UDP):
                match_fields.update({'hdr.udp.dstPort': (dstPort, 0xFFFF)})
                priority += 10
        # print("--> Using match fields : ")
        # print(match_fields)
       
        # Add table entry for INT sampling
        table_entry = p4info_helper.buildTableEntry(
            table_name = 'SwitchEgress.sample_int',
            match_fields = match_fields,
            action_name = 'SwitchEgress.increment',
            action_params = {
                'id': flowId,
                'sampling': sampling
            },
            priority = priority
        )
        print("Writing entry in INT sampling table, for flow id " + str(flowId))
        switch.WriteTableEntry(table_entry)
        
        # Add table entry to setup INT
        table_entry = p4info_helper.buildTableEntry(
            table_name = 'SwitchEgress.add_int_hdr',
            match_fields = { 'meta.flow_id': flowId},
            action_name = 'SwitchEgress.setup_int',
            action_params = {
                'instructionBitmap': instruction
            }
        )
        print("Writing entry in INT add headers table, for flow id " + str(flowId))
        switch.WriteTableEntry(table_entry)

        

# INT roles : 0 source, 1 transit, 2 sink
def configure_switch(switch_name, switch_role, scenario, config_file):
    
    # INT role
    if switch_role == SOURCE:
        p4file_prefix = "build/global_switch"
        RoleNumber = 1
    elif switch_role == TRANSIT:
        p4file_prefix = "build/global_switch"
        RoleNumber = 2
    elif switch_role == SINK:
        p4file_prefix = "build/sink_switch"
        RoleNumber = 3

    p4info_helper = p4runtime_lib.helper.P4InfoHelper("%s.p4.p4info.txt" % p4file_prefix)
            
    # Assumption : switch name sX where X is a number.
    switch_addr = "127.0.0.1:5005%s" % switch_name[1] # only one digit? TO FIX.
    device_id = int(switch_name[1])-1

    try:
        # Creates a switch connection object backed by a P4Runtime gRPC connection
        switch = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name=switch_name,
            address=switch_addr,
            device_id=device_id,
            proto_dump_file='logs/%s-p4runtime-requests.txt' % switch_name)
        switch.MasterArbitrationUpdate()
        switch.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                           bmv2_json_file_path="%s.json" % p4file_prefix)
        print("Installed P4 Program using SetForwardingPipelineConfig on %s" % switch_name)
        # Basic forwarding rules
        print("Writing basic forwarding rules from %s-runtime.json" % switch_name)        
        push_rules("%s/%s-runtime.json"% (scenario, switch_name), switch, p4info_helper)
       

        # Add the switch's id to a data plane table (for the Node ID metadata) 
        if switch_role != SINK: 
            table_entry = p4info_helper.buildTableEntry(
                table_name="SwitchEgress.add_node_id_hdr",
                action_name="SwitchEgress.add_node_id",
                action_params={
                    "switch_id": int(switch_name[1]),
                }
            ) 
            switch.WriteTableEntry(table_entry)
            print('role attribution')
            table_entry = p4info_helper.buildTableEntry(
                table_name="SwitchIngress.switch_roles",
                action_name="SwitchIngress.set_int_role",
                action_params={"role": RoleNumber}
            ) 
            switch.WriteTableEntry(table_entry)

 


        if switch_role == SOURCE: 
            # Source rules
            setup_source_instructions(switch, config_file, p4info_helper)
      
        elif switch_role == SINK:
            # Sink rules
            table_entry = p4info_helper.buildTableEntry(
                table_name="SwitchIngress.trgh",
                action_name="SwitchIngress.trgh_digest",
                action_params={
                    "switch_id": int(switch_name[1]),
                }
            ) 
            switch.WriteTableEntry(table_entry)
            print("Writing DigestEntry to SINK")
            switch.WriteDigestEntry(digest_list=[392481334])
        
    except grpc.RpcError as e:
        printGrpcError(e)

    print("Shutting down.")
    ShutdownAllSwitchConnections()


def main(path):
    config_file = "%s/%s" % (path, WATCHLIST)
    print("Opening config file %s" % config_file)
    with open(config_file) as file:
        config = yaml.full_load(file)
        for switch in config['source']:
            print("Setting up %s as source" % switch)
            configure_switch(switch, SOURCE, path, config)
        for switch in config['transit']:
            print("Setting up %s as transit" % switch)
            configure_switch(switch, TRANSIT, path, config)
        for switch in config['sink']:
            print("Setting up %s as sink" % switch)
            configure_switch(switch, SINK, path, config)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Path for runtime configuration files (INT+Forwarding)')
    parser.add_argument('--dir', help='Path for runtime configuration files',
                        type=str, action="store", required=True)
    args = parser.parse_args()
    main(args.dir)