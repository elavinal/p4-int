#!/usr/bin/env python2

import os, sys, json, subprocess, re, argparse
from time import sleep

from p4_mininet import P4Switch, P4Host

from mininet.net import Mininet
from mininet.topo import Topo
from mininet.link import TCLink
from mininet.cli import CLI

from p4runtime_switch import P4RuntimeSwitch
import p4runtime_lib.simple_controller


def configureP4Switch(**switch_args):
    """ Helper class that is called by mininet to
        init virtual P4 switches.
    """
    if "sw_path" in switch_args and 'grpc' in switch_args['sw_path']:
        class ConfiguredP4RuntimeSwitch(P4RuntimeSwitch):
            def __init__(self, *opts, **kwargs):
                kwargs.update(switch_args)
                P4RuntimeSwitch.__init__(self, *opts, **kwargs)
            
            def describe(self):
                print "%s -> gRPC port : %d" % (self.name, self.grpc_port)
        
        return ConfiguredP4RuntimeSwitch
    else:
        class ConfiguredP4Switch(P4Switch):
            next_thrift_port = 9090
            def __init__(self, *opts, **kwargs):
                global next_thrift_port
                kwargs.update(switch_args)
                kwargs['thrift_port'] += 1
                P4Switch.__init__(self, *opts, **kwargs)

            def describe(self):
                print "%s -> gRPC port : %d" % (self.name, self.thrift_port)
        
        return ConfiguredP4Switch

class NetworkTopo(Topo):
    """ The mininet topology class for the P4 tutorial exercises.
    """
    def __init__(self, hosts, switches, links, log_dir, bmv2_exe, pcap_dir, **opts):
        Topo.__init__(self, **opts)
        host_links = []
        switch_links = []

        # assumes host always comes first for host<-->switch links
        for link in links:
            if link['node1'][0] == 'h':
                host_links.append(link)
            else:
                switch_links.append(link)
        
        for sw, params in switches.iteritems():
            if "program" in params:
                switchClass = configureP4Switch(
                    sw_path=bmv2_exe,
                    json_path=params["program"],
                    log_console=True,
                    pcap_dump=pcap_dir)
            else:
                # add default switch
                switchClass = None
            self.addSwitch(sw, log_file="%s/%s.log" % (log_dir,sw), cls=switchClass)
    
        for link in host_links:
            host_name = link['node1']
            sw_name, sw_port = self.parse_switch_node(link['node2'])
            host_ip = hosts[host_name]['ip']
            host_mac = hosts[host_name]['mac']
            self.addHost(host_name, ip=host_ip, mac=host_mac)
            self.addLink(host_name, sw_name,
                         delay=link['latency'], bw=link['bandwidth'],
                         port2=sw_port)
        
        for link in switch_links:
            sw1_name, sw1_port = self.parse_switch_node(link['node1'])
            sw2_name, sw2_port = self.parse_switch_node(link['node2'])
            self.addLink(sw1_name, sw2_name,
                         port1=sw1_port, port2=sw2_port,
                         delay=0, bw=0.5)

    def parse_switch_node(self, node):
        assert(len(node.split('-')) == 2)
        sw_name, sw_port = node.split('-')
        try:
            sw_port = int(sw_port[1:])
        except:
            raise Exception('Invalid switch node in topology file: {}'.format(node))
        return sw_name, sw_port

class NetworkStarter:
    """
    Attributes:
        log_dir  : string //mininet log files' directory
        pcap_dir : string //mininet switch pcap files' directory
        
        hosts    : dict<string, dict> //mininet host names and associated properties
        switches : dict<string, dict> //mininet switch names and associated properties
        links    : list<dict>         //list of mininet link properties

        switch_json : string // json of the compiled p4 file
        bmv2_exe    : string // name or path of the p4 switch binary

        topo : Topo object //mininet topo instance
        net  : Mininet obj //mininet instance
    """
    def logger(self, *items):
        print(' '.join(items))
    
    def format_latency(self, l):
        """ Helper method for parsing link latencies from the topology json."""
        if isinstance(l, (str, unicode)):
            return l
        else:
            return str(l) + "ms"
    
    def __init__(self, topo_file, log_dir, pcap_dir,
                 switch_json, bmv2_exe='simple_switch'):
        """
        Arguments:
            topo_file : string // json topo file

            log_fir   : string // Path to log directory
            pcap_dir  : string // Path to pcap directory
            switch_json : string // Path to compiled p4 json
            bmv2_exe    : string // Path to p4 behavioral binary
        """

        self.logger('Reading topology file.')
        with open(topo_file, 'r') as f:
            topo = json.load(f)
        self.hosts = topo['hosts']
        self.switches = topo['switches']
        self.links = self.parse_links(topo['links'])

        for dir_name in [log_dir, pcap_dir]:
            if not os.path.isdir(dir_name):
                if os.path.exists(dir_name):
                    raise Exception("'%s' exists and is not a directory!" % dir_name)
                os.mkdir(dir_name)
        self.log_dir = log_dir
        self.pcap_dir = pcap_dir
        self.switch_json = switch_json
        self.bmv2_exe = bmv2_exe

    def start_network(self):
        """Sets up mininet instance, programs the switches,
           and starts the mininet CLI.
        """
        # Initialize mininet with the topology specified by the config
        self.create_network()
        self.net.start()
        sleep(1)

        # some programming that must happen after net has started
        self.program_hosts()
        self.program_switches()

        # wait for it
        sleep(1)

        self.do_net_cli()
        self.net.stop()

    def parse_links(self, unparsed_links):
        """ Given a list of links descritpions of the form [node1, node2, latency, bandwidth]
            with the latency and bandwidth being optional, parses these descriptions into
            dictionaries and store them as self.links
        """
        links = []
        for link in unparsed_links:
            # has to be in alpha order
            s, t, = link[0], link[1]
            if s > t:
                s,t = t,s

            link_dict = {'node1':s,
                         'node2':t,
                         'latency':'0ms',
                         'bandwidth':None
                         }
            if len(link) > 2:
                link_dict['latency'] = self.format_latency(link[2])
            if len(link) > 3:
                link_dict['bandwidth'] = link[3]

            if link_dict['node1'][0] == 'h':
                assert link_dict['node2'][0] == 's', 'Hosts should be connected to switchs, not ' + str(link_dict['node2'])
            links.append(link_dict)
        return links

    def create_network(self):
        """ Creates the mininet object and stores it as self.net

            Side effects:
                - Mininet topology instance stored as self.topo
                - Mininet instance stored as self.net
        """
        self.logger("Building mininet topology.")

        defaultSwitchClass = configureP4Switch(
                                sw_path=self.bmv2_exe,
                                json_path=self.switch_json,
                                log_console=True,
                                pcap_dump=self.pcap_dir)
        
        self.topo = NetworkTopo(self.hosts, self.switches, self.links, self.log_dir, self.bmv2_exe, self.pcap_dir)

        self.net = Mininet(topo=self.topo,
                link=TCLink,
                host=P4Host,
                switch=defaultSwitchClass,
                controller=None)

    def program_switch_p4runtime(self, sw_name, sw_dict):
        """This method will use P4Runtime to program the switch
           using the content of the runtime JSON file as input.
        """
        sw_obj = self.net.get(sw_name)
        thrift_port = sw_obj.thrift_port
        grpc_port = sw_obj.grpc_port
        device_id = sw_obj.device_id
        print "%s" % str(thrift_port)
        print "Configuring switch to handle cloning"
        with open("topo/cloning-command.txt", 'r') as fin:
            cli_outfile = 'logs/%s_cli_output.log' % sw_name
            with open(cli_outfile, 'w') as fout:
                subprocess.Popen(['simple_switch_CLI', '--thrift-port', str(thrift_port)],
                                  stdin=fin)
        runtime_json = sw_dict['runtime_json']
        self.logger('Configurng switch %s using P4Runtime with file %s' % (sw_name, runtime_json))
        with open(runtime_json, 'r') as sw_conf_file:
            outfile = '%s/%s-p4runtime-request.txt' %(self.log_dir, sw_name)
            p4runtime_lib.simple_controller.program_switch(
                addr='127.0.0.1:%d' % grpc_port,
                device_id=device_id,
                sw_conf_file=sw_conf_file,
                workdir=os.getcwd(),
                proto_dump_fpath=outfile
            )
    
    def program_switch_cli(self, sw_name, sw_dict):
        """ This method will start up the CLI and use the contents
            of the command files as input
        """
        cli = 'simple_switch_CLI'
        #get the port for this particular switch's thrift server
        sw_obj = self.net.get(sw_name)
        thrift_port = sw_obj.thrift_port
        print "%s" % str(thrift_port)
        cli_input_commands = sw_dict['cli_input']
        self.logger('Configuring switch %s with file %s' % (sw_name, cli_input_commands))
        with open(cli_input_commands, 'r') as fin:
            cli_outfile = '%s/%s_cli_output.log' % (self.log_dir, sw_name)
            with open(cli_outfile, 'w') as fout:
                subprocess.Popen([cli, '--thrift-port', str(thrift_port)],
                                  stdin=fin, stdout=fout)
    
    def program_switches(self):
        """ This method will program each switch using the BMv2 CLI and/or
            P4Runtime, depending if any command or runtime JSON files were
            provided for the switchs.
        """
        for sw_name, sw_dict in self.switches.iteritems():
            if 'cli_input' in sw_dict:
                self.program_switch_cli(sw_name,sw_dict)
            if 'runtime_json' in sw_dict:
                self.program_switch_p4runtime(sw_name, sw_dict)

    def program_hosts(self):
        """ Execute any commands provided in the topology.json
            file on each Mininet host
        """
        for host_name, host_info in self.hosts.items():
            h = self.net.get(host_name)
            if "commands" in host_info:
                for cmd in host_info["commands"]:
                    h.cmd(cmd)

    def do_net_cli(self):
        """ Starts up the mininet CLI and prints helpful output.
            
            Assumes:
                - A mininet instance is stored as self.net
                - self.net.start() has been called.
        """
        for s in self.net.switches:
            s.describe()
        for h in self.net.hosts:
            h.describe()
        self.logger("Starting mininet CLI")

        print('')
        print('======================================================================')
        print('Welcome to the BMV2 Mininet CLI!')
        print('======================================================================')
        print('Your P4 program is installed into the BMV2 software switch')
        print('and your initial runtime configuration is loaded. You can interact')
        print('with the network using the mininet CLI below.')
        print('')
        if self.switch_json:
            print('To inspect or change the switch configuration, connect to')
            print('its CLI from your host operating system using this command:')
            print('  simple_switch_CLI --thrift-port <switch thrift port>')
            print('')
        print('To view a switch log, run this command from your host OS:')
        print('  tail -f %s/<switchname>.log' %  self.log_dir)
        print('')
        print('To view the switch output pcap, check the pcap files in %s:' % self.pcap_dir)
        print(' for example run:  sudo tcpdump -xxx -r s1-eth1.pcap')
        print('')
        if 'grpc' in self.bmv2_exe:
            print('To view the P4Runtime requests sent to the switch, check the')
            print('corresponding txt file in %s:' % self.log_dir)
            print(' for example run:  cat %s/s1-p4runtime-requests.txt' % self.log_dir)
            print('')

        CLI(self.net)


def get_args():
    cwd = os.getcwd()
    default_logs = os.path.join(cwd, 'logs')
    default_pcaps = os.path.join(cwd, 'pcaps')
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--topo', help='Path to topology json',
                        type=str, required=False, default='./topology.json')
    parser.add_argument('-l', '--log-dir', type=str, required=False, default=default_logs)
    parser.add_argument('-p', '--pcap-dir', type=str, required=False, default=default_pcaps)
    parser.add_argument('-j', '--switch_json', type=str, required=False)
    parser.add_argument('-b', '--behavioral-exe', help='Path to behavioral executable',
                        type=str, required=False, default='simple_switch')
    return parser.parse_args()

if __name__ == '__main__':
    args = get_args()
    network = NetworkStarter("topo/topology.json", args.log_dir, args.pcap_dir,
                             "build/basic_switch.json", "simple_switch_grpc")
    network.start_network()

