#!/usr/bin/env python3.6
import binascii
import os
import random
import sys
import math
import collections
import getopt
import pprint


try:
    from graph import GraphGenerator
    import stem
    import socket
    import json
    import stem.descriptor
    import stem.util.str_tools
    import ntor
    import operator
    import configparser
    from graphviz import Digraph
    from pathlib import Path
    from graphviz import Graph
    from collections import namedtuple
    from stem.descriptor.server_descriptor import RelayDescriptor, _truncated_b64encode
    from stem.descriptor.extrainfo_descriptor import RelayExtraInfoDescriptor
    from stem.descriptor.networkstatus import NetworkStatusDocumentV3
    from stem.descriptor.router_status_entry import RouterStatusEntryV3
except ImportError:
    print('Requirements:')
    sys.exit(1)


def parse_config_file(file):
    config = configparser.ConfigParser(allow_no_value=True)

    try:
        config.read(file)
    except configparser.DuplicateSectionError:
        print('Duplicate sections in .ini file')  # todo
        sys.exit(1)

    conf = []
    all_nodes = []
    all_sims = []

    try:
        dic = {'remove_duplicate_paths': config.getboolean('general', 'remove_duplicate_paths'),
               'generate_graph': config.getboolean('general', 'generate_graph'),
               'create_html': config.getboolean('general', 'create_html'),
               'path': config['general']['path'],
               'same_bandwidth': config.getboolean('general', 'same_bandwidth'),
               'bandwidth_value': None if config['general']['bandwidth_value'] == '' else config.getint('general', 'bandwidth_value'),
               'simulation_type': config['general']['simulation_type'],
               }
    except KeyError:
        print('Key Error: config.ini')
        sys.exit(1)

    if config['general']['simulation_type'] == 'path':
        try:
            dic['guard'] = config.getint('path_simulation', 'guard')
            dic['middle'] = config.getint('path_simulation', 'middle')
            dic['exit'] = config.getint('path_simulation', 'exit')
            dic['guard_exit'] = config.getint('path_simulation', 'guard_exit')
            dic['number_of_simulations'] = config.getint('path_simulation', 'number_of_simulations')
            dic['adv_exit'] = 0
            dic['adv_guard'] = 0
            dic['adv_guard_bandwidth'] = 0
            dic['adv_exit_bandwidth'] = 0
            dic['path_selection'] = config['path_simulation']['path_selection']
            dic['simulation_size'] = config['path_simulation']['simulation_size']
        except ValueError:
            print()
            sys.exit(1)
    elif config['general']['simulation_type'] == 'hidden_service':
        try:
            dic['guard'] = 0
            dic['middle'] = 0
            dic['exit'] = 0
            dic['guard_exit'] = config.getint('hiden_service_simulation', 'nodes')
            dic['number_of_simulations'] = 8
            dic['adv_exit'] = 0
            dic['adv_guard'] = 0
            dic['adv_guard_bandwidth'] = 0
            dic['adv_exit_bandwidth'] = 0
            dic['path_selection'] = 'random'
        except ValueError:
            print()
            sys.exit()
    elif config['general']['simulation_type'] == 'attack':
        try:
            dic['guard'] = config.getint('attack_simulation', 'guard')
            dic['middle'] = 0
            dic['exit'] = config.getint('attack_simulation', 'exit')
            dic['guard_exit'] = 0
            dic['number_of_simulations'] = config.getint('attack_simulation', 'number_of_simulations')
            dic['adv_exit'] = config.getint('attack_simulation', 'adv_exit')
            dic['adv_guard'] = config.getint('attack_simulation', 'adv_guard')
            dic['adv_guard_bandwidth'] = config.getint('attack_simulation', 'adv_guard_bandwidth')
            dic['adv_exit_bandwidth'] = config.getint('attack_simulation', 'adv_exit_bandwidth')
            dic['path_selection'] = 'random'
        except ValueError:
            print()
            sys.exit(1)
    elif config['general']['simulation_type'] == 'multiple_sim':
        try:
            dic['number_of_simulations'] = config.getint('attack_simulation', 'number_of_simulations')
            dic['path_selection'] = 'random'
        except ValueError:
            print()
            sys.exit(1)
        except KeyError:
            ...

        try:
            for s in config.sections():
                sim = {}
                if 'sim_' in s:
                    sim['guard'] = config.getint(s, 'guard')
                    sim['middle'] = 0
                    sim['exit'] = config.getint(s, 'exit')
                    sim['guard_exit'] = 0
                    sim['number_of_simulations'] = config.getint('multiple_sim', 'number_of_simulations')
                    sim['adv_exit'] = config.getint(s, 'adv_exit')
                    sim['adv_guard'] = config.getint(s, 'adv_guard')
                    sim['adv_guard_bandwidth'] = config.getint(s, 'adv_guard_bandwidth')
                    sim['adv_exit_bandwidth'] = config.getint(s, 'adv_exit_bandwidth')
                    sim['path_selection'] = 'random'
                    all_sims.append(sim)
        except KeyError:
            print('Key Error: ')
            sys.exit(1)
        except ValueError:
            print()
            sys.exit(1)
    else:
        ...

    try:
        for n in config.sections():
            node = {}
            if 'node' in n:
                node['type'] = config[n]['type']
                if config[n]['name'].isalpha():
                    node['name'] = config[n]['name']
                else:
                    node['name'] = ''
                node['ip'] = config[n]['ip']
                node['port'] = config[n]['port']
                node['bandwidth'] = "{} {} {}".format(config[n]['bandwidth'], config[n]['bandwidth'],
                                                      config[n]['bandwidth'])
                all_nodes.append(node)
    except KeyError:
        print('Key Error: user defined node must have these parameters: Type, Name, IP, Port, Bandwidth')
        sys.exit(1)

    conf.append(dic)
    conf.append(all_nodes)
    conf.append(all_sims)
    # pprint.pprint(conf)
    return conf


def parse_config_file_old():
    config = configparser.ConfigParser(allow_no_value=True)
    try:
        config.read('config.ini')
    except configparser.DuplicateSectionError:
        print('Node already exists')  # todo
        sys.exit(1)

    conf = []
    all_nodes = []

    try:
        dic = {'guard': config['path_simulation']['guard'],
               'middle': config['path_simulation']['middle'],
               'exit': config['path_simulation']['exit'],
               'guard_exit': config['path_simulation']['guard_exit'],
               'number_of_simulations': config['path_simulation']['number_of_simulations'],
               'simulation_size': config['path_simulation']['simulation_size'],
               'path_selection': config['path_simulation']['path_selection'],
               'remove_duplicate_paths': config['general']['remove_duplicate_paths'].upper() in ['TRUE'],
               'generate_graph': config['general']['generate_graph'].upper() in ['TRUE'],
               'create_html': config['general']['create_html'].upper() in ['TRUE'],
               'path': config['general']['path'],
               'same_bandwidth': config['general']['same_bandwidth'].upper() in ['TRUE'],
               'bandwidth_value': config['general']['bandwidth_value'],
               'simulation_type': config['general']['simulation_type'],
               'nodes': config['hiden_service_simulation']['nodes'],
               'adv_guard_bandwidth': config['attack_simulation']['adv_guard_bandwidth'],
               'adv_exit_bandwidth': config['attack_simulation']['adv_exit_bandwidth'],
               'adv_guard': config['attack_simulation']['adv_guard'],
               'adv_exit': config['attack_simulation']['adv_exit'],
               }
        conf.append(dic)
    except KeyError:
        print('Key Error: config.ini')
        sys.exit(1)

    try:
        for n in config.sections():
            node = {}
            if 'node' in n:
                node['type'] = config[n]['type']
                if config[n]['name'].isalpha():
                    node['name'] = config[n]['name']
                else:
                    node['name'] = ''
                node['ip'] = config[n]['ip']
                node['port'] = config[n]['port']
                node['bandwidth'] = "{} {} {}".format(config[n]['bandwidth'], config[n]['bandwidth'],
                                                      config[n]['bandwidth'])
                all_nodes.append(node)
        conf.append(all_nodes)
    except KeyError:
        print('Key Error: user defined node must have these parameters: Type, Name, IP, Port, Bandwidth')
        sys.exit(1)

    try:
        conf[0]['number_of_simulations'] = int(conf[0]['number_of_simulations'])
    except ValueError:
        print('Number of simulations have to be >= 1')
        sys.exit(1)

    try:
        conf[0]['bandwidth_value'] = int(conf[0]['bandwidth_value'])
    except ValueError:
        conf[0]['bandwidth_value'] = None

    if conf[0]['simulation_type'] == 'path':
        try:
            conf[0]['exit'] = int(conf[0]['exit'])
            conf[0]['middle'] = int(conf[0]['middle'])
            conf[0]['guard'] = int(conf[0]['guard'])
            conf[0]['guard'] = int(conf[0]['guard'])
            conf[0]['guard_exit'] = int(conf[0]['guard_exit'])
            if conf[0]['guard'] < 0:
                print('Number of guards have to be > 0')
                sys.exit(1)
            if conf[0]['exit'] < 0:
                print('Number of exits have to be > 0')
                sys.exit(1)
            if conf[0]['guard_exit'] < 0:
                print('Number of guard_exit have to be >= 0')
                sys.exit(1)
            if conf[0]['guard_exit'] + conf[0]['guard'] == 0:
                print('Number of guards have to be > 0')
                sys.exit(1)
            if conf[0]['guard_exit'] + conf[0]['exit'] == 0:
                print('Number of exits have to be > 0')
                sys.exit(1)
            if conf[0]['exit'] + conf[0]['guard'] + conf[0]['middle'] + conf[0]['guard_exit'] < 3:
                print('Number of nodes have to be > 3')
                sys.exit(1)
        except ValueError:
            print('Number of nodes have to be > 3\n'
                  'Number of guards have to be > 1\n'
                  'Number of exits have to be > 1')
            sys.exit(1)
    elif conf[0]['simulation_type'] == 'attack':  # todo max 255 overflow
        try:
            conf[0]['number_of_simulations'] = int(config['attack_simulation']['number_of_simulations'])
            conf[0]['adv_guard_bandwidth'] = int(config['attack_simulation']['adv_guard_bandwidth'])
            conf[0]['adv_exit_bandwidth'] = int(config['attack_simulation']['adv_exit_bandwidth'])
            conf[0]['adv_guard'] = int(conf[0]['adv_guard'])
            conf[0]['adv_exit'] = int(conf[0]['adv_exit'])
            conf[0]['guard_exit'] = int(config['attack_simulation']['nodes'])
            conf[0]['guard'] = 0
            conf[0]['middle'] = 0
            conf[0]['exit'] = 0
            if conf[0]['adv_guard'] + conf[0]['adv_exit'] + conf[0]['guard_exit'] < 3:
                print('Number of nodes + adv. guard + adv. exit have to be > 3\n')
                sys.exit(1)
        except ValueError:
            print('Value of nodes, bandwidth, simulations have to be number')
            sys.exit(1)
    elif conf[0]['simulation_type'] == 'hidden_service':
        conf[0]['adv_exit'] = 0
        conf[0]['adv_guard'] = 0
        conf[0]['adv_guard_bandwidth'] = 0
        conf[0]['adv_exit_bandwidth'] = 0
        conf[0]['number_of_simulations'] = 8
        try:
            conf[0]['guard_exit'] = int(conf[0]['nodes'])
            conf[0]['guard'] = 0
            conf[0]['middle'] = 0
            conf[0]['exit'] = 0
            if conf[0]['guard_exit'] < 3:
                print('Number of nodes have to be > 3\n')
                sys.exit(1)
        except ValueError:
            print('Value of nodes and bandwidth have to be number')

    if conf[0]['simulation_type'] == 'path':
        conf[0]['adv_exit'] = 0
        conf[0]['adv_guard'] = 0
        conf[0]['adv_guard_bandwidth'] = 0
        conf[0]['adv_exit_bandwidth'] = 0
        if conf[0]['simulation_size'] == 'small':
            if conf[0]['path_selection'] != 'random':
                print('Value of path_selection have to be: random')
        
        if conf[0]['path_selection'] == '3_guards':
            if conf[0]['guard'] + conf[0]['guard_exit'] < 3:
                print('Number of guards have to be > 3')
                sys.exit(1)
        if conf[0]['path_selection'] == '1_guard':
            if conf[0]['guard'] + conf[0]['guard_exit'] < 1:
                print('Number of guards have to be > 1')
                sys.exit(1)

    return conf


def run_simulation(file):
    loop_count = 0
    config = parse_config_file(file)

    if config[0]['simulation_type'] == 'multiple_sim':
        output_from_all_sims = []
        for sim in config[2]:
            routers = make_descriptors(
                check_params(sim['path_selection'], sim['guard'], sim['middle'], sim['exit'], sim['guard_exit'],
                             config[0]['same_bandwidth'], config[1], config[0]['simulation_type'],
                             config[0]['bandwidth_value']))
            run_tor_path_simulator(config[0]['path'], sim['adv_guard'], sim['adv_exit'], sim['adv_guard_bandwidth'],
                                   sim['adv_exit_bandwidth'], sim['number_of_simulations'])
            circuits_output = get_circuits(config[0]['remove_duplicate_paths'], routers, sim['adv_guard_bandwidth'],
                                           sim['adv_exit_bandwidth'], config[0]['simulation_type'], loop_count,
                                           sim['adv_guard'], sim['adv_exit'])
            output_from_all_sims.append(circuits_output)
            loop_count += 1
        if config[0]['generate_graph']:
            g = GraphGenerator(sim_type=config[0]['simulation_type'], output_from_all_sims=output_from_all_sims)
            GraphGenerator.generate_graph(g)
    else:
        routers = make_descriptors(check_params(config[0]['path_selection'], config[0]['guard'], config[0]['middle'],
                                                config[0]['exit'], config[0]['guard_exit'], config[0]['same_bandwidth'],
                                                config[1], config[0]['simulation_type'], config[0]['bandwidth_value']))
        run_tor_path_simulator(config[0]['path'], config[0]['adv_guard'], config[0]['adv_exit'],
                               config[0]['adv_guard_bandwidth'], config[0]['adv_exit_bandwidth'],
                               config[0]['number_of_simulations'])
        circuits_output = get_circuits(config[0]['remove_duplicate_paths'], routers, config[0]['adv_guard_bandwidth'],
                                       config[0]['adv_exit_bandwidth'], config[0]['simulation_type'], loop_count)

    if config[0]['simulation_type'] == 'hidden_service' and config[0]['generate_graph']:
        g = GraphGenerator(routers=routers, paths=circuits_output[0], sim_type=config[0]['simulation_type'])
        exit_code_graph = GraphGenerator.generate_graph(g)      # todo exit code graph
    elif config[0]['simulation_type'] == 'attack' and config[0]['generate_graph']:
        g = GraphGenerator(routers=routers, adv_guard_c=config[0]['adv_guard'], adv_exit_c=config[0]['adv_exit'],
                           color=circuits_output[1], sim_type=config[0]['simulation_type'])
        GraphGenerator.generate_graph(g)
    elif config[0]['simulation_type'] == 'path' and config[0]['generate_graph']:
        g = GraphGenerator(routers=routers, paths=circuits_output[0], guard_exit=config[0]['guard_exit'],
                           guards_to_generate=config[0]['path_selection'], guard_len=config[0]['guard'],
                           exit_len=config[0]['exit'], sim_size=config[0]['simulation_size'],
                           sim_type=config[0]['simulation_type'])
        GraphGenerator.generate_graph(g)
    if config[0]['create_html'] and config[0]['generate_graph']:
        create_html()


def write_descriptors(descs, filename):
    cwd = os.getcwd()
    output_folder = Path(cwd + '/torps/in/server-descriptors-2019-02')
    
    if not output_folder.exists():
        output_folder.mkdir(parents=True)
    
    output_file = output_folder / "2019-02-23-12-05-01-server-descriptors"
    
    if filename == 'server-descriptors':
        with open(output_file, 'w') as file:
            for descriptor in descs:
                file.write('@type server-descriptor 1.0\n')
                file.write(str(descriptor))
            file.flush()


def write_descriptor(desc, filename):
    cwd = os.getcwd()
    output_folder_desc = Path(cwd + '/torps/in/server-descriptors-2019-02')
    output_folder_cons = Path(cwd + '/torps/in/consensuses-2019-02')
    
    if not output_folder_desc.exists():
        output_folder_desc.mkdir(parents=True)
    
    if not output_folder_cons.exists():
        output_folder_cons.mkdir(parents=True)
    
    output_file_desc = output_folder_desc / "2019-02-23-12-05-01-server-descriptors"
    output_file_cons = output_folder_cons / "2019-02-23-12-00-00-consensus"
    
    if filename == 'server-descriptors':
        with open(output_file_desc, 'w') as file:
            file.write('@type server-descriptor 1.0\n')
            file.write(str(desc))

    elif filename == 'consensus':
        with open(output_file_cons, 'w') as file:
            file.write('@type network-status-consensus-3 1.0\n')
            file.write(str(desc))


def get_circuits(remove_duplicate_paths, routers, guard_bandwidth, exit_bandwidth, sim_type, loop_count, adv_guard=None,
                 adv_exit=None):
    circuits = []
    attackers_guards = []
    attackers_exits = []
    attackers_middle = []
    ip_bandwidth = {}
    node_usage = collections.Counter()
    statistic = collections.Counter({'bad_guard_used': 0,
                                     'bad_exit_used': 0,
                                     'bad_circuit': 0,
                                     'bad_node': 0,
                                     'bad_gu_and_ex': 0,
                                     'adv_guard': adv_guard,
                                     'adv_exit': adv_exit,
                                     'adv_guard_bandwidth': guard_bandwidth,
                                     'adv_exit_bandwidth': exit_bandwidth
                                     })
    output_file_path = Path(os.getcwd() + '/torps/out/simulation/output')
    with open(output_file_path, 'r+') as file:
        lines = file.readlines()

    for i in range(0, len(lines)):
        if not lines[i].split()[2].__eq__('Guard'):
            circuit = (lines[i].split()[2], lines[i].split()[3], lines[i].split()[4])
            node_usage.update(circuit)
            if circuit not in circuits and remove_duplicate_paths:
                circuits.append(circuit)
            elif not remove_duplicate_paths:
                circuits.append(circuit)

            # attack nodes
            if sim_type == 'attack' or sim_type == 'multiple_sim':
                if circuit[0][:3] == '10.':
                    statistic.update(['bad_guard_used', 'bad_node'])
                    attackers_guards.append(circuit[0]) if circuit[0] not in attackers_guards else None
                if circuit[1][:3] == '10.':
                    statistic.update(['bad_node'])
                    attackers_middle.append(circuit[1]) if circuit[1] not in attackers_middle else None
                if circuit[2][:3] == '10.':
                    statistic.update(['bad_exit_used', 'bad_node'])
                    attackers_exits.append(circuit[2]) if circuit[2] not in attackers_exits else None
                if circuit[0][:3] == '10.' and circuit[1][:3] == '10.' and circuit[2][:3] == '10.':
                    statistic.update(['bad_circuit'])
                elif circuit[2][:3] == '10.' and circuit[0][:3] == '10.':
                    statistic.update(['bad_gu_and_ex'])

    cwd = os.getcwd()
    output_folder = Path(cwd + '/torps/out/simulation')
    output_file = output_folder / 'usage'
    statistic_file = output_folder / 'statistic'

    if not output_folder.exists():
        output_folder.mkdir(parents=True)

    for r in routers:
        try:
            ip_bandwidth['{}'.format(r.address)] = (node_usage['{}'.format(r.address)], round(r.bandwidth / math.pow(10, 6), 3))
        except KeyError:
            ip_bandwidth['{}'.format(r.address)] = (0, round(r.bandwidth / math.pow(10, 6), 3))

    if sim_type == 'attack' or sim_type == 'multiple_sim':
        for node in attackers_guards:
            ip_bandwidth['{}'.format(node)] = (node_usage['{}'.format(node)], round(guard_bandwidth / math.pow(10, 6), 3))

        for node in attackers_exits:
            ip_bandwidth['{}'.format(node)] = (node_usage['{}'.format(node)], round(exit_bandwidth / math.pow(10, 6), 3))

        for node in attackers_middle:
            if node not in ip_bandwidth.keys():
                ip_bandwidth['{}'.format(node)] = (node_usage['{}'.format(node)], '-')

    with open(output_file, 'w') as file:
        json.dump(collections.OrderedDict(sorted(ip_bandwidth.items(), key=lambda kv: kv[1], reverse=True)), file)

    if loop_count == 0:
        with open(statistic_file, 'w') as file:
            json.dump(statistic, file)
    else:
        with open(statistic_file, 'a') as file:
            json.dump(statistic, file)

    dict_max = node_usage[max(node_usage.items(), key=operator.itemgetter(1))[0]]
    for k in node_usage.keys():
        node_usage[k] = hex(round((100 * node_usage[k] / dict_max) * 255 / 100))[2:]
    data = [circuits, node_usage, statistic]
    return data


def get_multipurpose_nodes(routers, paths, fake_guards):
    path_middle_node = []
    all_guard_node = []
    all_exit_node = []
    
    gu_mi_node = []
    ex_mi_node = []
    
    for path in paths:
        if path[1] not in path_middle_node:
            path_middle_node.append(path[1])
    
    i = 0
    for r in routers:
        if "Guard" in r.flags:
            all_guard_node.append(str(r.address))
        elif "Exit" in r.flags:
            all_exit_node.append(str(r.address))
        else:
            if i < fake_guards:
                i = i + 1
                all_guard_node.append(r.address)
    
    for guard_n in all_guard_node:
        if guard_n in path_middle_node:
            gu_mi_node.append(guard_n)
    
    for exit_n in all_exit_node:
        if exit_n in path_middle_node:
            ex_mi_node.append(exit_n)
    
    output = [gu_mi_node, ex_mi_node]
    return output


def generate_router_status_entry(self, flags='Fast Running Stable Valid'):
    """
    Odebrano ze stem knihovny
    :param self:
    :param flags:
    :return:
    """
    if not self.fingerprint:
        raise ValueError('Server descriptor lacks a fingerprint. '
                         'This is an optional field, but required to make a router status entry.')

    attr = {'r': ' '.join([
            self.nickname,
            _truncated_b64encode(binascii.unhexlify(stem.util.str_tools._to_bytes(self.fingerprint))),
            _truncated_b64encode(binascii.unhexlify(stem.util.str_tools._to_bytes(self.digest()))),
            self.published.strftime('%Y-%m-%d %H:%M:%S'),
            self.address,
            str(self.or_port),
            str(self.dir_port) if self.dir_port else '0', ]), }
    
    if self.tor_version:
        attr['v'] = 'Tor %s' % self.tor_version
    
    if self.tor_version:
        attr['v'] = 'Tor %s' % self.tor_version
    
    attr['s'] = '%s' % flags
    attr['w'] = 'Bandwidth=%i' % self.average_bandwidth
    attr['p'] = self.exit_policy.summary().replace(', ', ',')
    
    if self.or_addresses:
        attr['a'] = ['%s:%s' % (addr, port) for addr, port, _ in self.or_addresses]
    
    if self.certificate:
        attr['id'] = 'ed25519 %s' % _truncated_b64encode(self.certificate.key)
    
    return RouterStatusEntryV3.create(attr)


def generate_nickname():
    return ('Unnamed%i' % random.randint(0, 100000000000000))[:19]


def generate_ipv4_address():
    return '%i.%i.%i.%i' % (random.randint(11, 255), random.randint(0, 255),
                            random.randint(0, 255), random.randint(0, 255))


def generate_port():
    return '%i' % (random.randint(1, 65535))


def generate_bandwidth(same_bandwidth, bandwidth_value, variance=30):
    if same_bandwidth and bandwidth_value is not None:
        # bandwidth = "229311978 259222236 199401720"
        bandwidth = "{} {} {}".format(bandwidth_value, bandwidth_value, bandwidth_value)
        return bandwidth
    elif same_bandwidth:
        bandwidth = "229311978 259222236 199401720"
        return bandwidth
    observed = random.randint(20 * 2 ** 10, 2 * 2 ** 30)
    percentage = float(variance) / 100.
    burst = int(observed + math.ceil(observed * percentage))
    bandwidths = [burst, observed]
    nitems = len(bandwidths) if (len(bandwidths) > 0) else float('nan')
    avg = int(math.ceil(float(sum(bandwidths)) / nitems))
    bandwidth = "{} {} {}".format(avg, burst, observed)
    return bandwidth


def generate_ntor_key():
    """
    odebrano z leekspin
    :return:
    """
    public_ntor_key = None
    
    try:
        secret_ntor_key = ntor.createNTORSecretKey()
        public_ntor_key = ntor.getNTORPublicKey(secret_ntor_key)
    except ntor.NTORKeyCreationError:
        secret_ntor_key = None
    
    return public_ntor_key


def make_node(x, y, descriptor_entries):
    node = []
    server_descriptors = []
    consensus_entries = []
    
    for i in range(x, y):
        server_desc = None
        signing_key = stem.descriptor.create_signing_key()
        if descriptor_entries[i - x]['type'] == 'exit':
            server_desc = RelayDescriptor.create({'published': '2019-03-04 13:37:39',
                                                  'reject': '0.0.0.0/8:*',
                                                  'accept': '*:*',
                                                  'ntor-onion-key': '%s' % generate_ntor_key(),
                                                  'bandwidth': '%s' % (descriptor_entries[i - x]['bandwidth']),
                                                  'router': '%s %s %s 0 0' % (descriptor_entries[i - x]['name'],
                                                                              descriptor_entries[i - x]['ip'],
                                                                              descriptor_entries[i - x]['port']),
                                                  }, validate=True, sign=True, signing_key=signing_key)

            consensus_entries.append(generate_router_status_entry(server_desc, 'Exit Fast Running Stable Valid'))
        elif descriptor_entries[i - x]['type'] == 'middle':
            server_desc = RelayDescriptor.create({'router': '%s %s %s 0 0' % (descriptor_entries[i - x]['name'],
                                                                              descriptor_entries[i - x]['ip'],
                                                                              descriptor_entries[i - x]['port']),
                                                  'protocols': 'Link 1 2 Circuit 1',
                                                  'platform': 'Tor 0.2.4.8 on Linux',
                                                  'bandwidth': '%s' % (descriptor_entries[i - x]['bandwidth']),
                                                  'published': '2019-03-04 13:37:39',
                                                  'reject': '*:*',
                                                  'ntor-onion-key': '%s' % generate_ntor_key(),
                                                  }, validate=True, sign=True, signing_key=signing_key)

            consensus_entries.append(generate_router_status_entry(server_desc, 'Fast Running Stable Valid'))
        elif descriptor_entries[i - x]['type'] == 'guard':
            server_desc = RelayDescriptor.create({'router': '%s %s %s 0 0' % (descriptor_entries[i - x]['name'],
                                                                              descriptor_entries[i - x]['ip'],
                                                                              descriptor_entries[i - x]['port']),
                                                  'protocols': 'Link 1 2 Circuit 1',
                                                  'platform': 'Tor 0.2.4.8 on Linux',
                                                  'bandwidth': '%s' % (descriptor_entries[i - x]['bandwidth']),
                                                  'published': '2019-03-04 13:37:39',
                                                  'reject': '*:*',
                                                  'ntor-onion-key': '%s' % generate_ntor_key(),
                                                  }, validate=True, sign=True, signing_key=signing_key)

            consensus_entries.append(generate_router_status_entry(server_desc, 'Fast Guard Running Stable Valid'))

        server_descriptors.append(server_desc)
        write_descriptor(server_desc, 'server_descriptor_%i' % i)
    
    node.append(server_descriptors)
    node.append(consensus_entries)
    return node


def make_descriptors(descriptor_entries):
    guard_len = len(descriptor_entries[0])
    middle_len = len(descriptor_entries[1])
    exit_len = len(descriptor_entries[2])
    
    guard_n = make_node(0, guard_len, descriptor_entries[0])
    middle_n = make_node(guard_len, guard_len + middle_len, descriptor_entries[1])
    exit_n = make_node(guard_len + middle_len, guard_len + middle_len + exit_len, descriptor_entries[2])
    
    server_descriptors = guard_n[0] + middle_n[0] + exit_n[0]
    consensus_entries = guard_n[1] + middle_n[1] + exit_n[1]
    
    consensus = NetworkStatusDocumentV3.create({'valid-after': '2019-03-04 14:00:00',
                                                'fresh-until': '2019-03-04 15:00:00',
                                                'valid-until': '2019-03-04 17:00:00',
                                                'consensus-method': '28',
                                                'bandwidth-weights': 'Wbd=0 Wbe=0 Wbg=4143 Wbm=10000 Wdb=10000 '
                                                                     'Web=10000 Wed=10000 Wee=10000 Weg=10000 '
                                                                     'Wem=10000 Wgb=10000 Wgd=0 Wgg=5857 Wgm=5857 '
                                                                     'Wmb=10000 Wmd=0 Wme=0 Wmg=4143 Wmm=10000',
                                                }, routers=consensus_entries)
    write_descriptor(consensus, 'consensus')
    write_descriptors(server_descriptors, 'server-descriptors')

    return consensus_entries


def validate_node_entries(node_entries, list_of_names, list_of_ip, same_bandwidth, bandwidth_value):
    """
    Checks if node entries from config file are valid
    :param node_entries: node entries from config file
    :param list_of_names: list of used names
    :param list_of_ip: list of used IP adresses
    :param same_bandwidth: True/False every node will have same bandwidth
    :param bandwidth_value: value of bandwidth
    :return: valid node
    """
    if node_entries['name'] not in list_of_names and node_entries['name'] != '':
        list_of_names.append(node_entries['name'])
    else:
        node_entries['name'] = generate_nickname()
        list_of_names.append(node_entries['name'])
    
    try:
        socket.inet_aton(node_entries['ip'])
        if node_entries['ip'] in list_of_ip:
            node_entries['ip'] = generate_ipv4_address()
    except socket.error:
        node_entries['ip'] = generate_ipv4_address()
    finally:
        list_of_ip.append(node_entries['ip'])
    
    try:
        if int(node_entries['port']) not in range(1, 65535):
            node_entries['port'] = generate_port()
    except ValueError:
        node_entries['port'] = generate_port()
    
    if same_bandwidth:
        node_entries['bandwidth'] = generate_bandwidth(same_bandwidth, bandwidth_value)
    else:
        try:
            bandwidth = node_entries['bandwidth'].split(' ')
            if len(bandwidth) == 3:
                for b in bandwidth:
                    if int(b) <= 0:
                        node_entries['bandwidth'] = generate_bandwidth(same_bandwidth, bandwidth_value)
            else:
                node_entries['bandwidth'] = generate_bandwidth(same_bandwidth, bandwidth_value)
        except ValueError:
            node_entries['bandwidth'] = generate_bandwidth(same_bandwidth, bandwidth_value)


def create_node_entries(node_type, same_bandwidth, bandwidth_value):
    """
    Creates node
    :param node_type: type of node (guard/middle/exit)
    :param same_bandwidth: True/False every node will have same bandwidth
    :param bandwidth_value: value of bandwidth
    :return: valid node
    """
    node = {'type': '{}'.format(node_type),
            'name': '{}'.format(generate_nickname()),
            'ip': '{}'.format(generate_ipv4_address()),
            'port': '{}'.format(generate_port()),
            'bandwidth': '{}'.format(generate_bandwidth(same_bandwidth, bandwidth_value))}
    return node


def check_params(path_selection, guard_c=0, middle_c=0, exit_c=0, guard_exit_c=0, same_bandwidth=False,
                 node_entries=None, sim_type=None, bandwidth_value=None):
    """
    Creates node entries or checks if node entries are valid
    :param path_selection: type of path selection for Path simulations
    :param guard_c: guard count
    :param middle_c: middle count
    :param exit_c: exit count
    :param guard_exit_c: guard exit count
    :param same_bandwidth: True/False every node will have same bandwidth
    :param node_entries: node entries from config file
    :param sim_type: type of simulation
    :param bandwidth_value: value od bandwidth
    :return: list of nodes to generate, every node is represented as dictionary
    """
    all_names = []
    all_ip = []
    guard_node = []
    middle_node = []
    exit_node = []
    
    if exit_c == 0:
        guard_to_generate = round(guard_exit_c / 2)
        exit_to_generate = guard_exit_c - round(guard_exit_c / 2)
    else:
        guard_to_generate = guard_exit_c - round(guard_exit_c / 2)
        exit_to_generate = round(guard_exit_c / 2)
    
    if path_selection == '3_guards':
        if guard_c + guard_exit_c == 3:
            guard_to_generate = guard_exit_c
        if guard_c == 1 and guard_exit_c == 3:
            guard_to_generate = round(guard_exit_c / 2)
            exit_to_generate = guard_exit_c - round(guard_exit_c / 2)
    
    if node_entries is not None:
        for node in node_entries:
            validate_node_entries(node, all_names, all_ip, same_bandwidth, bandwidth_value)
            guard_node.append(node) if node['type'] == 'guard' and len(guard_node) < guard_c else None
            middle_node.append(node) if node['type'] == 'middle' and len(middle_node) < middle_c else None
            exit_node.append(node) if node['type'] == 'exit' and len(exit_node) < exit_c else None
    for i in range(0, guard_c - len(guard_node) + guard_to_generate):
        guard_node.append(create_node_entries('guard', same_bandwidth, bandwidth_value))
    for i in range(0, middle_c - len(middle_node)):
        middle_node.append(create_node_entries('middle', same_bandwidth, bandwidth_value))
    for i in range(0, exit_c - len(exit_node) + exit_to_generate):
        exit_node.append(create_node_entries('exit', same_bandwidth, bandwidth_value))
    
    if path_selection == '1_guard' and sim_type == 'path':
        for node in guard_node[1:guard_c + guard_to_generate]:
            node['type'] = 'middle'
        middle_node = guard_node[1:guard_c + guard_to_generate] + middle_node[:middle_c]
        descriptor_entries = [guard_node[:1], middle_node, exit_node[:exit_c + exit_to_generate]]
        return descriptor_entries
    elif path_selection == '3_guards' and sim_type == 'path':
        for node in guard_node[3:guard_c + guard_to_generate]:
            node['type'] = 'middle'
        middle_node = guard_node[3:guard_c + guard_to_generate] + middle_node[:middle_c]
        descriptor_entries = [guard_node[:3], middle_node, exit_node[:exit_c + exit_to_generate]]
        return descriptor_entries
    else:
        descriptor_entries = [guard_node[:guard_c + guard_to_generate], middle_node[:middle_c],
                              exit_node[:exit_c + exit_to_generate]]
        # pprint.pprint(descriptor_entries)
        return descriptor_entries


def create_html():
    cwd = os.getcwd()
    
    output_file = Path(cwd + '/picture.html')
    svg_file = Path(cwd + '/graph/simulation.dot.svg')
    svg_file_legend = Path(cwd + '/graph/legend.dot.svg')
    try:
        with open(svg_file, 'r') as svg:
            s = svg.read()
            svg.close()
    except (OSError, IOError) as e:
        print("File Error: Can not read file {}".format(svg_file))
        sys.exit(1)
    try:
        with open(svg_file_legend, 'r') as svg:
            legend = svg.read()
            svg.close()
    except (OSError, IOError) as e:
        print("File Error: Can not read file {}".format(svg_file_legend))
        print(e)
        sys.exit(1)
    try:
        with open(output_file, 'w') as html_file:
            html_file.write(
                "<!DOCTYPE html>"
                "<html lang=\"en\">"
                "<head>"
                "<meta charset=\"utf-8\">"
                "<meta content=\"width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no\" name=\"viewport\">"
                "<link rel=\"stylesheet\" href=\"resources//animation.css\">"
                "<script defer=\"\" src=\"resources//animation.js\"></script>"
                "<link href=\"css/style.css\" rel=\"stylesheet\" type=\"text/css\">"
                "<link href=\"css/bootstrap.min.css\" rel=\"stylesheet\" type=\"text/css\">"
                "<script src=\"https://ajax.googleapis.com/ajax/libs/jquery/3.4.0/jquery.min.js\"></script>"
                "<script src=\"https://maxcdn.bootstrapcdn.com/bootstrap/3.4.0/js/bootstrap.min.js\"></script>"
                "<script src=\"js/show.js\"></script>"
                "<title>Simulator</title>"
                "</head>"
                "<body>\n"
                "<ul id=\"link-container\" style=\"justify-content: flex-start\">"
                "<h3 id=\"current_num\"></h3>"
                "<button id=\"button_prev\" type=\"button\" class=\"btn btn-primary\" disabled>Prev</button>"
                "<button id=\"button_next\" type=\"button\" class=\"btn btn-primary\" disabled>Next</button>"
                "</ul>")
            html_file.write(s)
            html_file.write("<br>\n")
            html_file.write(legend)
            html_file.write("</body>\n"
                            "</html>\n")
            html_file.close()
    except (OSError, IOError) as e:
        print("File Error: Can not write to file {}".format(output_file))
        print(e)
        sys.exit(1)


def run_tor_path_simulator(path, adv_guards, adv_exits, adv_guard_bandwidth, adv_exit_bandwidth, n_samples=5):
    cwd = os.getcwd()
    output_folder = Path(cwd + '/torps/out/network-state-2019-02')
    simulation_folder = Path(cwd + '/torps/out/simulation')

    if not output_folder.exists():
        output_folder.mkdir(parents=True)
    
    if not simulation_folder.exists():
        simulation_folder.mkdir(parents=True)
    
    simulation_file = simulation_folder / "output"

    torps_path = Path(path + '/pathsim.py')
    dir_path = output_folder
    output_file_path = simulation_file
    num_samples = n_samples
    tracefile = Path(path + '/in/users2-processed.traces.pickle')
    usermodel = 'simple=600000000'
    format_arg = 'normal'  # relay-adv
    adv_guard_bw = adv_guard_bandwidth
    adv_exit_bw = adv_exit_bandwidth
    adv_time = '0'
    num_adv_guards = adv_guards
    num_adv_exits = adv_exits
    num_guards = '1'
    gard_expiration = '1'
    loglevel = 'INFO'
    path_alg = 'tor'
    
    start_year = '2019'
    end_year = '2019'
    start_month = '2'
    end_month = '2'
    in_dir = Path(cwd + '/torps/in')
    out_dir = Path(cwd + '/torps/out')
    initial_descriptors_dir = Path(cwd + '/torps/in/server-descriptors-2019-02')
    
    ret = os.system("python {} process --start_year {} --start_month {} --end_year {} --end_month {} --in_dir {} "
                    "--out_dir {} --initial_descriptor_dir {} > /dev/null 2>&1".format(torps_path, start_year,
                                                                                       start_month, end_year,
                                                                                       end_month, in_dir, out_dir,
                                                                                       initial_descriptors_dir))

    if ret != 0:
        print('Path Simulator requires: Python2.7 and stem. Make sure torps has right permissions')
        sys.exit(1)

    # os.system("python {} simulate -h".format(torps_path))
    
    os.system("python {} simulate --nsf_dir {} --num_samples {} --trace_file {} --user_model {} --format {} "
              "--adv_guard_cons_bw {} --adv_exit_cons_bw {} --adv_time {} --num_adv_guards {} --num_adv_exits {} "
              "--num_guards {} --guard_expiration {} --loglevel {} {} > {}".format(torps_path, dir_path, num_samples,
                                                                                   tracefile, usermodel, format_arg,
                                                                                   adv_guard_bw, adv_exit_bw, adv_time,
                                                                                   num_adv_guards, num_adv_exits,
                                                                                   num_guards, gard_expiration,
                                                                                   loglevel, path_alg,
                                                                                   output_file_path))


if __name__ == '__main__':
    input_file = 'config.ini'
    try:
        opts, args = getopt.getopt(sys.argv[1:], "hi:", ["ifile="])
    except getopt.GetoptError:
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            sys.exit(0)
        elif opt in ("-i", "--ifile"):
            cwd = os.getcwd()
            input_file_path = Path(cwd + '/' + arg)
            if input_file_path.exists():
                input_file = input_file_path
            elif Path(arg).exists():
                input_file = arg
            else:
                print('Invalid file')
                sys.exit(1)

    run_simulation(input_file)

    # todo grapph size in config file
    # todo ip generate function
    # todo 3 graph layout
