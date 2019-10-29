#!/usr/bin/env python3.6
import binascii
import os
import random
import sys
import math
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


def parse_config_file():
    config = configparser.ConfigParser(allow_no_value=True)
    try:
        config.read('config.ini')
    except configparser.DuplicateSectionError:
        print('Node already exists')  # todo
        sys.exit(1)
    
    conf = []
    all_nodes = []

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
           'simulation_type': config['general']['simulation_type'],
           'nodes': config['hiden_service_simulation']['nodes'],
           'adv_guard_bandwidth': config['attack_simulation']['adv_guard_bandwidth'],
           'adv_exit_bandwidth': config['attack_simulation']['adv_exit_bandwidth'],
           'adv_guard': config['attack_simulation']['adv_guard'],
           'adv_exit': config['attack_simulation']['adv_exit'],
           }

    conf.append(dic)

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
            node['bandwidth'] = config[n]['bandwidth']
            all_nodes.append(node)

    conf.append(all_nodes)

    try:
        conf[0]['number_of_simulations'] = int(conf[0]['number_of_simulations'])
    except ValueError:
        print('Number of simulations have to be >= 1')
        sys.exit(1)

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

    if conf[0]['simulation_type'] == 'attack':  # todo max 255 overflow
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

    if conf[0]['simulation_type'] == 'hidden_service':
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


def run_simulation():
    config = parse_config_file()
    routers = make_descriptors(check_params(config[0]['path_selection'], config[0]['guard'], config[0]['middle'],
                                            config[0]['exit'], config[0]['guard_exit'], config[0]['same_bandwidth'],
                                            config[1], config[0]['simulation_type']))
    run_tor_path_simulator(config[0]['path'], config[0]['adv_guard'], config[0]['adv_exit'],
                           config[0]['adv_guard_bandwidth'], config[0]['adv_exit_bandwidth'],
                           config[0]['number_of_simulations'])
    circuits_output = get_circuits(config[0]['remove_duplicate_paths'])

    if config[0]['simulation_type'] == 'hidden_service' and config[0]['generate_graph']:
        g = GraphGenerator(routers=routers, paths=circuits_output[0])
        exit_code_graph = GraphGenerator.generate_graph(g)      # todo exit code graph
    elif config[0]['simulation_type'] == 'attack' and config[0]['generate_graph']:
        g = GraphGenerator(routers=routers, adv_guard_c=config[0]['adv_guard'], adv_exit_c=config[0]['adv_exit'],
                           color=circuits_output[1])
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


def get_circuits(remove_duplicate_paths):
    circuits = []
    node_usage = {}
    statistic = {'bad_guard_used': 0,
                 'bad_exit_used': 0,
                 'bad_circuit': 0,
                 'bad_node': 0,
                 'bad_gu_and_ex': 0}
    output_file_path = Path(os.getcwd() + '/torps/out/simulation/output')
    with open(output_file_path, 'r+') as file:
        lines = file.readlines()
    
    for i in range(0, len(lines)):
        if not lines[i].split()[2].__eq__('Guard'):
            guard_bad = False
            exit_bad = False
            middle_bad = False
            circuit = (lines[i].split()[2], lines[i].split()[3], lines[i].split()[4])
            if circuit not in circuits and remove_duplicate_paths:
                circuits.append(circuit)
            elif not remove_duplicate_paths:
                circuits.append(circuit)

            if circuit[0][:3] == '10.':
                guard_bad = True
            if circuit[1][:3] == '10.':
                middle_bad = True
            if circuit[2][:3] == '10.':
                exit_bad = True

            if guard_bad and middle_bad and exit_bad:
                statistic['bad_circuit'] = statistic['bad_circuit'] + 1
            elif exit_bad and guard_bad:
                statistic['bad_gu_and_ex'] = statistic['bad_gu_and_ex'] + 1
            elif exit_bad or guard_bad:
                statistic['bad_node'] = statistic['bad_node'] + 1
                if exit_bad:
                    statistic['bad_exit_used'] = statistic['bad_exit_used'] + 1
                else:
                    statistic['bad_guard_used'] = statistic['bad_guard_used'] + 1

            if circuit[0] not in node_usage.keys():
                node_usage[circuit[0]] = 1
            else:
                node_usage[circuit[0]] = node_usage[circuit[0]] + 1

            if circuit[1] not in node_usage.keys():
                node_usage[circuit[1]] = 1
            else:
                node_usage[circuit[1]] = node_usage[circuit[1]] + 1  # todo chcek middle?

            if circuit[2] not in node_usage.keys():
                node_usage[circuit[2]] = 1
            else:
                node_usage[circuit[2]] = node_usage[circuit[2]] + 1

    cwd = os.getcwd()
    output_folder = Path(cwd + '/torps/out/simulation')

    if not output_folder.exists():
        output_folder.mkdir(parents=True)

    output_file = output_folder / 'usage'
    with open(output_file, 'w') as file:
        json.dump(node_usage, file)
    
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


def generate_bandwidth(same_bandwidth, variance=30):
    if same_bandwidth:
        bandwidth = "229311978 259222236 199401720"
        return bandwidth
    observed = random.randint(20 * 2 ** 10, 2 * 2 ** 30)
    percentage = float(variance) / 100.
    burst = int(observed + math.ceil(observed * percentage))
    bandwidths = [burst, observed]
    nitems = len(bandwidths) if (len(bandwidths) > 0) else float('nan')
    avg = int(math.ceil(float(sum(bandwidths)) / nitems))
    bandwidth = "%s %s %s" % (avg, burst, observed)
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


def validate_node_entries(node_entries, list_of_names, list_of_ip, same_bandwidth):
    """
    Checks if node entries from config file are valid
    :param node_entries: node entries from config file
    :param list_of_names: list of used names
    :param list_of_ip: list of used IP adresses
    :param same_bandwidth: True/False every node will have same bandwidth
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
        node_entries['bandwidth'] = generate_bandwidth(same_bandwidth)
    else:
        try:
            bandwidth = node_entries['bandwidth'].split(' ')
            if len(bandwidth) == 3:
                for b in bandwidth:
                    if int(b) <= 0:
                        node_entries['bandwidth'] = generate_bandwidth(same_bandwidth)
            else:
                node_entries['bandwidth'] = generate_bandwidth(same_bandwidth)
        except ValueError:
            node_entries['bandwidth'] = generate_bandwidth(same_bandwidth)


def create_node_entries(node_type, same_bandwidth):
    """
    Creates node
    :param node_type: type of node (guard/middle/exit)
    :param same_bandwidth: True/False every node will have same bandwidth
    :return: valid node
    """
    node = {'type': '{}'.format(node_type),
            'name': '{}'.format(generate_nickname()),
            'ip': '{}'.format(generate_ipv4_address()),
            'port': '{}'.format(generate_port()),
            'bandwidth': '{}'.format(generate_bandwidth(same_bandwidth))}
    return node


def check_params(path_selection, guard_c=0, middle_c=0, exit_c=0, guard_exit_c=0, same_bandwidth=False,
                 node_entries=None, sim_type=None):
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
            validate_node_entries(node, all_names, all_ip, same_bandwidth)
            guard_node.append(node) if node['type'] == 'guard' and len(guard_node) < guard_c else None
            middle_node.append(node) if node['type'] == 'middle' and len(middle_node) < middle_c else None
            exit_node.append(node) if node['type'] == 'exit' and len(exit_node) < exit_c else None
    for i in range(0, guard_c - len(guard_node) + guard_to_generate):
        guard_node.append(create_node_entries('guard', same_bandwidth))
    for i in range(0, middle_c - len(middle_node)):
        middle_node.append(create_node_entries('middle', same_bandwidth))
    for i in range(0, exit_c - len(exit_node) + exit_to_generate):
        exit_node.append(create_node_entries('exit', same_bandwidth))
    
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
            html_file.write("<!DOCTYPE html>"
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
              "--out_dir {} --initial_descriptor_dir {} > /dev/null 2>&1".format(torps_path, start_year, start_month,
                                                                                 end_year, end_month, in_dir, out_dir,
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
    run_simulation()

    # get_circuits(False)

    # todo grapph size in config file
    # todo ip generate function
    # todo 3 graph layout
