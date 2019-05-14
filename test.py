import binascii
import os
import random
import sys

import math

try:
    import stem
    import socket
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
    print('Creating descriptors requires stem (https://stem.torproject.org/)')
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
        conf[0]['exit'] = int(conf[0]['exit'])
        conf[0]['middle'] = int(conf[0]['middle'])
        conf[0]['guard'] = int(conf[0]['guard'])
        conf[0]['guard'] = int(conf[0]['guard'])
        conf[0]['guard_exit'] = int(conf[0]['guard_exit'])
        conf[0]['number_of_simulations'] = int(conf[0]['number_of_simulations'])
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
                                            config[1]))
    run_tor_path_simulator(config[0]['path'], config[0]['adv_guard'], config[0]['adv_exit'],
                           config[0]['adv_guard_bandwidth'], config[0]['adv_exit_bandwidth'],
                           config[0]['number_of_simulations'])
    circuits_output = get_circuits(config[0]['remove_duplicate_paths'])

    if config[0]['simulation_type'] == 'hidden_service' and config[0]['generate_graph']:
        generate_hidden_service_graph(routers, circuits_output[0])
    elif config[0]['simulation_type'] == 'attack' and config[0]['generate_graph']:
        generate_attack_graph(routers, config[0]['adv_guard'], config[0]['adv_exit'], circuits_output[1])
    elif config[0]['simulation_type'] == 'path' and config[0]['generate_graph']:
        if config[0]['simulation_size'] == 'large':
            generate_large_graph(routers, circuits_output[0], config[0]['path_selection'], config[0]['guard'],
                                 config[0]['exit'], config[0]['guard_exit'])
        elif config[0]['simulation_size'] == 'small':
            generate_simple_graph(routers, circuits_output[0], config[0]['guard'], config[0]['exit'])

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
    return '%i.%i.%i.%i' % (random.randint(15, 255), random.randint(0, 255),
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


def check_params(sim_type, guard_c=0, middle_c=0, exit_c=0, guard_exit_c=0, same_bandwidth=False, node_entries=None):
    """
    Creates node entries or checks if node entries are valid
    :param sim_type: type of simulation
    :param guard_c: guard count
    :param middle_c: middle count
    :param exit_c: exit count
    :param guard_exit_c: guard exit count
    :param same_bandwidth: True/False every node will have same bandwidth
    :param node_entries: node entries from config file
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
    
    if sim_type == '3_guards':
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
    
    if sim_type == '1_guard':
        for node in guard_node[1:guard_c + guard_to_generate]:
            node['type'] = 'middle'
        middle_node = guard_node[1:guard_c + guard_to_generate] + middle_node[:middle_c]
        descriptor_entries = [guard_node[:1], middle_node, exit_node[:exit_c + exit_to_generate]]
        return descriptor_entries
    elif sim_type == '3_guards':
        for node in guard_node[3:guard_c + guard_to_generate]:
            node['type'] = 'middle'
        middle_node = guard_node[3:guard_c + guard_to_generate] + middle_node[:middle_c]
        descriptor_entries = [guard_node[:3], middle_node, exit_node[:exit_c + exit_to_generate]]
        return descriptor_entries
    else:
        descriptor_entries = [guard_node[:guard_c + guard_to_generate], middle_node[:middle_c],
                              exit_node[:exit_c + exit_to_generate]]
        return descriptor_entries


def generate_simple_graph(routers, paths, guard_len, exit_len):
    guard_node = []
    middle_node = []
    exit_node = []
    
    graph = Digraph('test', format='svg')

    graph.attr(layout="dot")
    graph.attr(rankdir='TB')
    graph.attr(fontsize='10')

    if len(paths) >= 15:
        graph.attr(splines='false')
    else:
        graph.attr(splines="true")

    layers = []
    for i in range(0, len(paths)):
        layers.append("path{}:".format(i))

    graph.attr(layers=''.join(layers)[:-1])

    subgraph_guards = Digraph('subgraph_guards')
    subgraph_pc = Digraph('subgraph_pc')
    subgraph_server = Digraph('subgraph_server')
    subgraph_middles = Digraph('subgraph_middles')
    subgraph_exits = Digraph('subgraph_exits')

    subgraph_guards.graph_attr.update(rank='same')
    subgraph_middles.graph_attr.update(rank='same')
    subgraph_exits.graph_attr.update(rank='same')
    subgraph_pc.graph_attr.update(rank='same')
    subgraph_server.graph_attr.update(rank='same')

    computer_icon_path = "resources//computer.png"
    server_icon_path = "resources//SE.svg"
    subgraph_pc.node("PC", label="", shape="none", image=computer_icon_path, fixedsize="true", width="0.6",
                     height="0.6")
    subgraph_server.node("SERVER", label="", shape="none", image=server_icon_path, imagescale="true", width="0.7",
                         height="0.7", margin="20")
    
    guard_count = 0
    exit_count = 0
    for r in routers:
        if "Guard" in r.flags:
            guard_node.append(r.address)
            if guard_count >= guard_len:
                subgraph_guards.node(str(r.address), shape='box', color="blue", fillcolor="white", fontsize='10',
                                     fontname='Verdana')
            else:
                guard_count = guard_count + 1
                subgraph_guards.node(str(r.address), shape='ellipse', color="blue", fillcolor="white", fontsize='10',
                                     fontname='Verdana')
        elif "Exit" in r.flags:
            exit_node.append(r.address)
            if exit_count >= exit_len:
                subgraph_exits.node(str(r.address), shape='box', color="blue", fillcolor="white", fontsize='10',
                                    fontname='Verdana')
            else:
                exit_count = exit_count + 1
                subgraph_exits.node(str(r.address), shape='box', fontsize='10', fontname='Verdana')
        else:
            middle_node.append(r.address)
            subgraph_middles.node(str(r.address), shape='ellipse', fontsize='10', fontname='Verdana')

    graph.subgraph(subgraph_pc)
    graph.subgraph(subgraph_guards)
    graph.subgraph(subgraph_middles)
    graph.subgraph(subgraph_exits)
    graph.subgraph(subgraph_server)

    for guard in guard_node:
        graph.edge("PC", guard, style='invis')

    for exit_n in exit_node:
        graph.edge(exit_n, "SERVER", style='invis')
    
    for index, path in enumerate(paths, start=0):
        graph.edge("PC", path[0], constraint="false", weight='0', layer="path{}".format(index))
        graph.edge(path[0], path[1], constraint="false", weight='0', layer="path{}".format(index))
        graph.edge(path[1], path[2], constraint="false", weight='0', layer="path{}".format(index))
        graph.edge(path[2], "SERVER", constraint="false", weight='0', layer="path{}".format(index))

    if len(middle_node) == 0:
        for i in range(0, len(guard_node)):
            for j in range(0, len(exit_node)):
                if len(guard_node) == len(exit_node):
                    if i is j:
                        graph.edge(guard_node[i], exit_node[j], style='invis')
                elif len(guard_node) < len(exit_node):
                    if i is j:
                        graph.edge(guard_node[i], exit_node[j], style='invis')
                    if len(guard_node) - 1 == i and j > i:
                        graph.edge(guard_node[i], exit_node[j], style='invis')
                else:
                    if i is j:
                        graph.edge(guard_node[i], exit_node[j], style='invis')
                    if len(exit_node) - 1 == j and i > j:
                        graph.edge(guard_node[i], exit_node[j], style='invis')
    else:
        for i in range(0, len(guard_node)):
            for j in range(0, len(middle_node)):
                if len(guard_node) == len(middle_node):
                    if i is j:
                        graph.edge(guard_node[i], middle_node[j], style='invis')
                elif len(guard_node) < len(middle_node):
                    if i is j:
                        graph.edge(guard_node[i], middle_node[j], style='invis')
                    if len(guard_node) - 1 == i and j > i:
                        graph.edge(guard_node[i], middle_node[j], style='invis')
                else:
                    if i is j:
                        graph.edge(guard_node[i], middle_node[j], style='invis')
                    if len(middle_node) - 1 == j and i > j:
                        graph.edge(guard_node[i], middle_node[j], style='invis')

    for i in range(0, len(middle_node)):
        for j in range(0, len(exit_node)):
            if len(middle_node) == len(exit_node):
                if i is j:
                    graph.edge(middle_node[i], exit_node[j], style='invis')
            elif len(middle_node) < len(exit_node):
                if i is j:
                    graph.edge(middle_node[i], exit_node[j], style='invis')
                if len(middle_node) - 1 == i and j > i:
                    graph.edge(middle_node[i], exit_node[j], style='invis')
            else:
                if i is j:
                    graph.edge(middle_node[i], exit_node[j], style='invis')
                if len(exit_node) - 1 == j and i > j:
                    graph.edge(middle_node[i], exit_node[j], style='invis')

    graph.render('graph/simulation.dot', view=False)
    fix_svg_links()
    generate_graph_legend("small")


def generate_large_graph(routers, paths, guards_to_generate, guard_len, exit_len, guard_exit):
    guard_node = []
    middle_node = []
    exit_node = []
    
    graph = Digraph('test', format='svg')

    graph.attr(layout='twopi')
    graph.attr(ranksep='5.5 2 2')
    graph.attr(root='PC')
    graph.attr(size="7.5")
    graph.attr(overlap="false")
    graph.attr(splines="true")
    # graph.attr(concentrate="true")
    
    layers = []
    for i in range(0, len(paths)):
        layers.append("path{}:".format(i))
    
    graph.attr(layers=''.join(layers)[:-1])
    
    subgraph_guards = Digraph('subgraph_guards')
    subgraph_middles = Digraph('subgraph_middles')
    subgraph_exits = Digraph('subgraph_exits')
    
    subgraph_guards.graph_attr.update(rank='same')
    subgraph_middles.graph_attr.update(rank='same')
    subgraph_exits.graph_attr.update(rank='same')

    computer_icon_path = "resources//computer.png"
    server_icon_path = "resources//SE.svg"
    graph.node("PC", label="", shape="none", image=computer_icon_path, fixedsize="true", width="1", height="1")
    graph.node("SERVER", label="", shape="none", image=server_icon_path, imagescale="true", width="1.3", height="1.3",
               margin="20")
    
    x = 0
    fill_color = 'coral2'  # blue / coral2
    if guards_to_generate == '3_guards':
        x = guard_len - 3 + round(guard_exit / 2)
        fill_color = 'darkorchid1'  # coral2 / darkorchid1
    elif guards_to_generate == '1_guard':
        x = guard_len - 1 + round(guard_exit / 2)
        fill_color = 'darkorchid1'  # coral2 / darkorchid1
    # darkorchid1 forestgreen dodgerblue lawngreen
    fake_guards = 0
    guard_generated = 0
    exits_generated = 0
    for index, r in enumerate(routers, start=0):
        if "Guard" in r.flags:
            guard_node.append(r.address)
            if guard_generated >= guard_len:  # gu_ex
                subgraph_guards.node(str(r.address), label="", style='filled', fillcolor='lawngreen'.format(fill_color),
                                     shape='box', height='0.3', width='0.3')  # FILL / lawngreen
            else:
                guard_generated = guard_generated + 1
                subgraph_guards.node(str(r.address), label="", style='filled', fillcolor='{}'.format(fill_color),
                                     shape='circle', height='0.3', width='0.3')  # FILL / FILL
        elif "Exit" in r.flags:
            exit_node.append(r.address)
            if exits_generated >= exit_len:  # gu_ex
                subgraph_exits.node(str(r.address), label="", style='filled', fillcolor='lawngreen', shape='box',
                                    height='0.3', width='0.3')  # BLUE / lawngreen
            else:
                exits_generated = exits_generated + 1
                subgraph_exits.node(str(r.address), label="", style='filled', fillcolor='forestgreen', shape='box',
                                    height='0.3', width='0.3')  # WH / forestgreen
        else:
            if fake_guards < x:
                fake_guards = fake_guards + 1
                guard_node.append(r.address)
                if guard_generated >= guard_len:  # gu_ex
                    subgraph_guards.node(str(r.address), label="", style='filled', fillcolor='lawngreen', shape='box',
                                         height='0.3', width='0.3')  # BLUE / lawngreen
                else:
                    guard_generated = guard_generated + 1
                    subgraph_guards.node(str(r.address), label="", style='filled', fillcolor='coral2', shape='circle',
                                         height='0.3', width='0.3')  # BLUE / coral2
            else:
                middle_node.append(r.address)
                subgraph_middles.node(str(r.address), label="", style='filled', fillcolor="dodgerblue", shape='circle',
                                      height='0.3', width='0.3')  # WH / dodgerblue

    graph.subgraph(subgraph_guards)
    graph.subgraph(subgraph_middles)
    graph.subgraph(subgraph_exits)
    
    for i in range(0, len(guard_node)):
        graph.edge("PC", guard_node[i], style="invis")
    
    if len(middle_node) > len(guard_node):
        div = len(middle_node) / len(guard_node)
        x = 0
        for i in range(0, len(guard_node)):
            for j in range(x, round(div) + x):
                if j < len(middle_node):
                    graph.edge(guard_node[i], middle_node[j], style="invis")
            x = x + round(div)
            if i == (len(guard_node) - 1) and div != round(div):
                for j in range(x, len(middle_node)):
                    graph.edge(guard_node[i], middle_node[j], style="invis")
    else:
        for i in range(0, len(guard_node)):
            for j in range(0, len(middle_node)):
                if i == j:
                    graph.edge(guard_node[i], middle_node[j], style="invis")

    if len(middle_node) == 0:
        if len(exit_node) > len(guard_node):
            div = len(exit_node) / len(guard_node)
            x = 0
            for i in range(0, len(guard_node)):
                for j in range(x, round(div) + x):
                    if j < len(exit_node):
                        graph.edge(guard_node[i], exit_node[j], style="invis")
                x = x + round(div)
                if i == (len(guard_node) - 1) and div != round(div):
                    for j in range(x, len(exit_node)):
                        graph.edge(guard_node[i], exit_node[j], style="invis")
        else:
            for i in range(0, len(guard_node)):
                for j in range(0, len(exit_node)):
                    if i == j:
                        graph.edge(guard_node[i], exit_node[j], style="invis")

    elif len(exit_node) > len(middle_node):
        div = len(exit_node) / len(middle_node)
        x = 0
        for i in range(0, len(middle_node)):
            for j in range(x, round(div) + x):
                if j < len(exit_node):
                    graph.edge(middle_node[i], exit_node[j], style="invis")
            x = x + round(div)
            if i == (len(middle_node) - 1) and div != round(div):
                for j in range(x, len(exit_node)):
                    graph.edge(middle_node[i], exit_node[j], style="invis")
    else:
        for i in range(0, len(middle_node)):
            for j in range(0, len(exit_node)):
                if i == j:
                    graph.edge(middle_node[i], exit_node[j], style="invis")
    
    for index, path in enumerate(paths, start=0):
        graph.edge("PC", path[0], constraint="false", weight='0', layer="path{}".format(index))
        graph.edge(path[0], path[1], constraint="false", weight='0', layer="path{}".format(index))
        graph.edge(path[1], path[2], constraint="false", weight='0', layer="path{}".format(index))
        graph.edge(path[2], "SERVER", constraint="false", layer="path{}".format(index))

    graph.render('graph/simulation.dot', view=False)
    fix_svg_links()
    generate_graph_legend("large")


def generate_hidden_service_graph(routers, paths):
    graph = Digraph('test', format='svg')

    graph.attr(layout='neato')
    graph.attr(size="8.5")
    graph.attr(sep="-0.5")
    graph.attr(overlap="scalexy")
    graph.attr(splines="true")
    
    layers = []
    for i in range(0, 10):
        layers.append("path{}:".format(i))
    
    graph.attr(layers=''.join(layers)[:-1])
    
    pc_icon_path = "resources//PC.png"
    rp_icon_path = "resources//RP.png"
    ip_icon_path = "resources//IP.png"
    hs_icon_path = "resources//HS.png"
    dir_icon_path = "resources//DIR.png"
    graph.node("NODE", label="", shape="none")
    graph.node("PC", label="", shape="none", image=pc_icon_path, fixedsize="true", width="0.75", height="1")
    graph.node("HS", label="", shape="none", image=hs_icon_path, fixedsize="shape", width="0.75", height="1")
    graph.node("IP1", label="", shape="none", image=ip_icon_path, fixedsize="shape", width="0.75", height="1")
    graph.node("IP2", label="", shape="none", image=ip_icon_path, fixedsize="shape", width="0.75", height="1")
    graph.node("IP3", label="", shape="none", image=ip_icon_path, fixedsize="shape", width="0.75", height="1")
    graph.node("DIR", label="", shape="none", image=dir_icon_path, fixedsize="shape", width="0.75", height="1")
    graph.node("RP", label="", shape="none", image=rp_icon_path, fixedsize="shape", width="0.75", height="1")
    
    for index, r in enumerate(routers, start=0):
        graph.node(str(r.address), label="", shape='box', height='0.3', width='0.3')
        graph.edge("NODE", str(r.address), style="invis", constraint="false")
    
    graph.edge("NODE", "PC", style="invis", len="1.1", constraint="false")
    graph.edge("NODE", "HS", style="invis", len="0.1", constraint="false")
    graph.edge("NODE", "IP1", style="invis", len="1", constraint="false")
    graph.edge("NODE", "IP2", style="invis", len="1", constraint="false")
    graph.edge("NODE", "IP3", style="invis", len="1", constraint="false")
    graph.edge("NODE", "DIR", style="invis", len="1", constraint="false")
    graph.edge("NODE", "RP", style="invis", len="1", constraint="false")

    # HS -> IP1
    graph.edge("HS", paths[0][0], layer="path0", color="red", penwidth="1.8")
    graph.edge(paths[0][0], paths[0][1], layer="path0", color="red", penwidth="1.8")
    graph.edge(paths[0][1], paths[0][2], layer="path0", color="red", penwidth="1.8")
    graph.edge(paths[0][2], "IP1", layer="path0", color="red", penwidth="1.8")

    # HS -> IP1 + HS -> IP2
    graph.edge("HS", paths[0][0], layer="path1", color="red", penwidth="1.8")
    graph.edge(paths[0][0], paths[0][1], layer="path1", color="red", penwidth="1.8")
    graph.edge(paths[0][1], paths[0][2], layer="path1", color="red", penwidth="1.8")
    graph.edge(paths[0][2], "IP1", layer="path1", color="red", penwidth="1.8")
    graph.edge("HS", paths[1][0], layer="path1", color="navy", penwidth="1.8")
    graph.edge(paths[1][0], paths[1][1], layer="path1", color="navy", penwidth="1.8")
    graph.edge(paths[1][1], paths[1][2], layer="path1", color="navy", penwidth="1.8")
    graph.edge(paths[1][2], "IP2", layer="path1", color="navy", penwidth="1.8")

    # HS -> IP1 + HS -> IP2 + HS -> IP3
    graph.edge("HS", paths[0][0], layer="path2", color="red", penwidth="1.8")
    graph.edge(paths[0][0], paths[0][1], layer="path2", color="red", penwidth="1.8")
    graph.edge(paths[0][1], paths[0][2], layer="path2", color="red", penwidth="1.8")
    graph.edge(paths[0][2], "IP1", layer="path2", color="red", penwidth="1.8")
    graph.edge("HS", paths[1][0], layer="path2", color="navy", penwidth="1.8")
    graph.edge(paths[1][0], paths[1][1], layer="path2", color="navy", penwidth="1.8")
    graph.edge(paths[1][1], paths[1][2], layer="path2", color="navy", penwidth="1.8")
    graph.edge(paths[1][2], "IP2", layer="path2", color="navy", penwidth="1.8")
    graph.edge("HS", paths[2][0], layer="path2", color="green", penwidth="1.8")
    graph.edge(paths[2][0], paths[2][1], layer="path2", color="green", penwidth="1.8")
    graph.edge(paths[2][1], paths[2][2], layer="path2", color="green", penwidth="1.8")
    graph.edge(paths[2][2], "IP3", layer="path2", color="green", penwidth="1.8")

    # HS -> DIR
    graph.edge("HS", paths[7][0], layer="path3", penwidth="1.8")
    graph.edge(paths[7][0], paths[7][1], layer="path3", penwidth="1.8")
    graph.edge(paths[7][1], paths[7][2], layer="path3", penwidth="1.8")
    graph.edge(paths[7][2], "DIR", layer="path3", penwidth="1.8")

    # PC -> DIR
    graph.edge("PC", paths[4][0], layer="path4", penwidth="1.8")
    graph.edge(paths[4][0], paths[4][1], layer="path4", penwidth="1.8")
    graph.edge(paths[4][1], paths[4][2], layer="path4", penwidth="1.8")
    graph.edge(paths[4][2], "DIR", layer="path4", penwidth="1.8")

    # PC -> RP
    graph.edge("PC", paths[3][0], layer="path5", color="red", penwidth="2.3")
    graph.edge(paths[3][0], paths[3][1], layer="path5", color="red", penwidth="2.3")
    graph.edge(paths[3][1], "RP", layer="path5", color="red", penwidth="2.3")

    # PC -> RP + PC -> IP3
    graph.edge("PC", paths[3][0], layer="path6", color="red", penwidth="2.3")
    graph.edge(paths[3][0], paths[3][1], layer="path6", color="red", penwidth="2.3")
    graph.edge(paths[3][1], "RP", layer="path6", color="red", penwidth="2.3")
    graph.edge("PC", paths[5][0], layer="path6", penwidth="1.8")
    graph.edge(paths[5][0], paths[5][1], layer="path6", penwidth="1.8")
    graph.edge(paths[5][1], paths[5][2], layer="path6", penwidth="1.8")
    graph.edge(paths[5][2], "IP3", layer="path6", penwidth="1.8")

    # PC -> RP + IP3 -> HS
    graph.edge("PC", paths[3][0], layer="path7", color="red", penwidth="2.3")
    graph.edge(paths[3][0], paths[3][1], layer="path7", color="red", penwidth="2.3")
    graph.edge(paths[3][1], "RP", layer="path7", color="red", penwidth="2.3")
    graph.edge("IP3", paths[2][2], layer="path7", penwidth="1.8")
    graph.edge(paths[2][2], paths[2][1], layer="path7", penwidth="1.8")
    graph.edge(paths[2][1], paths[2][0], layer="path7", penwidth="1.8")
    graph.edge(paths[2][0], "HS", layer="path7", penwidth="1.8")

    # PC -> RP + HS -> RP
    graph.edge("PC", paths[3][0], layer="path8", color="red", penwidth="2.3")
    graph.edge(paths[3][0], paths[3][1], layer="path8", color="red", penwidth="2.3")
    graph.edge(paths[3][1], "RP", layer="path8", color="red", penwidth="2.3")
    graph.edge("HS", paths[6][0], layer="path8", color="black", penwidth="2.3")
    graph.edge(paths[6][0], paths[6][1], layer="path8", color="black", penwidth="2.3")
    graph.edge(paths[6][1], paths[6][2], layer="path8", color="black", penwidth="2.3")
    graph.edge(paths[6][2], "RP", layer="path8", color="black", penwidth="2.3")

    # PC -> RP -> HS
    graph.edge("PC", paths[3][0], layer="path9", color="red", penwidth="2.3")
    graph.edge(paths[3][0], paths[3][1], layer="path9", color="red", penwidth="2.3")
    graph.edge(paths[3][1], "RP", layer="path9", color="red", penwidth="2.3")
    graph.edge("RP", paths[6][2], layer="path9", color="red", penwidth="2.3")
    graph.edge(paths[6][2], paths[6][1], layer="path9", color="red", penwidth="2.3")
    graph.edge(paths[6][1], paths[6][0], layer="path9", color="red", penwidth="2.3")
    graph.edge(paths[6][0], "HS", layer="path9", color="red", penwidth="2.3")

    graph.render('graph/simulation.dot', view=False)
    fix_svg_links()
    generate_graph_legend('hidden_service')


def generate_attack_graph(routers, adv_guard_c, adv_exit_c, node_usage):  # todo alpha by node usage, colr by True/Flase
    graph = Digraph('test', format='svg')
    
    graph.attr(layout='neato')
    graph.attr(size="8.5")
    graph.attr(sep="-0.5")
    graph.attr(overlap="scalexy")
    graph.attr(splines="true")
    
    layers = []
    for i in range(0, 10):
        layers.append("path{}:".format(i))
    
    graph.attr(layers=''.join(layers)[:-1])
    
    pc_icon_path = "resources//computer.png"
    se_icon_path = "resources//SE.svg"
    graph.node("NODE", label="", shape="none")
    graph.node("PC", label="", shape="none", image=pc_icon_path, fixedsize="shape", width="0.75", height="1")
    graph.node("SE", label="", shape="none", image=se_icon_path, fixedsize="shape", width="0.75", height="1")

    for index, r in enumerate(routers, start=0):  # todo guard or exit
        try:
            graph.node(str(r.address), label="", style='filled',
                       fillcolor="#0000FF{}".format(node_usage[str(r.address)]), shape='box', height='0.3', width='0.3')
        except KeyError:
            graph.node(str(r.address), label="", style='filled', fillcolor="#0000FF00", shape='box', height='0.3',
                       width='0.3')
        graph.edge("NODE", str(r.address), style="invis", constraint="false")
    
    for i in range(1, adv_guard_c):
        if '10.{}.0.0'.format(i) in node_usage.keys():
            graph.node('10.{}.0.0'.format(i), label="", style='filled',
                       fillcolor="#FF0000{}".format(node_usage['10.{}.0.0'.format(i)]), shape='box', height='0.3',
                       width='0.3')
        else:
            graph.node('10.{}.0.0'.format(i), label="", style='filled', fillcolor="green", shape='box', height='0.3',
                       width='0.3')  # guard was not used
        graph.edge("NODE", '10.{}.0.0'.format(i), style="invis", constraint="false")
    for i in range(adv_guard_c, adv_guard_c + adv_exit_c):
        if '10.{}.0.0'.format(i) in node_usage.keys():
            graph.node('10.{}.0.0'.format(i), label="", style='filled',
                       fillcolor="#FF0000{}".format(node_usage['10.{}.0.0'.format(i)]), shape='circle', height='0.3',
                       width='0.3')
        else:
            graph.node('10.{}.0.0'.format(i), label="", style='filled', fillcolor="green", shape='circle', height='0.3',
                       width='0.3')  # exit was not used
        
        graph.edge("NODE", '10.{}.0.0'.format(i), style="invis", constraint="false")
    
    graph.edge("NODE", "PC", style="invis", len="0.1", constraint="false")
    graph.edge("NODE", "SE", style="invis", len="1.1", constraint="false")
    
    graph.render('graph/simulation.dot', view=False)
    fix_svg_links()
    generate_graph_legend('attack')


def generate_graph_legend(graph_type):
    graph = Digraph('test', format='svg')
    graph.attr(layout='dot', rankdir="TB", rankstep="0.8", constraint="false")
    graph.attr(size="3.5,5")
    
    subgraph_legend = Digraph('cluster_legend')
    subgraph_legend.attr(label="Key")

    if graph_type is 'hidden_service':
        dir_l = Digraph('cluster_dir_l')
        ip_l = Digraph('cluster_ip_l')
        rp_l = Digraph('cluster_rp_l')
        hs_l = Digraph('cluster_hs_l')

        dir_l.attr(label="Directory\nauthority", penwidth="0")
        rp_l.attr(label="Rendezvous\npoint", penwidth="0")
        ip_l.attr(label="Introductory\npoint", penwidth="0")
        hs_l.attr(label="Hidden\nservice", penwidth="0")

        rp_icon_path = "resources//RP.png"
        ip_icon_path = "resources//IP.png"
        hs_icon_path = "resources//HS.png"
        dir_icon_path = "resources//DIR.png"

        dir_l.node("DIR_L", label="", shape="none", image=dir_icon_path, fixedsize="true", width="0.75", height="1")
        ip_l.node("IP_L", label="", shape="none", image=ip_icon_path, fixedsize="true", width="0.75", height="1")
        rp_l.node("RP_L", label="", shape="none", image=rp_icon_path, fixedsize="true", width="0.75", height="1")
        hs_l.node("HS_L", label="", shape="none", image=hs_icon_path, fixedsize="true", width="0.75", height="1")

        subgraph_legend.subgraph(dir_l)
        subgraph_legend.subgraph(ip_l)
        subgraph_legend.subgraph(rp_l)
        subgraph_legend.subgraph(hs_l)
    elif graph_type is 'attack':
        enemy_gu_l = Digraph('cluster_enemy_gu_l')
        enemy_ex_l = Digraph('cluster_enemy_ex_l')
        friend_gu_l = Digraph('cluster_friend_gu_l')
        friend_ex_l = Digraph('cluster_friend_ex_l')
        unused_l = Digraph('cluster_unused_l')

        enemy_gu_l.attr(label="Enemy\nGuard", penwidth="0")
        enemy_ex_l.attr(label="Enemy\nExit", penwidth="0")
        friend_gu_l.attr(label="Friendly\nGuard", penwidth="0")
        friend_ex_l.attr(label="Friendly\nExit", penwidth="0")
        unused_l.attr(label="Enemy\nUnused", penwidth="0")

        enemy_gu_l.node("EN_GU", label="", shape="box", style='filled', fillcolor="red", height='0.3', width='0.3')
        enemy_ex_l.node("EN_EX", label="", shape="circle", style='filled', fillcolor="red", height='0.3', width='0.3')
        friend_gu_l.node("FR_GU", label="", shape="box", style='filled', fillcolor="blue", height='0.3', width='0.3')
        friend_ex_l.node("FR_EX", label="", shape="circle", style='filled', fillcolor="blue", height='0.3', width='0.3')
        unused_l.node("UNSET", label="", shape="circle", style='filled', fillcolor="green", height='0.3', width='0.3')

        subgraph_legend.subgraph(unused_l)
        subgraph_legend.subgraph(enemy_gu_l)
        subgraph_legend.subgraph(enemy_ex_l)
        subgraph_legend.subgraph(friend_gu_l)
        subgraph_legend.subgraph(friend_ex_l)

    else:
        guard_l = Digraph('cluster_guard_l')
        mid_l = Digraph('cluster_middle_l')
        exit_l = Digraph('cluster_exit_l')
        gu_mi_l = Digraph('cluster_gu_mi_l')
        ex_mi_l = Digraph('cluster_gu_ex_l')

        guard_l.attr(label="Guard\nMiddle", penwidth="0")
        mid_l.attr(label="Middle", penwidth="0")
        exit_l.attr(label="Exit\nMiddle", penwidth="0")
        gu_mi_l.attr(label="Guard\nMiddle", penwidth="0")
        ex_mi_l.attr(label="Guard\nExit\nMiddle", penwidth="0")
        if graph_type is "large":
            """
            guard_l.node("GU", label="", style='filled', fillcolor="dodgerblue", shape='circle', height='0.3',
                         width='0.3')
            exit_l.node("EX", label="", style='filled', fillcolor="white", shape='box', height='0.3',
                        width='0.3')
            mid_l.node("MI", label="", style='filled', fillcolor="white", shape='circle', height='0.3',
                       width='0.3')
            ex_mi_l.node("GU_EX", label="", style='filled', fillcolor="dodgerblue", shape='box', height='0.3',
                         width='0.3')
    
            """
            guard_l.node("GU", label="", style='filled', fillcolor="coral2", shape='circle', height='0.3', width='0.3')
            exit_l.node("EX", label="", style='filled', fillcolor="forestgreen", shape='box', height='0.3', width='0.3')
            mid_l.node("MI", label="", style='filled', fillcolor="dodgerblue", shape='circle', height='0.3',
                       width='0.3')
            ex_mi_l.node("EX_MI", label="", style='filled', fillcolor="lawngreen", shape='box', height='0.3',
                         width='0.3')

        else:
            guard_l.node("GU", label="", shape='circle', color="blue", fillcolor="white", height='0.3', width='0.3',
                         penwidth="2")
            exit_l.node("EX", label="", shape='circle', height='0.3', width='0.3', penwidth="2")
            mid_l.node("MI", label="", shape='box', height='0.3', width='0.3', penwidth="2")
            ex_mi_l.node("GU_EX", label="", shape='box', color="blue", fillcolor="white", height='0.3', width='0.3',
                         penwidth="2")
        subgraph_legend.subgraph(exit_l)
        subgraph_legend.subgraph(mid_l)
        subgraph_legend.subgraph(gu_mi_l)
        subgraph_legend.subgraph(ex_mi_l)
        subgraph_legend.subgraph(guard_l)

    graph.subgraph(subgraph_legend)

    graph.render('graph/legend.dot', view=False)


def fix_svg_links():
    cwd = os.getcwd()
    svg_file = Path(cwd + '/graph/simulation.dot.svg')
    
    with open(svg_file, "r") as svg:
        buf = svg.read()
    
    with open(svg_file, "w") as svg:
        buf = buf.replace('resources//computer.png', 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAMgAAADICAYAAACtWK6'
                                                     'eAAAABHNCSVQICAgIfAhkiAAAAAlwSFlzAAALEwAACxMBAJqcGAAACu5JREFUeJzt'
                                                     '3W2MHVUdx/Hv3W1pkQcrsCJPlVIhCLSoiEAETHmmBRQlig8xCBJRERARJUUjMURFX'
                                                     '4ggEA3RREgQtUTlSR4VRR6CAQsUqARBQMUisKmFtpSuL86WNLPn/Luzu3fn3t3vJ5'
                                                     'kQzj1z53Tv/O7MOXPuTIuhdgdOBg4FZgKbZupIE8Vq4EngVuAyYHGp4lTgIuA1YMD'
                                                     'FZRIua4EfAtMY1Br871TgBuBgJN0GLABW9g4WXAgc31x7pI4yC9gCuL5F6nMsBnoa'
                                                     'bZLUWQaAPXuBhcB+DTdG6jQtYG0LeBjYreHGSJ3o0RawHIdypZxVLdK5lqQMO+ZSw'
                                                     'IBIgSk16+8I9LehHdJ4ugo4fDgV6wakH3ipdnOkzrJmuBU9xZICBkQKGBApYECkgA'
                                                     'GRAgZEChgQKWBApIABkQIGRAoYEClgQKSAAZECBkQKGBApYECkgAGRAgZEChgQKWB'
                                                     'ApIABkQIGRAoYEClgQKSAAZECBkQKGBApYECkgAGRAgZEChgQKWBApIABkQIGRAoY'
                                                     'EClgQKSAAZECBkQKGBApYECkgAGRAgZEChgQKWBApIABkQIGRAoYEClgQKSAAZECB'
                                                     'kQKGBApYECkgAGRAgZEChgQKWBApIABkQIGRAoYEClgQKSAAZECBkQKGBApYECkgA'
                                                     'GRAgZEChgQKWBApIABkQIGRAoYEClgQKSAAZECBkQKGBApYECkgAGRAgZEChgQKWB'
                                                     'ApIABkQIGRAoYEClgQKSAAZECBkQKGBApYECkgAGRAgZEChgQKWBApIABkQIGRAoY'
                                                     'EClgQKSAAZECBkQKGBApMKVm/bOAle1oiDSO3jbcii1goI0Nkbqap1hSwIBIAQMiB'
                                                     'QyIFDAgUsCASAEDIgUMiBQwIFLAgEgBAyIFDIgUqDubV+3zCvAb4D7SjOkdgWOAnR'
                                                     'tsk0izeV2aXRYBW2c+mxZwIrCiA9o4KRenuzfvCuCTxJ/DgcDNwEbj0iK9zj5Is54'
                                                     'FPsOGv6TuAL7d/uaoyoA061Lg5WHWvRBY08a2KMOANOv2GnVfAP7aroYoz4A06/k2'
                                                     '19coGZBmbVWzfl9bWqEiA9Ksg2rU3QqY266GKM+ANOtzwKbDrPtFvLA77npIV3DVj'
                                                     'G2Ay9nwF9VBwNntb44qVvQAS5tuxST3YeBaYIfMa1OAzwPX4dGjCY9NAW4A9my6JZ'
                                                     'PckcDjwO9Ic7FeAXYCFpAPjsbHjS1gJukoMq3hxkidZCWwcy/QT7pCe0iz7ZE6yjn'
                                                     'Ajb2D/3MnsC2wV3PtkTrGZcBCgN71Cn8LLAP2B6Y30CipaS8BZwDnrStoZSrNAI4H'
                                                     'DgZmYVg0sa0EngBuBa4idTkkSRql3CmWYucA72+6ESPwIul6i2rw6mx9s4F9mm7EC'
                                                     'CxrugHdyMmK9fkb/knEgNS3tukGjJDBHgEDIgUMSH3degTRCBgQKWBA6nNofBIxIP'
                                                     'VNbboBI+TPGUbAgNT35qYbMEKb461LazMg9e3UdANGqEW6Y7xqMCD1TAd2aboRozC'
                                                     'n6QZ0GwNSz7509/ScA5puQLcxIPUc03QDRumophugiWsj4N90wENdRrl4FFFbrHuO'
                                                     'R7cv1431H0Z6ExPj6LFuOWxs/zya7K6m+Z16LJdn8E7xGiPfpPkduh3LXQz/xtnSE'
                                                     'C3gAprfkdsdEo8kqm0rUme26R14PJanSNd3pGGZD/yT5nfc8VxeJd0srVsnYmocTA'
                                                     'EuovmdtcnlXtLNzKUhrqD5HbQTln9Q/9mJmuB2oPkds5OWU0f355w4nIuVPAf8vel'
                                                     'GdIjXSA/xEf58dH0zgUtIN+2erH+XJ4HTSU+6kiRJkiSNs3Z3RvcgdXznjMO2NHmt'
                                                     'AH7Eeo9O6wbbM/mmbLg0u5zBGGvXt/omwB+Bd7bp/aWclcDewENj9YbtCEgLWAR8o'
                                                     'PD6z0mP2V3fNOBKYMtK+QBwEkMv4u0I/CTz3ktJP42tmg98OVN+KenHUFVfBQ7PlB'
                                                     '8H/DdTfjVDp40/CJyWqbsdaVpL1SXALzLlHwS+kCn/KOlXjlUXkHaS9T0FnJCpOxW'
                                                     '4KVP+K+DiTPk84OuZ8nOAuzPl5wEHVsrWkp7Q9b9K+Sak/aZ6c7vHgZMz770AOCtT'
                                                     'vhh4D7Aq81pH+A7lQ+D9wMaZdb5fqP+DwjauKdTP3bWjBTyQqbuC/Jyj6cALmfr3F'
                                                     'Noyq9CW7xbqLyjUP7ZQ/2uF+tsU6i/K1H22UBfSrwur9UsXCrcvtOWCQv2PF+p/ul'
                                                     'D/8kL9asggBWlpof73Cu9f21jf4+kE4OzCa2tJ35LvrZTvRP6bdjlwC3BIpXwX8ke'
                                                     'nv5EOsdX6c4A9M/XvAt6RKd+H9Bv0qocy7w1waKYM4OVC/QWF+lsX6u9RqL8v6W9U'
                                                     'tXmmbIvCe0P6MtiuUla6wdwzpJ2yevO8o8kfiZaTpq70Vso/S7pqX/UX4MRM+fnkO'
                                                     '+DXkN/fzgSuB27LvNaYA0mHtaY7ai5js5Rm9F7SAW0bzvI0MKPwbxi2sZqsOJv8+a'
                                                     'O619xC+S3j2oqR256hfd3axiIgM4BrGdrBVncrnWbdTvc8ZesjwCdG8waj7YNMIY3'
                                                     'g7Fp4/XnyHcQtSQmvehVYUnivOeQDvRR4JVP+FtJ5fdVz5Ed/esmf768CHi20aSb5'
                                                     '/spjpP5Q1RuAnTPl/wH+VdjGrgx9tsca4OFC/T5g20z5E+T7LCWbFcpfJA227JV57'
                                                     'eHBtlVtQfrNTVXdz2ItaXQwZzb5u7RcTLrk8FRhvbaKzkeXA2/PrDOV9HuD3DrnFr'
                                                     'ZzdKH+Esohv7ewzn6F+kcV6v+0UB9Sp7Ja/1XSkGXOhwrbODPYxpOZ+tGHfWphG8c'
                                                     'F69RVGqmcV6i/R6H+74Nt3FNY532F+tGdL/9AA799Oi1oUPSBfKtQ/x6GjnZAGnZ9'
                                                     'orDOEYVtHFGof0fw78kNjw5QHqXqI32jVevfFWzjG4VtHB2s81Km/iNB/U8VtpG7l'
                                                     'jBShxW2URruhXTUya2TO6JCGqnM1S+NTPUE2xgAvjKsf1nFSC8UHkHqd+R2aEhHj9'
                                                     'zO2BpcN5fmB8ifjvWRLvxUrQZuLmx/DvmbDzxCClvOYeTv6nED+XPuLcnfLudp0sW'
                                                     'qnLnkTzX+BPQX1pnP0M+p9PeFdHqVm8GwhLH71eQ08sPGy0hH7pzdyT/AZzHpb1bV'
                                                     'Ao4kv4/eRDpSV80CditsfzXp87q/8HrWSAKyO/Bn8uPtUid7hNR3yvVZs0pHgJI+0'
                                                     'ihGrvMrdbo+4I2ks4JhqROQaaSrk6Xxcakb7E3q7z4+nMp1TrF+Rjym/CXyHai3Ar'
                                                     '8kP9p0Nvl+xMakMOauhC4cfC3nSvLnoOcPtmEymE3+33of5Y76DNKZQdWzlJ9KtRF'
                                                     'wJ0M/19XA/uT7CL2D28kNIR9Dvi/SA9xI/h7Cp5GGcHPr/Jr8pQRIQ+pzSZchxsRC'
                                                     '4hGrHxfW6yF1JnPrlHZySPNucus8SPmod0BhnReYXHcxL02e3FDntD+zzmvkJ5euc'
                                                     '3dhW6XhXkjD5rl1crOE1zm3sE401+pjhXXWLYuCdV83nAuFx5EeAVDSTxrPzg3rHk'
                                                     'D+kV8DpG+F3DrTKU94vJ3yrNfTC+X3UR4OnohK84+2Jb4W8iJDB156gFPIf7ND+vL'
                                                     'JOYXyzIplhfKTKF8kfo60z1TPeOaRPvfc6OfqwfVK/eVjB7d5eeF1yGywqo80NFi6'
                                                     '8CV1s+WkoedS0Dd4dfHdGA5NXJsB74oqbCggS0jnodJEtIZ4VsIGh3n7Sedx83Aqu'
                                                     'yaW5aQfbuVGwV73f18dfj8mwSVzAAAAAElFTkSuQmCC')
        buf = buf.replace('resources//SE.svg', 'data:image/svg+xml;base64,PD94bWwgdmVyc2lvbj0iMS4wIj8+CjxzdmcgeG1sbnM9I'
                                               'mh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIiB2aWV3Qm94PSIwIDAgNjQgNjQiPgoJPHBh'
                                               'dGggZD0iTSAxNC44NTM1MTYgNiBDIDEzLjMyODUxNiA2IDExLjk1NzM5MSA2Ljg0NzkzNzU'
                                               'gMTEuMjc1MzkxIDguMjEwOTM3NSBMIDYuNTI3MzQzOCAxNy43MDg5ODQgQyA2LjE4MzM0Mz'
                                               'cgMTguMzk4OTg0IDYgMTkuMTcyMzU5IDYgMTkuOTQzMzU5IEwgNiAzMCBDIDYgMzEuMjAxI'
                                               'DYuNTQyODEyNSAzMi4yNjYgNy4zODI4MTI1IDMzIEMgNi41NDI4MTI1IDMzLjczNCA2IDM0'
                                               'Ljc5OSA2IDM2IEwgNiA0MiBDIDYgNDMuMjAxIDYuNTQyODEyNSA0NC4yNjYgNy4zODI4MTI'
                                               '1IDQ1IEMgNi41NDI4MTI1IDQ1LjczNCA2IDQ2Ljc5OSA2IDQ4IEwgNiA1NCBDIDYgNTYuMj'
                                               'A2IDcuNzk0IDU4IDEwIDU4IEwgNTQgNTggQyA1Ni4yMDYgNTggNTggNTYuMjA2IDU4IDU0I'
                                               'EwgNTggNDggQyA1OCA0Ni43OTkgNTcuNDU3MTg4IDQ1LjczNCA1Ni42MTcxODggNDUgQyA1'
                                               'Ny40NTcxODcgNDQuMjY2IDU4IDQzLjIwMSA1OCA0MiBMIDU4IDM2IEMgNTggMzQuNzk5IDU'
                                               '3LjQ1NzE4OCAzMy43MzQgNTYuNjE3MTg4IDMzIEMgNTcuNDU3MTg3IDMyLjI2NiA1OCAzMS'
                                               '4yMDEgNTggMzAgTCA1OCAxOS45NDMzNTkgQyA1OCAxOS4xNzIzNTkgNTcuODE2NjU2IDE4L'
                                               'jM5ODAzMSA1Ny40NzI2NTYgMTcuNzA3MDMxIEwgNTIuNzI0NjA5IDguMjEwOTM3NSBDIDUy'
                                               'LjA0MjYwOSA2Ljg0NzkzNzUgNTAuNjcxNDg0IDYgNDkuMTQ2NDg0IDYgTCAxNC44NTM1MTY'
                                               'gNiB6IE0gMTQuODUzNTE2IDggTCA0OS4xNDQ1MzEgOCBDIDQ5LjkwNzUzMSA4IDUwLjU5Mj'
                                               'U5NCA4LjQyNDQ2ODcgNTAuOTMzNTk0IDkuMTA1NDY4OCBMIDU1LjY4MzU5NCAxOC42MDE1N'
                                               'jIgQyA1NS44OTE1OTQgMTkuMDE3NTYzIDU2IDE5LjQ4MDM1OSA1NiAxOS45NDMzNTkgTCA1'
                                               'NiAyMCBMIDggMjAgTCA4IDE5Ljk0MzM1OSBDIDggMTkuNDgwMzU5IDguMTA5NDA2MyAxOS4'
                                               'wMTU1NjMgOC4zMTY0MDYyIDE4LjYwMTU2MiBMIDEzLjA2NDQ1MyA5LjEwNTQ2ODggQyAxMy'
                                               '40MDU0NTMgOC40MjQ0Njg3IDE0LjA5MTUxNiA4IDE0Ljg1MzUxNiA4IHogTSAxNSAxMCBDI'
                                               'DE0LjQ0NyAxMCAxNCAxMC40NDcgMTQgMTEgQyAxNCAxMS41NTMgMTQuNDQ3IDEyIDE1IDEy'
                                               'IEwgNDEgMTIgQyA0MS41NTMgMTIgNDIgMTEuNTUzIDQyIDExIEMgNDIgMTAuNDQ3IDQxLjU'
                                               '1MyAxMCA0MSAxMCBMIDE1IDEwIHogTSA0NSAxMCBDIDQ0LjQ0NyAxMCA0NCAxMC40NDcgND'
                                               'QgMTEgQyA0NCAxMS41NTMgNDQuNDQ3IDEyIDQ1IDEyIEwgNDkgMTIgQyA0OS41NTMgMTIgN'
                                               'TAgMTEuNTUzIDUwIDExIEMgNTAgMTAuNDQ3IDQ5LjU1MyAxMCA0OSAxMCBMIDQ1IDEwIHog'
                                               'TSA4IDIyIEwgNTYgMjIgTCA1NiAzMCBDIDU2IDMxLjEwMyA1NS4xMDMgMzIgNTQgMzIgTCA'
                                               'xMCAzMiBDIDguODk3IDMyIDggMzEuMTAzIDggMzAgTCA4IDIyIHogTSA0OSAyNCBDIDQ3Lj'
                                               'M0NiAyNCA0NiAyNS4zNDYgNDYgMjcgQyA0NiAyOC42NTQgNDcuMzQ2IDMwIDQ5IDMwIEMgN'
                                               'TAuNjU0IDMwIDUyIDI4LjY1NCA1MiAyNyBDIDUyIDI1LjM0NiA1MC42NTQgMjQgNDkgMjQg'
                                               'eiBNIDEzIDI1IEMgMTIuNDQ3IDI1IDEyIDI1LjQ0NyAxMiAyNiBMIDEyIDI4IEMgMTIgMjg'
                                               'uNTUzIDEyLjQ0NyAyOSAxMyAyOSBDIDEzLjU1MyAyOSAxNCAyOC41NTMgMTQgMjggTCAxNC'
                                               'AyNiBDIDE0IDI1LjQ0NyAxMy41NTMgMjUgMTMgMjUgeiBNIDE4IDI1IEMgMTcuNDQ3IDI1I'
                                               'DE3IDI1LjQ0NyAxNyAyNiBMIDE3IDI4IEMgMTcgMjguNTUzIDE3LjQ0NyAyOSAxOCAyOSBD'
                                               'IDE4LjU1MyAyOSAxOSAyOC41NTMgMTkgMjggTCAxOSAyNiBDIDE5IDI1LjQ0NyAxOC41NTM'
                                               'gMjUgMTggMjUgeiBNIDIzIDI1IEMgMjIuNDQ3IDI1IDIyIDI1LjQ0NyAyMiAyNiBMIDIyID'
                                               'I4IEMgMjIgMjguNTUzIDIyLjQ0NyAyOSAyMyAyOSBDIDIzLjU1MyAyOSAyNCAyOC41NTMgM'
                                               'jQgMjggTCAyNCAyNiBDIDI0IDI1LjQ0NyAyMy41NTMgMjUgMjMgMjUgeiBNIDI4IDI1IEMg'
                                               'MjcuNDQ3IDI1IDI3IDI1LjQ0NyAyNyAyNiBMIDI3IDI4IEMgMjcgMjguNTUzIDI3LjQ0NyA'
                                               'yOSAyOCAyOSBDIDI4LjU1MyAyOSAyOSAyOC41NTMgMjkgMjggTCAyOSAyNiBDIDI5IDI1Lj'
                                               'Q0NyAyOC41NTMgMjUgMjggMjUgeiBNIDMzIDI1IEMgMzIuNDQ3IDI1IDMyIDI1LjQ0NyAzM'
                                               'iAyNiBMIDMyIDI4IEMgMzIgMjguNTUzIDMyLjQ0NyAyOSAzMyAyOSBDIDMzLjU1MyAyOSAz'
                                               'NCAyOC41NTMgMzQgMjggTCAzNCAyNiBDIDM0IDI1LjQ0NyAzMy41NTMgMjUgMzMgMjUgeiB'
                                               'NIDQ5IDI1Ljc5Mjk2OSBDIDQ5LjY2NyAyNS43OTI5NjkgNTAuMjA3MDMxIDI2LjMzNCA1MC'
                                               '4yMDcwMzEgMjcgQyA1MC4yMDcwMzEgMjcuNjY3IDQ5LjY2NiAyOC4yMDcwMzEgNDkgMjguM'
                                               'jA3MDMxIEMgNDguMzM0IDI4LjIwNzAzMSA0Ny43OTI5NjkgMjcuNjY3IDQ3Ljc5Mjk2OSAy'
                                               'NyBDIDQ3Ljc5Mjk2OSAyNi4zMzMgNDguMzMzIDI1Ljc5Mjk2OSA0OSAyNS43OTI5NjkgeiB'
                                               'NIDM3IDI2IEMgMzYuNDQ3IDI2IDM2IDI2LjQ0NyAzNiAyNyBDIDM2IDI3LjU1MyAzNi40ND'
                                               'cgMjggMzcgMjggTCA0MyAyOCBDIDQzLjU1MyAyOCA0NCAyNy41NTMgNDQgMjcgQyA0NCAyN'
                                               'i40NDcgNDMuNTUzIDI2IDQzIDI2IEwgMzcgMjYgeiBNIDEwIDM0IEwgNTQgMzQgQyA1NS4x'
                                               'MDMgMzQgNTYgMzQuODk3IDU2IDM2IEwgNTYgNDIgQyA1NiA0My4xMDMgNTUuMTAzIDQ0IDU'
                                               '0IDQ0IEwgMTAgNDQgQyA4Ljg5NyA0NCA4IDQzLjEwMyA4IDQyIEwgOCAzNiBDIDggMzQuOD'
                                               'k3IDguODk3IDM0IDEwIDM0IHogTSA0OSAzNiBDIDQ3LjM0NiAzNiA0NiAzNy4zNDYgNDYgM'
                                               'zkgQyA0NiA0MC42NTQgNDcuMzQ2IDQyIDQ5IDQyIEMgNTAuNjU0IDQyIDUyIDQwLjY1NCA1'
                                               'MiAzOSBDIDUyIDM3LjM0NiA1MC42NTQgMzYgNDkgMzYgeiBNIDEzIDM3IEMgMTIuNDQ3IDM'
                                               '3IDEyIDM3LjQ0NyAxMiAzOCBMIDEyIDQwIEMgMTIgNDAuNTUzIDEyLjQ0NyA0MSAxMyA0MS'
                                               'BDIDEzLjU1MyA0MSAxNCA0MC41NTMgMTQgNDAgTCAxNCAzOCBDIDE0IDM3LjQ0NyAxMy41N'
                                               'TMgMzcgMTMgMzcgeiBNIDE4IDM3IEMgMTcuNDQ3IDM3IDE3IDM3LjQ0NyAxNyAzOCBMIDE3'
                                               'IDQwIEMgMTcgNDAuNTUzIDE3LjQ0NyA0MSAxOCA0MSBDIDE4LjU1MyA0MSAxOSA0MC41NTM'
                                               'gMTkgNDAgTCAxOSAzOCBDIDE5IDM3LjQ0NyAxOC41NTMgMzcgMTggMzcgeiBNIDIzIDM3IE'
                                               'MgMjIuNDQ3IDM3IDIyIDM3LjQ0NyAyMiAzOCBMIDIyIDQwIEMgMjIgNDAuNTUzIDIyLjQ0N'
                                               'yA0MSAyMyA0MSBDIDIzLjU1MyA0MSAyNCA0MC41NTMgMjQgNDAgTCAyNCAzOCBDIDI0IDM3'
                                               'LjQ0NyAyMy41NTMgMzcgMjMgMzcgeiBNIDI4IDM3IEMgMjcuNDQ3IDM3IDI3IDM3LjQ0NyA'
                                               'yNyAzOCBMIDI3IDQwIEMgMjcgNDAuNTUzIDI3LjQ0NyA0MSAyOCA0MSBDIDI4LjU1MyA0MS'
                                               'AyOSA0MC41NTMgMjkgNDAgTCAyOSAzOCBDIDI5IDM3LjQ0NyAyOC41NTMgMzcgMjggMzcge'
                                               'iBNIDMzIDM3IEMgMzIuNDQ3IDM3IDMyIDM3LjQ0NyAzMiAzOCBMIDMyIDQwIEMgMzIgNDAu'
                                               'NTUzIDMyLjQ0NyA0MSAzMyA0MSBDIDMzLjU1MyA0MSAzNCA0MC41NTMgMzQgNDAgTCAzNCA'
                                               'zOCBDIDM0IDM3LjQ0NyAzMy41NTMgMzcgMzMgMzcgeiBNIDQ5IDM3Ljc5Mjk2OSBDIDQ5Lj'
                                               'Y2NiAzNy43OTI5NjkgNTAuMjA3MDMxIDM4LjMzNCA1MC4yMDcwMzEgMzkgQyA1MC4yMDcwM'
                                               'zEgMzkuNjY3IDQ5LjY2NyA0MC4yMDcwMzEgNDkgNDAuMjA3MDMxIEMgNDguMzMzIDQwLjIw'
                                               'NzAzMSA0Ny43OTI5NjkgMzkuNjY2IDQ3Ljc5Mjk2OSAzOSBDIDQ3Ljc5Mjk2OSAzOC4zMzM'
                                               'gNDguMzM0IDM3Ljc5Mjk2OSA0OSAzNy43OTI5NjkgeiBNIDM3IDM4IEMgMzYuNDQ3IDM4ID'
                                               'M2IDM4LjQ0NyAzNiAzOSBDIDM2IDM5LjU1MyAzNi40NDcgNDAgMzcgNDAgTCA0MyA0MCBDI'
                                               'DQzLjU1MyA0MCA0NCAzOS41NTMgNDQgMzkgQyA0NCAzOC40NDcgNDMuNTUzIDM4IDQzIDM4'
                                               'IEwgMzcgMzggeiBNIDEwIDQ2IEwgNTQgNDYgQyA1NS4xMDMgNDYgNTYgNDYuODk3IDU2IDQ'
                                               '4IEwgNTYgNTQgQyA1NiA1NS4xMDMgNTUuMTAzIDU2IDU0IDU2IEwgMTAgNTYgQyA4Ljg5Ny'
                                               'A1NiA4IDU1LjEwMyA4IDU0IEwgOCA0OCBDIDggNDYuODk3IDguODk3IDQ2IDEwIDQ2IHogT'
                                               'SA0OSA0OCBDIDQ3LjM0NiA0OCA0NiA0OS4zNDYgNDYgNTEgQyA0NiA1Mi42NTQgNDcuMzQ2'
                                               'IDU0IDQ5IDU0IEMgNTAuNjU0IDU0IDUyIDUyLjY1NCA1MiA1MSBDIDUyIDQ5LjM0NiA1MC4'
                                               '2NTQgNDggNDkgNDggeiBNIDEzIDQ5IEMgMTIuNDQ3IDQ5IDEyIDQ5LjQ0NyAxMiA1MCBMID'
                                               'EyIDUyIEMgMTIgNTIuNTUzIDEyLjQ0NyA1MyAxMyA1MyBDIDEzLjU1MyA1MyAxNCA1Mi41N'
                                               'TMgMTQgNTIgTCAxNCA1MCBDIDE0IDQ5LjQ0NyAxMy41NTMgNDkgMTMgNDkgeiBNIDE4IDQ5'
                                               'IEMgMTcuNDQ3IDQ5IDE3IDQ5LjQ0NyAxNyA1MCBMIDE3IDUyIEMgMTcgNTIuNTUzIDE3LjQ'
                                               '0NyA1MyAxOCA1MyBDIDE4LjU1MyA1MyAxOSA1Mi41NTMgMTkgNTIgTCAxOSA1MCBDIDE5ID'
                                               'Q5LjQ0NyAxOC41NTMgNDkgMTggNDkgeiBNIDIzIDQ5IEMgMjIuNDQ3IDQ5IDIyIDQ5LjQ0N'
                                               'yAyMiA1MCBMIDIyIDUyIEMgMjIgNTIuNTUzIDIyLjQ0NyA1MyAyMyA1MyBDIDIzLjU1MyA1'
                                               'MyAyNCA1Mi41NTMgMjQgNTIgTCAyNCA1MCBDIDI0IDQ5LjQ0NyAyMy41NTMgNDkgMjMgNDk'
                                               'geiBNIDI4IDQ5IEMgMjcuNDQ3IDQ5IDI3IDQ5LjQ0NyAyNyA1MCBMIDI3IDUyIEMgMjcgNT'
                                               'IuNTUzIDI3LjQ0NyA1MyAyOCA1MyBDIDI4LjU1MyA1MyAyOSA1Mi41NTMgMjkgNTIgTCAyO'
                                               'SA1MCBDIDI5IDQ5LjQ0NyAyOC41NTMgNDkgMjggNDkgeiBNIDMzIDQ5IEMgMzIuNDQ3IDQ5'
                                               'IDMyIDQ5LjQ0NyAzMiA1MCBMIDMyIDUyIEMgMzIgNTIuNTUzIDMyLjQ0NyA1MyAzMyA1MyB'
                                               'DIDMzLjU1MyA1MyAzNCA1Mi41NTMgMzQgNTIgTCAzNCA1MCBDIDM0IDQ5LjQ0NyAzMy41NT'
                                               'MgNDkgMzMgNDkgeiBNIDQ5IDQ5Ljc1IEMgNDkuNjkgNDkuNzUgNTAuMjUgNTAuMzEgNTAuM'
                                               'jUgNTEgQyA1MC4yNSA1MS42OSA0OS42OSA1Mi4yNSA0OSA1Mi4yNSBDIDQ4LjMxIDUyLjI1'
                                               'IDQ3Ljc1IDUxLjY5IDQ3Ljc1IDUxIEMgNDcuNzUgNTAuMzEgNDguMzEgNDkuNzUgNDkgNDk'
                                               'uNzUgeiBNIDM3IDUwIEMgMzYuNDQ3IDUwIDM2IDUwLjQ0NyAzNiA1MSBDIDM2IDUxLjU1My'
                                               'AzNi40NDcgNTIgMzcgNTIgTCA0MyA1MiBDIDQzLjU1MyA1MiA0NCA1MS41NTMgNDQgNTEgQ'
                                               'yA0NCA1MC40NDcgNDMuNTUzIDUwIDQzIDUwIEwgMzcgNTAgeiIvPgo8L3N2Zz4K')
        buf = buf.replace('resources//PC.png', 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAWsAAAHgCAYAAABjMUxjAAAdD'
                                               'klEQVR4nO3debhddX3v8fc5CYHEkBCGMM+EEAYZFAHFItZaLUhFy6QgVtSi0oFHb6/X4oCi'
                                               'PN6rtZZSixdrbW+pbbkXZLZKnZmcmCEMQglEICGBhATCSc6+f/xOICYn5+y9fr+91v6e/X4'
                                               '9z3kIyV7f9T0nyees/PZvGKB7dgO2BbYH5gEHAbsDWwGzgcldvLckdcsw8AzwGLAI+CVwF/'
                                               'AIsBj4FfBC6ZsOFK43B/ht4ADgLcDOhetLUi9bCVwO/Ay4CbixVOFSYX0E8AHgMGDvQjUlK'
                                               'bLFwE+AbwNfyS2WG9YHA+cDhwJb5jYjSRNQizRM8kngSmCoSpGqYb0T8EHgz4FJFWtIUr/5'
                                               'D1Ju3tbphVWC9g3APwJvBwYrXC9J/WpP4ERgFXBzJxd2+mT9CeAjwOYdXidJ+k3/DPwRsKK'
                                               'dF7cb1pOBLwFnVWxKkrShHwCnAo+O98J2wnoKcDFwWmZTkqQN3QScAjw81ovaCeuLgTMKNC'
                                               'RJGt3NwLGk6X6jGu8Nwi9iUEtStx1GGsPeZGMvGGs2yOnA50t3JEka1Z7AdsDVpLnZv2FjY'
                                               'T0X+Cowq3t9SZLWczDwAHDH+r8w2pj1dNLj+HFdbkqStKH7gaNJG0W9aLQn62OBj1N+kydJ'
                                               '0vi2AjYDrln3J9cP5GnAfNJy8pIWActIWwf+fOT/V41yf0nqZS3Sm4BbAPsAh5Byc8fC9xk'
                                               'GDgTu3NgL3jfSTKmPn5NmlMwt/IlIUq/YmrTfx/WUzc9LN3bDKcC9hW7yLPBp0uEDktQPJp'
                                               'GmOs+nTI4+Qzq0ZQN/QBqayL3BPcDrCn3ykhTNLqTx5hKBfdFoN/hmgcJ3k8ZxJKmfbUI6M'
                                               'SY3U28hjY+/aGfS5tg5RRezkUd2SepDU4Efk5era0ijHi96x8hP5hT9w658upIU177Ar8nL'
                                               '1v8BL+0Nsit5BwlcCvxDxvWSNBHdTf75i4eQntKZBHyN6qn/HHB8ZjOSNFHtSpp4UTVjlwB'
                                               'zBkmrZQ7MaOQm4LqM6yVpIvsv0huFVc0CZg4Cs4EDMgo9SHq6liSN7grycnKLQdIa9CkVC6'
                                               'wirdqRJG3c90jDGVVtNUi1E87XWk6FI9Ulqc8sAV7IuH76IGOcTNCGIdKSSEnS2IYzrp2R+'
                                               '2TdAlZnXC9JGt9mOXOrJUk1MawlKQDDWpICMKwlKQDDWpICMKwlKQDDWpICMKwlKQDDWpIC'
                                               'MKwlKQDDWpICMKwlKQDDWpICMKwlKQDDWpICMKwlKQDDWpICMKwlKQDDWpICMKwlKQDDWpI'
                                               'CMKwlKQDDWpICMKwlKQDDWpICMKwlKQDDWpICMKwlKQDDWpICMKwlKQDDWpICMKwlKQDDWp'
                                               'ICMKwlKQDDWpICMKwlKQDDWpICMKwlKQDDWpICMKwlKQDDWpICMKwlKQDDWpICMKwlKQDDW'
                                               'pICMKwlKQDDWpICMKwlKQDDWpICMKwlKQDDWpICMKwlKQDDWpICMKwlKQDDWpICMKwlKQDD'
                                               'WpICMKwlKQDDWpICMKwlKQDDWpICMKwlKQDDWpICMKwlKQDDWpICMKwlKQDDWpICMKwlKQD'
                                               'DWpICMKwlKQDDWpICMKwlKQDDWpICMKwlKQDDWpICMKwlKQDDWpICMKwlKQDDWpICMKwlKQ'
                                               'DDWpICMKwlKQDDWpICMKwlKQDDWpICMKwlKQDDWpICMKwlKQDDWpICMKwlKQDDWpICMKwlK'
                                               'QDDWpICMKwlKQDDWpICMKwlKQDDWpICMKwlKQDDWpICMKwlKQDDWpICMKwlKQDDWpICMKwl'
                                               'KQDDWpICMKwlKQDDWpICMKwlKQDDWpICMKwlKQDDWpICMKwlKQDDWpICMKwlKQDDWpICMKw'
                                               'lKQDDWpICMKwlKQDDWpICMKwlKQDDWpICMKwlKQDDWpICMKwlKQDDWpICMKwlKQDDWpICMK'
                                               'wlKQDDWpICMKwlKQDDWpICMKwlKQDDWpICMKwlKQDDWpICMKwlKQDDWpICMKwlKQDDWpICM'
                                               'KwlKQDDWpICMKwlKQDDWpICMKwlKQDDWpICMKwlKQDDWpICMKwlKQDDWpICMKwlKQDDWpIC'
                                               'MKwlKQDDWpICMKwlKQDDWpICMKwlKQDDWpICMKwlKQDDWpICMKwlKQDDWpICMKwlKQDDWpI'
                                               'CMKwlKQDDWpICMKwlKQDDWpICMKwlKQDDWpICMKwlKQDDWpICMKwlKQDDWpICMKwlKYASYd'
                                               '0qUEOSNIbcsB7AsJakdmRl5eTMm88GfgGszqwjSRPdTjkX54b1pNwGJEnj8w1GSQrAsJakA'
                                               'AxrSQrAsJakAAxrSQrAsJakAAxrSQrAsJakAAxrSQrAsJakAAxrSQrAsJakAAxrSQogd9e9'
                                               '54CLgYcK1JKkiahFejD+KDCrapHcgF0KfAZYlFlHkia695MR1iWGQRxKkaQuM2glKQDDWpI'
                                               'CMKwlKQDDWpICMKwlKQDDWpICGASGM64fwMCXpG4bGgSGMgpMBmYUakaSJrKcB9tnBoE1GQ'
                                               'WmA/tkXC9J/WAGsEnG9c8OAqtIa9ermAq8KaMBSeoHhwNbZFy/ZBBYDNyTUWR3YFLG9ZI00'
                                               'R1PGomoaukgaROmWzOKvAo4OuN6SZrItiU9WVe1Ali29g3GnCfrWcDJGddL0kR2AvDyjOt/'
                                               'ADy69n/eTRq3rvqxGseuJWl9u5P2+8/J10+sW3AO8EBmwYeB3brwyUpSVN8kL1eHgdPWL3p'
                                               'ZZtEW8H1gh9KfrSQF9CXyM/U2YLv1C59BGr/OLf5jYN/Cn7QkRTEV+Cr5WdoC/nG0G7wM+F'
                                               'WhGzwBnAJsXuqzl6QAjgRuoEyOrgRet7EbnVPoJms/rgHeBeyS/SWQpN40gzSP+m8pm5/Xr'
                                               '3uTgfVuOpP0zmXlQx034nbgbmA56el9MXnL3CWpKQOkUYM5pKDeFfitLtzntaRh5Rdvur73'
                                               'Axd14cbrWkP6ziFJ0QzQ/VXblwDvXP+m65sJXM4YYyWSpK55GngNaTTiRaNt2fcMaex6SQ1'
                                               'NSZJesgb4GOsFNWz8UX4BaTe+NzL607ckqbyrgI8zyjkDY427/Iy0V/X+XWpKkvSSu4HfB5'
                                               'aN9otjhXULuBY4FNizfF+SpBGPkvZXemxjLxjvmJkVwKmsM31EklTUQ8CxpP2ZNqqd6ScrS'
                                               'OMo+wJ75/clSRoxH3grcMd4L2x3ruBK0kZPs4ED8URzScp1I/AW4MF2XtzJxO7VwJXAI8Bh'
                                               'uO+HJFWxCriAtPXp0nYvqrIK5zbgh8AU4KAK10tSv7oJOBv4Mh1uuZE7h/o44FPAwZl1JGk'
                                               'iWwR8Gvh30q6kHSux4GU66cDcc0kbmmxZoKYkRfc8KZi/RtqR76mcYqVXJ76ctBHUPsA8PD'
                                               'VGUn95lrTL6ELSkV6XU2iH0W4tJR8AXkk6fn0W6ViaPUd+vBXpoAPFMUz6PZuRUeNZ0ha5/'
                                               'TKTaJD0r8yqu7OtJm3osxq3fOg1A8BzpDcHnyFt+/wY6ffrDtLhA89246Z1mUk67mYq6c1J'
                                               'xdEC3gBcWPH6xcCZpD/I/RI8A8B/A95T8fqfAO8lfaPsl69ZFAOkvTueI83sWEr6feqqyd2'
                                               '+wTqeGflQTDnnai4FfkAK7X5yT8a1Q6QFE+77LqB//kmqfBucsNyB50lDIP3mhYxrtwZ2Kt'
                                               'WI4jOs1a6csF418tFvcsJ6G2D7Uo0oPsNa7ZhEmpZZVb+et5kz7LMNHjStdRjWasdU8jbxW'
                                               'lGqkWAWAE9WvHYQ2LZgLwrOsFY7NgP2y7j+rlKNBPM41cMaYJNSjSg+w1rt2JQ09bKKFv0b'
                                               '1ovIW7U2rVQjis+wVjs2zbh2iLS5ej9aSd4smC1KNaL4DGu1o+pTNaQ3Fzd6VFEfeC7j2m2'
                                               'ovgJSE4xhrXbMzrh2DZkb2AS3wSnVHdiJtFGaZFirLTnT9obZyGnNfSJnGGQPHArRCMNa7Z'
                                               'iTeX3O02V08zOu3Y20+ZlkWKst+2dcu4C0c1y/up/q88wHSdMmJcNabclZEHMb/b0Z0SOkW'
                                               'SFVGdYCDGu1J2fq3r3FuojpcdJGVlU5Zi3AsNb4NiNvP+VHSjUS1FLyxuxzZuJoAjGsNZ5Z'
                                               '5O17/nipRoIaIm8jq51LNaLYDGuNZ3vyhkGWlGoksJwn6zn491T4h0Dj25W8sO7nOdZrPZh'
                                               'x7QG4oZOo91gvxbQXeTMS3kbaG6RfA2eIdOpLVXuS/p724+ENWodhrfHkbI0K8LkiXfSvQf'
                                               'r3G53W4TCIxpPzVKgyNm+6ATXPsNZ4/DPSrEH8hin8i6jxuYKuWYPADk03oeYZ1hrLdOBlT'
                                               'TfR5waA3ZtuQs0zrDWW2eQdPKAyct/k1QRgWGssW2NY94K5TTeg5hnWGstkPFaqFzjFVoa1'
                                               'xvQE8HTTTahvT4fXOgxrjeUhYGHTTYjLmm5AzTOsNZZh4Jqmm+hzTwA3NN2EpN43BfgZ6bQ'
                                               'XP+r/OGn83yJJSvYF7qH54Oq3jy/ioiRJHdoDuJLmA6wfPpYBHyD9q0YC8o5rUv+ZBhwK/B'
                                               'Hw2/jnp6QWsBj4KukNxX4/Dk3r8S+bckzCN6lLyTlNRpIkSZIkSZIkSZIkSZIkSZIkSZJ6z'
                                               '0RawThIWlE3kT4nSXnWjHyENxGCbQ5wNHAKcAgeQyXpJQ8ClwLX8dJWvyFFDuvJwNnAx4HN'
                                               'G+5FUu+7iJQXi5pupIqoYT0I/D1wetONSArlJuAYYEnTjXQq6o5pH8GgltS5w4FvNN1EFRH'
                                               'Hd3cmPVVPb7oRSSHtATwA3Nl0I52I+GT9EWC7ppuQFNZk4Cxgi6Yb6US0sH45adaHJOV4FX'
                                               'Bs0010IlpYnwZs03QTksKbDPwxMKvpRtoVacx6X+BiYJOmG5E0IewI3A7c0XQj7Yj0ZP1hY'
                                               'GrTTUiaUD4DbNp0E+2I8mS9H2lCe9R54ZJ60yzgaeDGphsZT5Qn688Tp1dJsZxJgJkhEQLw'
                                               'aOA1TTchacLai/RmY0/r9bCeAvwJAb7rSQrtdGD3ppsYS6+H9dHAG5tuQtKEtydwYtNNjKW'
                                               'X37DbBPhX4PjMOlcA14/8uJc/X0nVDAFzgQ+RN2liCXAQsKBEU/3k9aS9Z3M+FpK+Y0qa2D'
                                               'YFvkV+ZpxXd+MTwY3kf+E/UXvXkppyDLCUvMxYCexQd+OR/QH5QX0vaYWSpP4wCFxLfnZ8v'
                                               'e7Go5rCS8fv5HycW3fjkhr3amAVednxa9KmcRrHe8j/Yi/A/a6lfnUZ+Q97F+OEhDFtC9xM'
                                               '/hf6g3U3Lqln7AcMk5chTwKvrLvxSE4nP6jvwwN0pX73N+RnifsRbcRM4B7yv8Cn1t24pJ5'
                                               'zMLCcvCwZBg6su/EIPkh+UN8MzK67cUk96QLyM+Xy2rvucdOBR8n7og4BZ9TduKSetT/5ud'
                                               'IiLdDTiHPJ/4LeAmxWd+OSetrfkp8t38GxayAtXLmP/C/oyXU3LqnnbUf+qsbngbfV3Xgv+'
                                               'jT5QX39BlUlKfkL8jPmWmBG3Y2va3KTNwfmAO8tUOdG0pzIKMeUSarHGuDuAnV+F3gtcHWB'
                                               'WpU0PQ7zKeCTBeosB1YXqCNp4hmgzAEmN5H22H++QK2ONRnWuwDz8U1BSXG8Hfh/Tdy4yZN'
                                               'iPoZBLSmWz9DQcGtTY7z7ABeSToORpCi2Ap4iTRWuVVNP1h8FpjV0b0mqahA4iQYmZzQR1t'
                                               'OBeQ3cV5JK2B/4nbpv2kRY7wvs1MB9JamEmTRwOEETYb0FbmEqKba+GAZZTJoXLUlR1b6uo'
                                               '4mwng881sB9JamEZaTtmGvVRFivIB2IK0kR3QbcUPdNm5q6dx6wqKF7S1JVLwB/NfLfWjUV'
                                               '1gtJp5ivbOj+klTFBTS03LzJXeruA+4CXkFaFSRJveoZ4LPAOU010PSuewB7kzb2/j3SFoS'
                                               'S1CvuBS4DrgN+2GQjvRDWa21JOjXG/UIk9YIW8CQ9MnttoNVqNd2DJGkcTW6RKklqk2EtSQ'
                                               'EY1pIUgGEtSQEY1pIUgGEtSQEY1pIUgGEtSQEY1pIUgGEtSQEY1pIUgGEtSQEY1pIUgGEtS'
                                               'QEY1pIUgGEtSQEY1pIUgGEtSQEY1pIUgGEtSQEY1pIUgGEtSQEY1pIUgGEtSQEY1pIUgGEt'
                                               'SQEY1pIUgGEtSQEY1pIUwOSmG1B7BgYGmm5B+XYDDgDmjfx4N2ArYEtgM2Dzkdc9N/Lx1Mj'
                                               'Hr4AHgduBnwNLSjfWarVKl1RhA/4mxTAwMDAXmNrQ7ZcDa0Y+lgPPAP7BGd/ewJuA1wNHAL'
                                               'ML1b0L+E/gW8D3Sb8vWcyB3mdYBzEwMHArcGDTfazjKdIT3pOkJ7+HRz7uAu4EVjTVWMPmA'
                                               'O8CTgDm1nC/RcA/AV8BHqhaxBzofYZ1ED0Y1mNpAfcDPwW+B1xPCvKJahB4G3AWcFRDPbSA'
                                               'S4HzSMMlnV1sDvQ8wzqIYGE9mvuBfwH+z8iPJ4LJpKfovwD2aLiXtVrA14BzgCfavsgc6Hm'
                                               'GdRATIKzXdSPwP0ljrlH/AB4HfBHYq+lGNmI5cD7wBWBovBebA73PqXtqwhHAZaR/rp8ARJ'
                                               'rqsgtwDekbTa8GNaSZJZ8DbgL2b7gXFWBYq0n7A/9GmtGwT7OttOW9pDdP39x0Ix04hDTd7'
                                               '2PApIZ7UQbDWr3gt4BbSW/Q9aLNgW8C/5uX5kJHMgX4LHAtaV63AjKs1Ss2BS4ALhn5ca/Y'
                                               'nTSUcFLTjRTwO8DPgH2bbkSdM6zVa04hPQFOa7oR4FDgFiZWuO0G3AC8puE+1CHDWr3oaNK'
                                               'beE2t2IS06vC7wNYN9tAtM4HvkD5HBWFYq1cdBXyDZmaKHAVcBcxo4N51mQp8sukm1D7DWr'
                                               '3sBODPa77nIcAVNPtUX4dfk4acFIRhrV53HilA67ALE/+JGuB54K3AwqYbUfvcIrW/XEXaa'
                                               'rMTU0hv9r0MmEXaOW4X0rhnHSaTpsy9igK7y41hKmmhy/ZdvMdaq0h7ptxImrc9n7Q0fPnI'
                                               'r00mTRHcljT/fD/gdaQpjlMK3P8M0hunCsTl5kEUWm5+PHB5gXYAtiDtzXwgcCTpTcFSW4C'
                                               'O5n3AxV2s/3Xg3V2s3wKuJO3b8V1gZYUamwNvAf6U9M2rivNJC2R+szlzoOcZ1kH0YFivb5'
                                               'A0Hew04FTKj/kuIC3vfqFwXYCTSZtMdcMa4CLgf1F258EjSft+HNbBNVeQ/gwMr/8L5kDvc'
                                               '8xapQwDPwLeD+wEfJ40NlrKzqRQLW1H0l7Q3fAd0jfYD1F+i9gfk/ZYOY20t/h47gTeyShB'
                                               'rRgMa3XDEuCjwMHAbQXrnlmw1loXkIZ0SlpFGqr4XdJhDN3SIm05uz/p/YiNeYo0fPJsF3t'
                                               'RlxnW6qZ7gVeT3kwr4QjK7ht9LGlYoKRHgMOBv6a+7V8fJ23Z+t/Z8Ml5iHQwwsM19aIuMa'
                                               'zVbStJ08R+VajeWwrV2YS0H3VJd5LGkG8tXLcdLdIe4ccAy9b5+bOAHzbQjwozrFWHZZSba'
                                               'fGGQnXOJB1oW8qdpOXbjxesWcV1pK/RYtIQz1ebbUelOM9adfkRaR7z72fWeXWBXqYyyvS1'
                                               'DI+R9rheVLBmjp+ShowearoRleOTtep0YYEaW5J2jsvxfmC7/FaA9GbiccCjheqV8gDdXUS'
                                               'kmhnWqtP1wJMF6szLuHYycHaBHtY6G/hFwXrSqAxr1WmYdIRXrt0yrj0e2LVAD5BWIv5doV'
                                               'rSmAxr1e3mAjV2ybj2AwXuD7CaNNPCpX+qhWGtupWYwld1KftepD1MSriQtAGTVAvDWnUr8'
                                               'UZc1RWHpxe4N8AK4NxCtaS2GNaq27LxXzKuqk/WJxa4N6QtW5cWqiW1xbBW3Ursmlfl9POD'
                                               'KbMIZg3w5QJ1pI4Y1qpbiYVYVQL/mAL3Bbga99lQAwxr1a3EkVlVNu5/U4H7AlxSqI7UEcN'
                                               'adduhQI2nO3z9NNJOeLlWkDbwl2pnWKtuJbY4XdHh6w8HJhW479XAcwXqSB0zrFW3QwvUeK'
                                               'TD15fY/AnSikWpEYa16vbaAjU6PaH94AL3BPjPQnWkjhnWqtMrKLMvx50dvv6gAvdcQOffJ'
                                               'KRiDGvV6YwCNRbS2Qb/UykzTv7LAjWkygxr1WV74A8L1PlRh6/fq8A9Ae4oVEeqxLBWXf4S'
                                               '2KxAnW93+PpSB+x2OvQiFWVYqw6nACcXqDNMmj7XiR0L3BfgvkJ1pEoMa3XbUcDfF6r1H3R'
                                               '+0sxOhe69sFAdqRLDWt10HHAtZYY/oNqpLLML3HcNZY4jkyozrNUNLwO+RDrNvOp2put7AL'
                                               'iywnVV975e15OkIRipMSV2QJPWmgqcBnyKNPujpHOpFpgzC9zbvavVOMNauSaRlnOfCLwD2'
                                               'LIL9/g51Xe7m1bg/kMFakhZDGu1YzNgOrA1sC2wJzAXOAQ4gjTs0S3DwIeoPgxRordON46S'
                                               'ijOs+8tlTTdQwRcocyJ6Dp+s1TjfYFQvuwU4p+kmpF5gWKtXPQYcT2881Zaa0SJVZlirFz0'
                                               'FvJkyC1FKTLmrckCvVJRhrV6zGHgj5TZOWlagxiYFakhZDGv1kgeAI4FfFKy5vECNrQvUkL'
                                               'IY1uoVVwGHAfML1y3xZL0N/l1Rw/wDqKatAM4i7SOypAv1S9QcIAW21BjDWk36d2AecCHQ6'
                                               'tI9Su2Wt12hOlIlhrXq1gKuAQ4nLVFf0OX7PVGozpxCdaRKXMGouiwDvgFcANxf430fLlRn'
                                               'XqE6UiWGtbppCXA5aZn7d4BVDfRQ6kTyuYXqSJUY1iplCLgXuB34Melg27vp3lh0uxaQvkn'
                                               'kLmw5uEAvUmWGdX+5i7TopIplpNWAz478+Nek8eCFpOl2DwGrC/RY2jDp8z4ks8480vav3Z'
                                               'ixIo3LsO4v55CGJfrN7eSH9QBpO9hOD+yVinA2iPrBTwvVeV2hOlLHDGv1g58UqnN8oTpSx'
                                               'wxr9YM7KbPsfE/ggAJ1pI4Z1uoHa4DrC9U6qVAdqSOGtfrFdYXqvAe3TFUDDGv1i6soM+d7'
                                               'e+DtBepIHTGs1S8WUu6NxrML1ZHaZlirn/xLoTqvwpkhqplhrX5yCfB8oVrn46Iy1ciwVj9'
                                               '5mrSHdglzSYcmSLUwrNVvLihY67O4z7VqYlir3/yUcm80TiONg+fu6Nct04ArgVc03YjyGd'
                                               'bqR+cVrPUK4KKC9UqZRpqueOzIf3duth3lMqzVj66j3OZOAKcDnypYL9dWwLeBo0f+fzvgC'
                                               'mB6Yx0pm2GtfvWxwvU+2YWaVcwFbgKOXO/nDyIN2UyqvSMVYVirX30XuLZwzc+S3sBsakrf'
                                               'ycAtwF4b+fVjgS/U145KMqzVz/6M8udCnkX6RrBj4bpjmQn8A+nJecY4r/0z4MxuN6TyDGv'
                                               '1s/uAz3Wh7lGko8TOpLt/xwaAd5E+j9M7uO5vgDd2pSN1jWGtfnc+8Msu1J0JfIV0pNhJwJ'
                                               'SCtQeAN5PGpr8BzO7w+kmkxUHzCvakLjOs1e+GgHcCK7tUfz/gm6RT1s8HDqP6m3x7AR8F7'
                                               'gGuIe1RUtWMkRqdBr0aMtBqldg1Ut02MDBwK3BgZpnj6c8Dc9txKvBPNd1rKfBD0lDJfOAR'
                                               '0lL4Z0knxG9BCtOtgf1Jp9McAuzRhV5uAF7farVKj92rMMM6CMO6Fn8F/GnTTTTg661W6z1'
                                               'NN6GxOQwiveTDwLeabqJmQ8C/Nd2ExmdYSy9ZA7wD+F7TjdRkGHg35Y48UxcZ1tJvWklaPP'
                                               'L9hvvotmHStL9Lmm5E7TGspQ2tBI4Brm66kS55ATgR+OemG1H7DGtpdCuBt5IWkEwkS0gLY'
                                               'v5v042oM4a1tHGrgT8G3ku548CadAfwSuAHTTeizhnW0vi+Rgq525puJMPfkRbkPNR0I6rG'
                                               'sJbacxdwKPAJYj1lP0p6w/QDwHMN96IMhrXUviHgM6Q9NS5tuJfxDAF/SVruPlHfKO0rhrX'
                                               'UuYeBE0hLwC8DemkZcAv4V9Iy9Q8Dy5ptR6UY1lJ1vwTeBuwNfBl4qsFengcuJj1Jn0zaNl'
                                               'UTiGEt5XuAtKn/DsDbSYcA1PFE2yJtk/qhkXu/j7Qjnyag/w+NgjXnuXdnbQAAAABJRU5Er'
                                               'kJggg==')
        buf = buf.replace('resources//HS.png',
                          'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAWsAAAHoCAYAAACPYs4OAAAgAElEQVR4nOy9eZQkZ3nu+Y'
                          'ustfe9W63uVrf2pSW07wIhCQmDwIBYxG4wyJdruGZ8r+2Z8Xh8PGfmnDuMfT0eX19hMGYTCBAIBBI7CNC+L6i1qxe11C'
                          '31vlfXlpnzxxOhLJWqq+KLjFyi6vmdk6d6qcj8MjLj+d5414jJRwcwGzgaWA2cDJwR/1wERK1bmjEmR6rANmAN8FD883'
                          'FgLbAXKLduafkzWYSrE1gBHA8sRWK9FDgCWAUcByxo1eKMMQ1lB/AMsAHYCLyExPol4GngBWC4VYvLiyKLdbL2EnAi8A'
                          'fAVcBJSLxL8aMjfhT5vRpjDk0VWdFloBI/hoEngO8DP4v/XEGaUGnNMuujyALWAVwOnItcHMciy7q3lYsyxrQN/ciyfg'
                          'a4D7gt/llIOlq9gAx0ASuBy4CPA+8FTgGWAN0tXJcxpr3oBBYiQ+4MYAYyUIeAAxTMwi6iZX008D8DFyO/9KzWLscYUx'
                          'B2oIDk7cDnUCCyMBTJsp4DXAh8BPgAsBzoaemKjDFFYjqytI9E2jEE7AQGWrmotBRBrEvoBF8CfBa4EpjX0hUZY4rMNO'
                          'AEJNq7gO3Iv11t5aImoghi3YOE+hrg9Sgtzxhj6qEXOAyl9G5FaX9tnd7X7mLdCVwEfAx4M7qNMcaYPOhG7tRuJNgv0M'
                          'ZBx3YX6yOBvwDeCsxs8VqMMZOPLlQ8NwtVQe5q7XIOTTuL9ZHAR4H3Yx+1MaZx9KDMsgHgeWB3a5czNp2tXsAhmAu8E/'
                          'gTFFzMi8H4UUZpi0VMXTRmKlONHx3IfZFXbcVCpDd7gK/QhoLdjmLdjSoSL0W7XV7sAJ5FFU27qZWhG2OKQ1JWPhdVLB'
                          '9Lfn1/liLduR9VOg7m9Ly50I5ifTjq87G6zucpo5ScnUion0Y+qQdQYnwnFmtjikYZZW0sAs5ClYnHI8Gejyzkeq7r1U'
                          'h/XkQZIm1Du4l10pTpD1G3vCxUUbL7U8ANwN0oaHAAWdS7qe2YdoMYUyySXOhNSEx/hcrI5wHnA+9DOdRdZLu+VyH9uR'
                          'N18Gub7JB2EusSSqO5CN3aZDnRVXSCHwd+DtyIPtTxft8YUzwGUbrd1hH/9jSwD6X5rkZZHqE6EiH9uQjpyIu0iWC3kx'
                          'tgNrr9eAcS7dCNpAq8DPwA+FfgF8j9YYyZGuwHnkRd9pKUvJmEC/YwMh53AespSDl6MzkK+Boq+6xQi/qmeZTRDvvvwH'
                          'nNXrgxpu04D+nBVqQPIXpSQTr0NaRLbUG7WNYdwKmoSdNywnfCPuBW4BvAXUyycT7GmGC2IsFdiFoqh6T4RejOvgLciy'
                          'obW+4ybQexjlDb03chP1Foy9MqsAW5Pm5Ft0LGmKlNGWWCgQKPswk3Aqso73ojbVDZ2A5i3YnKyT+CqhZD17QDuAlZ1S'
                          '/nuzRjTIE5iER2MdKW0N5Cvag18yYUbGxpoLHUyhePmYaKYE5CQYFQ7gK+iYOJxpjXsgPpw10Zju1CunQy0qmW0mqxno'
                          'ZuUU4j+yCBdSin+kBeizLGTBoOIH1Yl/H4HqRP59NiwW61WK9CqXqrCXfgD6G0mjXodscYY8biINKJ9Ug3QqgifXoH2Q'
                          'v1cqHVPutTgT9CSeihG8dGdHvzUxRgbHm01hjTllSQYFeR4IZ08YxQhWQJZYasz3txaWmVZV1CjvuzUVpNlnW8DPwINW'
                          'dyqp4x5lCUkU78iGxJCCWkU2cj3WqJbraq3HwmcAWaUB46VKCKdrsNZLut6aIWyLQ1biYbERKngRF/z/t7nuQhdyDhau'
                          'Z1lKTfDRF27Sdu0w3I/5zoSFpmIr1ai1pZ7A04NhdaJda9wGXAOYQHFodR+8Ifoz4AaTkMeDtq8tJNm9T7G9Mg+lCXyT'
                          'yFpQu4AF23y2hdI7QS6g3yFHAz6a3lfUg3jkDvIST7rCc+5nngd0whsT4OvfH5GY49CHwf+arT7Kyd6MO5CvhjYAXutm'
                          'cmP2XgCWQY/QY1JMpKCV2r5wIfRHfFrU5lq6LKwjlIDzYy8cDbIaQbS4BTCBPr5Bycg/Rr6/i/Pjk4EvhbYDNh9frJ4w'
                          'XgyoDXOwb4PEpsD+0R4IcfRX4MAo8C/wEF1bL6WmejRICfobzlVr+v5FFG1/Xn0XWeliuplZCHPjYj/Toy4PVyoRXZIG'
                          '8CPoQapIRY9lV0u/MLtDsmX5qJOBP4NIoC26I2U4kOZEXORG6RDahfRijHIsG/gvB2EI0kQuuZjTI11qY4poQs6iXINR'
                          'rala8LVUJuRHcuTaPZUc1e1A3r5PjPIQyhhuBfQF+6ND7n6WhT8GR0M5U5D/gY2eaZdiKr9RSyF641mhnIGEtTTl5B+v'
                          'EFpCehCQq9SL/OI1zD6qKZYj0d+XtOIZt4dqD0mwdIV63YjZLZz6D1/jVjWkkvmi84k/BrfgYaodXO11Av8iOvIt3d+g'
                          'GkI8+SzbswE+nYOYT3G8lMM8V6OfAesk2BGaJWVp42p7o3fq2jae8vmjHNYD8SppBrLykImU57Z091o8SBlaS3/svUyt'
                          'BDretkmsx7kK41hWaK9XHI57Ui8HUrKF3mq8BvA46rolzTZJiBMVOZCtliNiWan0udhQ5kVYe8x98iXXmeMI0oIR27Au'
                          'laU2iGWHeg9JrTUG5mlnTBF4FbkFM/LQMoCf552mykvDEtYAayIENEt4pcBvtp7+B8BaXSbSbsWt+IdCVLWmMn0rPTkL'
                          '41PFmjGWI9DbgcuJBsLVD3o4DAS4HHDaLo8LMoEm7MVGUIie4Bwi3kfSgLq50Nnj40d3Et4S6Nl5C+ZBla0oV07XKa4G'
                          'pthljPQpWDZxEeTR5AEdsfALszvPYe4BGyt0c0ZjLwKGp6tpNwsR5Gd6dp0uJaxVrgYaQRoe9vN9KXOwkfjNuDdO3tNC'
                          'GlsdGme9K8+xMoiTz0VmoX8EVUoTRMNr/ZMCoIOAzlY7a606AxzWIAuQe+hIa/7iVb/KaKrqEkK6SpKWvjMIjunG8Gfk'
                          'W2EvAIuUOmo54hMwKPnxY/x52o+2fD4mONLjc/DngbEsos8892U78bYwsa+bUZFeOcjaLH7R4wMaYeBlGhyI2o8nDn+L'
                          '8+LjuAG1D2xOUoC2IhrbuGIvT+7kd3DLei6zwLZaQvzyK9WUh4xsxhSOf2ovFfDaHRYn0Omq84E32waU9CUq14K/X3jx'
                          '0CngO2o8yQDcDhaAcsQpTbmLQk19cwEp5bkNVZb9OhMroO16My7QMosAbNvYYiatftZuDXqO1pFhfpaNYjvZlJmHFZjY'
                          '95K9KZwol1hFwgq1E+4nTCdqt+4A7gOuprQDOSvdQaQPUi69pibSYTETWrs2/EI08eB/5vdA31ouu8WamxiVgPIo04SH'
                          '7v70WkN/ORlZw2YBghfTsW6V034Vk3LSNC/q1L0M6X+JpDHruAv6P1Y8eMMVOHEtKdXYRr1jDSu0uQ/uWe6tgIMSyhYO'
                          'LVqC9HFl/1VuBpXMxijGkeFaQ7Wwm3jCOkd1cj/ctdWxsh1hHqQ3AZ8v2EvsaLwPXA3TmvyxhjJuJupD+h7tcS0rvLkP'
                          '61vWWdLPgc1JMjS4rPWhQUeZ72rpoyxkwuIqQ7N5Mtr7wX6d45ZDNUxyVvsZ6BKnrOZ+KpDWORNPfeTs0XZIwxzSDRnO'
                          '3UhqOEMoz070LCc7bHJe8CkVnANcjJPp2wzaAfJZZ/G1UjhZaNGmNMHgwj7VqALOTQrLm5qCDptyhjpe3oQbvJo8hRHx'
                          'pN3Qh8Bgm+3R/GmFaRTKD5DNKlUC2rIB28kBwHNuTlBulAkdBL0W6URWyTUfH7sPvDGNM6qkiH1pPtDj9COngp0sVcPB'
                          'h5iXU3mnV4FboFCGUPKoJp52YxxpipxVqkS3syHDsX6eGZSB/bhnnAP6NdKNQFMoRKRi+lzd6UMWZK04106UfUqhJDXC'
                          'FDSBfn5bGYei3rZOzPqajUMnRSQ7KGp4CHaO+eucaYqcUg0qWnCNfKCOnhaqSPM6gzFpeHG+RI4N3ACRmOraLmJ2uov9'
                          'mMMcbkzV6kT8+RLZZ2AtLHI+tdSB6O7/OAT6PBkVmqFa9DSej1tHA0xphGkAQbO1DBy5zA46ejtqv3o1L2zNRjWUdoBt'
                          'npaAR8FuHfiHrt1tsG1RhjGsV6pFMhM2ATOpA+no70MrMrpB6xnoWc75dlfJ4yira+iFP1jDHtSxXp1FqkW6GUkE5eSh'
                          '3jv+pxgyxG47ouRY700GrFh3C1ojGmGJRRdsgy5NYIqWqsxMf0A3eRMT6XdfhAB7ASOAVNSQhlD/A94Bdo6oQxxrQzB5'
                          'BeLUHBwpAmdR1IJ09BurmZDBZ6FvdFJ5qK8AfAigzHg2a6PYT6xhpjTBHYinRrR8bjVyDdPJYMhnIWse4BLkLj12cHHp'
                          'tEVu8nm7PeGGNayUakX1naYsxGunkRGXqGZBHrWWhY5imEVxxGwG3A14FNGV7bGGNaySakX7cRntnRjXTzNDIEGkPFug'
                          'fVup9BbThnCFXgAbQz9Qcea4wxraYf6dcDZBv9FSH9PJNA6zpUrI8G3oLyBkMpozH2G8iW/mKMMe1AGenYC2TTslVIR4'
                          '8OOSgkdS9C1YqfCH2RmI2oWvGnwBacW22MKSZlNFSgioQ3tNPoLFTZ+DDwbNqD0lrWEcoTPBf1Z83CM8B38dRyY0yxSa'
                          'agfxfpWhaOQnq6kJTu5LRiPRt4A/KzZAlKJnPNktmKxhhTZOrVtBLS0zeQMqsurRvkcODjwJuR+R4SWBxA5v63UI6iqx'
                          'WNMZOBMgoSLie8qrGEqsAHUbBy90QHpH3yFSiCOZvwDJCdSKh/DvQFHmuMMe1KH9K1BUiwlwYcW0J6egbS1wmb2U3k0o'
                          'jiRVyAyiyzdIwaRv4dt0A1xkw2diJ9G85wbIR09QKks+Pq60RukA7gSuADZCuR3Inq6W9Cvh1jjJlMJP7qI5CFPC3w+B'
                          '7kWt4GPME4/u+JLOte4CzUizW0PLIK3I6qfZyqZ4yZjFSRvn0d6V2ozvUgfT2LCZpDjSfWPcifkrWzXgQ8CTyI6uiNMW'
                          'Yysg/p3JNkcxUnHfnOYByjeDyxPgqNUj+e8N1iGDXrfhLYn+F4Y4wpClWkc08i3Qv1X1eRzl7FOHUs4/msz0HpesdM8H'
                          'ujqQDPAzcAP0G+GIu1MWayM4jiesvQrMa0VnaEpp/3Mk5V41iWdQk5vE9FjbJDg4pVVDd/AxqD42pFY8xkp4L07gakf6'
                          'EGaifS21OR/r5Gm8cS69loVNeFZPdVb0C3BAMZjjfGmCIygHRvA9l91xci/X1NVeNY7o0FwKeANxJeBDOAHO3fQea83R'
                          '/GmKlEGYnuMmAR4VWNc+KfdzFBYkYEvB5Yg8z6auBjK/BZJPiZR64bY0xBiZD+fRbpYaiGVpD+vp5RGjrSDRKhdn+XoV'
                          '4gWcR2J7UZZbaqjTFTjSq1GbNZqrYjpL+XIT1+RYdHinUVOD/+pSwFMNuAe1CCuDHGTGW2ID3Mkg3Xg3T4gpHHjvRZd6'
                          'BUvSsInw/WjxqafJ7sdfLGGDNZ6ANeQr0/jga6Ao7tQr7rHcCviDPqEsu6G6WNHEOGQY6o7enDwJ1ogoIxxkxlDiI9fJ'
                          'hsbaFnogKZVcRCn4j1QuASFL3MUq24FRXCGGOMqfE80scsVY0LgYuRLr/iBjkDpeu9jrDhAtV4MdcDPwL2BC7IGGMmM/'
                          'uQZbwKzWoMrWqci7rxPQ+yrj8C7CI8zWQIuAVYXfdbMsaYyclq4Gakl6Eauwvpc6mE6tFnEOYATxgAXkaOdGOMMa9lM9'
                          'LJwQzHdhH3DSmhaGXqCbsjGECpKT/D7g9jjDkUe4HfoNzrUMGOkD4vSZqHZBHrrcCNwC9xAYwxxhyKCPgdmiRzNGGzGh'
                          'OxXtmJujwdRVgbVFBqynpsVRtjzHiUgU3U+vuH0IH0+dROlAFyNOFivRc5v40xxhyaxPPwMuHGbQfS522Jz3o+E89jHM'
                          'kAmohwIPCFjTFmqtKHdDOkdXQJ6fOSEnASMI/0PusKKoN8IX5xY4wxE9OHdHMH6YeyREifTyqhEeohjZvKKFVvPRZrY4'
                          'xJSx/SzZeQjqalBziiRLivegD1W70V+WCMMcZMzMtIN9cQPkWrI3S+IshZXkbNnxbE/xbi7zbGmKlG4vboRvoZnO6cRa'
                          'x7gdOADwHPoSBjd4bnMcaYqcIgqkQ8Bulnb+gTRIQrfBUJ9FbUWLufcFeKMcZMJcpIoBcBi5FwBxUiZhHrkS+eyZw3xp'
                          'gpSIQM20zGbT1ibYwxpkk4MGiMMQXAYm2MMQXAYm2MMQXAYm2MMQXAYm2MMQXAYm2MMQXAYm2MMQXAYm2MMQXAYm2MMQ'
                          'XAYm2MMQUgS9e9Chr6uAcYync5xhgzqekC5gAzCTSWs4h1P/Br4AZgIxLvoO5RxhgzxagicT4CeB/wZmB6yBNkEesh4F'
                          'kk2NsyHG+MMVOVZ4HTgUtDD8zisy4hE34+tqiNMSYtEdLNYBcIWQ4Y8aIWamOMCSOzdjobxBhjCoDF2hhjCoDF2hhjCo'
                          'DF2hhjCoDF2hhjCoDF2hhjCoDF2hhjCoDF2hhjCkCWcnNjjGk0EdKnEtDBqwtJItSTqBw/KvFjUmOxNsa0I4uAY4ElwM'
                          'r47x2oIVIHsAt4BngR2AS80JplNg+LtTGmHZiGhHkmMAs4GTgHOAY4EYn1SLftPuAR4AngqfjP24GD8c89zVp4s7BYG2'
                          'NazSzgQuCDwHIk3HOBhfH/9RzimPOA44G9wE6gD9gC/Az4afznSYPF2hjTKuagdqEnAxcD7wk8vgtYHD9GsgwJ/T3I6t'
                          '5e3zLbA4u1MabZRMBs4ArgPyPruCun564CZyP3yRrgm8DNyC0ynNNrtASLtTGm2SwGPgC8Hzg35+eOkNvksPgxB20G1w'
                          'OP5fxaTaXIYt2BPpQS2k0BBmnNXMhOoDteU5JSNBT/bDY98TqSYMwwMEDtHDWTbmQxJWlXQ+gzasVaenl1CtgwGlFnmk'
                          'eEfM1vAf4cjbhqNGcDr0Pfu03Iwm7FdVk3RRPrCF1wHeg251R0OzWAPoCngCeBAzQ+7zJZyzTgKGA1MA9Fo3egtKJ1SK'
                          'CatZb56JwsRhfFEAqyPA5sbuJaOlGAaDWwAs2aqwDr0eezDYlls87LQuBMdH6moY3seeBh9FklubqmsSwAPg78MXB4E1'
                          '+3C/gwsrI/j0ZrFe7zLpJYR0gMjwOOBM4CTqMm1sNIIO8B7gKeo7E+qgVIGI8HTgBOQgLVjwTgaeAh4PcovaiRzEFBmv'
                          'OQKI0U621IIB+L17OWxt59zI/XkASOlqF0rESs1yCRfAxtII20cmYjq+o84AL0/Rkp1vfG63gO5ekONHAtU53pyKL+JL'
                          'qGm0kJGVSfRHnZ30ZWdivu8OqiGvjYC1yLBKqZo726gDehqerr0O1MHxLHPmTR7o/X9/do527U+krA24D74tfeE79+f/'
                          'zzQLyOTcC/kHHmWkq60PDN21HUe/+otexHOalbgX9A4tmo89IJvBN4EJ2XsdayA7gT+FMkpo1cy+vj19qBPpNkLcl3Zn'
                          'u81v+V5lp6U40ScAkypEL1Js/HQfR9+DhyizWbCOnmtUgfQtdfCLEuAUuB/xPYnWKN64D/C1jVgLX0Iov6i0gAJlrLC8'
                          'D/TmPO1wwUUb8eWa4TreVJ4FMo8JI304G3Az9PsZYy8GPgMnQH0AiuBL5HzUc+3uN3wBvwXNFG0IPuPv+RdNduox8HUI'
                          'bIsTS/N1JdYl2ERk6J++M8lDg/J8UxRwLXoFvfvFkIvAvlhY6VrD+a5cBnUaAjTzFIJiV/ELgq5XMfA1yNXEh5C9NCFO'
                          'G/PMVzR8AZwB+i6rQ83XERcnV8BG0eaVLCjkbflcNxc7O8mYfuti5HxkUWqmjTTe6K6glST0MuukuQ0VKYDboIX8wSih'
                          'q/G13gaemMj1uQ83oWAecj4etIecws5M/OkwhtXKtIt2mAzskJSJzSrj3NOkCuniWk+/JH6HN5J9r0unNaC+jO5zjkYk'
                          'n7/V6ErPzzaM3t8WRmDjKyTiL7phwBG1GM4T4Ub8gaIIyQLvwRShvMK7+74RQhwBihgNnr0QWYlgr6osxBPsu8mEe4BR'
                          'Yhy3M68pXmFYnuJd2dxkjmIXHqJN8A7Hwk2GnpQncdeW4coPe1hLCLsBvd+TwC/Bp9RnmsYy7aqEvUXEPtRpIxU0axl9'
                          '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')
        buf = buf.replace('resources//IP.png',
                          'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAWsAAAHoCAYAAACPYs4OAAAgAElEQVR4nOy9d5Qc53nm++'
                          'ueiJwBIhFgABMIMYiZlChG2aJoSVSgskVL9GpXWvt61/bd6+vr43vunrNX116fXdtLWTlTEiWKlEhliaKYcwRJkCACQQ'
                          'Ikch5M6u77x1PFHgwHM/VVV4eaeX7n9BmEqe6vq7ue7603Fhh/tAHTgeOAlcCpwJnRz3lAoXlLM8ZkSAXYDqwGHot+Pg'
                          'OsA/YBpeYtLXvGi3C1A0uBE4GFSKwXAkcDy4ETgDnNWpwxpq7sBF4ANgKbgFeRWL8KPA+8DAw2a3FZkWexjtdeBE4G/g'
                          'C4BjgFiXcxerRFjzy/V2PMkakgK7oElKPHIPAs8CPgF9Gfy0gTys1ZZm3kWcDagCuAc5GLYwWyrLubuShjTMvQiyzrF4'
                          'CHgLuin7mkrdkLSEEHsAy4DLgOeD+wClgAdDZxXcaY1qIdmIsMuTOBKchAHQAOkjMLO4+W9XHA/w5cjPzS05q7HGNMTt'
                          'iJApJ3A59DgcjckCfLegZwIfAx4EPAEqCrqSsyxuSJycjSPgZpxwCwC+hr5qKSkgexLqITfAnw58BVwKymrsgYk2cmAS'
                          'ch0d4N7ED+7UozFzUWeRDrLiTU1wNvQWl5xhhTC93AUSildxtK+2vp9L5WF+t24CLgE8Db0W2MMcZkQSdyp3YiwX6ZFg'
                          '46trpYHwP8JfAOYGqT12KMGX90oOK5aagKcndzl3NkWlmsjwE+DnwQ+6iNMfWjC2WW9QEvAXuau5yRaW/2Ao7ATODdwJ'
                          '+i4GJW9EePEkpbzGPqojETmUr0aEPui6xqK+YivdkLfI0WFOxWFOtOVJF4KdrtsmInsBZVNO2hWoZujMkPcVn5TFSxvI'
                          'Ls+v4sRLrzMKp07M/oeTOhFcV6EerzsbLG5ymhlJxdSKifRz6pR1BifDsWa2PyRgllbcwDzkKViSciwZ6NLORaruuVSH'
                          '9eQRkiLUOriXXclOmPULe8NFRQsvsa4CbgfhQ0OIgs6j1Ud0y7QYzJF3Eu9GYkpr9BZeSzgPOBD6Ac6g7SXd/Lkf7ciz'
                          'r4tUx2SCuJdRGl0VyEbm3SnOgKOsHPAL8EbkYf6mi/b4zJH/0o3W7bkH97HtiP0nxXoiyPUB0pIP25COnIK7SIYLeSG2'
                          'A6uv14FxLt0I2kArwG3AL8G/Ar5P4wxkwMDgDPoS57cUreVMIFexAZj7uBDeSkHL2RHAt8A5V9lqlGfZM8SmiH/QpwXq'
                          'MXboxpOc5DerAN6UOInpSRDn0D6VJL0CqWdRtwGmrStITwnbAHuAP4NnAf42ycjzEmmG1IcOeilsohKX4FdGdfBh5ElY'
                          '1Nd5m2glgXUNvT9yA/UWjL0wqwFbk+7kC3QsaYiU0JZYKBAo/TCTcCKyjvehMtUNnYCmLdjsrJP4aqFkPXtBO4FVnVr2'
                          'W7NGNMjjmERHY+0pbQ3kLdqDXzZhRsbGqgsdjMF4+YhIpgTkFBgVDuA76Dg4nGmDeyE+nDfSmO7UC6dCrSqabSbLGehG'
                          '5RTif9IIH1KKf6YFaLMsaMGw4ifVif8vgupE/n02TBbrZYL0epeisJd+APoLSa1eh2xxhjRuIQ0okNSDdCqCB9ehfpC/'
                          'Uyodk+69OAP0ZJ6KEbxyZ0e/NzFGBserTWGNOSlJFgV5DghnTxLKAKySLKDNmQ9eKS0izLuogc92ejtJo063gN+Alqzu'
                          'RUPWPMkSghnfgJ6ZIQikinzka61RTdbFa5+VTgSjShPHSoQAXtdhtJd1vTQTWQaWvcjDcKSJz6hvw96+95nIfchoSrkd'
                          'dRnH43QNi1H7tNNyL/c6wjSZmK9GodamWxL+DYTGiWWHcDlwHnEB5YHETtC3+K+gAk5SjgatTkpZMWqfc3pk70oC6TWQ'
                          'pLB3ABum4X07xGaEXUG2QNcBvJreX9SDeORu8hJPusKzrmJeD3TCCxPgG98dkpjj0E/Aj5qpPsrO3ow7kG+BNgKe62Z8'
                          'Y/JeBZZBj9DjUkSksRXavnAh9Gd8XNTmWroMrCGUgPNjH2wNsBpBsLgFWEiXV8Ds5B+rVt9F8fHxwD/B2whbB6/fjxMn'
                          'BVwOsdD3weJbaH9gjww488P/qBJ4F/h4JqaX2t01EiwC9Q3nKz31f8KKHr+vPoOk/KVVRLyEMfW5B+HRPwepnQjGyQy4'
                          'GPoAYpIZZ9Bd3u/ArtjvGXZizeDHwGRYFtUZuJRBuyIqcit8hG1C8jlBVI8K8kvB1EPSmg9UxHmRrrEhxTRBb1AuQaDe'
                          '3K14EqITehO5eG0eioZjfqhnVq9OcQBlBD8C+gL10Sn/NktCl4MrqZyJwHfIJ080zbkdW6ivSFa/VmCjLGkpSTl5F+fA'
                          'HpSWiCQjfSr/MI17CaaKRYT0b+nlWkE882lH7zCMmqFTtRMvuZNN+/Zkwz6UbzBacSfs1PQSO0Wvka6kZ+5OUku1s/iH'
                          'RkLem8C1ORjp1DeL+R1DRSrJcA7yPdFJgBqmXlSXOqu6PXOo7W/qIZ0wgOIGEKufbigpDJtHb2VCdKHFhGcuu/RLUMPd'
                          'S6jqfJvA/pWkNopFifgHxeSwNft4zSZb4O3BlwXAXlmsbDDIyZyJRJF7Mp0vhc6jS0Ias65D3eiXTlJcI0ooh07Eqkaw'
                          '2hEWLdhtJrTke5mWnSBV8BbkdO/aT0oST4l2ixkfLGNIEpyIIMEd0KchkcoLWD82WUSreFsGt9E9KVNGmN7UjPTkf6Vv'
                          'dkjUaI9STgCuBC0rVAPYACAq8GHtePosNrUSTcmInKABLdg4RbyPtRFlYrGzw9aO7iOsJdGq8ifUkztKQD6doVNMDV2g'
                          'ixnoYqB88iPJrchyK2twB7Urz2XuAJ0rdHNGY88CRqeraLcLEeRHenSdLimsU64HGkEaHvbw/Sl3sJH4zbhXTtahqQ0l'
                          'hv0z1u3v1JlEQeeiu1G/giqlAaJJ3fbBAVBByF8jGb3WnQmEbRh9wDX0bDX/eRLn5TQddQnBXS0JS1UehHd863Ab8hXQ'
                          'l4AblDJqOeIVMCj58UPce9qPtn3eJj9S43PwF4JxLKNPPP9lC7G2MrGvm1BRXjnI2ix60eMDGmFvpRocjNqPJw1+i/Pi'
                          'o7gZtQ9sQVKAtiLs27hgro/T2M7hjuQNd5GkpIX9YivZlLeMbMUUjn9qHxX3Wh3mJ9DpqvOBV9sElPQlyteAe1948dAF'
                          '4EdqDMkI3AIrQD5iHKbUxS4utrEAnP7cjqrLXpUAldhxtQmfZBFFiDxl5DBarX7Rbgt6jtaRoX6XA2IL2ZSphxWYmOeQ'
                          'fSmdyJdQG5QFaifMTJhO1WvcA9wLeorQHNUPZRbQDVjaxri7UZTxSoWp09Qx5Z8gzw/6JrqBtd541KjY3Fuh9pxCGye3'
                          '+vIL2ZjazkpAHDAtK3FUjvOgnPumkaBeTfugTtfLGvOeSxG/h7mj92zBgzcSgi3dlNuGYNIr27BOlf5qmO9RDDIgomXo'
                          'v6cqTxVW8DnsfFLMaYxlFGurONcMu4gPTuWqR/mWtrPcS6gPoQXIZ8P6Gv8QpwI3B/xusyxpixuB/pT6j7tYj07jKkfy'
                          '1vWccLPgf15EiT4rMOBUVeorWrpowx44sC0p3bSJdX3o107xzSGaqjkrVYT0EVPecz9tSGkYibe++g6gsyxphGEGvODq'
                          'rDUUIZRPp3IeE526OSdYHINOB65GSfTNhm0IsSy7+HqpFCy0aNMSYLBpF2zUEWcmjW3ExUkHQnylhpObrQbvIkctSHRl'
                          'M3AZ9Fgm/3hzGmWcQTaD6LdClUy8pIBy8kw4ENWblB2lAk9FK0G6UR23hU/H7s/jDGNI8K0qENpLvDLyAdvBTpYiYejK'
                          'zEuhPNOrwG3QKEshcVwbRysxhjzMRiHdKlvSmOnYn08M1IH1uGWcA/o10o1AUygEpGL6XF3pQxZkLTiXTpJ1SrEkNcIQ'
                          'NIF2dlsZhaLet47M9pqNQydFJDvIY1wGO0ds9cY8zEoh/p0hrCtbKA9HAl0scp1BiLy8INcgzwXuCkFMdWUPOT1dTebM'
                          'YYY7JmH9KnF0kXSzsJ6eMxtS4kC8f3ecBn0ODINNWK30JJ6LW0cDTGmHoQBxvbUMHLjMDjJ6O2qw+jUvbU1GJZF9AMsj'
                          'PQCPg0wr8J9dqttQ2qMcbUiw1Ip0JmwMa0IX08A+llaldILWI9DTnfL0v5PCUUbX0Fp+oZY1qXCtKpdUi3QikinbyUGs'
                          'Z/1eIGmY/GdV2KHOmh1YqP4WpFY0w+KKHskMXIrRFS1ViOjukF7iNlfC7t8IE2YBmwCk1JCGUv8EPgV2jqhDHGtDIHkV'
                          '4tQMHCkCZ1bUgnVyHd3EIKCz2N+6IdTUX4A2BpiuNBM90eQ31jjTEmD2xDurUz5fFLkW6uIIWhnEasu4CL0Pj16YHHxp'
                          'HVh0nnrDfGmGayCelXmrYY05FuXkSKniFpxHoaGpa5ivCKwwJwF/BNYHOK1zbGmGayGenXXYRndnQi3TydFIHGULHuQr'
                          'XuZ1IdzhlCBXgE7Uy9gccaY0yz6UX69QjpRn8VkH6+mUDrOlSsjwP+EOUNhlJCY+w3ki79xRhjWoES0rGXSadly5GOHh'
                          'dyUEjqXgFVK34y9EUiNqFqxZ8DW3FutTEmn5TQUIEKEt7QTqPTUGXj48DapAcltawLKE/wXNSfNQ0vAD/AU8uNMfkmno'
                          'L+A6RraTgW6elcErqTk4r1dOCtyM+SJigZzzWLZysaY0yeqVXTikhP30rCrLqkbpBFwHXA25H5HhJY7EPm/ndRjqKrFY'
                          '0x44ESChIuIbyqsYiqwPtRsHLPWAckffKlKII5nfAMkF1IqH8J9AQea4wxrUoP0rU5SLAXBhxbRHp6JtLXMZvZjeXSKE'
                          'SLuACVWabpGDWI/DtugWqMGW/sQvo2mOLYAtLVC5DOjqqvY7lB2oCrgA+RrkRyF6qnvxX5dowxZjwR+6uPRhbypMDju5'
                          'BreTvwLKP4v8eyrLuBs1Av1tDyyApwN6r2caqeMWY8UkH69k2kd6E614X09SzGaA41mlh3IX9K2s56BeA54FFUR2+MMe'
                          'OR/UjnniOdqzjuyHcmoxjFo4n1sWiU+omE7xaDqFn3c8CBFMcbY0xeqCCdew7pXqj/uoJ09hpGqWMZzWd9DkrXO36M3x'
                          'tOGXgJuAn4GfLFWKyNMeOdfhTXW4xmNSa1sgto+nk3o1Q1jmRZF5HD+zTUKDs0qFhBdfM3oTE4rlY0xox3ykjvbkL6F2'
                          'qgtiO9PQ3p7xu0eSSxno5GdV1Iel/1RnRL0JfieGOMySN9SPc2kt53fSHS3zdUNY7k3pgDfBp4G+FFMH3I0f59ZM7b/W'
                          'GMmUiUkOguBuYRXtU4I/p5H2MkZhSAtwCrkVlfCXxsA/4cCX7qkevGGJNTCkj//hzpYaiGlpH+voVhGjrUDVJA7f4uQ7'
                          '1A0ojtLqozymxVG2MmGhWqM2bTVG0XkP5ehvT4dR0eKtYV4Pzol9IUwGwHHkAJ4sYYM5HZivQwTTZcF9LhC4YeO9Rn3Y'
                          'ZS9a4kfD5YL2po8nnS18kbY8x4oQd4FfX+OA7oCDi2A/mudwK/Icqoiy3rTpQ2cjwpBjmitqePA/eiCQrGGDOROYT08H'
                          'HStYWeigpklhMJfSzWc4FLUPQyTbXiNlQIY4wxpspLSB/TVDXOBS5Guvy6G+RMlK73JsKGC1SixdwI/ATYG7ggY4wZz+'
                          'xHlvFyNKsxtKpxJurG9xLIuv4YsJvwNJMB4HZgZc1vyRhjxicrgduQXoZq7G6kz8UiqkefQpgDPKYPeA050o0xxryRLU'
                          'gn+1Mc20HUN6SIopWJJ+wOoQ+lpvwCuz+MMeZI7AN+h3KvQwW7gPR5Qdw8JI1YbwNuBn6NC2CMMeZIFIDfo0kyxxE2qz'
                          'EW62XtqMvTsYS1QQWlpmzAVrUxxoxGCdhMtb9/CG1In09rRxkgxxEu1vuQ89sYY8yRiT0PrxFu3LYhfd4e+6xnM/Y8xq'
                          'H0oYkIBwNf2BhjJio9SDdDWkcXkT4vKAKnALNI7rMuozLIl6MXN8YYMzY9SDd3knwoSwHp8ylFNEI9pHFTCaXqbcBibY'
                          'wxSelBuvkq0tGkdAFHFwn3Vfehfqt3IB+MMcaYsXkN6eZqwqdotYXOVwQ5y0uo+dOc6N9C/N3GGDPRiN0enUg/g9Od04'
                          'h1N3A68BHgRRRk7EzxPMYYM1HoR5WIxyP97A59ggLhCl9BAr0NNdbuJdyVYowxE4kSEuh5wHwk3EGFiGnEeuiLpzLnjT'
                          'FmAlJAhm0q47YWsTbGGNMgHBg0xpgcYLE2xpgcYLE2xpgcYLE2xpgcYLE2xpgcYLE2xpgcYLE2xpgcYLE2xpgcYLE2xp'
                          'gcYLE2xpgckKbrXhkNfdwLDGS7HGOMGdd0ADOAqQQay2nEuhf4LXATsAmJd1D3KGOMmWBUkDgfDXwAeDswOeQJ0oj1AL'
                          'AWCfb2FMcbY8xEZS1wBnBp6IFpfNZFZMLPxha1McYkpYB0M9gFQpoDhryohdoYY8JIrZ3OBjHGmBxgsTbGmBxgsTbGmB'
                          'xgsTbGmBxgsTbGmBxgsTbGmBxgsTbGmBxgsTbGmByQptzcGGPqTQHpUxFo4/BCkgLqSVSKHuXoMa6xWBtjWpF5wApgAb'
                          'As+nsbaojUBuwGXgBeATYDLzdnmY3DYm2MaQUmIWGeCkwDTgXOAY4HTkZiPdRtux94AngWWBP9eQdwKPq5t1ELbxQWa2'
                          'NMs5kGXAh8GFiChHsmMDf6v64jHHMecCKwD9gF9ABbgV8AP4/+PG6wWBtjmsUM1C70VOBi4H2Bx3cA86PHUBYjoX8AWd'
                          '07altma2CxNsY0mgIwHbgS+E/IOu7I6LkrwNnIfbIa+A5wG3KLDGb0Gk3BYm2MaTTzgQ8BHwTOzfi5C8htclT0mIE2gx'
                          'uBpzN+rYaSZ7FuQx9KEe2mAP00Zy5kO9AZrSlOKRqIfjaarmgdcTBmEOijeo4aSSeymOK0qwH0GTVjLd0cngI2iEbUmc'
                          'ZRQL7mPwT+Ao24qjdnA29C37vNyMJuxnVZM3kT6wK64NrQbc5p6HaqD30Aa4DngIPUP+8yXssk4FhgJTALRaN3orSi9U'
                          'igGrWW2eiczEcXxQAKsjwDbGngWtpRgGglsBTNmisDG9Dnsx2JZaPOy1zgzej8TEIb2UvA4+izinN1TX2ZA1wH/AmwqI'
                          'Gv2wF8FFnZn0ejtXL3eedJrAtIDE8AjgHOAk6nKtaDSCAfAO4DXqS+Pqo5SBhPBE4CTkEC1YsE4HngMeAplF5UT2agIM'
                          '15SJSGivV2JJBPR+tZR33vPmZHa4gDR4tROlYs1quRSD6NNpB6WjnTkVV1HnAB+v4MFesHo3W8iPJ0++q4lonOZGRRfw'
                          'pdw42kiAyqT6G87O8hK7sZd3g1UQl87ANuQALVyNFeHcDlaKr6enQ704PEsQdZtAei9f0D2rnrtb4i8E7goei190av3x'
                          'v9PBitYzPwr6ScuZaQDjR8824U9T4wbC0HUE7qNuAfkXjW67y0A+8GHkXnZaS17ATuBf4DEtN6ruUt0WvtRJ9JvJb4O7'
                          'MjWuv/QWMtvYlGEbgEGVKhepPl4xD6PlyH3GKNpoB08wakD6Hrz4VYF4GFwP8D7EmwxvXAfwWW12Et3cii/iISgLHW8j'
                          'Lwf1Gf8zUFRdRvRJbrWGt5Dvg0CrxkzWTgauCXCdZSAn4KXIbuAOrBVcAPqfrIR3v8HngrnitaD7rQ3ec/kezarffjIM'
                          'oQWUHjeyPVJNZ5aOQUuz/OQ4nzMxIccwxwPbr1zZq5wHtQXuhIyfrDWQL8OQp0ZCkG8aTkDwPXJHzu44FrkQspa2Gaiy'
                          'L8VyR47gJwJvBHqDotS3dcAbk6PoY2jyQpYceh78oi3Nwsa2ahu60rkHGRhgradOO7olqC1JOQi+4SZLTkZoPOwxeziK'
                          'LG70UXeFLao+PmZLyeecD5SPjaEh4zDfmzs6SANq7lJNs0QOfkJCROSdeeZB0gV88Ckn35C+hzeTfa9DozWgvozucE5G'
                          'JJ+v2eh6z882jO7fF4ZgYysk4h/aZcADahGMNDKN6QNkBYQLrwxyhtMKv87rqThwBjAQXM3oIuwKSU0RdlBvJZZsUswi'
                          '2wArI8JyNfaVaR6G6S3WkMZRYSp3ayDcDORoKdlA5015HlxgF6XwsIuwg70Z3PE8Bv0WeUxTpmoo26SNU11GrEGTMlFH'
                          'vZQzbfzwJ6v8dEj1DDsES1SdNLKFC/mapL9DjU4Ol4lHEUomWTUd+RM5Dbrj9wbU0hD2INWmc3YbcsFeqTHlYg/IsXV2'
                          'zNRRkQWX05yoQLbgmdm6zuqipI7GYSbqUUyT7vukK6HPfpSOSz2DjakJi8KfrZjTJNWvGWu4JcA4dQ1tIjSBRrpYjcDC'
                          'sJNyhAAn0z8CMUg+ql+pnGdQRzgY+gVMCQnO04vXQOeu9ZbM51Jy9iDenE5fUoaoakveDakZhl7XoKfX/1OCdF9P7SnJ'
                          't65LumeY8FtOnUIqhHId/3GeiuYRG6K+ygtUudO9CmuQWl172Ksot+R/rvSgEFFs9Dd11JqKBNYy3wE+DHyKI+UqrpHu'
                          'Db6Nx+AlnZIcxCn9l+cmBd50msWyWJPe2XN26Q3oq3wrVSYXy8t1rew3yUzvlpJBodVAu4Wp3YZXESsl4HkcjuQ7n5aa'
                          '69AsqzPxO5HZJQRlb0t5BF/Qpj1wRsAL6GzvOfIJdIUoPoaLSx7kTFYy39/c2TWBtTb2q5WFehW/IzyEfgfiSG6sHbgP'
                          '+CUu7uS/FccSAvadA5PmYtcDsKKCZxZZXRHcG3UHzgepK7XY5DQcbHUPFYS5eh5/VLZUyr0IZupS9D+ffj5ZrqRpk6Z6'
                          'U8vgPFMZJm+gwiK/leVFEaKpwbgN8Q1sN6Hnp/c2jNeMJhjJcvljHNYjrwDiTWIdlKeaAD+d2HT2lJQhdhd+4HkNj+nv'
                          'QW7nZkkSd127ShTJV6FWZlisXamNqYCrwd5RHnwT8dQjuq9DuX8IKWuBtmUtdSH3KBbCL9eexBVvmugGPibpktj8XamN'
                          'roRJkfITnmeSHOWV9C8sKrtJSp9m9JyyHkBgmZv5ibjosWa2NqYxDlJdciMq3KIPAajelIGNcv1KJJbcjXnmVFbMtgsT'
                          'amNnqAh5GgjTfKwEbUmfBg4LFx8VXSwF0X6hOznPSW7hTktglpMRGvs+WxWBtTGwdRv4rHCBe0VucgqiR8jXAB7UeWeV'
                          'IhnIpa/V5Eel1aglIok+Z1g9rk5uKuyGJtTG30omEKv0JW6HhhEPWffrSG4w+RXOQ7UDHRGaTz/89GBTjDJ52PRg8aEr'
                          'KfHFjXFuvGUSAHuZwTnLTl8vuA+4Ffo2yE/eQkaDUCvWhQxZ3Ad9FIuDSUUbBvT8AxBeTGOI+wNMgZqK/7WwlLF9yIeq'
                          'HsJgdi7QrGcNIKboHxK9jj6X2lfR/r0ECKp1Cv5LNQV7iQW/Jmsxf533+FNp9nCcusGEoFnYtHUA76pATHtKPCor8Bvg'
                          'p8n7GHPU9CHTmvQ31ZkrxOzFrUA2XbGK/REuRFrIuki/DWQ0TSfKhx8/Q+srW40r6/rM9J3E8izbmpx91d2vNSS7BpAE'
                          '3i2RA9nkG9MZbQ+nm8RbT+9agw5afobqEWKqjl7N3ItbE4wTFxj/a3os/iIOoP8hrq39FLtWPeDFSwcxLqyXIB4e6TV6'
                          'm6QVqevIh1nNYTEl2uNQ3oSMQNmUI5gG4JsxpWG5+H0PcYn5esBLtA1T8ZWnmWZavWoaRpY3sIWZG1bqZ9KOD4DEojy0'
                          'Nz+7iRUz8SriwCpWUktM+j734IFdRv+mgk1HcCd0R/jtsNn48qR49D3fNC7mDi0XK15nU3lDyIdQX5vu6mOqE6CQUkji'
                          'E+syQcpBqQCBG8gyigkdXtVoXqiKMQyugLmuWE8wo6zyG5uIPoPKbJNBiNAVTBFvL+BlCQ8GFqb5VZQZ9zLnok15H4e7'
                          '4RfcYnENbQaQoS4uOo9sXejTbhSSjNbyXpNvv9aBN5hGyvg7qSB7EuoxLUH6CI7/kJjqkgK2kj2Yv1HuBp9OVLks8Z9+'
                          'jdSbaiVEbv8UUUBU/iJiqjW7+XyK5/b3xR7kS9GQZJ9r2K85OfJdtez32oC9tOZD0lWcsOdPt/H9oATXbsQRklJ6AJL2'
                          'mIRTsLKqiI6VtoTFjL97GOyUM2SAVdTHejgMVYPYcraCf/MRLVrNkEfB24K8Fayih48RUkTFkHMXYB/4YatQ+M8fwVVL'
                          'jxBTS6Kmt2ooDQvYwuvnHv616UbfDgGL+fhj3ofG9gdF963LtiFxKUteQ3i6NVeQ0FC39Ka2yEcZbK3WhTb/nAYkwb8P'
                          'eBx/Qj0XyQbGcbjkbcN6CIehVUGNkf2IP8ZLehCRLPkv3FNxi9Ri+6PZuBqq+G3+L1Ay8AtwJfRrddWffLHYjWshd1D2'
                          'tHQZbha9mPNo0fRmvJYmzTcPrRZrAXdWmbyxv7ScTukvXAL4AvUZ+m7yX0+ZTRHcek6DH0vFTQbfWmaC23kf1dmNFnsR'
                          '1dvyehQGOzjMS4IvN7aPOodwn9cOJZrOeikW/B/VYqgY99wA3oxDcyXSsOLJyJUnueGWFtq4G/QL6seqZMFdCJvhD4Jl'
                          'Uf9tDHGuA/ovSt4UKRNdNQxP0f0QY6fC0PoSkai6lvZkIBuarehTap3mHr6EfC+FF0S1zPtXSjc3812rjjeEH86AFuAT'
                          '5A/c+L0Qb+79F1Eao5WT36gP+bdC1fs6CAdPMGpKNB68+Dzzom3iieRLv0dpRA3znk/59F04pfob63s/EH/xiyVF9A/u'
                          'v4CzCALOlfI8ut3rda+9F5aUOWajz3LxbIp5BPtt75pLG1emf0uk+igHDs+tiNXFN3IddDPdfSi879TiTMa9BGEs+L3I'
                          'kq9B5AFnVubodzyg50bc4HPoyu3UYZe3Hc61bgpmgtufy882JZD6WILKcp6LZ/avTnbhq/Y7YjK74V1tKGrPh4LVOix0'
                          'humnrTgc7L0HMymdqH0taylqGf0eTo38dLMU8eKCKR/lsUGG+URU6IIoMAACAASURBVL0T+P/Q597MO6gJY1kPJQ5QtQ'
                          'KDtM7k6hKtkzc6QOukRbXSWiYyZRT0vRl9Hp9A4lVPDgL/AtxIeL53S5FXsTbG5JNB5Db8DnKVXYPS+kIaMI1FbE2/DN'
                          'yDpp/nvoWtxdoY02hKKCPpa2jm4ieBj5PdtJ1tKJ31JhSv2U5OfdRDsVgbY5pBBQV2H0cZVdtQ9s5i1PPj1MDn24Dy5F'
                          '9BPVoeQOnF48b9lUashzq9jTGmFiooq2otCo4fg9JzP0A1iSHuXQKHB4TjorSXgJ+hbJP1KPsn65YKWZFaP9Na1iXGrp'
                          'gzxpgkxP1cQC6LjaiO4iiUsdNBNYsjFu9BlGQwGB27LjquFQU6poLWl6o4Lo1Yx+1K49Q0l+caY7KiH7kyXon+XkBCPT'
                          'QNtoAEb6SWtoUR/q1ViFOOO0mR1psmD7gN+ZSOJ7uAgDHGjEQFWc/9Qx59HLnnS6sKNUgvj0f6GZzvXaTanSwpncj5fz'
                          '7J25UaY8xEZxbSzVMJG6ZSAnYWURnuAZLvSG2oKfg5wMyAFzTGmInMTKpDFZJa1hWkz2uKKHq6lTDfc+wKmRJwjDHGTG'
                          'SmEO4CiVu6ri+iGv00jY8mI/9LyIBKY4yZiExCehnaDTQej/ZiG2o7Og9YRVh2SAdqELQNdbRyVogxxryRDuBiVKW5ir'
                          'C5nAOoi+Xv21HLytMJj6JORiPgt6Gk9OcDjzfGmInAscD7kF6GWtYV1Nfk6SLyh+wg3SyyGWjqweWoTNTtJo0xRhSQLl'
                          '6OdHJGiufoR/q8tQ3lKx6FxszMIsxEL0bHLIwWtgm1JGzlXEdjjKk3cRLGh9BkpJWEaSuoZP551JTq2Tgq2YbM86VIfE'
                          'Ms5DYk1vOQf6WMdoN4pJMxxkwUimjO4krg7UiozyS8WryM3Ms/Rp0Jd8RivR/l8p1BWA7gUGYCJ0fPUUFdsEpUa/mL0a'
                          'OVy0GNMSYJxWGPNiTIM1CP7s8isY4HWYe6iAfQWLwvonGFpVjt43mCjyGxnRv4xAWUmnIccqZPQ6K/EflbtlGdYLKT6l'
                          'DXZk05NsaYNJSR3s2JHiDtm490czlwGfJR1xLD20dVk/vgcNO8H/WWfRY4i/TTwQvAedGjF3XDehQJdDF6/meRWHdiK9'
                          'sYkw8KSCcLwCnRo4xE+83IWO3O4HV6kEY+zpDEj6FiXUG+kUXRItKK9VC6gRORHzy2rC+gOl3YlrUxJk/ElvVcYHb0b7'
                          'FlndUwlx40if33DDFmh5vpBeRj+QfgUuR/ySIdb2izbQ8uMMbknTgWN/zPtVAB9gJ3AH+F4n6va+XwnaCCShs/h1wY15'
                          'CNWZ/VmzHGmPFKH5p48z+RDh9m1I6U9VECXkP510uBJdhdYYwx9WQQuB/4KiovHxz+C0dK0aug8Tr9SKwXYME2xph6UA'
                          'KeQEL9K1RY+AZGy6c+hAKBPSgVbwHhFTjGGGOOzCFkUX8H+DnyaozIWNbyy2jq8G5SDnk0xhhzREpIX9civT0iY4n1ZO'
                          'BtKGfafauNMSZbJiF9fRtjpEuP5gaZDlwL/AlK57PP2hhjsqWIBunORW0/1hFVLA5nJLGOU+yuAv4zakhioTbGmPoxG7'
                          'Xo2Aw8xwipziOJ9WTgEuB64CKyq8oxxhgzMkXUuXQKsAt4FTVzep2RxPoE4C+BK8mmIMYYY8zYFFGq9AyUyrd96H8OF+'
                          't5yP1xLeGd94ZSwRWLxpiJSS3614lSpTejrqU98X8Md3G8Fbga5VTXQgFYj1JRtiNz3v1AjDHjkQKqQZmHqr6PrfH5Fi'
                          'Adfg24Of7HoWLdBVyB0kg6U75ICUU04xe5A3gR9RlxnrYxZjzShlzGx6MGeO9FoxKnkW6QSyfS4Y3A7QzrZ92N2qKeEL'
                          '1AGsrImr4NuAdYjYTaFrUxZiLwcvR4FCVnXI16XKfJppuG9Hgl6m3dG6v+MWg3OBOZ8qFP3o/STW4G/hfwIIpoGmPMRG'
                          'IXsAbpYTdKyZtFuIVdQqMWS2gQ+S6Qv+W90ZP3UO03nfTRi8T5ejS4wIFFY8xEp4D08Hqkj/EA8ZBHD9Ll9wKFeKr5ld'
                          'E/hKbqlZG742vAD9CsRWOMMYrfbUTW8VIUOAwxZjuQO+Rx4Ili9ARdhAcAK2io471IqO32MMaYw9mF9PFepJehMbwS0u'
                          'cFRWAFsJBw98UB1NLvJoYlbxtjjHmd7Ugnf450M4QC0ucVRZQFsoxwB/gOqpkf9lMbY8zIFJBO3oZ0M4Q2pM+ntKNMkE'
                          'WEi/UAMvGdmmeMMUcm1shdDOv3kYA2pM/HtAMXIuVOmq5XQal6LwJbAl/YGGMmKluQbi5DhS9JPBLF6Pcr7cDp0T8kdW'
                          'WUUB7h3cDO0NUaY8wEZSfSzcWo2CVJR9MCytWeWURmdojPeRAlaa9GqSnGGGPGZj/SzU2MML18FApAW5pe1YMourkZDX'
                          's0xpisaUcpa0U0+mpK9OcKqu/oR/rTF/05RPyaxSGkm9tJsd40Yh37rN2cyRhTLxah5IcpwDkotjYJBeh6UB+ix9EYrJ'
                          'dQ8UmrU0K62U+KxIy0Yl2OHsYYkwXTgJNRe9EZaMTVEiTWZwDLqSZBlFBmxWlIpF9BDZR2oAkrz9K6RXqxdjZErAtDHs'
                          'YYUwsFNOjkIuDjwJuRLnVGjyJqiTFUb9pQw7npKEGiH1nc/cjS/jrwMyTeBVorvTi1fnq+ojGmWUwH3ol6N68Ezor+LS'
                          'ld0WMocfuMs9BorLtQulzusVgbYxpNG3JzXA58Cgl1J2pcVCudyMd9GnKNLAF+hCzuXCdEWKyNMY1mOfDXSKzTtLoYjQ'
                          'LStXbgJOBPkXj/E5pclVvyLNZdyG/VjfxVfSjpPLScMwva0BifKchvto/mBTimolvJySgQ04NShZoREJ6FAkcdyG+4C9'
                          'jThHWAzslUlFFQQN+V3U1ay0RmBRLQa1Egsd4sjh670XX5FLpGc0fexDqedTYVRYjPQsGJ/UgInkaR4J1Ec8vqSDFay3'
                          'Q0fudC9KXYi265ngI2oC9IvTeQOAgzD037WQHMR+fgVeAx4PlobfUeXlxEn88S9PkciwS7jM7JA6jveQ+NOS9TUNeyM5'
                          'EVNx99j55G1WSvoXQqD3WuP8uB/w34CI0R6pgK8Efoe/C3wCPkIy/7MPIk1gXk53oL8ketRB/+FCRKB5EwbQJuAX5Fff'
                          'PAjwL+kKoIHAvMRH6xHSidaB1wK3BfHdcB+hK+l2qK03y0iQwggX47CrL8Evgd9fXdLQPej4R6CdpM4yDQhejW90kklI'
                          '9SX4t/HvAhdF6OBeagjaQIXIAyEJ4FHgIeRhuIqQ8LgU8CH6CxQg3SjunA29D3oQ99B3OXfhw6amYfcAPyBzUyfa8bne'
                          'hHkNiMtsZbUIQ5dPJNEgpog7gWfeCjraMf+CISiil1WEsRCdKn0OYw1mf3Q+BU0g3wTLKW+cBfoc1qtHW8Avw3dCdSj7'
                          'WAzssnUZBptLXsAD6PBpua+tAOfBDlRIfqTZaPOLXvbwnLOsmKAtLNG6gOIkj8qNeFkjVdqJrpUmQljSXClwF/gyzwrJ'
                          'kGXII2jhPH+N0O4D1ImN5M9pvbdGSpfBoJ31icA1yFLN6smQF8FPkj54zxu4uRtX8ZSrXK+ntYAD4G/Dljv9c5yMI+DW'
                          'USmGzpAlYBV6DNvJl0oDvPt6I+/sPT/lqaPIh1Ebkc3oFuo5OseRr6cpyR8PdDWIAE+G0k+7DnIkFdSbZiHRcTXIU2gi'
                          'QsBK5GLoqsz8scJMDHJ/jdCtroPog2kCzdccVoLVcikUjCUrRxnEI26WOmymx0vVxMbed2AAXKt1Kbv7mI7i7fj76DWW'
                          'ai1JU8+KwLyDp6NwqcJeUAEu1pyG+bFXORCIT43QaQr7SN7Pxkheg5x7Jih9KONo34S5rFWuIKsWko0yLpMZPQHcrTwG'
                          '/ILkI/ieodzyDJvuPT0Oa7Bt0mZxX4zFuVbz0CrPOQUKdxMw0i/3IfaoD0NPpszkCa0I7uskPviOYjQ2Et8AI56XGUF7'
                          'GeifoGhKy3gsQsa7GeEj1nKHOQwO8muy9H3JkshGnROtrJVpTmoIyUkGO6keWVlZVfQO/vGPTZJxXLIhL4VWRjWcdxjc'
                          'mk7APRYOINdxBlxmSRSVVA5/VYdEcXyiBqJ/oQymTagmIdJSTUi9Bd7rnA2YRdk/H0lRPQ592bYn0NJw9iHZPGCiyQ/W'
                          '1O3MgqdB2TUd7xAbIT67hVZAiHomOysvoqSHTjFpahHCBbMYv7SoR+7m3ogq/lvHSgTWIx8o3OIB9Nz+LWowMo7XU9cj'
                          'n0kv6zibO3TiUsuF5Gm8UzqPLwuxy5o147yoKqoOyepHd2MTOpXpOtvqHmSqzTXET1uA1N+5ytckvcKuuIyXo9Pciv2U'
                          'P4BVhLg7IO4E3A+5AffibaAOJofisTv+d4Y9mMMqpupZq1EEoRNVm6hOSuujg75+7o9e9H7U+PxCCaGH4QGUCXEqZpc5'
                          'HlvwfVarT055QnsU5jndTj5Kd9ztStEXNAqwhSBVmDe0h3a1si/fs4HmUIXYdcO3nmLBTUH0QTufeleI4i2rxOJ7mrrg'
                          'Q8B3wT1Ukk+Qz3ofqBSdHrnBfweouR62sdOZh6lYdsEGNCKCIrt5Hf7QLKyPkj8i/UoA3rHODPop9pmUuYa2IABfzuJc'
                          'y9NwDcDnyPsBYC85G7KiS+0TQs1sbURheyHq9AQavxQOwOWobSGdMQt4VIGrDtRZNf7kR+89A76UMoIPlqwDFzgfNRxk'
                          'rLa2HLL9CYFmcm8C500YcGuFqdLuTeOZHwLJk4nS6p6B5ErRAeIn1SwAEUjEzqAutG760Z1YzBWKyNqY1JyFWwjPF3PX'
                          'UhMTsTWckhhMYxBlAztlo6IR5AzdN21PAcLct4+3IZ02jizn7jsVQ97qA4g3BrNzSzpoKs61pyvOP2xCH+7twE/S3Wxt'
                          'RGH9W2vOONAaqdLNOIaIgIxpteSGHVcLpRmmBIXncuhBos1sbUSg8KjMXd/cYTBVQ1+BjhbXXj/h1JrevJyJ10CumLxq'
                          'ZGx4e0YBig9YuWAIu1MbVyCHgQFXI0azpQvdiKhs6maZ7UHz2SbmBTUPfDi0hf8r8C+dhD6kc2I/dLy2+0FmtjaqMPNY'
                          'D6LWoMNF7Yj6oDHyKdkMUj5ZIeW0SpdGmzM5ajXPeQHiG7kAsrbZVmQ7FYh5M2eb4YPVo++X4Ck+bzqSDBfgQVZfwSuQ'
                          '7ySj9qnPR94CZU3ZeGMioVD3EPtaGqx4+g7JqkLEYtTy8nrLHZOjTFaXvAGptGXsrNW+lEplnL8KkPpjWp5bN5FfgOGg'
                          '92Ncq9Po78ZIlUkIX5KJoodAcS27TZGWXk674HFZ0kaSncjizrv0D56/+KOmbGGRvxRhp/TkN7un8YNY0KyVpZi8Q6nm'
                          'zU0uRFrDtJd2vUTn267qX5YA+Rbce9uAVl6N1RfFyWFn4Rnes0d2pZfz61dFqsJdhURhf9TuRCeAHdmnfT+kJQQN/Lfc'
                          'il8wAaJFwL8YDkh1GDpaT937vQefsAOncvofF5T6NrKP6eLURW+FmoF3loC2XQ5/QK9R+unQl5Ees+dBEsJLkgtKOgSN'
                          'Zj5wdJd/EdRFZClo3Oy4QLZBu6OLOMgMfnuRWabZXROQ4V7D1IoGo9LxXkB12bYg3NJu5pnUWf8wr6vr9AuiZJJ6EWq3'
                          'uBXwM/jf7cia7tU9H0qJOQIRcSlIz96a+SvT7UjTyIdRntfreh252lAcduI/tqpgPIxxUilB1IrEOi42NRjtYSeiHEFl'
                          'SWX9I4HzckvasUrSFNH4jR6EPCO0jyz6cP3bI/RjbnpUROpo80gC3IOj6JsM0r7i8+DU2JOgN9NvFd4Rwk5mnu5raj7J'
                          '17sFhnShkl5d+MJoAkFesNwItkPwXiNRREOppko4rKKGCznmxFqYJE6X6UWzo3wTEDyEf3KNmLyWbUSOc0khUllFAbzE'
                          'epbabecAbRZ7QRWU9JyqT3or4UD5KjizcnbAN+hq7bpDMxhzMremTFVhRAfYIcbap5yQbZh6yeB9CFNdpt2gC6Bf0J6o'
                          '2bNVtRIOnHVIMfR6IXfSH+CaVAZc0e4EY0UWM/R/7ixdNtHgP+GbWgrMdafojSvUZLhYp7Tq8D/gVZN1mNF4vZgbq3Pc'
                          'Ton1E8aed54C4k8Lm5eHPCTuAH6LvRCnnovcg18yBaT6vHE16nDfj7wGP6UeDgQRpbYtuLRKAPuRWO4o2bzQAS9BuRWG'
                          '8g++qkOGq+OfrzbBTtHs5+JETfQmK6LeN1gIRlK/rStaNbxpEs7G1IuL6O+v721GEtsUW7GZ3zOYxsDe1GA3K/jja80M'
                          'q4JJTRd3MX+k7MY+QA9TpkUX8fiXUuZvHlkIPoeliGJrM0847+98AXUKplo4mzV85FwdGg+al5cIPEVJBlGLs3BpErIg'
                          '6YEf3fF9Dtdb3TcZ4B/jF6nWuRIMTrGEDR669Ha6n3FIqHkEhujdYymeoQ1DL6gn4ZbbD1EqQC2gTuRj7BPSh9bWb0/3'
                          'E+8mPIor6rTuuIeQ1t2Ouj172cat+JChLy29Fd0nPYoq4369CmOA8VrzS6newgin19FX3u8fWRG9IseD/wbXQ7/XyK47'
                          'NgAcrHnI2iw7FIbkVWfyNvt5ai4MlMqsGPPiSeLyDRahTHR2uZHK2lFK3lFeRPbpQ/tojiCyvQeYnTHXuQiK6mcVZsB5'
                          'pifRzV6rYS+lxeJPtYgjky89Cm+VHgYsIaLtVCbDx9Gd3lbm3Q6w6ngHTrz9A5CKm2BN5YsDHWYx9wAxIFV+MZY0KYgo'
                          'YK/5rq9PR6PvrRHeVnCO/JnTUFpJs3UI3rJH7kyQ1ijMk/B5Fbrgu5Yc9Fd8dZ56SXkEW9AfhvqHdLPWI1DcNibYxpNN'
                          'tR1tAB4BLkEllFdoLdg1y0j6GN4ZfUJ5DdUCzWxphmsAtlA90BfAr4Y6rl+QUUawhxsw6i2MMhFPz/IWqsFTJAt6WxWB'
                          'tjmskh4BbUk2QRCgSfiKbFJw3A9aIS//vQIIh1qJCuWYHEupBGrON0MEfQjTG1MojK0TchN8hRKAd5O3KNtHNkCztuWf'
                          'AKqq/4DcrAauUOl7F2Bq8trWUdC3YrngxjTL6IhbWMUjv3IH9zPJOxkzcahxUUQOyNHj0oeNnK+fI16WYasS6iarA5aD'
                          'd0LwVjTFYMRI/9VCekj1YP0qoW9Eh0It2cTopWH0XC32gHKgQ5kebnLRpjxi+xJVqi6j4Y/siLUIP08kSkn6FzJitFwi'
                          'vJYrE+gcZVIBljTN6ZgnQzjVj3FlHkNCQHsYgasqwk3fQWY4yZiExHurmMMDfIIWBdEXWf2kCYY74Dpdhk2WPWGGPGM7'
                          'OQboZOtdkAPFKkmpcYGkWdD1zIyO1BjTHGVJmH9HJ+4HElpM+Pt6EI5VHAmYQpfhcagrkfNfvPuoG8McaMB6YA7wE+gi'
                          'zrkLL6ftT06ndFlESepiSzAyWtvwP5YYwxxryRlUgnVxEeWATp8wtFNFFjN+mSySejrlnvRwMt8zImzBhj6k0R6eL7kU'
                          '5OHv3XR6SE9HlnG8pVXAycjhzgIYUyBeQKWYpyCLegmXdZDkA1xpi8MQk4FTWpugZpZGj//z7kYr4NWBP7TkpUp3vMTv'
                          'GkM5DfeybyZe9Dom2MMRONo1EjqvcDVyGhDqWCskBuRHNCd8divRc1QzkVjYZKU4Y+DVXnrKA6sLQTtTyM/TStXLdvjD'
                          'GhdCGvwjRktC4C3g1cj3p1zyHdRK1+1Iv7fwAbGTIppoxm0T0EnI12gtBG4MVowWej5O9L0DDZLair1rPRa/Rz+JBbY4'
                          'zJExVkeHaiae2noEKXRWh6+QpkuKalhIKKDyHNBN5oQT+AHOLvorZS8hOpLvYgyjh5CAl2H+kiosYY0yoMIKv6FOAcsm'
                          '2/0Yt6cz8w9B+Hi/XDKGn7HLRjZJHdMQW9oSXA29GuZKvaGJNnYh2bgjwJXRk9bxlZ1TcjPX6dkURzDvCfkXM8K8E2xh'
                          'gzOrE7+gfAf0dxv9cZyS89gNwWU5FpPxlbwsYYU08qKMb3XeDf0KScwwYujCTWZZQdshcJ9nKUM2jBNsaY7KlQHSD8LR'
                          'Tbe8PYxNEyPraj8TrTkR/bFrYxxmRLGdiG+n98A/mpR5xvO5pYl1GZ4w7kPF9GunJJY4wxI7MLuB34DvAomiU5ImMFD/'
                          'eirnrTyC7aaYwxRnQhfd3PGFXfYxW+TAc+DlyLqnPsBjHGmOzoQK06dqOJ7n1H+sXRxPoY4LPA+1BlTmhFozHGmNEpUJ'
                          '0pMAuVlu8Z6RdHEuB2lAXyEeDfo2yQNL1CjDHGjE0RNdA7Hgn1M1Qnur/OSGI9G/go8DFU426L2hhj6ksRVUPGYxJfZF'
                          'iwcSQhPhn4DGqWbYvaGGMaQxGJdTcaZH7YBK/hYrwAeAsS7FqbLZWHPCo1PpcxxrQyBSS28SMtHUh/34LaVm+N/2O4WL'
                          '8D9QTJYmL5CyhvcA1KSxnAom2MGV8UkMBOA04C3hz9rIV5SIf3Al+L/3GoWE9F0w3OQNHJtKyPHr+LHs+hdJQRq3KMMS'
                          'bnFFG+9Mmoj/8lqAnesSmfrxPp8BWoqdOBof85HbgUTSYoIQs4zWMDyiA5BaWiuG+1MWaiEOdMn4J0cAPptbSE9PhSpM'
                          '+vBxhXAZ9EQ3PTFL8cBO4Hvgl8D02GOYCtaWPMxKGMdG870sBDKFg4j3BvRewyno48FVtAJvx1KPIY+5VDHruAHwFXRk'
                          '/sKkdjzESngPTwSqSPuwjX1gGky9cBxfboCeei6pk0qXpPAl8G7gAG070vY4wZV1SAfUgX25G+vi3wOeLj5gLT24HFKL'
                          'gYOnm8hEojf4ECiRZqY4w5nEGkj6vQIPLlhBUalpA+L25Dan8W8CbCLOtdwLdRs+ztAccZY8xEYhC5M7pR8DGk1XQZeB'
                          'nYU0TpJssIT+TeC9zDkFHpxhhjRmQ90stR26COQBHp88lFlMC9hDDTvIIKXfYFvrAxxkxU9iHdDCkObEP6fFI7cBFyYC'
                          'fN4ighF8ijDKtdN8YYc0ReRbq5GDXMS2IgF5BYdxeR0ztkIG4JDXS8BzXMNsYYMza7kW4+S/KEjgLS56VpUvXi3L8NjD'
                          'IvzBhjaqQ45GeBqkF5pLzkVqcH6WZc0xJUKJNGrMvISb6dUUbQGGNMDUwB5iBBmx09pkf/F88rjH3Auwn3BTeDPqSbe0'
                          'lR3Z22X3WedjNjTOtTQHoUN0VaiXKTZwKnosZGy6LfXYeyK9ahWo/ngKeRYJcZYcpKi1CTbqYR6wrVPtXGGFMrbcDRwG'
                          'VImCeh3voLUE7yAmA+VTfIm1BxyZuQVb0N9X3eg9wMdyABb0VjMnWP/zRiXeBw/5ExxqShA7k6lqG2oh9BRSNwuL4M15'
                          'oisrhnDPm3WPy2AAuBW5FwHwB6M111baTWT4/tMsY0i4VohOBbkeV8FGHFeSMJ+nzg49Fz3gH8ELlIco/F2hjTaKYA5w'
                          'HvBN6D8ojjsVi10onymBci18ps4E7gPnJeF5LFyWkl7JoxpvU5E/g74HpU59FGtlpUiJ5zKWov+g/A2zN8/qaQZ8u6Gw'
                          'UZ4nmR29Dcx2YwFfVYmY1yKbei5uPNSG2cDByPLIt+5Lfb2IR1gAJDS5F/sRytZUOT1rKMasCqF9hE1NDdNJTLgb9Asw'
                          'qn1Pm1CtFrLEOiDfJl76nz69aFvIl1NxLEuainSRwVLiNxfAxYi6YC76O+GSvtKDiyGKUYXYAEch9KK3oKDQveRP17qH'
                          'QiX90ctGmcgwS7J1rHw6hz1zb0Ra33eVkIHIci+6eiDbUUreUBtHlsRalW9aQDfT4nIGvuGDTY9AD6bB5Hm8cONO2oFb'
                          'MHxgtFlH73GSTYtcx5TfPa51G9Pn/FsLmGeSBPYt2GIsXvRbvyEhQNnoQuskPANeii+xrwVepr2S4EPoyGWsbWYzeqTD'
                          'qIvgyvAl8EbqrjOkDC+J/Q+ZmFzstU1JrxPOBalIj/A+Dr1Fckj47Wcgm6IKdTvTDPBd6NRPtW4OfofNWLZcDfoHF1s5'
                          'BV3Y7OyxVo83oM+DFwF67IrScnA3+FJqc0UqhjOtH34UPoc/4t9f3uZU7exPoclN6zlNF9XAVkLf2c+uygM5EYfRA4jT'
                          'f6yudEP0+KXv8VZMntJlvrrRNZ0B9CgjxthN+ZPeTPg0go70cukizpQBbsh9GGetQIvzMTifkJ6DysA56nPoMrVkVruY'
                          'bDU7yGsjxaSxuy9tfUYR2matm+lbBezlnTjvr3b0LXQGi70qaSlwBjN3Ai8BaS9d4+Hfhs9DNrZqDk/WuRtTBaULOIRP'
                          '3/ZGRRr4UCEr+Po2HHIwn1cFYh8To5w3XEzInW8afINzwa04CLUTbAMWT/PWwHPoX8lEcS6piZ6AK+CM8QrQddwNlIqM'
                          'f6LEZjaDFe2irAIvqenou0obuG9TScPIh1EVljH0RinYR2ZNWeRPa3XAuBd6EvX1eC35+OhOA4sveJTkNTfhYm/P05aK'
                          'M5g+w++1jcZqANKWm73aXojuBisv2MOpHFfDJjbxpD13Ilcq814xZ9PDMXfc5XUNu5XUc1DrSe9HdjBaQL16NNJDfehT'
                          'wsNG7j+p7oZ1IKKOg2HblEsmIBCmxODTimOzqui+yqqeLWiSHWSgFtGsegzz5LV8jMaD1J6USW/unA9zJcRyfa3EEXdJ'
                          'LveDdwIbAa+bCzinUUcNByCdXgewiDVAO/m1Gu9F70WU1G8ZkTkAEym7CNYDYyuJ4CHiEn82PzINYgERjJBzoasZhl7S'
                          'PrIvz2Kb79moOCWlkFNjoIm/BD9PudKY4bjXZ0ASS50xhKMTo2a/dQG+EiuQhtZFldE3PRRpqHPjpFtMZBlC10MIPnLK'
                          'DrZAXVGE4Ia1D14RMoxfI1dN20oc9oGsoyOhsJ7zkk/+wKyNgKrZhsKnkR6wrh09fjizXrD6OUYi0gYZ2KpuxkJdaFFM'
                          '/VhyzqrASygt5bd8rnPES21mcFvb80Apn2PQw9/njUWlPUzQAAEnhJREFUMe5YJCh5EesKVbGOU09fqvE5T0AiOjPhMR'
                          'V05/ki8H3gO4xdI/A02lw60B1vJ8k/w5loI+kjB9Z1XsQa0l/QWd+Gpr2Y4w2n2eupRxOuOPiThnoE9NI+Z5pNOKYbWX'
                          'mfQZkPk4eso9VdIcOb+u8Gbga+hAQ7bTDvLBSTSOqqq6DsoM+jTK7NCY7ZAdyC3sPHUdwkqUtkKXLDHURGVEt/TuNdrO'
                          'tx8mvZNMZrD/Dx8r5qeR+nokyYdxPuDmo15gN/jAT3C6SrgC2gDK7jSe5y60eFSrcTVl26BdUQzCcsqWAJ+tyeIfu02s'
                          'zJjb/GmBaliNxblwNXkX+hBonWYlTTcG7K52hDboakBuEAyvh4GMV1Qu+OtgL3opqGpC6NeShraPpYv9gKWKyNqY0pKC'
                          '3tCsIyhFqZWCinIut4KuHi2Y0s3KQasw/4GfAbJLZprNzno+dIapXPQi6rpOmmTcVibUxtTEfFPaehINd4oh0FCc8gPA'
                          'MqzshJGss4iPrGrCW9Lm1HKX4vJvz9IsoIGRpfaFks1sbURhfyy6ZJT2t14pz1kwnvkBfq/y9TbQ2RNljdiwQ7pHFaLz'
                          'nIBAGLtTG1UkaNsXLVFCghFfS++ggX0DRZR7Vat0XS1RC0vFUNFmtjauUQ8CgKbI03BlDq3rPofYYQalnHLYdrSS2dgX'
                          'zsIQV0af3jDcdibUxt9KAqu+dprcGsWVBGbX7TvLcBwtwLHagkfVbg6wxlJsrtPjbgmINk34GyLlisjamNQ8BDqOVmvY'
                          'cpNJISyj9+EPmAQ63PAaQvSTVmKmqOdnGK14pZhsR6TsLniNMF99fwmg3DYm1MbQyiVLGnCHcVtDLrURXjoymPj33cSV'
                          '0aU5BQv4N0xXqdqLdL3GkxyetuQeXqe7FYj0vS+tOKZD8Y1LQGFdSt73Oo4u8x8htw3AH8FLgh+pl2IngZuYeeJrmbYR'
                          'pq4fuXqDNkUmYAn0D9y0OyctYB96AMkpYX67yUm6cNOtQjypu27H0QXcDNbupTj94gtTxnK/UGqeV9vIJGyc1CXeCuRy'
                          'l9efBjF5DbYydwHyrdfgD549N+X0vA71D/jUWoFHwsisiV8dfR634tWkMvb+zbUkRpkwU04OPfoUZOIZkgG1F5+x4s1p'
                          'nRQfiUibhVZtbvMe0FfQjdbmWZ05mmX3IBfdGzFMm41Wmau4YsW7VC9XNP8/6STNs5EmUkKq+i3hZrUMFMLc2hGknc8W'
                          '47GntVq/89bsq0mrCWq0W04V2HxPc21NRpeO70JCTSlwLno1zw0Gu9j+yvybqRB7GuoBP6HErLSVpJ1YY+jKyHoMYtRk'
                          'PpQUn/WV68JcJLnAtIWLJcRy+6uNN86fvJ1qopoY0xZOOIO829SDbnJe6/nEfisVm1Et9NrkPnNsStAaqcXI5KwRehFM'
                          'K4tW8FFetciQYbzCJMy/rRprSG+g7VzpS8iPVG1Ij8WtQlKwkDqCHMzozXswfYQNjG0UH2O3gZbQChvtEedF6y/JKWgZ'
                          'epWmMVxrZs+9G53EK2rqE+1O7yIMlFZz9wB/BrsgkS5qGHdaPYjizsEwmrgiyi6+ti4Ez0uQ79PDvRnUvIdCKi59iMgq'
                          'd3kZO0PchHsCvO9fwFEoSkrEeWUtYfxsvAd1HgJAl9KFDzNNn7xXYh/2LSqdyH0G3lPXVYyzbUl+FVkrkgimjtd5FtMK'
                          '6ErNqXSG4l9yD/6j3k6OLNCa8BN6LUxjR0o+54S5D/O34sIFyoQd/NPci1ktWdVENoA/4+8Jh+lKb0INlbrUdiEFk/i5'
                          'BlPZov+gDKD70Z+C3Z5772IiFoQ7dq0ziy33UnErB/RilQWQeb+oEXqA4I7mJkf3RcNvw74H+goErWlt8Aer9xe80ZI6'
                          'yD6HV3oe/P59BnlbVA9qPmPLOin5MZ2TCpoO/HnWgqSdpG++bIDCADp4h80EmnxtSLXch4upHG58UXkFvnXHQugtrp5k'
                          'WsQR/6FhR1n4H8WcPpA34EfAXd0m6mPhdfP/LFbUGzB0fyx+1AG8ZXUGS9Hl+MuPlN3LxmJrJAhnMgWssXkYVTD+uxjL'
                          '4Pm9CmdCwjV6NtQcJ4A/Ak9fEZVtA5eTH6uQhZZ8PZA3wTpdutJkdWVs4YRN/BmSgXOuu5qCHcCPwr0pFGb8w1iXUefN'
                          'YxFXTxbUH+yJ3IZxXPXKsgAf0WEsd6pkwVqIpxP7rVW0B1+OshtKHdgqrb6hltLiDr+hsokLMVnZci1TFia9B5ebjOax'
                          'mMXuu70boupvr5lNDn9iSaZp7UjZSWHchi3og+j4upNpkvRWt9FqWHPVnntRjdtdyKDJt3NuH1y+iO8iZ0N5eL5k1DSZ'
                          'P6tR/4Nrq1fz7F8VkQD7rsRMG7+H3sQz7TRkZ44ynLk6mmjPWjgOKOBq9lNtq5u6mKNdFaXqVxhRoFlFc7h2pKXwmdi/'
                          '3I2m1UulRszcTT1+NsmNi19loD1zLRmYGSBP4DVbddI+hDhUpfQjGbHQ163eHEo87+DPgogamiebKsh7InerQC+2mdnh'
                          'C7okezqSALf2uzF0LVJbK92Qsx7AV+iTbHP0R50vXuAz6ILPofAnfTGtdHKvIq1saYfPIS8H10V74Hza48ivBJNGPRjy'
                          'zoJ5AXIHYB5jaAbLE2xjSagyjQvQtZu59AVnZW9AKPoJjR71FMIveuLou1MaYZlFFV8nNUU0tnILfIAsJL/w8gt9tuNM'
                          'fxNygBYG9G6206acU6dAqEMcaMRAEF/R5A2TpnozapF1ANCI91fD9qQHU7Ev9XULZYyCzGRpFaO9OIdTyx2OW0xphaqX'
                          'B4wsBLKN3yLpRR1EF1UvpQ4gywChLmh1DhWbMyPZISa2ewYKcR66Hd7NKk/hljzJHYgVpL/CL6ewdK0R1uHBaR9hzicA'
                          '1qZU0qIN1M1RUyjVi3ox1vKapWC2l/aIwxIQwQVh/QqkIN6mWyFOlnsPYWCY+StqNS75XU1v/XGGMmEtOQbi4nXKwHiy'
                          'h6GjoyfgmwgubW+BtjTJ6YjHRzCWFiXQF2F1EDm7hbWhIKKLXmJKq9FowxxozOdKSbC0jus44DqKuLKHn8BcI7ji0GFg'
                          'YeY4wxE5WFSDdDKCF9fiS2rEMatcfMQ/mQbwo8zhhjJhpvQno5Uqve0SghfV7djtoGnkC4WM+MXnwb6hvdyN7WxhiTF+'
                          'agiffvIHz4QglNvXq8iKY4pEkkL6Cm7ucDp6Q43hhjJgKnIJ1cRLo+2juAl4uodn436aaHdAFnUW3EkruG3sYYUycKSB'
                          'c/gXQyTf/ufqTPe+PZgXPQuJ05hLUqLKB0lGNQE5atqKHKAC5HN8ZMTNqRu+PNwKeBq9Hwi1Bjdi9KAPkpsCEW6wOoEn'
                          'EFSisJmXpeQJU5C5DgL6I6XsoYYyYaq4CPAR8CLkKTikKFuoTGj30RNanqiROzd6COVZehqOWRpnWPxjzUSPxUtIv8gu'
                          'og14PRzx6UN2h3iTEmz8Q6NhnlT0+Jfs4D/gC4Bg1V6Ej5/LFY307U5CoW6wqyhteghuAhSdsxBdRw5Wi0q7wDWderUX'
                          '/ZZ1Awc4CUjUyMMaYFqCAx7UC9PlYir8SpSDvnUNu4sgrS4TVIl4E3ljz+Gg10/CC1jdmJF3sCehObUdvD7ehNhrhZjD'
                          'Gm1Sgjo3Me6vWxGFnSWdCHPBO/HvqPw63bNuBi4B9J7w4ZTgU1ixogPJfbGGNamTZkYccto2ulBDwF/CUaSfa6Zg63rE'
                          'toXtlN0f+dQu2CXUBvJq3vxhhjJgIl4Fmkv08yzLgdSYgHkdtiJhLrSXVeoDHGGAUSfwB8E1WGH5b+PJJYl5FTu4R8MX'
                          'FE0wFBY4zJngrVie/fBB5jhDqV0Vwce4D9wFQU8ezMfo3GGDPh6QHuAL4F3Av0jvRLo4l1L7AheqIFyC3SjS1sY4zJgj'
                          'JK0XsI+CqqVNx/pF8eK3g4AGxBor0HpanMzWSZxhgzsXkeuBFZ1PegSvIjkiTTow+J9Xq0E0xHrpFa8rCNMWaishd4Gm'
                          'V9fAP5qPvGOigkLe8gSit5guocxvj4AnaPGGPMSAytNdkF3AL8d+CXjJD1cSRCxLqM/NcvIdfITlSROIgtbWOMORJ7Ud'
                          '7074GfIYv6fqSnibuTprGGC1SbmCxGPUA+AJyDysgLaBOIH7a4jTETgbhnSPyoIDF+CPgaEuq410eso4mpVUgLaAjkyc'
                          'gtMgMFIY8DlqHeIHMyeB1jjGll4inkLyDvwzqqXUdfRiXk22t5gSxFtIDEeilwBupAdVb0cxZvLG03xpjxwCCymFejYQ'
                          'Gr0Wzbl5ELJMiCPhKFSiWT5zHGGFNH3KrUGGNygMXaGGNygMXaGGNygMXaGGNygMXaGGNygMXaGGNygMXaGGNygMXaGG'
                          'NygMXaGGNygMXaGGNygMXaGGNygMXaGGNygMXaGGNygMXaGGNygMXaGGNygMXaGGNygMXaGGNygMXaGGNygMXaGGNygM'
                          'XaGGNygMXaGGNygMXaGGNygMXaGGNygMXaGGNygMXaGGNygMXaGGNygMXaGGNyQHuzF2DyR6FQOBGYVOPTbAD2ZrCcoW'
                          'SxrrTsB0rRYz96b5UmrQWASqWpL28ypuAP1IRSKBSeAE6r8WneA9yawXKGksW6smQnsAvYBqwHNkaPZ4DVwMF6vriv7f'
                          'GFLWtj6sec6LECuHDY/1WAtcDDwO+A3yIhN2ZELNbGNIcCcEL0+Ej0b2uB7wLfjv5szOs4wGhM67AC+DvgBeA+4N1I1I'
                          '2xWBvTopwP3AI8Bbwfi/aEx2JtTGtzKnATcCdwUnOXYpqJxdqYfPBWlO3y2WYvxDQHi7Ux+aEL+BfgxujPZgJhsTYmf3'
                          'wI+DkwudkLMY3DYm1MPrkE+BnNq9g0DcZibUx+uRj4Bs4UmRBYrI3JN+8H/rrZizD1x2JtTP75r8CZzV6EqS8uNzfmcG'
                          '4H1gUe04mCfVOAWcB84GhgRrZLOyLtwJeAc1DXPzMOsVgbczhfIbtugDOBVagT4EUoKDg/o+cezpnAdcCX6/T8psnYDW'
                          'JM/dgD3A38K/BBYCEqbvkScKgOr/d3yMo34xCLtTGNo4zE+0+BJcDngN4Mn38p2hTMOMRibUxz2AX8F+AM4MkMn/fTGT'
                          '6XaSEs1sY0lzXABWgAQRacDxyb0XOZFsJibUzz6UG9q9dn9HxXZ/Q8poWwWBvTGuwDPpHRc12e0fOYFsJibUzrcDfw4w'
                          'ye54IMnsO0GBZrY1qL/5XBc8wGlmfwPKaFsFgb01r8FtiWwfOcnMFzmBbCYm1Ma1FGI7xqZXkGz2FaiP+/vbsH+XUM4D'
                          'j+LcsRSVJiYDDYSV4im7Ioi1AGGdmsZ2AXg8WkLBYD5S2MLBSDt5ycUt4VJz05iqPD8Lc8izhdz3Nf13M+n+lMv3NN3/'
                          '7dz/0i1jCf9wZsXD1gg4mINcxnxC18PkpwxIg1zOebARuXDthgImIN89kbsOGX9REj1jCfPwZs+Pr5ESPWMJ8R75kfEX'
                          'wmItYwn0sGbPw2YIOJiDXM56oBG78M2GAiYg3zGfGK09MDNpiIWMN8bhyw8dWADSYi1jCf2wds/N8vtDM5sYa53FBdM2'
                          'DnkwEbTESsYS4PD9j4rvphwA4TEWuYx5XVQwN23hmwwWTEGubxVHVswM6bAzaYjFjDHO6v7huwc7Z6bcAOkxFr2N4d1X'
                          'ODtt5qzJdmmIxYw7burt5ozOWPqmcH7TAZsYZtXFQ93e5r5qNeZ3qyemXQFpMZ8XYv4L+7sHqwerzd3R8jPdHumjVHkF'
                          'jDwbugurW6t3qguuwA/o8PqhcOYJdJiDWMcay6uLq8uqK6trquur66pd1lj4Nytnokv6qPNLGG/V7a+gDn4MnGfBGdif'
                          'kDI6zt/er41ofg4Ik1rOvb6p7qzNYH4eCJNazp5+qudi9t4jwg1rCen6o7q4+3PgiHR6xhLSer26oPtz4Ih0usYR2vVj'
                          'dVJ7Y+CIdPrGF+p6tH271H5NTGZ2Ej7rOGub1YPVZ9vfVB2JZf1jCfv6rXq5vbPaIu1PhlDRPZq56vnqm+2PgsTEasYV'
                          'unqpfbPeb+dvX7tsdhVmINh+dM9Xn1UfVuuw/bftbusgf8K7GG/T5t99DJudhr9+a7X//59/fVj+2eMjxRfVn9OeCMnI'
                          'fEGvY73u6yBEzF3SAACxBrgAWINcACxBpgAWINsACxBliAWAMsQKwBFiDWAAsQa4AFiDXAAsQaYAFiDbAAsQZYgFgDLE'
                          'CsARYg1gALEGuABYg1wALEGmABYg2wALEGWIBYAyxArAEWINYACxBrgAWINcACxBpgAWINsACxBliAWAMsQKwBFiDWAA'
                          'sQa4AF/A0bVjb6AzWIxQAAAABJRU5ErkJggg==')
        
        buf = buf.replace('resources//DIR.png',
                          'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAWsAAAHoCAYAAACPYs4OAAAgAElEQVR4nOy9d5gkd53m+c'
                          'ks2953q526ZVqu1cggL4GQZUBoAGGEBwGaYRdu2NmdmbuZm5tjb/e5PW5mZ3dn58TA4I0AgUAgAcIJkPdCqCW11Gqjlr'
                          'ql9r66XGbeH2+EsrpUXRW/yEgTVe/nefKpNhWZvwzzxje+tsD4ow2YDhwHrAROBc6Mfs4DCs1bmjEmQyrAdmA18Gj080'
                          'lgHbAPKDVvadkzXoSrHVgKnAgsRGK9EDgaWA6cAMxp1uKMMXVlJ/AssBHYBLyExPol4BngBWCwWYvLijyLdbz2InAy8E'
                          'fANcApSLyL0asteuX5uxpjjkwFWdEloBy9BoGngB8At0d/LiNNKDdnmbWRZwFrA64AzkUujhXIsu5u5qKMMS1DL7Ksnw'
                          'UeBO6MfuaStmYvIAUdwDLgMuA64F3AKmAB0NnEdRljWot2YC4y5M4EpiADdQA4SM4s7Dxa1scB/ytwMfJLT2vucowxOW'
                          'EnCkjeBXwWBSJzQ54s6xnAhcAHgfcCS4Cupq7IGJMnJiNL+xikHQPALqCvmYtKSh7Euoh28CXAp4GrgFlNXZExJs9MAk'
                          '5Cor0b2IH825VmLmos8iDWXUiorwdeh9LyjDGmFrqBo1BK7zaU9tfS6X2tLtbtwEXAR4A3oscYY4zJgk7kTu1Egv0CLR'
                          'x0bHWxPgb4C+DNwNQmr8UYM/7oQMVz01AV5O7mLufItLJYHwN8CHgP9lEbY+pHF8os6wOeB/Y0dzkj097sBRyBmcDbgD'
                          '9BwcWs6I9eJZS2mMfURWMmMpXo1YbcF1nVVsxFerMX+AotKNitKNadqCLxUnS3y4qdwFpU0bSHahm6MSY/xGXlM1HF8g'
                          'qy6/uzEOnOQ6jSsT+j982EVhTrRajPx8oa36eEUnJ2IaF+BvmkHkaJ8e1YrI3JGyWUtTEPOAtVJp6IBHs2spBrua5XIv'
                          '15EWWItAytJtZxU6Y/Rt3y0lBBye5rgJuA+1DQ4CCyqPdQvWPaDWJMvohzoTcjMf0VKiOfBZwPvBvlUHeQ7vpejvTnHt'
                          'TBr2WyQ1pJrIsojeYi9GiTZkdX0A5+Evg5cDM6qKP9vjEmf/SjdLttQ/7tGWA/SvNdibI8QnWkgPTnIqQjL9Iigt1Kbo'
                          'Dp6PHjrUi0Q28kFeBl4IfAvwC/QO4PY8zE4ADwNOqyF6fkTSVcsAeR8bgb2EBOytEbybHA11DZZ5lq1DfJq4TusF8Czm'
                          'v0wo0xLcd5SA+2IX0I0ZMy0qGvIV1qCVrFsm4DTkNNmpYQfifsAe4Avgncyzgb52OMCWYbEty5qKVySIpfAT3Zl4EHUG'
                          'Vj012mrSDWBdT29O3ITxTa8rQCbEWujzvQo5AxZmJTQplgoMDjdMKNwArKu95EC1Q2toJYt6Ny8g+iqsXQNe0EbkFW9c'
                          'vZLs0Yk2MOIZGdj7QltLdQN2rNvBkFG5saaCw288MjJqEimFNQUCCUe4Fv4WCiMebV7ET6cG+KbTuQLp2KdKqpNFusJ6'
                          'FHlNNJP0hgPcqpPpjVoowx44aDSB/Wp9y+C+nT+TRZsJst1stRqt5Kwh34AyitZjV63DHGmJE4hHRiA9KNECpIn95K+k'
                          'K9TGi2z/o04MMoCT30xrEJPd78DAUYmx6tNca0JGUk2BUkuCFdPAuoQrKIMkM2ZL24pDTLsi4ix/3ZKK0mzTpeBn6Mmj'
                          'M5Vc8YcyRKSCd+TLokhCLSqbORbjVFN5tVbj4VuBJNKA8dKlBBd7uNpHus6aAayLQ1bsYbBSROfUP+nvV5HuchtyHhau'
                          'R1FKffDRB27cdu043I/xzrSFKmIr1ah1pZ7AvYNhOaJdbdwGXAOYQHFgdR+8KfoD4ASTkKuBo1eemkRer9jakTPajLZJ'
                          'bC0gFcgK7bxTSvEVoR9QZZA9xKcmt5P9KNo9F3CMk+64q2eR74HRNIrE9AX3x2im0PAT9Avuokd9Z2dHCuAT4KLMXd9s'
                          'z4pwQ8hQyj36CGRGkpomv1XOB96Km42alsFVRZOAPpwSbGHng7gHRjAbCKMLGO98E5SL+2jf7r44NjgL8DthBWrx+/Xg'
                          'CuCvi844HPocT20B4BfvmV51c/8DjwpyioltbXOh0lAtyO8pab/b3iVwld159D13lSrqJaQh762oL065iAz8uEZmSDXA'
                          '68HzVICbHsK+hx5xfo7hifNGPxWuCTKApsi9pMJNqQFTkVuUU2on4ZoaxAgn8l4e0g6kkBrWc6ytRYl2CbIrKoFyDXaG'
                          'hXvg5UCbkJPbk0jEZHNbtRN6xToz+HMIAagn8enXRJfM6T0U3Bk9HNROY84COkm2fajqzWVaQvXKs3U5AxlqScvIz04/'
                          'NIT0ITFLqRfp1HuIbVRCPFejLy96winXi2ofSbh0lWrdiJktnPpPn+NWOaSTeaLziV8Gt+Chqh1crXUDfyIy8n2dP6Qa'
                          'Qja0nnXZiKdOwcwvuNpKaRYr0EeCfppsAMUC0rT5pT3R191nG09olmTCM4gIQp5NqLC0Im09rZU50ocWAZya3/EtUy9F'
                          'DrOp4m806kaw2hkWJ9AvJ5LQ383DJKl/kq8NuA7Soo1zQeZmDMRKZMuphNkcbnUqehDVnVId/xt0hXnidMI4pIx65Eut'
                          'YQGiHWbSi95nSUm5kmXfBF4Dbk1E9KH0qCf54WGylvTBOYgizIENGtIJfBAVo7OF9GqXRbCLvWNyFdSZPW2I707HSkb3'
                          'VP1miEWE8CrgAuJF0L1AMoIPBS4Hb9KDq8FkXCjZmoDCDRPUi4hbwfZWG1ssHTg+YuriPcpfES0pc0Q0s6kK5dQQNcrY'
                          '0Q62mocvAswqPJfShi+0NgT4rP3gv8nvTtEY0ZDzyOmp7tIlysB9HTaZK0uGaxDngMaUTo99uD9OUewgfjdiFdu5oGpD'
                          'TW23SPm3d/DCWRhz5K7Qa+gCqUBknnNxtEBQFHoXzMZncaNKZR9CH3wBfR8Nd9pIvfVNA1FGeFNDRlbRT60ZPzrcCvSF'
                          'cCXkDukMmoZ8iUwO0nRe9xD+r+Wbf4WL3LzU8A3oKEMs38sz3U7sbYikZ+bUHFOGej6HGrB0yMqYV+VChyM6o83DX6r4'
                          '/KTuAmlD1xBcqCmEvzrqEC+n4PoSeGO9B1noYS0pe1SG/mEp4xcxTSuX1o/FddqLdYn4PmK05FBzbpToirFe+g9v6xA8'
                          'BzwA6UGbIRWITugHmIchuTlPj6GkTCcxuyOmttOlRC1+EGVKZ9EAXWoLHXUIHqdbsF+DVqe5rGRTqcDUhvphJmXFaibd'
                          '6MdCZ3Yl1ALpCVKB9xMmF3q17gbuAb1NaAZij7qDaA6kbWtcXajCcKVK3OniGvLHkS+H/QNdSNrvNGpcbGYt2PNOIQ2X'
                          '2/F5HezEZWctKAYQHp2wqkd52EZ900jQLyb12C7nyxrznktRv4DM0fO2aMmTgUke7sJlyzBpHeXYL0L/NUx3qIYREFE6'
                          '9FfTnS+Kq3Ac/gYhZjTOMoI93ZRrhlXEB6dy3Sv8y1tR5iXUB9CC5Dvp/Qz3gRuBG4L+N1GWPMWNyH9CfU/VpEencZ0r'
                          '+Wt6zjBZ+DenKkSfFZh4Iiz9PaVVPGmPFFAenOraTLK+9GuncO6QzVUclarKegip7zGXtqw0jEzb13UPUFGWNMI4g1Zw'
                          'fV4SihDCL9u5DwnO1RybpAZBpwPXKyTybsZtCLEsu/g6qRQstGjTEmCwaRds1BFnJo1txMVJD0W5Sx0nJ0obvJ48hRHx'
                          'pN3QR8Cgm+3R/GmGYRT6D5FNKlUC0rIx28kAwHNmTlBmlDkdBL0d0ojdjGo+L3Y/eHMaZ5VJAObSDdE34B6eClSBcz8W'
                          'BkJdadaNbhNegRIJS9qAimlZvFGGMmFuuQLu1Nse1MpIevRfrYMswC/gndhUJdIAOoZPRSWuxLGWMmNJ1Il35MtSoxxB'
                          'UygHRxVhaLqdWyjsf+nIZKLUMnNcRrWAM8Smv3zDXGTCz6kS6tIVwrC0gPVyJ9nEKNsbgs3CDHAO8ATkqxbQU1P1lN7c'
                          '1mjDEma/YhfXqOdLG0k5A+HlPrQrJwfJ8HfBINjkxTrfgNlIReSwtHY4ypB3GwsQ0VvMwI3H4yarv6ECplT00tlnUBzS'
                          'A7A42ATyP8m1Cv3VrboBpjTL3YgHQqZAZsTBvSxzOQXqZ2hdQi1tOQ8/2ylO9TQtHWF3GqnjGmdakgnVqHdCuUItLJS6'
                          'lh/FctbpD5aFzXpciRHlqt+CiuVjTG5IMSyg5ZjNwaIVWN5WibXuBeUsbn0g4faAOWAavQlIRQ9gLfB36Bpk4YY0wrcx'
                          'Dp1QIULAxpUteGdHIV0s0tpLDQ07gv2tFUhD8ClqbYHjTT7VHUN9YYY/LANqRbO1NuvxTp5gpSGMppxLoLuAiNX58euG'
                          '0cWX2IdM56Y4xpJpuQfqVpizEd6eZFpOgZkkasp6FhmasIrzgsAHcCXwc2p/hsY4xpJpuRft1JeGZHJ9LN00kRaAwV6y'
                          '5U634m1eGcIVSAh9GdqTdwW2OMaTa9SL8eJt3orwLSz9cSaF2HivVxwJtQ3mAoJTTGfiPp0l+MMaYVKCEde4F0WrYc6e'
                          'hxIRuFpO4VULXix0I/JGITqlb8GbAV51YbY/JJCQ0VqCDhDe00Og1VNj4GrE26UVLLuoDyBM9F/VnT8CzwPTy13BiTb+'
                          'Ip6N9DupaGY5GeziWhOzmpWE8HXo/8LGmCkvFcs3i2ojHG5JlaNa2I9PT1JMyqS+oGWQRcB7wRme8hgcU+ZO5/G+Uoul'
                          'rRGDMeKKEg4RLCqxqLqAq8HwUr94y1QdI3X4oimNMJzwDZhYT650BP4LbGGNOq9CBdm4MEe2HAtkWkp2cifR2zmd1YLo'
                          '1CtIgLUJllmo5Rg8i/4xaoxpjxxi6kb4Mpti0gXb0A6eyo+jqWG6QNuAp4L+lKJHehevpbkG/HGGPGE7G/+mhkIU8K3L'
                          '4LuZa3A08xiv97LMu6GzgL9WINLY+sAHehah+n6hljxiMVpG9fR3oXqnNdSF/PYozmUKOJdRfyp6TtrFcAngYeQXX0xh'
                          'gzHtmPdO5p0rmK4458ZzKKUTyaWB+LRqmfSPjdYhA1634aOJBie2OMyQsVpHNPI90L9V9XkM5ewyh1LKP5rM9B6XrHj/'
                          'F7wykDzwM3AT9FvhiLtTFmvNOP4nqL0azGpFZ2AU0/72aUqsaRLOsicnifhhplhwYVK6hu/iY0BsfVisaY8U4Z6d1NSP'
                          '9CDdR2pLenIf19lTaPJNbT0aiuC0nvq96IHgn6UmxvjDF5pA/p3kbS+64vRPr7qqrGkdwbc4BPAG8gvAimDznav4vMeb'
                          's/jDETiRIS3cXAPMKrGmdEP+9ljMSMAvA6YDUy6yuBr23Ap5Hgpx65bowxOaWA9O/TSA9DNbSM9Pd1DNPQoW6QAmr3dx'
                          'nqBZJGbHdRnVFmq9oYM9GoUJ0xm6Zqu4D09zKkx6/o8FCxrgDnR7+UpgBmO3A/ShA3xpiJzFakh2my4bqQDl8wdNuhPu'
                          's2lKp3JeHzwXpRQ5PPkb5O3hhjxgs9wEuo98dxQEfAth3Id70T+BVRRl1sWXeitJHjSTHIEbU9fQy4B01QMMaYicwhpI'
                          'ePka4t9FRUILOcSOhjsZ4LXIKil2mqFbehQhhjjDFVnkf6mKaqcS5wMdLlV9wgZ6J0vdcQNlygEi3mRuDHwN7ABRljzH'
                          'hmP7KMl6NZjaFVjTNRN77nQdb1B4HdhKeZDAC3AStr/krGGDM+WQncivQyVGN3I30uFlE9+hTCHOAxfcDLyJFujDHm1W'
                          'xBOtmfYtsOor4hRRStTDxhdwh9KDXlduz+MMaYI7EP+A3KvQ4V7ALS5wVx85A0Yr0NuBn4JS6AMcaYI1EAfocmyRxH2K'
                          'zGWKyXtaMuT8cS1gYVlJqyAVvVxhgzGiVgM9X+/iG0IX0+rR1lgBxHuFjvQ85vY4wxRyb2PLxMuHHbhvR5e+yzns3Y8x'
                          'iH0ocmIhwM/GBjjJmo9CDdDGkdXUT6vKAInALMIrnPuozKIF+IPtwYY8zY9CDd3EnyoSwFpM+nFNEI9ZDGTSWUqrcBi7'
                          'UxxiSlB+nmS0hHk9IFHF0k3Ffdh/qt3oF8MMYYY8bmZaSbqwmfotUWOl8R5CwvoeZPc6J/C/F3G2PMRCN2e3Qi/QxOd0'
                          '4j1t3A6cD7gedQkLEzxfsYY8xEoR9VIh6P9LM79A0KhCt8BQn0NtRYu5dwV4oxxkwkSkig5wHzkXAHFSKmEeuhH57KnD'
                          'fGmAlIARm2qYzbWsTaGGNMg3Bg0BhjcoDF2hhjcoDF2hhjcoDF2hhjcoDF2hhjcoDF2hhjcoDF2hhjcoDF2hhjcoDF2h'
                          'hjcoDF2hhjckCarntlNPRxLzCQ7XKMMWZc0wHMAKYSaCynEete4NfATcAmJN5B3aOMMWaCUUHifDTwbuCNwOSQN0gj1g'
                          'PAWiTY21Nsb4wxE5W1wBnApaEbpvFZF5EJPxtb1MYYk5QC0s1gFwhpNhjyoRZqY4wJI7V2OhvEGGNygMXaGGNygMXaGG'
                          'NygMXaGGNygMXaGGNygMXaGGNygMXaGGNygMXaGGNyQJpyc2OMqTcFpE9FoI3DC0kKqCdRKXqVo9e4xmJtjGlF5gErgA'
                          'XAsujvbaghUhuwG3gWeBHYDLzQnGU2Dou1MaYVmISEeSowDTgVOAc4HjgZifVQt+1+4PfAU8Ca6M87gEPRz72NWnijsF'
                          'gbY5rNNOBC4H3AEiTcM4G50f91HWGb84ATgX3ALqAH2ArcDvws+vO4wWJtjGkWM1C70FOBi4F3Bm7fAcyPXkNZjIT+fm'
                          'R176htma2BxdoY02gKwHTgSuDfI+u4I6P3rgBnI/fJauBbwK3ILTKY0Wc0BYu1MabRzAfeC7wHODfj9y4gt8lR0WsGuh'
                          'ncCDyR8Wc1lDyLdRs6KEV0NwXopzlzIduBzmhNcUrRQPSz0XRF64iDMYNAH9V91Eg6kcUUp10NoGPUjLV0c3gK2CAaUW'
                          'caRwH5mt8E/DkacVVvzgZeg867zcjCbsZ1WTN5E+sCuuDa0GPOaehxqg8dgDXA08BB6p93Ga9lEnAssBKYhaLRO1Fa0X'
                          'okUI1ay2y0T+aji2IABVmeBLY0cC3tKEC0EliKZs2VgQ3o+GxHYtmo/TIXeC3aP5PQjex54DF0rOJcXVNf5gDXAR8FFj'
                          'XwczuADyAr+3NotFbujneexLqAxPAE4BjgLOB0qmI9iATyfuBe4Dnq66Oag4TxROAk4BQkUL1IAJ4BHgX+gNKL6skMFK'
                          'Q5D4nSULHejgTyiWg966jv08fsaA1x4GgxSseKxXo1Eskn0A2knlbOdGRVnQdcgM6foWL9QLSO51Cebl8d1zLRmYws6o'
                          '+ja7iRFJFB9XGUl/0dZGU34wmvJiqBr33ADUigGjnaqwO4HE1VX48eZ3qQOPYgi/ZAtL6/R3fueq2vCLwFeDD67L3R5/'
                          'dGPw9G69gM/DMpZ64lpAMN37wLRb0PDFvLAZSTug34BySe9dov7cDbgEfQfhlpLTuBe4B/i8S0nmt5XfRZO9ExidcSnz'
                          'M7orX+NY219CYaReASZEiF6k2Wr0PofLgOucUaTQHp5g1IH0LXnwuxLgILgf8E7EmwxvXAfwaW12Et3cii/gISgLHW8g'
                          'Lwf1Cf/TUFRdRvRJbrWGt5GvgECrxkzWTgauDnCdZSAn4CXIaeAOrBVcD3qfrIR3v9Dng9nitaD7rQ0+c/kuzarffrIM'
                          'oQWUHjeyPVJNZ5aOQUuz/OQ4nzMxJscwxwPXr0zZq5wNtRXuhIyfrDWQJ8GgU6shSDeFLy+4BrEr738cC1yIWUtTDNRR'
                          'H+KxK8dwE4E/hjVJ2WpTuugFwdH0Q3jyQpYcehc2URbm6WNbPQ09YVyLhIQwXddOOnolqC1JOQi+4SZLTk5gadhxOziK'
                          'LG70AXeFLao+3mZLyeecD5SPjaEm4zDfmzs6SAblzLSXbTAO2Tk5A4JV17knWAXD0LSHbyF9BxeRu66XVmtBbQk88JyM'
                          'WS9Pyeh6z882jO4/F4ZgYysk4h/U25AGxCMYYHUbwhbYCwgHThwyhtMKv87rqThwBjAQXMXocuwKSU0YkyA/kss2IW4R'
                          'ZYAVmek5GvNKtIdDfJnjSGMguJUzvZBmBnI8FOSgd66sjyxgH6XgsIuwg70ZPP74Ffo2OUxTpmoht1kaprqNWIM2ZKKP'
                          'ayh2zOzwL6vsdEr1DDsES1SdPzKFC/mapL9DjU4Ol4lHEUomWTUd+RM5Dbrj9wbU0hD2INWmc3YY8sFeqTHlYg/MSLK7'
                          'bmogyIrE6OMuGCW0L7JqunqgoSu5mEWylFss+7rpAux306EvksbhxtSExeE/3sRpkmrfjIXUGugUMoa+lhJIq1UkRuhp'
                          'WEGxQggb4Z+AGKQfVSPaZxHcFc4P0oFTAkZztOL52DvnsWN+e6kxexhnTi8koUNUPSXnDtSMyydj2Ffr967JMi+n5p9k'
                          '098l3TfMcCuunUIqhHId/3GeipYRF6KuygtUudO9BNcwtKr3sJZRf9hvTnSgEFFs9DT11JqKCbxlrgx8CPkEV9pFTTPc'
                          'A30b79CLKyQ5iFjtl+cmBd50msWyWJPe3JGzdIb8VH4VqpMD6+Wy3fYT5K5/wEEo0OqgVcrU7ssjgJWa+DSGT3odz8NN'
                          'deAeXZn4ncDkkoIyv6G8iifpGxawI2AF9B+/mjyCWS1CA6Gt1Yd6LisZY+f/Mk1sbUm1ou1lXokfwM8hG4H4mhevAG4H'
                          '9DKXf3pnivOJCXNOgcb7MWuA0FFJO4ssroieAbKD5wPcndLsehIOOjqHispcvQ83pSGdMqtKFH6ctQ/v14uaa6UabOWS'
                          'm370BxjKSZPoPISr4HVZSGCucG4FeE9bCeh77fHFoznnAY4+XEMqZZTAfejMQ6JFspD3Qgv/vwKS1J6CLsyf0AEtvfkd'
                          '7C3Y4s8qRumzaUqVKvwqxMsVgbUxtTgTeiPOI8+KdDaEeVfucSXtASd8NM6lrqQy6QTaTfjz3IKt8VsE3cLbPlsVgbUx'
                          'udKPMjJMc8L8Q560tIXniVljLV/i1pOYTcICHzF3PTcdFibUxtDKK85FpEplUZBF6mMR0J4/qFWjSpDfnas6yIbRks1s'
                          'bURg/wEBK08UYZ2Ig6Ex4M3DYuvkoauOtCfWKWk97SnYLcNiEtJuJ1tjwWa2Nq4yDqV/Eo4YLW6hxElYQvEy6g/cgyTy'
                          'qEU1Gr34tIr0tLUApl0rxuUJvcXDwVWayNqY1eNEzhF8gKHS8Mov7Tj9Sw/SGSi3wHKiY6g3T+/9moAGf4pPPR6EFDQv'
                          'aTA+vaYt04CuQgl3OCk7Zcfh9wH/BLlI2wn5wErUagFw2q+C3wbTQSLg1lFOzbE7BNAbkxziMsDXIG6uv+esLSBTeiXi'
                          'i7yYFYu4IxnLSCW2D8CvZ4+l5pv8c6NJDiD6hX8lmoK1zII3mz2Yv8779AN5+nCMusGEoF7YuHUQ76pATbtKPCor8Bvg'
                          'x8l7GHPU9CHTmvQ31ZknxOzFrUA2XbGJ/REuRFrIuki/DWQ0TSHNS4eXof2Vpcab9f1vsk7ieRZt/U4+ku7X6pJdg0gC'
                          'bxbIheT6LeGEto/TzeIlr/elSY8hP0tFALFdRy9i7k2licYJu4R/vr0bE4iPqDvIz6d/RS7Zg3AxXsnIR6slxAuPvkJa'
                          'pukJYnL2Idp/WERJdrTQM6EnFDplAOoEfCrIbVxvsh9DvG+yUrwS5Q9U+GVp5l2ap1KGna2B5CVmStN9M+FHB8EqWR5a'
                          'G5fdzIqR8JVxaB0jIS2mfQuR9CBfWbPhoJ9W+BO6I/x+2Gz0eVo8eh7nkhTzDxaLla87obSh7EuoJ8X3dRnVCdhAISxx'
                          'CfWRIOUg1IhAjeQRTQyOpxq0J1xFEIZXSCZjnhvIL2c0gu7iDaj2kyDUZjAFWwhXy/ARQkfIjaW2VW0HHORY/kOhKf5x'
                          'vRMT6BsIZOU5AQH0e1L/ZudBOehNL8VpLuZr8f3UQeJtvroK7kQazLqAT1eyjie36CbSrIStpI9mK9B3gCnXxJ8jnjHr'
                          '07yVaUyug7Poei4EncRGX06Pc82fXvjS/Knag3wyDJzqs4P/kpsu313Ie6sO1E1lOStexAj//3ohugyY49KKPkBDThJQ'
                          '2xaGdBBRUxfQONCWv5PtYxecgGqaCL6S4UsBir53AF3cl/hEQ1azYBXwXuTLCWMgpefAkJU9ZBjF3Av6BG7QNjvH8FFW'
                          '58Ho2uypqdKCB0D6OLb9z7uhdlGzwwxu+nYQ/a3xsY3Zce967YhQRlLfnN4mhVXkbBwp/QGjfCOEvlLnRTb/nAYkwb8J'
                          'nAbfqRaD5AtrMNRyPuG1BEvQoqjOwP7EF+slvRBImnyP7iG4w+oxc9ns1A1VfDH/H6gWeBW4AvoseurPvlDkRr2Yu6h7'
                          'WjIMvwtexHN43vR2vJYmzTcPrRzWAv6tI2l1f3k4jdJeuB24F/pT5N30vo+JTRE8ek6DV0v1TQY/WmaC23kv1TmNGx2I'
                          '6u35NQoLFZRmJckfkddPOodwn9cOJZrOeikW/B/VYqga99wA1oxzcyXSsOLJyJUnueHGFtq4E/R76seqZMFdCOvhD4Ol'
                          'Uf9tDXGuB/Qelbw4Uia6ahiPs/oBvo8LU8iKZoLKa+mQkF5Kp6K7pJ9Q5bRz8Sxg+gR+J6rqUb7fur0Y07jhfErx7gh8'
                          'C7qf9+MbqB/xt0XYRqTlavPuA/kq7laxYUkG7egHQ0aP158FnHxDeKx9FdejtKoO8c8v9PoWnFL1Lfx9n4wD+KLNVnkf'
                          '86PgEGkCX9S2S51ftRaz/aL23IUo3n/sUC+Qfkk613Pmlsrf42+tzHUUA4dn3sRq6pO5HroZ5r6UX7ficS5jXoRhLPi9'
                          'yJKvTuRxZ1bh6Hc8oOdG3OB96Hrt1GGXtx3OsW4KZoLbk83nmxrIdSRJbTFPTYPzX6czeNv2O2Iyu+FdbShqz4eC1Tot'
                          'dIbpp604H2y9B9Mpnah9LWspahx2hy9O/jpZgnDxSRSP8tCow3yjQvsmYAACAASURBVKLeCfy/6Lg38wlqwljWQ4kDVK'
                          '3AIK0zubpE6+SNDtA6aVGttJaJTBkFfW9Gx+MjSLzqyUHgfwI3Ep7v3VLkVayNMflkELkNv4VcZdegtL6QBkxjEVvTLw'
                          'B3o+nnuW9ha7E2xjSaEspI+gqaufgx4ENkN21nG0pnvQnFa7aTUx/1UCzWxphmUEGB3cdQRtU2lL2zGPX8ODXw/TagPP'
                          'kXUY+W+1F68bhxf6UR66FOb2OMqYUKyqpai4Ljx6D03HdTTWKIe5fA4QHhuCjteeCnKNtkPcr+ybqlQlak1s+0lnWJsS'
                          'vmjDEmCXE/F5DLYiOqozgKZex0UM3iiMV7ECUZDEbbrou2a0WBjqmg9aUqjksj1nG70jg1zeW5xpis6EeujBejvxeQUA'
                          '9Ngy0gwRuppW1hhH9rFeKU405SpPWmyQNuQz6l48kuIGCMMSNRQdZz/5BXH0fu+dKqQg3Sy+ORfgbnexepdidLSidy/p'
                          '9P8nalxhgz0ZmFdPNUwoaplICdRVSGe4Dkd6Q21BT8HGBmwAcaY8xEZibVoQpJLesK0uc1RRQ93UqY7zl2hUwJ2MYYYy'
                          'YyUwh3gcQtXdcXUY1+msZHk5H/JWRApTHGTEQmIb0M7QYaj0d7rg21HZ0HrCIsO6QDNQjahjpaOSvEGGNeTQdwMarSXE'
                          'XYXM4B1MXyd+2oZeXphEdRJ6MR8NtQUvozgdsbY8xE4FjgnUgvQy3rCupr8kQR+UN2kG4W2Qw09eByVCbqdpPGGCMKSB'
                          'cvRzo5I8V79CN93tqG8hWPQmNmZhFmohejbRZGC9uEWhK2cq6jMcbUmzgJ471oMtJKwrQVVDL/DGpK9VQclWxD5vlSJL'
                          '4hFnIbEut5yL9SRneDeKSTMcZMFIpozuJK4I1IqM8kvFq8jNzLP0KdCXfEYr0f5fKdQVgO4FBmAidH71FBXbBKVGv5i9'
                          'GrlctBjTEmCcVhrzYkyDNQj+5PIbGOB1mHuogH0Fi8L6BxhaVY7eN5go8isZ0b+MYFlJpyHHKmT0OivxH5W7ZRnWCyk+'
                          'pQ12ZNOTbGmDSUkd7NiV4g7ZuPdHM5cBnyUdcSw9tHVZP74HDTvB/1ln0KOIv008ELwHnRqxd1w3oECXQxev+nkFh3Yi'
                          'vbGJMPCkgnC8Ap0auMRPu1yFjtzuBzepBGPsaQxI+hYl1BvpFF0SLSivVQuoETkR88tqwvoDpd2Ja1MSZPxJb1XGB29G'
                          '+xZZ3VMJceNIn9dwwxZoeb6QXkY/l74FLkf8kiHW9os20PLjDG5J04Fjf8z7VQAfYCdwB/ieJ+r2jl8DtBBZU2fha5MK'
                          '4hG7M+qy9jjDHjlT408eZ/IB0+zKgdKeujBLyM8q+XAkuwu8IYY+rJIHAf8GVUXj44/BeOlKJXQeN1+pFYL8CCbYwx9a'
                          'AE/B4J9S9QYeGrGC2f+hAKBPagVLwFhFfgGGOMOTKHkEX9LeBnyKsxImNZyy+gqcO7STnk0RhjzBEpIX1di/T2iIwl1p'
                          'OBN6CcafetNsaYbJmE9PUNjJEuPZobZDpwLfBRlM5nn7UxxmRLEQ3SnYvafqwjqlgczkhiHafYXQX8B9SQxEJtjDH1Yz'
                          'Zq0bEZeJoRUp1HEuvJwCXA9cBFZFeVY4wxZmSKqHPpFGAX8BJq5vQKI4n1CcBfAFeSTUGMMcaYsSmiVOkZKJVv+9D/HC'
                          '7W85D741rCO+8NpYIrFo0xE5Na9K8TpUpvRl1Le+L/GO7ieD1wNcqproUCsB6lomxH5rz7gRhjxiMFVIMyD1V9H1vj+y'
                          '1AOvwycHP8j0PFugu4AqWRdKb8kBKKaMYfcgfwHOoz4jxtY8x4pA25jI9HDfDegUYlTiPdIJdOpMMbgdsY1s+6G7VFPS'
                          'H6gDSUkTV9K3A3sBoJtS1qY8xE4IXo9QhKzrga9bhOk003DenxStTbujdW/WPQ3eBMZMqHvnk/Sje5Gfj/gAdQRNMYYy'
                          'YSu4A1SA+7UUreLMIt7BIatVhCg8h3gfwt74jevIdqv+mkr14kztejwQUOLBpjJjoFpIfXI32MB4iHvHqQLr8DKMRTza'
                          '+M/iE0Va+M3B1fAb6HZi0aY4xR/G4jso6XosBhiDHbgdwhjwG/L0Zv0EV4ALCChjreg4Tabg9jjDmcXUgf70F6GRrDKy'
                          'F9XlAEVgALCXdfHEAt/W5iWPK2McaYV9iOdPJnSDdDKCB9XlFEWSDLCHeA76Ca+WE/tTHGjEwB6eStSDdDaEP6fEo7yg'
                          'RZRLhYDyAT36l5xhhzZGKN3MWwfh8JaEP6fEw7cCFS7qTpehWUqvccsCXwg40xZqKyBenmMlT4ksQjUYx+v9IOnB79Q1'
                          'JXRgnlEd4F7AxdrTHGTFB2It1cjIpdknQ0LaBc7ZlFZGaH+JwHUZL2apSaYowxZmz2I93cxAjTy0ehALSl6VU9iKKbm9'
                          'GwR2OMyZp2lLJWRKOvpkR/rqD6jn6kP33Rn0PEr1kcQrq5nRTrTSPWsc/azZmMMfViEUp+mAKcg2Jrk1CArgf1IXoMjc'
                          'F6HhWftDolpJv9pEjMSCvW5ehljDFZMA04GbUXnYFGXC1BYn0GsJxqEkQJZVachkT6RdRAaQeasPIUrVukF2tnQ8S6MO'
                          'RljDG1UECDTi4CPgS8FulSZ/QqopYYQ/WmDTWcm44SJPqRxd2PLO2vAj9F4l2gtdKLU+un5ysaY5rFdOAtqHfzSuCs6N'
                          '+S0hW9hhK3zzgLjca6E6XL5R6LtTGm0bQhN8flwMeRUHeixkW10ol83Kch18gS4AfI4s51QoTF2hjTaJYDf4XEOk2ri9'
                          'EoIF1rB04C/gSJ9z+iyVW5Jc9i3YX8Vt3IX9WHks5DyzmzoA2N8ZmC/Gb7aF6AYyp6lJyMAjE9KFWoGQHhWShw1IH8hr'
                          'uAPU1YB2ifTEUZBQV0ruxu0lomMiuQgF6LAon1ZnH02o2uyz+gazR35E2s41lnU1GE+CwUnNiPhOAJFAneSTS3rI4Uo7'
                          'VMR+N3LkQnxV70yPUHYAM6Qep9A4mDMPPQtJ8VwHy0D14CHgWeidZW7+HFRXR8lqDjcywS7DLaJ/ejvuc9NGa/TEFdy8'
                          '5EVtx8dB49garJXkbpVB7qXH+WA/8OeD+NEeqYCvDH6Dz4W+Bh8pGXfRh5EusC8nO9DvmjVqKDPwWJ0kEkTJuAHwK/oL'
                          '554EcBb6IqAscCM5FfbAdKJ1oH3ALcW8d1gE7Cd1BNcZqPbiIDSKDfiIIsPwd+Q319d8uAdyGhXoJupnEQ6EL06Ps4Es'
                          'pHqK/FPw94L9ovxwJz0I2kCFyAMhCeAh4EHkI3EFMfFgIfA95NY4UapB3TgTeg86EPnYO5Sz8OHTWzD7gB+YMamb7XjX'
                          'b0w0hsRlvjD1GEOXTyTRIK6AZxLTrgo62jH/gCEoopdVhLEQnSx9HNYaxj933gVNIN8EyylvnAX6Kb1WjreBH4L+hJpB'
                          '5rAe2Xj6Eg02hr2QF8Dg02NfWhHXgPyokO1ZssX3Fq398SlnWSFQWkmzdQHUSQ+FWvCyVrulA106XIShpLhC8D/gZZ4F'
                          'kzDbgE3ThOHON3O4C3I2F6Ldnf3KYjS+UTSPjG4hzgKmTxZs0M4APIHzlnjN9djKz9y1CqVdbnYQH4IPBpxv6uc5CFfR'
                          'rKJDDZ0gWsAq5AN/Nm0oGePF+P+vgPT/trafIg1kXkcngzeoxOsuZp6OQ4I+Hvh7AACfAbSHaw5yJBXUm2Yh0XE1yFbg'
                          'RJWAhcjVwUWe+XOUiAj0/wuxV0o3sPuoFk6Y4rRmu5EolEEpaiG8cpZJM+ZqrMRtfLxdS2bwdQoHwrtfmbi+jp8l3oHM'
                          'wyE6Wu5MFnXUDW0dtQ4CwpB5BoT0N+26yYi0QgxO82gHylbWTnJytE7zmWFTuUdnTTiE/SLNYSV4hNQ5kWSbeZhJ5Qng'
                          'B+RXYR+klUn3gGSXaOT0M33zXoMTmrwGfeqnzrEWCdh4Q6jZtpEPmX+1ADpCfQsTkDaUI7esoOfSKajwyFtcCz5KTHUV'
                          '7EeibqGxCy3goSs6zFekr0nqHMQQK/m+xOjrgzWQjTonW0k60ozUEZKSHbdCPLKysrv4C+3zHo2CcVyyIS+FVkY1nHcY'
                          '3JpOwD0WDiG+4gyozJIpOqgPbrseiJLpRB1E70QZTJtAXFOkpIqBehp9xzgbMJuybj6SsnoOPdm2J9DScPYh2TxgoskP'
                          '1jTtzIKnQdk1He8QGyE+u4VWQIh6JtsrL6Kkh04xaWoRwgWzGL+0qEHvc2dMHXsl860E1iMfKNziAfTc/i1qMDKO11PX'
                          'I59JL+2MTZW6cSFlwvo5vFk6jy8NscuaNeO8qCqqDsnqRPdjEzqV6TrX5DzZVYp7mI6vEYmvY9W+WRuFXWEZP1enqQX7'
                          'OH8AuwlgZlHcBrgHciP/xMdAOIo/mtTPyd4xvLZpRRdQvVrIVQiqjJ0iUkd9XF2Tl3RZ9/H2p/eiQG0cTwg8gAupQwTZ'
                          'uLLP89qFajpY9TnsQ6jXVSj52f9j1Tt0bMAa0iSBVkDe4h3aNtifTf43iUIXQdcu3kmbNQUH8QTeTel+I9iujmdTrJXX'
                          'Ul4Gng66hOIskx3IfqByZFn3NewOctRq6vdeRg6lUeskGMCaGIrNxGntsFlJHzx+RfqEE3rHOAP4t+pmUuYa6JARTwu4'
                          'cw994AcBvwHcJaCMxH7qqQ+EbTsFgbUxtdyHq8AgWtxgOxO2gZSmdMQ9wWImnAthdNfvkt8puHPkkfQgHJlwK2mQucjz'
                          'JWWl4LW36BxrQ4M4G3oos+NMDV6nQh986JhGfJxOl0SUX3IGqF8CDpkwIOoGBkUhdYN/puzahmDMZibUxtTEKugmWMv+'
                          'upC4nZmchKDiE0jjGAmrHV0gnxAGqetqOG92hZxtvJZUyjiTv7jcdS9biD4gzCrd3QzJoKsq5ryfGO2xOH+LtzE/S3WB'
                          'tTG31U2/KONwaodrJMI6IhIhjf9EIKq4bTjdIEQ/K6cyHUYLE2plZ6UGAs7u43niigqsFHCW+rG/fvSGpdT0bupFNIXz'
                          'Q2Ndo+pAXDAK1ftARYrI2plUPAA6iQo1nTgerFVjR0Nk3zpP7olfQGNgV1P7yI9CX/K5CPPaR+ZDNyv7T8jdZibUxt9K'
                          'EGUL9GjYHGC/tRdeCDpBOyeKRc0m2LKJUubXbGcpTrHtIjZBdyYaWt0mwoFutw0ibPF6NXyyffT2DSHJ8KEuyHUVHGz5'
                          'HrIK/0o8ZJ3wVuQtV9aSijUvEQ91Abqnp8P8quScpi1PL0csIam61DU5y2B6yxaeSl3LyVdmSatQyf+mBak1qOzUvAt9'
                          'B4sKtR7vVx5CdLpIIszEfQRKE7kNimzc4oI1/33ajoJElL4XZkWf85yl//Z9QxM87YiG+k8XEa2tP9fahpVEjWylok1v'
                          'Fko5YmL2LdSbpHo3bq03UvzYE9RLYd9+IWlKFPR/F2WVr4RbSv0zypZX18aum0WEuwqYwu+p3IhfAsejTvpvWFoIDOy3'
                          '3IpXM/GiRcC/GA5IdQg6Wk/d+70H57N9p3z6PxeU+gayg+zxYiK/ws1Is8tIUy6Di9SP2Ha2dCXsS6D10EC0kuCO0oKJ'
                          'L12PlB0l18B5GVkGWj8zLhAtmGLs4sI+Dxfm6FZltltI9DBXsPEqha90sF+UHXplhDs4l7WmfR57yCzvdnSdck6STUYn'
                          'Uv8EvgJ9GfO9G1fSqaHnUSMuRCgpKxP/0lsteHupEHsS6ju9+t6HFnacC228i+mukA8nGFCGUHEuuQ6PhYlKO1hF4IsQ'
                          'WV5Uka5+OGpHeVojWk6QMxGn1IeAdJfnz60CP7o2SzX0rkZPpIA9iCrOOTCLt5xf3Fp6EpUWegYxM/Fc5BYp7maW47yt'
                          '65G4t1ppRRUv7NaAJIUrHeADxH9lMgXkZBpKNJNqqojAI268lWlCpIlO5DuaVzE2wzgHx0j5C9mGxGjXROI1lRQgm1wX'
                          'yE2mbqDWcQHaONyHpKUia9F/WleIAcXbw5YRvwU3TdJp2JOZxZ0SsrtqIA6u/J0U01L9kg+5DVcz+6sEZ7TBtAj6A/Rr'
                          '1xs2YrCiT9iGrw40j0ohPiH1EKVNbsAW5EEzX2c+QTL55u8yjwT6gFZT3W8n2U7jVaKlTcc3od8D+RdZPVeLGYHah724'
                          'OMfoziSTvPAHcigc/NxZsTdgLfQ+dGK+Sh9yLXzANoPa0eT3iFNuAzgdv0o8DBAzS2xLYXiUAfciscxatvNgNI0G9EYr'
                          '2B7KuT4qj55ujPs1G0ezj7kRB9A4nptozXARKWreika0ePjCNZ2NuQcH0V9f3tqcNaYot2M9rncxjZGtqNBuR+Fd3wQi'
                          'vjklBG5+YudE7MY+QA9TpkUX8XiXUuZvHlkIPoeliGJrM084n+d8DnUaplo4mzV85FwdGg+al5cIPEVJBlGLs3BpErIg'
                          '6YEf3f59Hjdb3TcZ4E/iH6nGuRIMTrGEDR669Ga6n3FIoHkUhujdYymeoQ1DI6Qb+IbrD1EqQCugnchXyCe1D62szo/+'
                          'N85EeRRX1nndYR8zK6Ya+PPvdyqn0nKkjIb0NPSU9ji7rerEM3xXmoeKXR7WQHUezry+i4x9dHbkiz4P3AN9Hj9DMpts'
                          '+CBSgfczaKDsciuRVZ/Y183FqKgiczqQY/+pB4PotEq1EcH61lcrSWUrSWF5E/uVH+2CKKL6xA+yVOd+xBIrqaxlmxHW'
                          'iK9XFUq9tK6Lg8R/axBHNk5qGb5geAiwlruFQLsfH0RfSUu7VBnzucAtKtP0P7IKTaEnh1wcZYr33ADUgUXI1njAlhCh'
                          'oq/Euq09Pr+epHT5SfJLwnd9YUkG7eQDWuk/iVJzeIMSb/HERuuS7khj0XPR1nnZNeQhb1BuC/oN4t9YjVNAyLtTGm0W'
                          'xHWUMHgEuQS2QV2Ql2D3LRPopuDD+nPoHshmKxNsY0g10oG+gO4OPAh6mW5xdQrCHEzTqIYg+HUPD/+6ixVsgA3ZbGYm'
                          '2MaSaHgB+iniSLUCD4RDQtPmkArheV+N+LBkGsQ4V0zQok1oU0Yh2ngzmCboyplUFUjr4JuUGOQjnI25FrpJ0jW9hxy4'
                          'IXUX3Fr1AGVit3uIy1M3htaS3rWLBbcWcYY/JFLKxllNq5B/mb45mMnbzaOKygAGJv9OpBwctWzpevSTfTiHURVYPNQX'
                          'dD91IwxmTFQPTaT3VC+mj1IK1qQY9EJ9LN6aRo9VEk/It2oEKQE2l+3qIxZvwSW6Ilqu6D4a+8CDVIL09E+hk6Z7JSJL'
                          'ySLBbrE2hcBZIxxuSdKUg304h1bxFFTkNyEIuoIctK0k1vMcaYich0pJvLCHODHALWFVH3qQ2EOeY7UIpNlj1mjTFmPD'
                          'ML6WboVJsNwMNFqnmJoVHU+cCFjNwe1BhjTJV5SC/nB25XQvr8WBuKUB4FnEmY4nehIZj7UbP/rBvIG2PMeGAK8Hbg/c'
                          'iyDimr70dNr35TREnkaUoyO1DS+puRH8YYY8yrWYl0chXhgUWQPj9bRBM1dpMumXwy6pr1LjTQMi9jwowxpt4UkS6+C+'
                          'nk5NF/fURKSJ93tqFcxcXA6cgBHlIoU0CukKUoh3ALmnmX5QBUY4zJG5OAU1GTqmuQRob2/+9DLuZbgTWx76REdbrH7B'
                          'RvOgP5vWciX/Y+JNrGGDPROBo1onoXcBUS6lAqKAvkRjQndHcs1ntRM5RT0WioNGXo01B1zgqqA0s7UcvD2E/TynX7xh'
                          'gTShfyKkxDRusi4G3A9ahX9xzSTdTqR724/zuwkSGTYspoFt2DwNnoThDaCLwYLfhslPx9CRomuwV11Xoq+ox+Dh9ya4'
                          'wxeaKCDM9ONK39FFTosghNL1+BDNe0lFBQ8UGkmcCrLej7kUP8rdRWSn4i1cUeRBknDyLB7iNdRNQYY1qFAWRVnwKcQ7'
                          'btN3pRb+77h/7jcLF+CCVtn4PuGFlkd0xBX2gJ8EZ0V7JVbYzJM7GOTUGehK6M3reMrOqbkR6/wkiiOQf4D8g5npVgG2'
                          'OMGZ3YHf094L+iuN8rjOSXHkBui6nItJ+MLWFjjKknFRTj+zbwL2hSzmEDF0YS6zLKDtmLBHs5yhm0YBtjTPZUqA4Q/g'
                          'aK7b1qbOJoGR/b0Xid6ciPbQvbGGOypQxsQ/0/vob81CPOtx1NrMuozHEHcp4vI125pDHGmJHZBdwGfAt4BM2SHJGxgo'
                          'd7UVe9aWQX7TTGGCO6kL7uZ4yq77EKX6YDHwKuRdU5doMYY0x2dKBWHbvRRPe+I/3iaGJ9DPAp4J2oMie0otEYY8zoFK'
                          'jOFJiFSsv3jPSLIwlwO8oCeT/wb1A2SJpeIcYYY8amiBroHY+E+kmqE91fYSSxng18APggqnG3RW2MMfWliKoh4zGJzz'
                          'Es2DiSEJ8MfBI1y7ZFbYwxjaGIxLobDTI/bILXcDFeALwOCXatzZbKQ16VGt/LGGNamQIS2/iVlg6kv69Dbau3xv8xXK'
                          'zfjHqCZDGx/FmUN7gGpaUMYNE2xowvCkhgpwEnAa+NftbCPKTDe4GvxP84VKynoukGZ6DoZFrWR6/fRK+nUTrKiFU5xh'
                          'iTc4ooX/pk1Mf/EtQE79iU79eJdPgK1NTpwND/nA5ciiYTlJAFnOa1AWWQnIJSUdy32hgzUYhzpk9BOriB9FpaQnp8Kd'
                          'LnVwKMq4CPoaG5aYpfDgL3AV8HvoMmwxzA1rQxZuJQRrq3HWngIRQsnEe4tyJ2GU9HnootIBP+OhR5jP3KIa9dwA+AK6'
                          'M3dpWjMWaiU0B6eCXSx12Ea+sA0uXrgGJ79IZzUfVMmlS9x4EvAncAg+m+lzHGjCsqwD6ki+1IX98Q+B7xdnOB6e3AYh'
                          'RcDJ08XkKlkbejQKKF2hhjDmcQ6eMqNIh8OWGFhiWkz4vbkNqfBbyGMMt6F/BN1Cx7e8B2xhgzkRhE7oxuFHwMaTVdBl'
                          '4A9hRRuskywhO59wJ3M2RUujHGmBFZj/Ry1DaoI1BE+nxyESVwLyHMNK+gQpd9gR9sjDETlX1IN0OKA9uQPp/UDlyEHN'
                          'hJszhKyAXyCMNq140xxhyRl5BuLkYN85IYyAUk1t1F5PQOGYhbQgMd70YNs40xxozNbqSbT5E8oaOA9HlpmlS9OPdvA6'
                          'PMCzPGmBopDvlZoGpQHikvudXpQboZ17QEFcqkEesycpJvZ5QRNMYYUwNTgDlI0GZHr+nR/8XzCmMf8G7CfcHNoA/p5l'
                          '5SVHen7Vedp7uZMab1KSA9ipsirUS5yTOBU1Fjo2XR765D2RXrUK3H08ATSLDLjDBlpUWoSTfTiHWFap9qY4yplTbgaO'
                          'AyJMyTUG/9BSgneQEwn6ob5DWouOQ1yKrehvo+70FuhjuQgLeiMZm6x38asS5wuP/IGGPS0IFcHctQW9H3o6IROFxfhm'
                          'tNEVncM4b8Wyx+W4CFwC1IuA8AvZmuujZS66fHdhljmsVCNELw9chyPoqw4ryRBH0+8KHoPe8Avo9cJLnHYm2MaTRTgP'
                          'OAtwBvR3nE8VisWulEecwLkWtlNvBb4F5yXheSxc5pJeyaMab1ORP4O+B6VOfRRrZaVIjecylqL/r3wBszfP+mkGfLuh'
                          'sFGeJ5kdvQ3MdmMBX1WJmNcim3oubjzUhtnAwcjyyLfuS329iEdYACQ0uRf7EcrWVDk9ayjGrAqhfYRNTQ3TSUy4E/R7'
                          'MKp9T5swrRZyxDog3yZe+p8+fWhbyJdTcSxLmop0kcFS4jcXwUWIumAu+jvhkr7Sg4shilGF2ABHIfSiv6AxoWvIn691'
                          'DpRL66OeimcQ4S7J5oHQ+hzl3b0Ila7/2yEDgORfZPRTfUUrSW+9HNYytKtaonHej4nICsuWPQYNMD6Ng8hm4eO9C0o1'
                          'bMHhgvFFH63SeRYNcy5zXNZ59H9fr8BcPmGuaBPIl1G4oUvwPdlZegaPAkdJEdAq5BF91XgC9TX8t2IfA+NNQyth67UW'
                          'XSQXQyvAR8AbipjusACeO/R/tnFtovU1FrxvOAa1Ei/veAr1JfkTw6Wssl6IKcTvXCPBd4GxLtW4Cfof1VL5YBf4PG1c'
                          '1CVnU72i9XoJvXo8CPgDtxRW49ORn4SzQ5pZFCHdOJzof3ouP8a+p77mVO3sT6HJTes5TRfVwFZC39jPrcQWciMXoPcB'
                          'qv9pXPiX6eFH3+i8iS20221lsnsqDfiwR52gi/M3vInweRUN6HXCRZ0oEs2PehG+pRI/zOTCTmJ6D9sA54hvoMrlgVre'
                          'UaDk/xGsryaC1tyNpfU4d1mKpl+3rCejlnTTvq378JXQOh7UqbSl4CjN3AicDrSNZ7+3TgU9HPrJmBkvevRdbCaEHNIh'
                          'L1/52RRb0WCkj8PoSGHY8k1MNZhcTr5AzXETMnWsefIN/waEwDLkbZAMeQ/XnYDnwc+SmPJNQxM9EFfBGeIVoPuoCzkV'
                          'CPdSxGY2gxXtoqwCI6T89F2tBdw3oaTh7EuoissfcgsU5CO7JqTyL7R66FwFvRydeV4PenIyE4jux9otPQlJ+FCX9/Dr'
                          'rRnEF2xz4WtxnohpS03e5S9ERwMdkeo05kMZ/M2DeNoWu5ErnXmvGIPp6Zi47zFdS2b9dRjQOtJ/3TWAHpwvXoJpIb70'
                          'IeFhq3cX179DMpBRR0m45cIlmxAAU2pwZs0x1t10V21VRx68QQa6WAbhrHoGOfpStkZrSepHQiS/904DsZrqMT3dxBF3'
                          'SSc7wbuBBYjXzYWcU6CjhouYRq8D2EQaqB380oV3ovOlaTUXzmBGSAzCbsRjAbGVx/AB4mJ/Nj8yDWIBEYyQc6GrGYZe'
                          '0j6yL88Sl+/JqDglpZBTY6CJvwQ/T7nSm2G412dAEkedIYSjHaNmv3UBvhIrkI3ciyuibmohtpHvroFNEaB1G20MEM3r'
                          'OArpMVVGM4IaxB1Ye/RymWL6Prpg0do2koy+hsJLznkPzYFZCxFVox2VTyItYVwqevxxdr1gejlGItIGGdiqbsZCXWhR'
                          'Tv1Ycs6qwEsoK+W3fK9zxEttZnBX2/NAKZ9jsM3f540syOQgAAGBpJREFU1DHuWCQoeRHrClWxjlNPn6/xPU9AIjoz4T'
                          'YV9OT5HPBd4FuMXSPwBLq5dKAn3k6SH8OZ6EbSRw6s67yINaS/oLN+DE17Mcc3nGavpx5NuOLgTxrqEdBL+55pbsIx3c'
                          'jK+yTKfJg8ZB2t7goZ3tR/N3Az8K9IsNMG885CMYmkrroKyg76HMrk2pxgmx3AD9F3+BCKmyR1iSxFbriDyIhq6eM03s'
                          'W6Hju/lpvGeO0BPl6+Vy3f41SUCfM2wt1BrcZ84MNIcD9PugrYAsrgOp7kLrd+VKh0G2HVpVtQDcF8wpIKlqDj9iTZp9'
                          'VmTm78Nca0KEXk3rocuIr8CzVItBajmoZzU75HG3IzJDUIB1DGx0MorhP6dLQVuAfVNCR1acxDWUPTx/rFVsBibUxtTE'
                          'FpaVcQliHUysRCORVZx1MJF89uZOEm1Zh9wE+BXyGxTWPlPhO9R1KrfBZyWSVNN20qFmtjamM6Ku45DQW5xhPtKEh4Bu'
                          'EZUHFGTtJYxkHUN2Yt6XVpO0rxey7h7xdRRsjQ+ELLYrE2pja6kF82TXpaqxPnrJ9MeIe8UP9/mWpriLTB6l4k2CGN03'
                          'rJQSYIWKyNqZUyaoyVq6ZACamg79VHuICmyTqq1botkq6GoOWtarBYG1Mrh4BHUGBrvDGAUveeQt8zhFDLOm45XEtq6Q'
                          'zkYw8poEvrH284FmtjaqMHVdk9Q2sNZs2CMmrzm+a7DRDmXuhAJemzAj9nKDNRbvexAdscJPsOlHXBYm1MbRwCHkQtN+'
                          's9TKGRlFD+8QPIBxxqfQ4gfUmqMVNRc7SLU3xWzDIk1nMSvkecLri/hs9sGBZrY2pjEKWK/YFwV0Ersx5VMT6ScvvYx5'
                          '3UpTEFCfWbSVes14l6u8SdFpN87hZUrr4Xi/W4JK0/rUj2g0FNa1BB3fo+iyr+HiW/AccdwE+AG6KfaSeCl5F76AmSux'
                          'mmoRa+f4E6QyZlBvAR1L88JCtnHXA3yiBpebHOS7l52qBDPaK8acveB9EF3OymPvXoDVLLe7ZSb5BavseLaJTcLNQF7n'
                          'qU0pcHP3YBuT12Avei0u37kT8+7flaAn6D+m8sQqXgY1FEroy/ij73K9Eaenl135YiSpssoAEff4oaOYVkgmxE5e17sF'
                          'hnRgfhUybiVplZf8e0F/Qh9LiVZU5nmn7JBXSiZymScavTNE8NWbZqhepxT/P9kkzbORJlJCovod4Wa1DBTC3NoRpJ3P'
                          'FuOxp7Vav/PW7KtJqwlqtFdMO7Donvraip0/Dc6UlIpC8Fzke54KHXeh/ZX5N1Iw9iXUE79GmUlpO0kqoNHYysh6DGLU'
                          'ZD6UFJ/1levCXCS5wLSFiyXEcvurjTnPT9ZGvVlNCNMeTGEXeae45s9kvcfzmPxGOzaiV+mlyH9m2IWwNUObkclYIvQi'
                          'mEcWvfCirWuRINNphFmJb1o5vSGuo7VDtT8iLWG1Ej8mtRl6wkDKCGMDszXs8eYANhN44Osr+Dl9ENINQ32oP2S5YnaR'
                          'l4gao1VmFsy7Yf7cstZOsa6kPtLg+SXHT2A3cAvySbIGEeelg3iu3Iwj6RsCrIIrq+LgbORMd16PHsRE8uIdOJiN5jMw'
                          'qe3klO0vYgH8GuONfzdiQISVmPLKWsD8YLwLdR4CQJfShQ8wTZ+8V2If9i0qnch9Bj5d11WMs21JfhJZK5IIpo7XeSbT'
                          'CuhKza50luJfcg/+rd5OjizQkvAzei1MY0dKPueEuQ/zt+LSBcqEHn5h7kWsnqSaohtAGfCdymH6UpPUD2VuuRGETWzy'
                          'JkWY/miz6A8kNvBn5N9rmvvUgI2tCj2jSO7HfdiQTsn1AKVNbBpn7gWaoDgrsY2R8dlw3/BvjvKKiSteU3gL5v3F5zxg'
                          'jrIPrcXej8+Sw6VlkLZD9qzjMr+jmZkQ2TCjo/foumkqRttG+OzAAycIrIB510aky92IWMpxtpfF58Abl1zkX7Iqidbl'
                          '7EGnTQt6Co+wzkzxpOH/AD4EvokXYz9bn4+pEvbguaPTiSP24HumF8CUXW63FixM1v4uY1M5EFMpwD0Vq+gCyceliPZX'
                          'Q+bEI3pWMZuRptCxLGG4DHqY/PsIL2yXPRz0XIOhvOHuDrKN1uNTmysnLGIDoHZ6Jc6KznooZwI/DPSEcafWOuSazz4L'
                          'OOqaCLbwvyR+5EPqt45loFCeg3kDjWM2WqQFWM+9Gj3gKqw18PoRvaD1F1Wz2jzQVkXX8NBXK2ov1SpDpGbA3aLw/VeS'
                          '2D0Wd9O1rXxVSPTwkdt8fRNPOkbqS07EAW80Z0PC6m2mS+FK31KZQe9nid12L01HILMmze0oTPL6MnypvQ01wumjcNJU'
                          '3q137gm+jR/pkU22dBPOiyEwXv4u+xD/lMGxnhjacsT6aaMtaPAoo7GryW2ejO3U1VrInW8hKNK9QooLzaOVRT+kpoX+'
                          'xH1m6j0qViayaevh5nw8SutZcbuJaJzgyUJPBvqbrtGkEfKlT6VxSz2dGgzx1OPOrsz4APEJgqmifLeih7olcrsJ/W6Q'
                          'mxK3o1mwqy8Lc2eyFUXSLbm70Qw17g5+jm+CaUJ13vPuCDyKL/PnAXrXF9pCKvYm2MySfPA99FT+V70OzKowifRDMW/c'
                          'iC/j3yAsQuwNwGkC3WxphGcxAFuncha/cjyMrOil7gYRQz+h2KSeTe1WWxNsY0gzKqSn6aamrpDOQWWUB46f8B5Hbbje'
                          'Y4/golAOzNaL1NJ61Yh06BMMaYkSigoN/9KFvnbNQm9QKqAeGxtu9HDahuQ+L/IsoWC5nF2ChSa2casY4nFruc1hhTKx'
                          'UOTxh4HqVb3okyijqoTkofSpwBVkHC/CAqPGtWpkdSYu0MFuw0Yj20m12a1D9jjDkSO1Bridujv3egFN3hxmERac8hDt'
                          'egVtakAtLNVF0h04h1O7rjLUXVaiHtD40xJoQBwuoDWlWoQb1MliL9DNbeIuFR0nZU6r2S2vr/GmPMRGIa0s3lhIv1YB'
                          'FFT0NHxi8BVtDcGn9jjMkTk5FuLiFMrCvA7iJqYBN3S0tCAaXWnES114IxxpjRmY50cwHJfdZxAHV1ESWPP0t4x7HFwM'
                          'LAbYwxZqKyEOlmCCWkzw/HlnVIo/aYeSgf8jWB2xljzETjNUgvR2rVOxolpM+r21HbwBMIF+uZ0YdvQ32jG9nb2hhj8s'
                          'IcNPH+zYQPXyihqVePFdEUhzSJ5AXU1P184JQU2xtjzETgFKSTi0jXR3sH8EIR1c7vJt30kC7gLKqNWHLX0NsYY+pEAe'
                          'niR5BOpunf3Y/0eW88O3AOGrczh7BWhQWUjnIMasKyFTVUGcDl6MaYiUk7cne8FvgEcDUafhFqzO5FCSA/ATbEYn0AVS'
                          'KuQGklIVPPC6gyZwES/EVUx0sZY8xEYxXwQeC9wEVoUlGoUJfQ+LEvoCZVPXFi9g7UseoyFLU80rTu0ZiHGomfiu4it1'
                          'Md5How+tmD8gbtLjHG5JlYxyaj/Okp0c95wB8B16ChCh0p3z8W69uImlzFYl1B1vAa1BA8JGk7poAarhyN7ipvRtb1at'
                          'Rf9kkUzBwgZSMTY4xpASpITDtQr4+VyCtxKtLOOdQ2rqyCdHgN0mXg1SWPv0QDHd9DbWN24sWegL7EZtT2cDv6kiFuFm'
                          'OMaTXKyOich3p9LEaWdBb0Ic/EL4f+43Drtg24GPgH0rtDhlNBzaIGCM/lNsaYVqYNWdhxy+haKQF/AP4CjSR7RTOHW9'
                          'YlNK/spuj/TqF2wS6gL5PWd2OMMROBEvAU0t/HGWbcjiTEg8htMROJ9aQ6L9AYY4wCid8Dvo4qww9Lfx5JrMvIqV1Cvp'
                          'g4oumAoDHGZE+F6sT3rwOPMkKdymgujj3AfmAqinh2Zr9GY4yZ8PQAdwDfAO4Bekf6pdHEuhfYEL3RAuQW6cYWtjHGZE'
                          'EZpeg9CHwZVSruP9IvjxU8HAC2INHeg9JU5mayTGOMmdg8A9yILOq7USX5EUmS6dGHxHo9uhNMR66RWvKwjTFmorIXeA'
                          'JlfXwN+aj7xtooJC3vIEor+T3VOYzx9gXsHjHGmJEYWmuyC/gh8F+BnzNC1seRCBHrMvJfP49cIztRReIgtrSNMeZI7E'
                          'V5078Dfoos6vuQnibuTprGGi5QbWKyGPUAeTdwDiojL6CbQPyyxW2MmQjEPUPiVwWJ8YPAV5BQx70+Yh1NTK1CWkBDIE'
                          '9GbpEZKAh5HLAM9QaZk8HnGGNMKxNPIX8WeR/WUe06+gIqId9eywdkKaIFJNZLgTNQB6qzop+zeHVpuzHGjAcGkcW8Gg'
                          '0LWI1m276AXCBBFvSRKFQqmbyPMcaYOuJWpcYYkwMs1sYYkwMs1sYYkwMs1sYYkwMs1sYYkwMs1sYYkwMs1sYYkwMs1s'
                          'YYkwMs1sYYkwMs1sYYkwMs1sYYkwMs1sYYkwMs1sYYkwMs1sYYkwMs1sYYkwMs1sYYkwMs1sYYkwMs1sYYkwMs1sYYkw'
                          'Ms1sYYkwMs1sYYkwMs1sYYkwMs1sYYkwMs1sYYkwMs1sYYkwMs1sYYkwMs1sYYkwPam72A8UShUDgRmNSAjyoD+6I/Hw'
                          'D2A30N+Nxmk8X+3QDszWAtQ2nUcR+Ng8AAUELnw57mLqdKpVJp9hLGBQXvyOwoFAq/B05r0sf3AVuBl4EXkCg9B6wGnq'
                          'SFLt4ayGL/vh24JYO1DKWZx/1IlIGd0WszsC56rQUeB9Y3aiHWmGywZT1+6AKOjl7njPD/a4EHgDuBXyExN+OXIjAvep'
                          '0EXDbs/3cDjwF3AL8AHkECb1oU+6wnDiuADwBfQFbVWuCzwHnNXJRpGrOAS4H/DDwIbAf+BZ8PLYvFeuJyPPBXwH3As8'
                          'BfIyvMTExmA3+Kzoc1wHVAZ1NXZA7DYm1AVvf/jXzdX0JCbiYuJwJfRjGPjwGF5i7HgMXaHE4X8FFkWX0V+b/NxGUp8E'
                          'XgbmBlk9cy4bFYm5FoAz4MPAP8R6C7ucsxTeYCFIz8d9jKbhoWazMa3cDfodS0C5u8FtNcOoD/BnwN+7KbgsXaJOFElP'
                          'L3GWR1m4nLB4HvY8FuOBZrk5Qi8H8Ct6O0LzNxuRq4Ed+4G4rF2oRyOSquccbIxOYdwH9q9iImEhZrk4YVKENgVbMXYp'
                          'rKXwNvavYiJgoWa5OWBahU2YI9sfkiML3Zi5gIuDdI6/EksGOM35mEcqJnAotp3nGcC/waOBf3GqmV21CjpTRMRufDLG'
                          'AOyo9eRGN8youA/wul9Zk6YrFuPf6WsK5wRWTlLked385GjZxOzXxlIzMP+ClwPuOjs9//3979x2pZ1nEcfxMHDTTQJt'
                          'nQ5SGcEUOXwaZ/SEE/RjXLpcs/1JFbViswNX/gMquxUGqiOGBaG5RSOGkrLd38kVGZush0YaWVE9wCRCeEiHImB/rje8'
                          '48O9zPee7nuT/Xc9/PuT+vjfkXn3NNDh/ucz3X/b3KsgbtNMBxxACn04GPEIOceoX5Q30duBX/g52Ut0G630FgBzHT4X'
                          'bi9eBTgROJWQ8PkH6a2nRgHX5hokreAp4B7gQuAaYCs4FVxAx0pXHA1eJMG8ZlPXptIybsfRqYRkzYezXh1zsbuDJhvh'
                          'X3V+BSYozAcuCAMPtivHedlMu6HrYC1/J2ae9P9HWW4hkS3WA3cBVwFvGPusJ44AuiLMvgsq6XPURpTycGzqsdQZwO8P'
                          'dVd/gzMBddYZ8ryrEM/ktVTy8CnwKuIPY2lc4EFogzLZ3niSdixZbIPPwaejIu6/o6BKwA5vP25bsqN1L+BbKW3xPAbY'
                          'Kc8cCHBTmWwWVtG4E5ND/b3Yr3AguFeZbeDWiermcJMiyDy9oANhOnRpRHuhbjOdjd5CXimGdR/oA5EZe1DXoS7V7zcc'
                          'CFwjxL735BxvsFGZbBZW1D/Yp4E03lG8IsS+8xQcYUQYZlcFnbcNcCL4iyTsMfOHWT/wgy/GJMIi5rG24/cJkw74vCLE'
                          'trP7CzYMa7FAuxw7msLct9wKOirPPwzJBuUvTtVh/ZTMRlbY3cIMo5gZgCaN2h6Ikgl3UiLmtr5EE0e5jg20S6ydEFf3'
                          '+quTO157K2Rg4RY08VPi7KsfQmFfz9fZJV2GFc1jaSn4lyzsQ/HneDYwZ+FaEeXWADXNY2ki3AXwQ5PfgIXzf4oCBjhy'
                          'DDMrisrZlHRDlniHIsnTmCjO2CDMvgsrZmVGV9mijH0jlbkPEvQYZlcFlbM4+jmcbWqQt8rT1T0TxZ/1OQYRlc1tbMG2'
                          'ielhT7oZbOYlHOJlGODeOytjz+LsiYALxHkGN6s4kb0IvaCTwnyLEMLmvLQ/Wjba8ox3QmAncAYwVZqs83LIPL2vJQfW'
                          'h0oijHNMYDG4AZorwNohzL4LK2PFTHsbwNUh2TiRvu54vydqO5acYacFlbHi+LciaLcqyYc4BngLOEmT/Cr5on5bK2PF'
                          'RP1seKcqx1Y4gZLRuBe4Djhdl9wGphnmXoKXsB1hX2Av0U/xDKg+k7qwf4EPEkfT5wSqKvswL4b6JsG+Cytrxep/hEtq'
                          'MUCxmlphLF2o5JwJHEJcVTgJOJc+2zSP//fDu62ec2Ape15XVQkDFBkDFa3Vz2Atp0MZ601xHes7a8/BfShlsGPFz2Iu'
                          'rCZW1m7bgXuK7sRdSJy9rMWrURuADN1pjl5LK2vCaWvQCrhIeIUapvlL2QunFZW16K75V9ggwrz1pc1KVxWVteiiNgLu'
                          'vu1Ad8BfgS8FbJa6ktH92zPI5C872yV5BhnfU4UdIefVoyP1lbHieIcnaJciy9bURJz8FFXQl+srY8VAOYXhHlWDpbge'
                          'XAGuDNcpdiQ7msLY8popydohzTOkQMd1pLjDlV3LlpYi5ry2OaKMfDfqppDHAbfhux0rxnbXmobhLZIsoxvZvxw1ul+Q'
                          '/H8pgpyHgNf8A4krXEhQCtGgN8j+IvLc0Evkw8YVsFuaytmR5guiDnWUHGaPYbYt+4HeOBpYI1LAHuAv4nyDIxb4NYM7'
                          'OJMiiqnadGy+cW4qhdUccB3xHkWAIua2tmrijnb6IcO9yb6CbgLSLdjTJWgMvampkrytkkyrFs64DNgpxxwE2CHBNzWd'
                          'tIJgHzBDl9wNOCHGvsIHCVKOuzwCdFWSbisraRnAccIch5DA8A6oSHgQdFWT7KVzEuaxvJBaKc34pyrLlriDcSixo8ym'
                          'cV4bK2RqYBHxNlPSDKseY2Az8VZS0BjhFlWUEua2vkcuKFi6K24P3qTrsezRAmH+WrEJe1ZXkfcIko65eiHMtvG7HnrO'
                          'CjfBXhsrYsS4F3irLuFOVYa36AZiStj/JVhMvahpsHXCTKehrN2V9r3V5iZoiCj/JVgMvahppEDBRSWS3Mstb9GPi3KM'
                          'tH+UrmsrZBY4A7gF5R3i5gvSjL2nMAWCzK8lG+krmsbdBNwDnCvJX4WqgquAf4kyjLR/lK5LI2gGXAN4V5e4AVwjwr5k'
                          'pRjo/ylchlXW9jgVXoflQetAzPRK6STcDdoiwf5SuJy7q+jgceAhaKc1/ET9VV9C0081l8lK8kLut6Op+4DED1OvlQlw'
                          'L7E+RaMS8QP0Up+ChfCVzW9XI6MZntbmBygvwNxPVUVk3fR7c95aN8HeayHv3eQTwJPQI8BXwi0dfZBnwtUbZp7EJzVy'
                          'P4KF/HuaxHp7HEFsdKYCvwa9JseQzqBy7Et5d3g5XE5woKPsrXQf4xprv1AFOIwUu9xDbHGQP/ndDBdVwB/KGDX8/a10'
                          'd82PhzQdbgUT7lsU9rwGVdPbfQeKZDD3A0cdv4kcBENGNMi1hFPK1Z97iLKNhZgqxFwO3oXmu3BlzW1dNb9gJasB64rO'
                          'xFWMsOEfc1bhRkDR7l+5wgy0bgPWtr13pgAXFRq3Wf3wP3ibJ8lK8DXNbWjtVEUfeXvRAr5Bp0f4Y+ypeYy9pa0U9c97'
                          'UIF/Vo8CywRpQ1E/iqKMsyuKwtrx3E8b9by16ISX0X2CfKWgIcK8qyYVzWlscvgFOBP5a9EJN7CfihKOvdRPlbAi5rG8'
                          'lW4PPELJFXy12KJbScKG2FhcAHRFk2hMvasuwhXpyYQQyvt9FtH3C9KKsH3c3qNoTL2oZ6Gfg2cdb7RnzTS538BPiHKO'
                          'szwHxRlg1wWRvEXvQC4CRi0I8vDqiffrSXUPgon5jLup4OAk8Qb7GdBHwUWIfnUNfd/cDvRFkz8FE+Kf/LVw99wGaioB'
                          '8lxqXuLnVFVlVXA0+imTmzhHjT1d9rAi7r7tcPvDbw6xVgJ7CduBnkeeC5gV8HylqgdZWniIl8FwmyBo/yXS7Iqr3/Aw'
                          'MkQ3KXnLLlAAAAAElFTkSuQmCC')
        buf = buf.replace('resources//RP.png',
                          'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAWsAAAHoCAYAAACPYs4OAAAgAElEQVR4nOy9eZRk5Xnm+Y'
                          'vItfa9itqoKoq9KLGIHQQCBLKEsCS0oN3CEra6pbHa3bZn2uPxcU/3OT0euz09tgdZsqxdSEJCIIF2CSH2fS2goKiFgi'
                          'qofc/KLSLmj+deIkmyMu9348ZyM5/fOXGylrwRX9yI+3zvfdcC4482YDqwElgFnAKcEf2cBxSatzRjTIZUgB3AGuDR6O'
                          'fTwHpgP1Bq3tKyZ7wIVzuwFDgBWIjEeiFwNLAcOB6Y06zFGWPqyi7geWATsBl4BYn1K8BzwEvAYLMWlxV5Fut47UXgJO'
                          'D3gKuBk5F4F6NHW/TI83s1xhyZCrKiS0A5egwCzwA/BH4e/bmMNKHcnGXWRp4FrA24HDgHuTiOQ5Z1dzMXZYxpGXqRZf'
                          '088CBwZ/Qzl7Q1ewEp6ACWAZcB1wIfAFYDC4DOJq7LGNNatANzkSF3BjAFGagDwCFyZmHn0bJeCfyvwMXILz2tucsxxu'
                          'SEXSggeRfwtygQmRvyZFnPAC4APg58GFgCdDV1RcaYPDEZWdorkHYMALuBvmYuKil5EOsiOsGXAJ8HrgRmNXVFxpg8Mw'
                          'k4EYn2HmAn8m9XmrmosciDWHchob4OeAtKyzPGmFroBo5CKb3bUdpfS6f3tbpYtwMXAp8E3o5uY4wxJgs6kTu1Ewn2S7'
                          'Rw0LHVxXoF8GfAO4GpTV6LMWb80YGK56ahKsg9zV3OkWllsV4BfAL4EPZRG2PqRxfKLOsDXgT2Nnc5I9Pe7AUcgZnAe4'
                          'A/QsHFrOiPHiWUtpjH1EVjJjKV6NGG3BdZ1VbMRXqzD/gqLSjYrSjWnagi8VK022XFLmAdqmjaS7UM3RiTH+Ky8pmoYv'
                          'k4suv7sxDpzkOo0rE/o+fNhFYU60Woz8eqGp+nhFJydiOhfg75pB5GifHtWKyNyRsllLUxDzgTVSaegAR7NrKQa7muVy'
                          'H9eRlliLQMrSbWcVOm30fd8tJQQcnua4EbgftQ0OAQsqj3Ut0x7QYxJl/EudBbkJj+GpWRzwLOAz6Icqg7SHd9L0f6cw'
                          '/q4Ncy2SGtJNZFlEZzIbq1SXOiK+gEPw38ArgJfaij/b4xJn/0o3S77UP+7TngAErzXYWyPEJ1pID050KkIy/TIoLdSm'
                          '6A6ej2491ItEM3kgrwKnAz8C/AL5H7wxgzMTgIPIu67MUpeVMJF+xBZDzuATaSk3L0RnIM8HVU9lmmGvVN8iihHfbfgH'
                          'MbvXBjTMtxLtKD7UgfQvSkjHTo60iXWoJWsazbgFNRk6YlhO+EPcDtwLeAexln43yMMcFsR4I7F7VUDknxK6A7+zLwAK'
                          'psbLrLtBXEuoDanr4X+YlCW55WgG3I9XE7uhUyxkxsSigTDBR4nE64EVhBedebaYHKxlYQ63ZUTv5xVLUYuqZdwC3Iqn'
                          '4126UZY3LMYSSy85G2hPYW6katmbegYGNTA43FZr54xCRUBHMyCgqEci/wbRxMNMa8kV1IH+5NcWwH0qVTkE41lWaL9S'
                          'R0i3Ia6QcJbEA51YeyWpQxZtxwCOnDhpTHdyF9Oo8mC3azxXo5StVbRbgDfwCl1axBtzvGGDMSh5FObES6EUIF6dO7SV'
                          '+olwnN9lmfCvwBSkIP3Tg2o9ubn6EAY9OjtcaYlqSMBLuCBDeki2cBVUgWUWbIxqwXl5RmWdZF5Lg/C6XVpFnHq8CPUX'
                          'Mmp+oZY45ECenEj0mXhFBEOnUW0q2m6Gazys2nAlegCeWhQwUqaLfbRLrbmg6qgUxb42a8UUDi1Dfk71l/z+M85DYkXI'
                          '28juL0uwHCrv3YbboJ+Z9jHUnKVKRX61Eri/0Bx2ZCs8S6G7gMOJvwwOIgal/4E9QHIClHAVehJi+dtEi9vzF1ogd1mc'
                          'xSWDqA89F1u5jmNUIrot4ga4FbSW4tH0C6cTR6DyHZZ13RMS8Cv2MCifXx6I3PTnHsYeCHyFedZGdtRx/O1cAfAktxtz'
                          '0z/ikBzyDD6LeoIVFaiuhaPQf4CLorbnYqWwVVFs5AerCZsQfeDiDdWACsJkys43NwNtKv7aP/+vhgBfDXwFbC6vXjx0'
                          'vAlQGvdyzwBZTYHtojwA8/8vzoB54A/hgF1dL6WqejRICfo7zlZr+v+FFC1/UX0HWelCuplpCHPrYi/VoR8HqZ0IxskL'
                          'cBH0UNUkIs+wq63fkl2h3jL81YvBn4LIoC26I2E4k2ZEVORW6RTahfRijHIcG/gvB2EPWkgNYzHWVqrE9wTBFZ1AuQaz'
                          'S0K18HqoTcjO5cGkajo5rdqBvWKdGfQxhADcG/iL50SXzOk9Gm4MnoZiJzLvBJ0s0zbUdW62rSF67VmynIGEtSTl5G+v'
                          'FFpCehCQrdSL/OJVzDaqKRYj0Z+XtWk04821D6zcMkq1bsRMnsZ9B8/5oxzaQbzRecSvg1PwWN0Grla6gb+ZGXk+xu/R'
                          'DSkXWk8y5MRTp2NuH9RlLTSLFeAryfdFNgBqiWlSfNqe6OXmslrf1FM6YRHETCFHLtxQUhk2nt7KlOlDiwjOTWf4lqGX'
                          'qodR1Pk3k/0rWG0EixPh75vJYGvm4Zpct8Dbgj4LgKyjWNhxkYM5Epky5mU6TxudRpaENWdch7vAPpyouEaUQR6dgVSN'
                          'caQiPEug2l15yGcjPTpAu+DNyGnPpJ6UNJ8C/SYiPljWkCU5AFGSK6FeQyOEhrB+fLKJVuK2HX+makK2nSGtuRnp2G9K'
                          '3uyRqNEOtJwOXABaRrgXoQBQReCTyuH0WH16FIuDETlQEkuocIt5APoCysVjZ4etDcxfWEuzReQfqSZmhJB9K1y2mAq7'
                          'URYj0NVQ6eSXg0uQ9FbG8G9qZ47X3A46Rvj2jMeOAJ1PRsN+FiPYjuTpOkxTWL9cBjSCNC399epC/3ED4Ytwvp2lU0IK'
                          'Wx3qZ73Lz7UyiJPPRWag/wJVShNEg6v9kgKgg4CuVjNrvToDGNog+5B76Mhr/uJ138poKuoTgrpKEpa6PQj+6cbwV+Tb'
                          'oS8AJyh0xGPUOmBB4/KXqOe1D3z7rFx+pdbn488C4klGnmn+2ldjfGNjTyaysqxjkLRY9bPWBiTC30o0KRm1Dl4e7Rf3'
                          '1UdgE3ouyJy1EWxFyadw0V0Pt7CN0x3I6u8zSUkL6sQ3ozl/CMmaOQzu1H47/qQr3F+mw0X3Eq+mCTnoS4WvF2au8fOw'
                          'C8AOxEmSGbgEVoB8xDlNuYpMTX1yASntuQ1Vlr06ESug43ojLtQyiwBo29hgpUr9utwG9Q29M0LtLhbER6M5Uw47ISHf'
                          'NOpDO5E+sCcoGsQvmIkwnbrXqBu4FvUlsDmqHsp9oAqhtZ1xZrM54oULU6e4Y8suRp4P9C11A3us4blRobi3U/0ojDZP'
                          'f+XkZ6MxtZyUkDhgWkb8chveskPOumaRSQf+sStPPFvuaQxx7gb2j+2DFjzMShiHRnD+GaNYj07hKkf5mnOtZDDIsomH'
                          'gN6suRxle9HXgOF7MYYxpHGenOdsIt4wLSu2uQ/mWurfUQ6wLqQ3AZ8v2EvsbLwA3AfRmvyxhjxuI+pD+h7tci0rvLkP'
                          '61vGUdL/hs1JMjTYrPehQUeZHWrpoyxowvCkh3biVdXnk30r2zSWeojkrWYj0FVfScx9hTG0Yibu69k6ovyBhjGkGsOT'
                          'upDkcJZRDp3wWE52yPStYFItOA65CTfTJhm0EvSiz/LqpGCi0bNcaYLBhE2jUHWcihWXMzUUHSHShjpeXoQrvJE8hRHx'
                          'pN3Qx8Dgm+3R/GmGYRT6D5HNKlUC0rIx28gAwHNmTlBmlDkdBL0W6URmzjUfEHsPvDGNM8KkiHNpLuDr+AdPBSpIuZeD'
                          'CyEutONOvwanQLEMo+VATTys1ijDETi/VIl/alOHYm0sM3I31sGWYB/4h2oVAXyAAqGb2UFntTxpgJTSfSpR9TrUoMcY'
                          'UMIF2clcViarWs47E/p6JSy9BJDfEa1gKP0to9c40xE4t+pEtrCdfKAtLDVUgfp1BjLC4LN8gK4H3AiSmOraDmJ2uovd'
                          'mMMcZkzX6kTy+QLpZ2ItLHFbUuJAvH97nAZ9HgyDTVit9ESei1tHA0xph6EAcb21DBy4zA4yejtqsPoVL21NRiWRfQDL'
                          'LT0Qj4NMK/GfXarbUNqjHG1IuNSKdCZsDGtCF9PB3pZWpXSC1iPQ053y9L+TwlFG19GafqGWNalwrSqfVIt0IpIp28lB'
                          'rGf9XiBpmPxnVdihzpodWKj+JqRWNMPiih7JDFyK0RUtVYjo7pBe4lZXwu7fCBNmAZsBpNSQhlH/AD4Jdo6oQxxrQyh5'
                          'BeLUDBwpAmdW1IJ1cj3dxKCgs9jfuiHU1F+D1gaYrjQTPdHkV9Y40xJg9sR7q1K+XxS5FuHkcKQzmNWHcBF6Lx69MDj4'
                          '0jqw+RzllvjDHNZDPSrzRtMaYj3byQFD1D0oj1NDQsczXhFYcF4E7gG8CWFK9tjDHNZAvSrzsJz+zoRLp5GikCjaFi3Y'
                          'Vq3c+gOpwzhArwMNqZegOPNcaYZtOL9Oth0o3+KiD9fDOB1nWoWK8E3oHyBkMpoTH2m0iX/mKMMa1ACenYS6TTsuVIR1'
                          'eGHBSSuldA1YqfCn2RiM2oWvFnwDacW22MySclNFSggoQ3tNPoNFTZ+BiwLulBSS3rAsoTPAf1Z03D88D38dRyY0y+ia'
                          'egfx/pWhqOQXo6l4Tu5KRiPR24CPlZ0gQl47lm8WxFY4zJM7VqWhHp6UUkzKpL6gZZBFwLvB2Z7yGBxT5k7n8H5Si6Wt'
                          'EYMx4ooSDhEsKrGouoCrwfBSv3jnVA0idfiiKY0wnPANmNhPoXQE/gscYY06r0IF2bgwR7YcCxRaSnZyB9HbOZ3VgujU'
                          'K0iPNRmWWajlGDyL/jFqjGmPHGbqRvgymOLSBdPR/p7Kj6OpYbpA24Evgw6Uokd6N6+luQb8cYY8YTsb/6aGQhTwo8vg'
                          'u5lncAzzCK/3ssy7obOBP1Yg0tj6wAd6FqH6fqGWPGIxWkb99Aeheqc11IX89kjOZQo4l1F/KnpO2sVwCeBR5BdfTGGD'
                          'MeOYB07lnSuYrjjnxnMIpRPJpYH4NGqZ9A+G4xiJp1PwscTHG8McbkhQrSuWeR7oX6rytIZ69mlDqW0XzWZ6N0vWPH+L'
                          '3hlIEXgRuBnyJfjMXaGDPe6UdxvcVoVmNSK7uApp93M0pV40iWdRE5vE9FjbJDg4oVVDd/IxqD42pFY8x4p4z07kakf6'
                          'EGajvS21OR/r5Bm0cS6+loVNcFpPdVb0K3BH0pjjfGmDzSh3RvE+l91xcg/X1DVeNI7o05wGeAtxJeBNOHHO3fQ+a83R'
                          '/GmIlECYnuYmAe4VWNM6Kf9zJGYkYBeAuwBpn1lcDHduDzSPBTj1w3xpicUkD693mkh6EaWkb6+xaGaehQN0gBtfu7DP'
                          'UCSSO2u6nOKLNVbYyZaFSozphNU7VdQPp7GdLj13R4qFhXgPOiX0pTALMDuB8liBtjzERmG9LDNNlwXUiHzx967FCfdR'
                          'tK1buC8PlgvaihyRdIXydvjDHjhR7gFdT7YyXQEXBsB/Jd7wJ+TZRRF1vWnSht5FhSDHJEbU8fA+5BExSMMWYicxjp4W'
                          'Okaws9FRXILCcS+lis5wKXoOhlmmrF7agQxhhjTJUXkT6mqWqcC1yMdPk1N8gZKF3vTYQNF6hEi7kB+DGwL3BBxhgznj'
                          'mALOPlaFZjaFXjTNSN70WQdf1xYA/haSYDwG3AqprfkjHGjE9WAbcivQzV2D1In4tFVI8+hTAHeEwf8CpypBtjjHkjW5'
                          'FO9qc4toOob0gRRSsTT9gdQh9KTfk5dn8YY8yR2A/8FuVehwp2Aenzgrh5SBqx3g7cBPwKF8AYY8yRKAC/Q5NkVhI2qz'
                          'EW62XtqMvTMYS1QQWlpmzEVrUxxoxGCdhCtb9/CG1In09tRxkgKwkX6/3I+W2MMebIxJ6HVwk3btuQPu+IfdazGXse41'
                          'D60ESEQ4EvbIwxE5UepJshraOLSJ8XFIGTgVkk91mXURnkS9GLG2OMGZsepJu7SD6UpYD0+eQiGqEe0riphFL1NmKxNs'
                          'aYpPQg3XwF6WhSuoCji4T7qvtQv9XbkQ/GGGPM2LyKdHMN4VO02kLnK4Kc5SXU/GlO9G8h/m5jjJloxG6PTqSfwenOac'
                          'S6GzgN+CjwAgoydqZ4HmOMmSj0o0rEY5F+doc+QYFwha8ggd6OGmv3Eu5KMcaYiUQJCfQ8YD4S7qBCxDRiPfTFU5nzxh'
                          'gzASkgwzaVcVuLWBtjjGkQDgwaY0wOsFgbY0wOsFgbY0wOsFgbY0wOsFgbY0wOsFgbY0wOsFgbY0wOsFgbY0wOsFgbY0'
                          'wOsFgbY0wOSNN1r4yGPu4DBrJdjjHGjGs6gBnAVAKN5TRi3Qv8BrgR2IzEO6h7lDHGTDAqSJyPBj4IvB2YHPIEacR6AF'
                          'iHBHtHiuONMWaisg44Hbg09MA0PusiMuFnY4vaGGOSUkC6GewCIc0BQ17UQm2MMWGk1k5ngxhjTA6wWBtjTA6wWBtjTA'
                          '6wWBtjTA6wWBtjTA6wWBtjTA6wWBtjTA6wWBtjTA5IU25ujDH1poD0qQi08fpCkgLqSVSKHuXoMa6xWBtjWpF5wHHAAm'
                          'BZ9Pc21BCpDdgDPA+8DGwBXmrOMhuHxdoY0wpMQsI8FZgGnAKcDRwLnITEeqjb9gDwOPAMsDb6807gcPRzX6MW3igs1s'
                          'aYZjMNuAD4CLAECfdMYG70f11HOOZc4ARgP7Ab6AG2AT8Hfhb9edxgsTbGNIsZqF3oKcDFwPsDj+8A5kePoSxGQn8/sr'
                          'p31rbM1sBibYxpNAVgOnAF8B+RddyR0XNXgLOQ+2QN8G3gVuQWGczoNZqCxdoY02jmAx8GPgSck/FzF5Db5KjoMQNtBj'
                          'cAT2X8Wg0lz2Ldhj6UItpNAfppzlzIdqAzWlOcUjQQ/Ww0XdE64mDMINBH9Rw1kk5kMcVpVwPoM2rGWrp5fQrYIBpRZx'
                          'pHAfma3wH8KRpxVW/OAt6EvndbkIXdjOuyZvIm1gV0wbWh25xT0e1UH/oA1gLPAoeof95lvJZJwDHAKmAWikbvQmlFG5'
                          'BANWots9E5mY8uigEUZHka2NrAtbSjANEqYCmaNVcGNqLPZwcSy0adl7nAm9H5mYQ2sheBx9BnFefqmvoyB7gW+ENgUQ'
                          'NftwP4GLKyv4BGa+Xu886TWBeQGB4PrADOBE6jKtaDSCDvB+4FXqC+Pqo5SBhPAE4ETkYC1YsE4DngUeBJlF5UT2agIM'
                          '25SJSGivUOJJBPRetZT33vPmZHa4gDR4tROlYs1muQSD6FNpB6WjnTkVV1LnA++v4MFesHonW8gPJ0++q4lonOZGRRfx'
                          'pdw42kiAyqT6O87O8iK7sZd3g1UQl87AeuRwLVyNFeHcDb0FT1Deh2pgeJYw+yaA9G6/s7tHPXa31F4F3Ag9Fr74tevz'
                          'f6eShaxxbgn0k5cy0hHWj45l0o6n1w2FoOopzU7cDfI/Gs13lpB94DPILOy0hr2QXcA/x7JKb1XMtbotfahT6TeC3xd2'
                          'ZntNb/TGMtvYlGEbgEGVKhepPl4zD6PlyL3GKNpoB083qkD6Hrz4VYF4GFwH8F9iZY4wbgvwHL67CWbmRRfwkJwFhreQ'
                          'n4P6jP+ZqCIuo3IMt1rLU8C3wGBV6yZjJwFfCLBGspAT8BLkN3APXgSuAHVH3koz1+B1yE54rWgy509/kPJLt26/04hD'
                          'JEjqPxvZFqEus8NHKK3R/nosT5GQmOWQFch259s2Yu8F6UFzpSsv5wlgCfR4GOLMUgnpT8EeDqhM99LHANciFlLUxzUY'
                          'T/8gTPXQDOAH4fVadl6Y4rIFfHx9HmkSQlbCX6rizCzc2yZha627ocGRdpqKBNN74rqiVIPQm56C5BRktuNug8fDGLKG'
                          'r8PnSBJ6U9Om5OxuuZB5yHhK8t4THTkD87Swpo41pOsk0DdE5OROKUdO1J1gFy9Swg2Ze/gD6X96BNrzOjtYDufI5HLp'
                          'ak3+95yMo/l+bcHo9nZiAj62TSb8oFYDOKMTyI4g1pA4QFpAt/gNIGs8rvrjt5CDAWUMDsLegCTEoZfVFmIJ9lVswi3A'
                          'IrIMtzMvKVZhWJ7ibZncZQZiFxaifbAOxsJNhJ6UB3HVluHKD3tYCwi7AT3fk8DvwGfUZZrGMm2qiLVF1DrUacMVNCsZ'
                          'e9ZPP9LKD3uyJ6hBqGJapNml5EgfotVF2iK1GDp2NRxlGIlk1GfUdOR267/sC1NYU8iDVond2E3bJUqE96WIHwL15csT'
                          'UXZUBk9eUoEy64JXRusrqrqiCxm0m4lVIk+7zrCuly3Kcjkc9i42hDYvKm6Gc3yjRpxVvuCnINHEZZSw8jUayVInIzrC'
                          'LcoAAJ9E3AD1EMqpfqZxrXEcwFPopSAUNytuP00jnovWexOdedvIg1pBOX16KoGZL2gmtHYpa16yn0/dXjnBTR+0tzbu'
                          'qR75rmPRbQplOLoB6FfN+no7uGReiusIPWLnXuQJvmVpRe9wrKLvot6b8rBRRYPBfddSWhgjaNdcCPgR8hi/pIqaZ7gW'
                          '+hc/tJZGWHMAt9ZgfIgXWdJ7FulST2tF/euEF6K94K10qF8fHeankP81E652eQaHRQLeBqdWKXxYnIeh1EIrsf5eanuf'
                          'YKKM/+DOR2SEIZWdHfRBb1y4xdE7AR+Co6z3+IXCJJDaKj0ca6CxWPtfT3N09ibUy9qeViXY1uyU8nH4H7kRiqB28F/j'
                          'eUcndviueKA3lJg87xMeuA21BAMYkrq4zuCL6J4gPXkdztshIFGR9FxWMtXYae1y+VMa1CG7qVvgzl34+Xa6obZeqcmf'
                          'L4DhTHSJrpM4is5HtQRWmocG4Efk1YD+t56P3NoTXjCa9jvHyxjGkW04F3IrEOyVbKAx3I7z58SksSugi7cz+IxPZ3pL'
                          'dwdyCLPKnbpg1lqtSrMCtTLNbG1MZU4O0ojzgP/ukQ2lGl3zmEF7TE3TCTupb6kAtkM+nPYw+yyncHHBN3y2x5LNbG1E'
                          'YnyvwIyTHPC3HO+hKSF16lpUy1f0taDiM3SMj8xdx0XLRYG1MbgygvuRaRaVUGgVdpTEfCuH6hFk1qQ772LCtiWwaLtT'
                          'G10QM8hARtvFEGNqHOhIcCj42Lr5IG7rpQn5jlpLd0pyC3TUiLiXidLY/F2pjaOIT6VTxKuKC1OodQJeGrhAtoP7LMkw'
                          'rhVNTq90LS69ISlEKZNK8b1CY3F3dFFmtjaqMXDVP4JbJCxwuDqP/0IzUcf5jkIt+BiolOJ53/fzYqwBk+6Xw0etCQkA'
                          'PkwLq2WDeOAjnI5ZzgpC2X3w/cB/wKZSMcICdBqxHoRYMq7gC+g0bCpaGMgn17A44pIDfGuYSlQc5Afd0vIixdcBPqhb'
                          'KHHIi1KxjDSSu4BcavYI+n95X2faxHAymeRL2Sz0Rd4UJuyZvNPuR//yXafJ4hLLNiKBV0Lh5GOeiTEhzTjgqL/hL4Cv'
                          'A9xh72PAl15LwW9WVJ8jox61APlO1jvEZLkBexLpIuwlsPEUnzocbN0/vI1uJK+/6yPidxP4k056Yed3dpz0stwaYBNI'
                          'lnY/R4GvXGWELr5/EW0fo3oMKUn6C7hVqooJazdyHXxuIEx8Q92i9Cn8Uh1B/kVdS/o5dqx7wZqGDnRNST5XzC3SevUH'
                          'WDtDx5Ees4rSckulxrGtCRiBsyhXIQ3RJmNaw2Pg+h7zE+L1kJdoGqfzK08izLVq1DSdPG9jCyImvdTPtQwPFplEaWh+'
                          'b2cSOnfiRcWQRKy0hon0Pf/RAqqN/00Uio7wBuj/4ctxs+D1WOrkTd80LuYOLRcrXmdTeUPIh1Bfm+7qI6oToJBSSOIT'
                          '6zJByiGpAIEbxDKKCR1e1WheqIoxDK6Aua5YTzCjrPIbm4g+g8psk0GI0BVMEW8v4GUJDwIWpvlVlBn3MueiTXkfh7vg'
                          'l9xscT1tBpChLilVT7Yu9Bm/AklOa3inSb/QG0iTxMttdBXcmDWJdRCer3UcT3vATHVJCVtInsxXov8BT68iXJ54x79O'
                          '4iW1Eqo/f4AoqCJ3ETldGt34tk1783vih3od4MgyT7XsX5yc+Qba/nPtSFbReynpKsZSe6/b8XbYAmO/aijJLj0YSXNM'
                          'SinQUVVMT0TTQmrOX7WMfkIRukgi6mu1DAYqyewxW0k/8IiWrWbAa+BtyZYC1lFLz4NyRMWQcxdgP/ghq1D4zx/BVUuP'
                          'FFNLoqa3ahgNA9jC6+ce/rXpRt8MAYv5+Gveh8b2R0X3rcu2I3EpR15DeLo1V5FQULf0JrbIRxlspdaFNv+cBiTBvwN4'
                          'HH9CPRfIBsZxuORtw3oIh6FVQY2R/Yg/xkt6IJEs+Q/cU3GL1GL7o9m4Gqr4bf4vUDzwO3AF9Gt11Z98sdiNayD3UPa0'
                          'dBluFrOYA2jR9Ea8libNNw+tFmsA91aZvLG/tJxO6SDcDPgX+lPk3fS+jzKaM7jknRY+h5qaDb6s3RWm4l+7swo89iB7'
                          'p+T0SBxmYZiXFF5nfR5lHvEvrhxLNYz0Ej34L7rVQCH/uB69GJb2S6VhxYOAOl9jw9wtrWAH+KfFn1TJkqoBN9AfANqj'
                          '7soY+1wP+C0reGC0XWTEMR979HG+jwtTyIpmgspr6ZCQXkqno32qR6h62jHwnjx9AtcT3X0o3O/VVo447jBfGjB7gZ+C'
                          'D1Py9GG/i/Q9dFqOZk9egD/gvpWr5mQQHp5vVIR4PWnwefdUy8UTyBdukdKIG+c8j/P4OmFb9MfW9n4w/+UWSpPo/81/'
                          'EXYABZ0r9Cllu9b7UOoPPShizVeO5fLJBPIp9svfNJY2v1juh1n0AB4dj1sQe5pu5Erod6rqUXnftdSJjXoo0knhe5C1'
                          'Xo3Y8s6tzcDueUnejanA98BF27jTL24rjXLcCN0Vpy+XnnxbIeShFZTlPQbf/U6M/dNH7HbEdWfCuspQ1Z8fFapkSPkd'
                          'w09aYDnZeh52QytQ+lrWUtQz+jydG/j5dinjxQRCL9Vygw3iiLeuFGSmgAACAASURBVBfwf6PPvZl3UBPGsh5KHKBqBQ'
                          'ZpncnVJVonb3SA1kmLaqW1TGTKKOh7E/o8PonEq54cAv4JuIHwfO+WIq9ibYzJJ4PIbfht5Cq7GqX1hTRgGovYmn4JuB'
                          'tNP899C1uLtTGm0ZRQRtJX0czFTwGfILtpO9tROuuNKF6zg5z6qIdisTbGNIMKCuw+hjKqtqPsncWo58cpgc+3EeXJv4'
                          'x6tNyP0ovHjfsrjVgPdXobY0wtVFBW1ToUHF+B0nM/SDWJIe5dAq8PCMdFaS8CP0XZJhtQ9k/WLRWyIrV+prWsS4xdMW'
                          'eMMUmI+7mAXBabUB3FUShjp4NqFkcs3oMoyWAwOnZ9dFwrCnRMBa0vVXFcGrGO25XGqWkuzzXGZEU/cmW8HP29gIR6aB'
                          'psAQneSC1tCyP8W6sQpxx3kiKtN00ecBvyKR1LdgEBY4wZiQqynvuHPPo4cs+XVhVqkF4ei/QzON+7SLU7WVI6kfP/PJ'
                          'K3KzXGmInOLKSbpxA2TKUE7CqiMtyDJN+R2lBT8LOBmQEvaIwxE5mZVIcqJLWsK0if1xZR9HQbYb7n2BUyJeAYY4yZyE'
                          'wh3AUSt3TdUEQ1+mkaH01G/peQAZXGGDMRmYT0MrQbaDwe7YU21HZ0HrCasOyQDtQgaDvqaOWsEGOMeSMdwMWoSnM1YX'
                          'M5B1AXy9+1o5aVpxEeRZ2MRsBvR0npzwUeb4wxE4FjgPcjvQy1rCuor8lTReQP2Um6WWQz0NSDt6EyUbebNMYYUUC6+D'
                          'akkzNSPEc/0udtbShf8Sg0ZmYWYSZ6MTpmYbSwzaglYSvnOhpjTL2JkzA+jCYjrSJMW0El88+hplTPxFHJNmSeL0XiG2'
                          'IhtyGxnof8K2W0G8QjnYwxZqJQRHMWVwFvR0J9BuHV4mXkXv4R6ky4MxbrAyiX73TCcgCHMhM4KXqOCuqCVaJay1+MHq'
                          '1cDmqMMUkoDnu0IUGegXp0fw6JdTzIOtRFPIDG4n0JjSssxWofzxN8FInt3MAnLqDUlJXImT4Nif4m5G/ZTnWCyS6qQ1'
                          '2bNeXYGGPSUEZ6Nyd6gLRvPtLN5cBlyEddSwxvP1VN7oPXm+b9qLfsM8CZpJ8OXgDOjR69qBvWI0igi9HzP4PEuhNb2c'
                          'aYfFBAOlkATo4eZSTab0bGancGr9ODNPIxhiR+DBXrCvKNLIoWkVash9INnID84LFlfT7V6cK2rI0xeSK2rOcCs6N/iy'
                          '3rrIa59KBJ7L9jiDE73EwvIB/L3wGXIv9LFul4Q5tte3CBMSbvxLG44X+uhQqwD7gd+HMU93tNK4fvBBVU2vi3yIVxNd'
                          'mY9Vm9GWOMGa/0oYk3/y/S4dcZtSNlfZSAV1H+9VJgCXZXGGNMPRkE7gO+gsrLB4f/wpFS9CpovE4/EusFWLCNMaYelI'
                          'DHkVD/EhUWvoHR8qkPo0BgD0rFW0B4BY4xxpgjcxhZ1N8Gfoa8GiMylrX8Epo6vIeUQx6NMcYckRLS13VIb4/IWGI9GX'
                          'grypl232pjjMmWSUhf38oY6dKjuUGmA9cAf4jS+eyzNsaYbCmiQbpzUduP9UQVi8MZSazjFLsrgf+EGpJYqI0xpn7MRi'
                          '06tgDPMkKq80hiPRm4BLgOuJDsqnKMMcaMTBF1Lp0C7AZeQc2cXmMksT4e+DPgCrIpiDHGGDM2RZQqPQOl8u0Y+p/DxX'
                          'oecn9cQ3jnvaFUcMWiMWZiUov+daJU6S2oa2lP/B/DXRwXAVehnOpaKAAbUCrKDmTOux+IMWY8UkA1KPNQ1fcxNT7fAq'
                          'TDrwI3xf84VKy7gMtRGklnyhcpoYhm/CK3Ay+gPiPO0zbGjEfakMv4WNQA731oVOI00g1y6UQ6vAm4jWH9rLtRW9Tjox'
                          'dIQxlZ07cCdwNrkFDbojbGTAReih6PoOSMq1CP6zTZdNOQHq9Cva17Y9VfgXaDM5ApH/rk/Sjd5Cbg/wMeQBFNY4yZSO'
                          'wG1iI97EYpebMIt7BLaNRiCQ0i3w3yt7wvevIeqv2mkz56kThfhwYXOLBojJnoFJAeXof0MR4gHvLoQbr8PqAQTzW/Iv'
                          'qH0FS9MnJ3fBX4Ppq1aIwxRvG7Tcg6XooChyHGbAdyhzwGPF6MnqCL8ABgBQ11vAcJtd0exhjzenYjfbwH6WVoDK+E9H'
                          'lBETgOWEi4++Igaul3I8OSt40xxrzGDqSTP0O6GUIB6fNxRZQFsoxwB/hOqpkf9lMbY8zIFJBO3op0M4Q2pM8nt6NMkE'
                          'WEi/UAMvGdmmeMMUcm1sjdDOv3kYA2pM8r2oELkHInTderoFS9F4CtgS9sjDETla1IN5ehwpckHoli9PuVduC06B+Suj'
                          'JKKI/wLmBX6GqNMWaCsgvp5mJU7JKko2kB5WrPLCIzO8TnPIiStNeg1BRjjDFjcwDp5mZGmF4+CgWgLU2v6kEU3dyChj'
                          '0aY0zWtKOUtSIafTUl+nMF1Xf0I/3pi/4cIn7N4jDSzR2kWG8asY591m7OZIypF4tQ8sMU4GwUW5uEAnQ9qA/RY2gM1o'
                          'uo+KTVKSHd7CdFYkZasS5HD2OMyYJpwEmovegMNOJqCRLr04HlVJMgSiiz4lQk0i+jBko70YSVZ2jdIr1YOxsi1oUhD2'
                          'OMqYUCGnRyIfAJ4M1IlzqjRxG1xBiqN22o4dx0lCDRjyzufmRpfw34KRLvAq2VXpxaPz1f0RjTLKYD70K9m1cBZ0b/lp'
                          'Su6DGUuH3GmWg01p0oXS73WKyNMY2mDbk53gZ8Ggl1J2pcVCudyMd9KnKNLAF+iCzuXCdEWKyNMY1mOfAXSKzTtLoYjQ'
                          'LStXbgROCPkHj/A5pclVvyLNZdyG/VjfxVfSjpPLScMwva0BifKchvtp/mBTimolvJySgQ04NShZoREJ6FAkcdyG+4G9'
                          'jbhHWAzslUlFFQQN+VPU1ay0TmOCSg16BAYr1ZHD32oOvySXSN5o68iXU862wqihCfiYITB5AQPIUiwbuI5pbVkWK0lu'
                          'lo/M4F6EuxD91yPQlsRF+Qem8gcRBmHpr2cxwwH52DV4BHgeeitdV7eHERfT5L0OdzDBLsMjon96O+5z005rxMQV3Lzk'
                          'BW3Hz0PXoKVZO9itKpPNS5/iwH/gPwURoj1DEV4PfR9+CvgIfJR17268iTWBeQn+styB+1Cn34U5AoHULCtBm4Gfgl9c'
                          '0DPwp4B1UROAaYifxiO1E60XrgFuDeOq4D9CV8H9UUp/loExlAAv12FGT5BfBb6uu7WwZ8AAn1ErSZxkGgC9Ct7xNIKB'
                          '+hvhb/PODD6LwcA8xBG0kROB9lIDwDPAg8hDYQUx8WAp8CPkhjhRqkHdOBt6LvQx/6DuYu/Th01Mx+4HrkD2pk+l43Ot'
                          'EPI7EZbY03owhz6OSbJBTQBnEN+sBHW0c/8CUkFFPqsJYiEqRPo81hrM/uB8AppBvgmWQt84E/R5vVaOt4Gfjv6E6kHm'
                          'sBnZdPoSDTaGvZCXwBDTY19aEd+BDKiQ7VmywfcWrfXxGWdZIVBaSb11MdRJD4Ua8LJWu6UDXTpchKGkuELwP+ElngWT'
                          'MNuARtHCeM8bsdwHuRML2Z7De36chS+QwSvrE4G7gSWbxZMwP4GPJHzhnjdxcja/8ylGqV9fewAHwc+Dxjv9c5yMI+FW'
                          'USmGzpAlYDl6PNvJl0oDvPi1Af/+Fpfy1NHsS6iFwO70S30UnWPA19OU5P+PshLEAC/FaSfdhzkaCuIluxjosJrkQbQR'
                          'IWAlchF0XW52UOEuBjE/xuBW10H0IbSJbuuGK0liuQSCRhKdo4Tiab9DFTZTa6Xi6mtnM7gALl26jN31xEd5cfQN/BLD'
                          'NR6koefNYFZB29BwXOknIQifY05LfNirlIBEL8bgPIV9pGdn6yQvScY1mxQ2lHm0b8Jc1iLXGF2DSUaZH0mEnoDuUp4N'
                          'dkF6GfRPWOZ5Bk3/FpaPNdi26Tswp85q3Ktx4B1nlIqNO4mQaRf7kPNUB6Cn02pyNNaEd32aF3RPORobAOeJ6c9DjKi1'
                          'jPRH0DQtZbQWKWtVhPiZ4zlDlI4PeQ3Zcj7kwWwrRoHe1kK0pzUEZKyDHdyPLKysovoPe3An32ScWyiAR+NdlY1nFcYz'
                          'Ip+0A0mHjDHUSZMVlkUhXQeT0G3dGFMojaiT6IMpm2olhHCQn1InSXew5wFmHXZDx95Xj0efemWF/DyYNYx6SxAgtkf5'
                          'sTN7IKXcdklHd8kOzEOm4VGcLh6JisrL4KEt24hWUoB8lWzOK+EqGfexu64Gs5Lx1ok1iMfKMzyEfTs7j16ABKe92AXA'
                          '69pP9s4uytUwgLrpfRZvE0qjz8DkfuqNeOsqAqKLsn6Z1dzEyq12Srb6i5Eus0F1E9bkPTPmer3BK3yjpisl5PD/Jr9h'
                          'B+AdbSoKwDeBPwfuSHn4k2gDia38rE7zneWLagjKpbqGYthFJETZYuIbmrLs7OuSt6/ftQ+9MjMYgmhh9CBtClhGnaXG'
                          'T570W1Gi39OeVJrNNYJ/U4+WmfM3VrxBzQKoJUQdbgXtLd2pZI/z6ORRlC1yLXTp45EwX1B9FE7v0pnqOINq/TSO6qKw'
                          'HPAt9AdRJJPsP9qH5gUvQ65wa83mLk+lpPDqZe5SEbxJgQisjKbeR3u4Aycn6f/As1aMM6G/iT6Gda5hLmmhhAAb97CH'
                          'PvDQC3Ad8lrIXAfOSuColvNA2LtTG10YWsx8tR0Go8ELuDlqF0xjTEbSGSBmx70eSXO5DfPPRO+jAKSL4ScMxc4DyUsd'
                          'LyWtjyCzSmxZkJvBtd9KEBrlanC7l3TiA8SyZOp0squodQK4QHSZ8UcBAFI5O6wLrRe2tGNWMwFmtjamMSchUsY/xdT1'
                          '1IzM5AVnIIoXGMAdSMrZZOiAdR87SdNTxHyzLevlzGNJq4s994LFWPOyjOINzaDc2sqSDrupYc77g9cYi/OzdBf4u1Mb'
                          'XRR7Ut73hjgGonyzQiGiKC8aYXUlg1nG6UJhiS150LoQaLtTG10oMCY3F3v/FEAVUNPkp4W924f0dS63oyciedTPqisa'
                          'nR8SEtGAZo/aIlwGJtTK0cBh5AhRzNmg5UL7ahobNpmif1R4+kG9gU1P3wQtKX/B+HfOwh9SNbkPul5Tdai7UxtdGHGk'
                          'D9BjUGGi8cQNWBD5JOyOKRckmPLaJUurTZGctRrntIj5DdyIWVtkqzoVisw0mbPF+MHi2ffD+BSfP5VJBgP4yKMn6BXA'
                          'd5pR81TvoecCOq7ktDGZWKh7iH2lDV40dRdk1SFqOWp28jrLHZejTFaUfAGptGXsrNW+lEplnL8KkPpjWp5bN5Bfg2Gg'
                          '92Fcq9Xkl+skQqyMJ8BE0Uuh2JbdrsjDLydd+Nik6StBRuR5b1n6L89X9GHTPjjI14I40/p6E93T+CmkaFZK2sQ2IdTz'
                          'ZqafIi1p2kuzVqpz5d99J8sIfJtuNe3IIy9O4oPi5LC7+IznWaO7WsP59aOi3WEmwqo4t+F3IhPI9uzbtpfSEooO/lfu'
                          'TSuR8NEq6FeEDyQ6jBUtL+713ovH0QnbsX0fi8p9A1FH/PFiIr/EzUizy0hTLoc3qZ+g/XzoS8iHUfuggWklwQ2lFQJO'
                          'ux84Oku/gOISshy0bnZcIFsg1dnFlGwOPz3ArNtsroHIcK9l4kULWelwryg65LsYZmE/e0zqLPeQV9358nXZOkE1GL1X'
                          '3Ar4CfRH/uRNf2KWh61InIkAsJSsb+9FfIXh/qRh7Euox2v1vR7c7SgGO3k30100Hk4woRyg4k1iHR8bEoR2sJvRBiCy'
                          'rLL2mcjxuS3lWK1pCmD8Ro9CHhHST559OHbtkfJZvzUiIn00cawFZkHZ9I2OYV9xefhqZEnY4+m/iucA4S8zR3cztQ9s'
                          '7dWKwzpYyS8m9CE0CSivVG4AWynwLxKgoiHU2yUUVlFLDZQLaiVEGidB/KLZ2b4JgB5KN7hOzFZAtqpHMqyYoSSqgN5i'
                          'PUNlNvOIPoM9qErKckZdL7UF+KB8jRxZsTtgM/Rddt0pmYw5kVPbJiGwqgPk6ONtW8ZIPsR1bP/ejCGu02bQDdgv4Y9c'
                          'bNmm0okPQjqsGPI9GLvhD/gFKgsmYvcAOaqHGAI3/x4uk2jwL/iFpQ1mMtP0DpXqOlQsU9p9cD/4Ssm6zGi8XsRN3bHm'
                          'T0zyietPMccCcS+NxcvDlhF/B99N1ohTz0XuSaeQCtp9XjCa/RBvxN4DH9KHDwAI0tse1FItCH3ApH8cbNZgAJ+g1IrD'
                          'eSfXVSHDXfEv15Nop2D+cAEqJvIjHdnvE6QMKyDX3p2tEt40gW9nYkXF9DfX976rCW2KLdgs75HEa2hvagAblfQxteaG'
                          'VcEsrou7kbfSfmMXKAej2yqL+HxDoXs/hyyCF0PSxDk1maeUf/O+CLKNWy0cTZK+eg4GjQ/NQ8uEFiKsgyjN0bg8gVEQ'
                          'fMiP7vi+j2ut7pOE8Dfx+9zjVIEOJ1DKDo9deitdR7CsWDSCS3RWuZTHUIahl9Qb+MNth6CVIBbQJ3IZ/gXpS+NjP6/z'
                          'gf+VFkUd9Zp3XEvIo27A3R676Nat+JChLy29Bd0rPYoq4369GmOA8VrzS6newgin19BX3u8fWRG9Is+ADwLXQ7/VyK47'
                          'NgAcrHnI2iw7FIbkNWfyNvt5ai4MlMqsGPPiSezyPRahTHRmuZHK2lFK3lZeRPbpQ/tojiC8eh8xKnO/YgEV1D46zYDj'
                          'TFeiXV6rYS+lxeIPtYgjky89Cm+THgYsIaLtVCbDx9Gd3lbmvQ6w6ngHTrT9A5CKm2BN5YsDHWYz9wPRIFV+MZY0KYgo'
                          'YK/4rq9PR6PvrRHeVnCe/JnTUFpJvXU43rJH7kyQ1ijMk/h5Bbrgu5Yc9Bd8dZ56SXkEW9EfjvqHdLPWI1DcNibYxpND'
                          'tQ1tBB4BLkEllNdoLdg1y0j6KN4RfUJ5DdUCzWxphmsBtlA90OfBr4A6rl+QUUawhxsw6i2MNhFPz/AWqsFTJAt6WxWB'
                          'tjmslh4GbUk2QRCgSfgKbFJw3A9aIS/3vRIIj1qJCuWYHEupBGrON0MEfQjTG1MojK0TcjN8hRKAd5B3KNtHNkCztuWf'
                          'Ayqq/4NcrAauUOl7F2Bq8trWUdC3YrngxjTL6IhbWMUjv3In9zPJOxkzcahxUUQOyNHj0oeNnK+fI16WYasS6iarA5aD'
                          'd0LwVjTFYMRI8DVCekj1YP0qoW9Eh0It2cTopWH0XC32gHKgQ5gebnLRpjxi+xJVqi6j4Y/siLUIP08gSkn6FzJitFwi'
                          'vJYrE+nsZVIBljTN6ZgnQzjVj3FlHkNCQHsYgasqwi3fQWY4yZiExHurmMMDfIYWB9EXWf2kiYY74Dpdhk2WPWGGPGM7'
                          'OQboZOtdkIPFykmpcYGkWdD1zAyO1BjTHGVJmH9HJ+4HElpM+PtaEI5VHAGYQpfhcagnkANfvPuoG8McaMB6YA7wU+ii'
                          'zrkLL6ftT06rdFlESepiSzAyWtvxP5YYwxxryRVUgnVxMeWATp8/NFNFFjD+mSySejrlkfQAMt8zImzBhj6k0R6eIHkE'
                          '5OHv3XR6SE9HlXG8pVXAychhzgIYUyBeQKWYpyCLeimXdZDkA1xpi8MQk4BTWpuhppZGj//z7kYr4VWBv7TkpUp3vMTv'
                          'GkM5DfeybyZe9Hom2MMRONo1Ejqg8AVyKhDqWCskBuQHNC98RivQ81QzkFjYZKU4Y+DVXnHEd1YGknankY+2lauW7fGG'
                          'NC6UJehWnIaF0EvAe4DvXqnkO6iVr9qBf3/wQ2MWRSTBnNonsQOAvtBKGNwIvRgs9Cyd+XoGGyW1FXrWei1+jn9UNujT'
                          'EmT1SQ4dmJprWfjApdFqHp5cchwzUtJRRUfBBpJvBGC/p+5BB/N7WVkp9AdbGHUMbJg0iw+0gXETXGmFZhAFnVJwNnk2'
                          '37jV7Um/v+of84XKwfQknbZ6MdI4vsjinoDS0B3o52JVvVxpg8E+vYFORJ6MroecvIqr4J6fFrjCSac4D/hJzjWQm2Mc'
                          'aY0Ynd0d8H/geK+73GSH7pAeS2mIpM+8nYEjbGmHpSQTG+7wD/giblvG7gwkhiXUbZIfuQYC9HOYMWbGOMyZ4K1QHC30'
                          'SxvTeMTRwt42MHGq8zHfmxbWEbY0y2lIHtqP/H15GfesT5tqOJdRmVOe5EzvNlpCuXNMYYMzK7gduAbwOPoFmSIzJW8H'
                          'Af6qo3jeyincYYY0QX0tcDjFH1PVbhy3TgE8A1qDrHbhBjjMmODtSqYw+a6N53pF8cTaxXAJ8D3o8qc0IrGo0xxoxOge'
                          'pMgVmotHzvSL84kgC3oyyQjwL/DmWDpOkVYowxZmyKqIHesUion6Y60f01RhLr2cDHgI+jGndb1MYYU1+KqBoyHpP4As'
                          'OCjSMJ8UnAZ1GzbFvUxhjTGIpIrLvRIPPXTfAaLsYLgLcgwa612VJ5yKNS43MZY0wrU0BiGz/S0oH09y2obfW2+D+Gi/'
                          'U7UU+QLCaWP4/yBteitJQBLNrGmPFFAQnsNOBE4M3Rz1qYh3R4H/DV+B+HivVUNN3gdBSdTMuG6PHb6PEsSkcZsSrHGG'
                          'NyThHlS5+E+vhfgprgHZPy+TqRDl+OmjodHPqf04FL0WSCErKA0zw2ogySk1EqivtWG2MmCnHO9MlIBzeSXktLSI8vRf'
                          'r8WoBxNfApNDQ3TfHLIeA+4BvAd9FkmIPYmjbGTBzKSPd2IA08jIKF8wj3VsQu4+nIU7EVZMJfiyKPsV855LEb+CFwRf'
                          'TErnI0xkx0CkgPr0D6uJtwbR1AunwtUGyPnnAuqp5Jk6r3BPBl4HZgMN37MsaYcUUF2I90sR3p61sDnyM+bi4wvR1YjI'
                          'KLoZPHS6g08ucokGihNsaY1zOI9HE1GkS+nLBCwxLS58VtSO3PBN5EmGW9G/gWapa9I+A4Y4yZSAwid0Y3Cj6GtJouAy'
                          '8Be4so3WQZ4Ync+4C7GTIq3RhjzIhsQHo5ahvUESgifT6piBK4lxBmmldQocv+wBc2xpiJyn6kmyHFgW1In09sBy5EDu'
                          'ykWRwl5AJ5hGG168YYY47IK0g3F6OGeUkM5AIS6+4icnqHDMQtoYGOd6OG2cYYY8ZmD9LNZ0ie0FFA+rw0TapenPu3kV'
                          'HmhRljTI0Uh/wsUDUoj5SX3Or0IN2Ma1qCCmXSiHUZOcl3MMoIGmOMqYEpwBwkaLOjx/To/+J5hbEPeA/hvuBm0Id0cx'
                          '8pqrvT9qvO025mjGl9CkiP4qZIq1Bu8kzgFNTYaFn0u+tRdsV6VOvxLPAUEuwyI0xZaRFq0s00Yl2h2qfaGGNqpQ04Gr'
                          'gMCfMk1Ft/AcpJXgDMp+oGeRMqLnkTsqq3o77Pe5Gb4XYk4K1oTKbu8Z9GrAu83n9kjDFp6ECujmWorehHUdEIvF5fhm'
                          'tNEVncM4b8Wyx+W4GFwC1IuA8CvZmuujZS66fHdhljmsVCNELwImQ5H0VYcd5Igj4f+ET0nLcDP0AuktxjsTbGNJopwL'
                          'nAu4D3ojzieCxWrXSiPOaFyLUyG7gDuJec14VkcXJaCbtmjGl9zgD+GrgO1Xm0ka0WFaLnXIrai/4d8PYMn78p5Nmy7k'
                          'ZBhnhe5HY097EZTEU9VmajXMptqPl4M1IbJwPHIsuiH/ntNjVhHaDA0FLkXyxHa9nYpLUsoxqw6gU2EzV0Nw3lbcCfol'
                          'mFU+r8WoXoNZYh0Qb5svfW+XXrQt7EuhsJ4lzU0ySOCpeROD4KrENTgfdT34yVdhQcWYxSjM5HArkfpRU9iYYFb6b+PV'
                          'Q6ka9uDto0zkaC3ROt4yHUuWs7+qLW+7wsBFaiyP4paEMtRWu5H20e21CqVT3pQJ/P8ciaW4EGmx5En81jaPPYiaYdtW'
                          'L2wHihiNLvPosEu5Y5r2le+1yq1+cvGTbXMA/kSazbUKT4fWhXXoKiwZPQRXYYuBpddF8FvkJ9LduFwEfQUMvYeuxGlU'
                          'mH0JfhFeBLwI11XAdIGP8jOj+z0HmZilozngtcgxLxvw98jfqK5NHRWi5BF+R0qhfmOcB7kGjfAvwMna96sQz4SzSubh'
                          'ayqtvRebkcbV6PAj8C7sQVufXkJODP0eSURgp1TCf6PnwYfc6/ob7fvczJm1ifjdJ7ljK6j6uArKWfUZ8ddCYSow8Bp/'
                          'JGX/mc6OeJ0eu/jCy5PWRrvXUiC/rDSJCnjfA7s4f8eRAJ5X3IRZIlHciC/QjaUI8a4XdmIjE/Hp2H9cBz1GdwxepoLV'
                          'fz+hSvoSyP1tKGrP21dViHqVq2FxHWyzlr2lH//s3oGghtV9pU8hJg7AZOAN5Cst7bpwGfi35mzQyUvH8NshZGC2oWka'
                          'j/74ws6rVQQOL3CTTseCShHs5qJF4nZbiOmDnROv4I+YZHYxpwMcoGWEH238N24NPIT3kkoY6ZiS7gC/EM0XrQBZyFhH'
                          'qsz2I0hhbjpa0CLKLv6TlIG7prWE/DyYNYF5E19iEk1kloR1btiWR/y7UQeDf68nUl+P3pSAhWkr1PdBqa8rMw4e/PQR'
                          'vN6WT32cfiNgNtSEnb7S5FdwQXk+1n1Iks5pMYe9MYupYrkHutGbfo45m56HO+nNrO7XqqcaANpL8bKyBduA5tIrnxLu'
                          'RhoXEb1/dGP5NSQEG36cglkhULUGBzasAx3dFxXWRXTRW3TgyxVgpo01iBPvssXSEzo/UkpRNZ+qcB381wHZ1ocwdd0E'
                          'm+493ABcAa5MPOKtZRwEHLJVSD7yEMUg38bkG50vvQZzUZxWeORwbIbMI2gtnI4HoSeJiczI/Ng1iDRGAkH+hoxGKWtY'
                          '+si/Dbp/j2aw4KamUV2OggbMIP0e93pjhuNNrRBZDkTmMoxejYrN1DbYSL5CK0kWV1TcxFG2ke+ugU0RoHUbbQoQyes4'
                          'Cuk+OoxnBCWIuqDx9HKZavouumDX1G01CW0VlIeM8m+WdXQMZWaMVkU8mLWFcIn74eX6xZfxilFGsBCetUNGUnK7EupH'
                          'iuPmRRZyWQFfTeulM+52GytT4r6P2lEci072Ho8ceiaZAr7QAAFmhJREFUjnHHIEHJi1hXqIp1nHr6Yo3PeTwS0ZkJj6'
                          'mgO88XgO8B32bsGoGn0ObSge54O0n+Gc5EG0kfObCu8yLWkP6Czvo2NO3FHG84zV5PPZpwxcGfNNQjoJf2OdNswjHdyM'
                          'r7LMp8mDxkHa3uChne1H8PcBPwr0iw0wbzzkQxiaSuugrKDvoCyuTakuCYncDN6D18AsVNkrpEliI33CFkRLX05zTexb'
                          'oeJ7+WTWO89gAfL++rlvdxCsqEeQ/h7qBWYz7wB0hwv0i6CtgCyuA6luQut35UqHQbYdWlW1ENwXzCkgqWoM/tabJPq8'
                          '2c3PhrjGlRisi99TbgSvIv1CDRWoxqGs5J+RxtyM2Q1CAcQBkfD6G4Tujd0TbgHlTTkNSlMQ9lDU0f6xdbAYu1MbUxBa'
                          'WlXU5YhlArEwvlVGQdTyVcPLuRhZtUY/YDPwV+jcQ2jZX7XPQcSa3yWchllTTdtKlYrI2pjemouOdUFOQaT7SjIOHphG'
                          'dAxRk5SWMZh1DfmHWk16UdKMXvhYS/X0QZIUPjCy2LxdqY2uhCftk06WmtTpyzfhLhHfJC/f9lqq0h0gare5FghzRO6y'
                          'UHmSBgsTamVsqoMVaumgIlpILeVx/hApom66hW67ZIuhqClreqwWJtTK0cBh5Bga3xxgBK3XsGvc8QQi3ruOVwLamlM5'
                          'CPPaSALq1/vOFYrI2pjR5UZfccrTWYNQvKqM1vmvc2QJh7oQOVpM8KfJ2hzES53ccEHHOI7DtQ1gWLtTG1cRh4ELXcrP'
                          'cwhUZSQvnHDyAfcKj1OYD0JanGTEXN0S5O8Voxy5BYz0n4HHG64IEaXrNhWKyNqY1BlCr2JOGuglZmA6pifCTl8bGPO6'
                          'lLYwoS6neSrlivE/V2iTstJnndrahcfR8W63FJWn9akewHg5rWoIK69f0tqvh7lPwGHHcCPwGuj36mnQheRu6hp0juZp'
                          'iGWvj+GeoMmZQZwCdR//KQrJz1wN0og6TlxTov5eZpgw71iPKmLXsfRBdws5v61KM3SC3P2Uq9QWp5Hy+jUXKzUBe461'
                          'BKXx782AXk9tgF3ItKt+9H/vi039cS8FvUf2MRKgUfiyJyZfxF9LpfjdbQyxv7thRR2mQBDfj4Y9TIKSQTZBMqb9+LxT'
                          'ozOgifMhG3ysz6Paa9oA+j260sczrT9EsuoC96liIZtzpNc9eQZatWqH7uad5fkmk7R6KMROUV1NtiLSqYqaU5VCOJO9'
                          '7tQGOvavW/x02Z1hDWcrWINrxrkfjeipo6Dc+dnoRE+lLgPJQLHnqt95H9NVk38iDWFXRCn0VpOUkrqdrQh5H1ENS4xW'
                          'goPSjpP8uLt0R4iXMBCUuW6+hFF3eaL30/2Vo1JbQxhmwccae5F8jmvMT9l/NIPDarVuK7yfXo3Ia4NUCVk8tRKfgilE'
                          'IYt/atoGKdK9Bgg1mEaVk/2pTWUt+h2pmSF7HehBqRX4O6ZCVhADWE2ZXxevYCGwnbODrIfgcvow0g1Dfag85Lll/SMv'
                          'ASVWuswtiWbT86l1vJ1jXUh9pdHiK56BwAbgd+RTZBwjz0sG4UO5CFfQJhVZBFdH1dDJyBPtehn2cnunMJmU5E9BxbUP'
                          'D0TnKStgf5CHbFuZ4/R4KQlA3IUsr6w3gJ+A4KnCShDwVqniJ7v9hu5F9MOpX7MLqtvLsOa9mO+jK8QjIXRBGt/U6yDc'
                          'aVkFX7Ismt5B7kX72bHF28OeFV4AaU2piGbtQdbwnyf8ePBYQLNei7uRe5VrK6k2oIbcDfBB7Tj9KUHiB7q/VIDCLrZx'
                          'GyrEfzRR9E+aE3Ab8h+9zXXiQEbehWbRpH9rvuQgL2jygFKutgUz/wPNUBwV2M7I+Oy4Z/C/xPFFTJ2vIbQO83bq85Y4'
                          'R1EL3ubvT9+Vv0WWUtkP2oOc+s6OdkRjZMKuj7cQeaSpK20b45MgPIwCkiH3TSqTH1Yjcynm6g8XnxBeTWOQedi6B2un'
                          'kRa9CHvhVF3Wcgf9Zw+oAfAv+Gbmm3UJ+Lrx/54rai2YMj+eN2og3j31BkvR5fjLj5Tdy8ZiayQIZzMFrLl5CFUw/rsY'
                          'y+D5vRpnQMI1ejbUXCeD3wBPXxGVbQOXkh+rkIWWfD2Qt8A6XbrSFHVlbOGETfwZkoFzrruagh3AD8M9KRRm/MNYl1Hn'
                          'zWMRV08W1F/shdyGcVz1yrIAH9JhLHeqZMFaiKcT+61VtAdfjrYbSh3Yyq2+oZbS4g6/rrKJCzDZ2XItUxYmvReXmozm'
                          'sZjF7rO9G6Lqb6+ZTQ5/YEmmae1I2Ulp3IYt6EPo+LqTaZL0VrfQalhz1R57UY3bXcggybdzXh9cvojvJGdDeXi+ZNQ0'
                          'mT+nUA+Ba6tX8uxfFZEA+67ETBu/h97Ec+00ZGeOMpy5Oppoz1o4DizgavZTbaubupijXRWl6hcYUaBZRXO4dqSl8JnY'
                          'sDyNptVLpUbM3E09fjbJjYtfZqA9cy0ZmBkgT+PVW3XSPoQ4VK/4piNjsb9LrDiUed/QnwMQJTRfNkWQ9lb/RoBQ7QOj'
                          '0hdkePZlNBFv62Zi+EqktkR7MXYtgH/AJtju9AedL17gM+iCz6HwB30RrXRyryKtbGmHzyIvA9dFe+F82uPIrwSTRj0Y'
                          '8s6MeRFyB2AeY2gGyxNsY0mkMo0L0bWbufRFZ2VvQCD6OY0e9QTCL3ri6LtTGmGZRRVfKzVFNLZyC3yALCS/8PIrfbHj'
                          'TH8dcoAWBfRuttOmnFOnQKhDHGjEQBBf3uR9k6Z6E2qedTDQiPdXw/akB1GxL/l1G2WMgsxkaRWjvTiHU8sdjltMaYWq'
                          'nw+oSBF1G65Z0oo6iD6qT0ocQZYBUkzA+iwrNmZXokJdbOYMFOI9ZDu9mlSf0zxpgjsRO1lvh59PcOlKI73DgsIu05zO'
                          's1qJU1qYB0M1VXyDRi3Y52vKWoWi2k/aExxoQwQFh9QKsKNaiXyVKkn8HaWyQ8StqOSr1XUVv/X2OMmUhMQ7q5nHCxHi'
                          'yi6GnoyPglwHE0t8bfGGPyxGSkm0sIE+sKsKeIGtjE3dKSUECpNSdS7bVgjDFmdKYj3VxAcp91HEBdU0TJ488T3nFsMb'
                          'Aw8BhjjJmoLES6GUIJ6fPDsWUd0qg9Zh7Kh3xT4HHGGDPReBPSy5Fa9Y5GCenzmnbUNvB4wsV6ZvTi21Hf6Eb2tjbGmL'
                          'wwB028fyfhwxdKaOrVY0U0xSFNInkBNXU/Dzg5xfHGGDMROBnp5CLS9dHeCbxURLXze0g3PaQLOJNqI5bcNfQ2xpg6UU'
                          'C6+Emkk2n6d/cjfd4Xzw6cg8btzCGsVWEBpaOsQE1YtqGGKgO4HN0YMzFpR+6ONwOfAa5Cwy9Cjdl9KAHkJ8DGWKwPok'
                          'rE41BaScjU8wKqzFmABH8R1fFSxhgz0VgNfBz4MHAhmlQUKtQlNH7sS6hJVU+cmL0Tday6DEUtjzStezTmoUbip6Bd5O'
                          'dUB7kein72oLxBu0uMMXkm1rHJKH96SvRzHvB7wNVoqEJHyuePxfo2oiZXsVhXkDW8FjUED0najimghitHo13lnci6Xo'
                          'P6yz6NgpkDpGxkYowxLUAFiWkH6vWxCnklTkHaOYfaxpVVkA6vRboMvLHk8VdooOOHqG3MTrzY49Gb2ILaHu5AbzLEzW'
                          'KMMa1GGRmd81Cvj8XIks6CPuSZ+NXQfxxu3bYBFwN/T3p3yHAqqFnUAOG53MYY08q0IQs7bhldKyXgSeDP0Eiy1zRzuG'
                          'VdQvPKboz+72RqF+wCejNpfTfGGDMRKAHPIP19gmHG7UhCPIjcFjORWE+q8wKNMcYokPh94BuoMvx16c8jiXUZObVLyB'
                          'cTRzQdEDTGmOypUJ34/g3gUUaoUxnNxbEXOABMRRHPzuzXaIwxE54e4Hbgm8A9QO9IvzSaWPcCG6MnWoDcIt3YwjbGmC'
                          'wooxS9B4GvoErFA0f65bGChwPAViTae1GaytxMlmmMMROb54AbkEV9N6okPyJJMj36kFhvQDvBdOQaqSUP2xhjJir7gK'
                          'dQ1sfXkY+6b6yDQtLyDqG0ksepzmGMjy9g94gxxozE0FqT3cDNwP8AfsEIWR9HIkSsy8h//SJyjexCFYmD2NI2xpgjsQ'
                          '/lTf8O+CmyqO9Depq4O2kaa7hAtYnJYtQD5IPA2aiMvIA2gfhhi9sYMxGIe4bEjwoS4weBryKhjnt9xDqamFqFtICGQJ'
                          '6E3CIzUBByJbAM9QaZk8HrGGNMKxNPIX8eeR/WU+06+hIqId9RywtkKaIFJNZLgdNRB6ozo5+zeGNpuzHGjAcGkcW8Bg'
                          '0LWINm276EXCBBFvSRKFQqmTyPMcaYOuJWpcYYkwMs1sYYkwMs1sYYkwMs1sYYkwMs1sYYkwMs1sYYkwMs1sYYkwMs1s'
                          'YYkwMs1sYYkwMs1sYYkwMs1sYYkwMs1sYYkwMs1sYYkwMs1sYYkwMs1sYYkwMs1sYYkwMs1sYYkwMs1sYYkwMs1sYYkw'
                          'Ms1sYYkwMs1sYYkwMs1sYYkwMs1sYYkwMs1sYYkwMs1sYYkwMs1sYYkwMs1sYYkwPam70AE06hUDgBmNTkZRwCBoAScA'
                          'DY29zl1EQzz+cBdA7j87gPqDRpLQBUKk19eXMECv5g8kehUHgcOLXZ6xhGGdgVPbYA66PHOuAJYEPzljYmrXY+dwG7ge'
                          '3ovG2KHk8Da9BGWTesCa2JxTqHtKhYj8Ue4DHgduCXwCNI4FuBPJ3PCtoAHwJ+C/wGCXl2L2BNaEks1jkkp2I9nN3A94'
                          'GvAfc3dym5EuuRWAd8B/hW9OeasCa0Jg4wmmYxG/hj4D5gLXAt0NnUFeWX44C/Bp4H7gXeAxSauiKTORZr0wqcAHwFeA'
                          'H4FBaaWjgPuBl4EvgAPpfjBou1aSWWAl8G7gZWNXkteecU4EbgDuDE5i7FZIHF2rQi56Ng5H/AlmGtXIR88p9r9kJMbV'
                          'isTavSAfw/wNexL7tWuoB/Am6I/mxyiMXatDofB36ABTsLPgz8DJjc7IWYcCzWJg9chazCtmYvZBxwCfBTml8BawKxWJ'
                          'u88D7gvzZ7EeOEi5F7yfGAHGGxNnniPwPvaPYixgkfAP6i2YswybFYm7zxZWB6sxcxTvhvwBnNXoRJhrvuTVxuQ42W0j'
                          'AZZRXMAuag/OhFNManvAj4P1FaXyuR5nx2onM5BZ3L+cDRwIxsl3ZE2oF/Bc5GXf9MC+PeIDkko94g7wVuyWA5MR2o+O'
                          'J0lNt7GbA8w+cfygCqetyY0fO12vmcCaxGa7oQBQXnZ/TcI3EdumMB3BukVbEbxGTFAPAU8A3g08CK/7+9+w3dq6zjOP'
                          '4eKvijsjUWYv8tURIfSFNCSSoqpT8W+iAsCIxIIxUi/ySmVsMso81Ay/7gKiIlfaCiUk5swfqDgwmZWubQ0jZd2lzLOZ'
                          'fzNx9cG4rIWvf5XPd17nPer0d7ss998YPf53fOub/nuoCjgCuBp8KftR9wbjizTzYDqyk/u1OAgyh/AH8EbKvweRfjaG'
                          'TvWdaqaS1wFuXWfhmwI5h9KuN5dj1PKe/TgDcAlwHPBPPfSPmjoB6zrDUNTwLnUG7p14cy5ygTDWOzCTif8rjpj8Hczw'
                          'WzVIFlrWm6E3gPucI+OZQzi/5C2UNlVSjvGOCtoSxVYFlr2tZRrogTj0Tey7iftT5N2bs6dWTaiaEcVWBZq4U/AFcFcu'
                          'ZwTngL5fl9wvtDOarAslYrl5K5ul4SyJh1q4GbAjnHBjJUiWWtVh4DfhXI8ZCC4ruBjEXUm41XR5a1Wro1kOGXYsUdwD'
                          '8DOW8PZKgCy1ot/S6Q8bpAxhDMU47w6uotgQxVYFmrpQcCGWN5MWZv3BnIeFMgQxVY1mrpGWBjx4xXJRYyEIkRPg8l6C'
                          'nLWq11fW3acnnBPwIZCwMZqsCyVmtdN3myrF+wJZDhz7OnLGu19sqO/z+5odGs+28gw9PPe8qyVmtdN9rfHlnFMCQOE0'
                          'kUviqwrNXSQro/I03c+g9FYjLm6UCGKrCs1VLiBYxHAxlDkZg53xzIUAWWtVo6LpCxIZAxFIm3ObcGMlSBZa2WPhLIuD'
                          '+QMRRHBzIeDmSoAstarRxM5sr6vkDGUCR+npOeeK/KLGu18qVQzppQzqxbArw5kHNPIEMVWNZq4SjKCehdbaQcbyX4TC'
                          'BjA2XrWvWQZa1pOwD4KbBPIOuOQMYQHAR8OpCzOpChSixrTdMccB1weCjvulDOrFsO7B/IuS2QoUosa03La4GVwAmhvC'
                          'fJnDQz6z4BnBLImSdzGIQqsaw1DR8D/gS8K5j5A3zV/N3AilDWSjInzagSy1q1LADeB6wCbgQODGZvJ3Pm4Cz7KPBLMo'
                          '8/AL4fylEliY1fpN32BY6kXEl/HDi00ud8h8zezbPoFcAlwBeCmeuAm4N5qsCyHq+DKcU6iVdTttJcTNmP4hDKPh9LKG'
                          'VS0wbgG5U/o4/mgE8BX6VMfyR9jfLMWj1mWY/X8tYLmNCpwL9bL2JK9gGOpdylfBJYVOEz1gLXVMhVmGWtWfJN4PbWiw'
                          'jbn3IAw2LKc/23AYcB7wCOoe6dyjxwBl5VzwTLWrPiJuDLrRexBze0XsAEvk3mRHRNgdMgmgWrKI8BvALMWQNc2HoR2n'
                          'uWtfpuJWUrVU8wyVkPnAQ823oh2nuWtfpsBRZ12r+AD+KhDTPHslYfbQdOo+wk59VfzhPA8ZS3STVj/IJRffN7Skm79W'
                          'nWOspdiifrzCivrNUX6yklfRwWddotwDuxqGeaV9Zq7W/AMuBqYFvbpQzOVsqJPN8DdjZeizqyrNXCTsrmTiso25zuaL'
                          'ucQboeOBt4pPVClGFZq4UFwFUM723E1nZSduJbii+7DI7PrNXKcrxYSNkCXEF5Tf3DWNSD5C/LeK1gshGuBZSd3w7o+P'
                          'lHAJ+lXGHr/7eJ8ijpBsodytgPYhg8y3q8bqb8sk9iDvh6YA1LgWuBzYGsIXuWMiFzN/BbysG29+GXhqNiWWsSlwOfB1'
                          '7fMWcxcDHwxc4rau9eyksnk9hC2ffkqV3/fhTYSHnL8H7gIfwSdvQsa01iG2UHvJ8Ess6kHCn110BWSxcy+Z2K9D/5Ba'
                          'Mm9TPKbXlX+1G26pS0B5a1JjUPnBPKOhH4QChLGiTLWl3cDtwWynKUT9oDy1pdnUdmKmH3KJ+kl2FZq6u7yXzRCGWUb2'
                          'EoSxoUy1oJF5HZhGn3KJ+kl7CslbCe8sw54Uzg0FCWNBiWtVIuAx4P5DjKJ70My1op/6HsGZLgKJ/0Epa1kn5I7k1ER/'
                          'mkF7GslbSDcjJJgqN80otY1kq7kbIzXIKjfNIulrVqODuU4yiftItlrRrWAL8IZTnKJ2FZq54LKJvmd+Uon4RlrXoeBK'
                          '4MZTnKp9GzrFXTJeSO7HKUT6NmWaumTWTOagRH+TRylrVquwL4eyjLUT6NlmWt2rZTvmxMcJRPo2VZaxquBdaGshzl0y'
                          'hZ1pqGneTOa3SUT6NkWWtafgPcEspylE+jY1lrms4DngtlOcqnUbGsNU1/Bq4OZR0BnB7KknrPsta0fQXYGspaCrwmlC'
                          'X1mmWtaXsM+FYoaxGl/KXBs6zVwjJKaSecARwWypJ6y7JWC1uBi0JZ+5I7WV3qLctarfwYuDeU9SHghFCW1EuWtVp5jt'
                          'x5jeAonwbOslZLtwK/DmUdjqN8GjDLWq2dS3kdPcFRPg2WZa3W7gJ+HspylE+D9TybtRZt+3rk2wAAAABJRU5ErkJggg'
                          '==')
        svg.write(buf)


def create_html():
    cwd = os.getcwd()
    
    output_file = Path(cwd + '/index.html')
    svg_file = Path(cwd + '/graph/simulation.dot.svg')
    svg_file_legend = Path(cwd + '/graph/legend.dot.svg')
    
    with open(svg_file, 'r') as svg:
        s = svg.read()
        svg.close()

    with open(svg_file_legend, 'r') as svg:
        legend = svg.read()
        svg.close()
    
    with open(output_file, 'w') as html_file:
        html_file.write("<!DOCTYPE html>\n"
                        "<html lang=\"en\">\n"
                        "<head>\n"
                        "<meta charset=\"UTF-8\">\n"
                        "<title>Title</title>\n"
                        "<link rel=\"stylesheet\" href=\"resources//animation.css\">\n"
                        "<script defer=\"\" src=\"resources//animation.js\"></script>\n"
                        "</head>\n"
                        "<body>\n"
                        "<ul id=\"link-container\">\n"
                        "</ul>\n")
        html_file.write(s)
        html_file.write("<br>\n")
        html_file.write(legend)
        html_file.write("</body>\n"
                        "</html>\n")
        html_file.close()


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
    
    os.system("python {} process --start_year {} --start_month {} --end_year {} --end_month {} --in_dir {} "
              "--out_dir {} --initial_descriptor_dir {} > /dev/null 2>&1".format(torps_path, start_year, start_month,
                                                                                 end_year, end_month, in_dir, out_dir,
                                                                                 initial_descriptors_dir))
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
