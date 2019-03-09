import binascii
import math
import os
import random
import sys

try:
    import stem
    import stem.descriptor
    import stem.util.str_tools
    import ntor
    from graphviz import Digraph
    from collections import namedtuple
    from stem.descriptor.server_descriptor import RelayDescriptor, _truncated_b64encode
    from stem.descriptor.extrainfo_descriptor import RelayExtraInfoDescriptor
    from stem.descriptor.networkstatus import NetworkStatusDocumentV3
    from stem.descriptor.router_status_entry import RouterStatusEntryV3
except ImportError:
    print('Creating descriptors requires stem (https://stem.torproject.org/)')
    sys.exit(1)

if not hasattr(stem.descriptor, 'create_signing_key'):
    print('This requires stem version 1.6 or later, you are running version %s' % stem.__version__)
    sys.exit(1)

OUTPUT_DIR = os.path.join(os.getcwd(), 'generated_descriptors')


def make_output_dir():
    if not os.path.exists(OUTPUT_DIR):
        os.mkdir(OUTPUT_DIR)


def write_descriptors(descs, filename):
    output_desc_path = '//home//petr//TorPs//in//server-descriptors-2019-02//2019-02-23-12-05-01-server-descriptors'
    
    if filename == 'server-descriptors':
        with open(output_desc_path, 'w') as descriptor_file:
            for descriptor in descs:
                descriptor_file.write('@type server-descriptor 1.0\n')
                descriptor_file.write(str(descriptor))
            descriptor_file.flush()


def write_descriptor(desc, filename):
    # make_output_dir()
    
    output_desc_path = '//home//petr//TorPs//in//server-descriptors-2019-02//2019-02-23-12-05-01-server-descriptors'
    output_consensus_path = '//home//petr//TorPs//in//consensuses-2019-02//2019-02-23-12-00-00-consensus'
    
    if filename == 'server-descriptors':
        with open(output_desc_path, 'w') as descriptor_file:
            descriptor_file.write('@type server-descriptor 1.0\n')
            descriptor_file.write(str(desc))
    elif filename == 'consensus':
        with open(output_consensus_path, 'w') as descriptor_file:
            descriptor_file.write('@type network-status-consensus-3 1.0\n')
            descriptor_file.write(str(desc))


def parse_out():
    # output_file_path = '//home//petr//TorPs//output'
    output_file_path = '//home//petr//PycharmProjects//Descriptors//generator_out//output'
    with open(output_file_path, 'r+') as fh:
        lines = fh.readlines()
        fh.close()
    
    guard_node = ['Guard']
    middle_node = ['Middle']
    exit_node = ['Exit']
    path = []
    
    for i in range(0, len(lines)):
        if lines[i].split()[2] not in guard_node and not lines[i].split()[2].__eq__('Guard'):
            guard_node.append(lines[i].split()[2])
        if lines[i].split()[3] not in middle_node and not lines[i].split()[3].__eq__('IP'):
            middle_node.append(lines[i].split()[3])
        if lines[i].split()[4] not in exit_node and not lines[i].split()[4].__eq__('Middle'):
            exit_node.append(lines[i].split()[4])
        if not lines[i].split()[2].__eq__('Guard'):
            path.append((lines[i].split()[2], lines[i].split()[3], lines[i].split()[4]))
    
    print(guard_node)
    print(middle_node)
    print(exit_node)
    
    return path


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
    
    attr = {
        'r': ' '.join([
            self.nickname,
            _truncated_b64encode(binascii.unhexlify(stem.util.str_tools._to_bytes(self.fingerprint))),
            _truncated_b64encode(binascii.unhexlify(stem.util.str_tools._to_bytes(self.digest()))),
            self.published.strftime('%Y-%m-%d %H:%M:%S'),
            self.address,
            str(self.or_port),
            str(self.dir_port) if self.dir_port else '0',
            ]),
        }
    
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
    return '%i.%i.%i.%i' % (random.randint(0, 255), random.randint(0, 255),
                            random.randint(0, 255), random.randint(0, 255))


def generate_port():
    return '%i' % (random.randint(20842, 65535))


def generate_bandwidth(variance=30):
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


def make_descriptors(guard_node=0, middle_node=0, exit_node=0):
    consensus_entries = []
    server_descriptors = []
    
    for i in range(0, guard_node):
        signing_key = stem.descriptor.create_signing_key()
        server_desc = RelayDescriptor.create({'router': '%s %s %s 0 0' % (generate_nickname(),
                                                                          generate_ipv4_address(),
                                                                          generate_port().__str__()),
                                              'protocols': 'Link 1 2 Circuit 1',
                                              'platform': 'Tor 0.2.4.8 on Linux',
                                              'bandwidth': '%s' % (generate_bandwidth()),
                                              'published': '2019-03-04 13:37:39',
                                              'uptime': '26963362',
                                              'reject': '*:*',
                                              'ntor-onion-key': '%s' % generate_ntor_key(),
                                              }, validate=True, sign=True, signing_key=signing_key)
        server_descriptors.append(server_desc)
        
        consensus_entries.append(generate_router_status_entry(server_desc, 'Fast Guard Running Stable Valid'))
        write_descriptor(server_desc, 'server_descriptor_%i' % i)
    
    for i in range(guard_node, guard_node + middle_node):
        signing_key = stem.descriptor.create_signing_key()
        server_desc = RelayDescriptor.create({'router': '%s %s %s 0 0' % (generate_nickname(),
                                                                          generate_ipv4_address(),
                                                                          generate_port().__str__()),
                                              'protocols': 'Link 1 2 Circuit 1',
                                              'platform': 'Tor 0.2.4.8 on Linux',
                                              'bandwidth': '%s' % (generate_bandwidth()),
                                              'published': '2019-03-04 13:37:39',
                                              'reject': '*:*',
                                              }, validate=True, sign=True, signing_key=signing_key)
        server_descriptors.append(server_desc)
        
        consensus_entries.append(generate_router_status_entry(server_desc, 'Fast Running Stable Valid'))
        write_descriptor(server_desc, 'server_descriptor_%i' % i)
    
    for i in range(guard_node + middle_node, guard_node + middle_node + exit_node):
        signing_key = stem.descriptor.create_signing_key()
        server_desc = RelayDescriptor.create({'published': '2019-03-04 13:37:39',
                                              'reject': '0.0.0.0/8:*',
                                              'accept': '*:*',
                                              'router': '%s %s %s 0 0' % (generate_nickname(),
                                                                          generate_ipv4_address(),
                                                                          generate_port().__str__()),
                                              }, validate=True, sign=True, signing_key=signing_key)
        server_descriptors.append(server_desc)
        consensus_entries.append(generate_router_status_entry(server_desc, 'Exit Fast Running Stable Valid'))
        
        write_descriptor(server_desc, 'server_descriptor_%i' % i)
    
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


def generate_graph(routers, paths):
    MyStruct = namedtuple("path", "guard middle exit")
    x = MyStruct(guard=('Unnamed1548', '214.215.85.37'),
                 middle=('Unnamed1549', '192.255.55.25'),
                 exit=('Unnamed1550', '87.84.85.37'))
    
    guard_node = []
    middle_node = []
    exit_node = []
    
    dot = Digraph(comment='Nodes')
    
    for r in routers:
        if "Guard" in r.flags:
            guard_node.append(r.address)
        elif "Exit" in r.flags:
            exit_node.append(r.address)
        else:
            middle_node.append(r.address)
        dot.node(r.address, r.address)
    
    for g in guard_node:
        print(g)
    
    g = ('; '.join(str(g) for g in guard_node))
    e = ('; '.join(str(e) for e in exit_node))
    m = ('; '.join(str(m) for m in middle_node))
    
    dot.attr(rank="same; " + g)
    dot.attr(rank="same; " + e)
    dot.attr(rank="same; " + m)
    
    for path in paths:
        dot.edge(path[0], path[1])
        dot.edge(path[1], path[2])
    
    dot.render('test-output/simple_simulation.gv', view=False)


def graph_test_generator(routers, paths):
    guard_node = []
    middle_node = []
    exit_node = []
    
    # graph = Digraph(comment='Nodes')
    graph = Digraph('test', format='png')
    
    subgraph_guards = Digraph('subgraph_guards')
    subgraph_middles = Digraph('subgraph_middles')
    subgraph_exits = Digraph('subgraph_exits')
    
    subgraph_guards.graph_attr.update(rank='same')
    subgraph_middles.graph_attr.update(rank='same')
    subgraph_exits.graph_attr.update(rank='same')
    
    for r in routers:
        if "Guard" in r.flags:
            # guard_node.append(r.address)
            subgraph_guards.node(str(r.address), color='red')
        elif "Exit" in r.flags:
            # exit_node.append(r.address)
            subgraph_exits.node(str(r.address), color='green')
        else:
            # middle_node.append(r.address)
            subgraph_middles.node(str(r.address), color='blue')
    
    for path in paths:
        graph.edge(path[0], path[1])
        graph.edge(path[1], path[2])
    
    graph.subgraph(subgraph_guards)
    graph.subgraph(subgraph_middles)
    graph.subgraph(subgraph_exits)
    
    graph.render('test-output/simple_simulation.gv', view=True)


def run_simulation():
    dir_path = '//home//petr//TorPs//out//network-state-2019-02'
    output_file_path = '//home//petr//PycharmProjects//Descriptors//generator_out//output'
    num_samples = '5'
    tracefile = '//home//petr//TorPs//in//users2-processed.traces.pickle'
    usermodel = 'simple=6000'
    format_arg = 'normal'
    adv_guard_bw = '0'
    adv_exit_bw = '0'
    adv_time = '0'
    num_adv_guards = '0'
    num_adv_exits = '0'
    num_guards = '1'
    gard_expiration = '80000000'
    loglevel = 'INFO'
    path_alg = 'tor'
    
    start_year = '2019'
    end_year = '2019'
    start_month = '2'
    end_month = '2'
    in_dir = '//home//petr//TorPs//in'
    out_dir = '//home//petr//TorPs//out'
    initial_descriptors_dir = '//home//petr//TorPs//in//server-descriptors-2019-02'
    
    # os.system("python //home//petr//TorPs//pathsim.py simulate --help")
    
    os.system("python //home//petr//TorPs//pathsim.py process --start_year {} --start_month {} --end_year {} "
              "--end_month {} --in_dir {} --out_dir {} --initial_descriptor_dir {} > /dev/null 2>&1"
              .format(start_year, start_month, end_year, end_month, in_dir, out_dir, initial_descriptors_dir))
    
    os.system("python //home//petr//TorPs//pathsim.py simulate --nsf_dir {} --num_samples {} --trace_file {} "
              "--user_model {} --format {} --adv_guard_cons_bw {} --adv_exit_cons_bw {} --adv_time {} "
              "--num_adv_guards {} --num_adv_exits {} --num_guards {} --guard_expiration {} --loglevel {} {} > {}"
              .format(dir_path, num_samples, tracefile, usermodel, format_arg, adv_guard_bw, adv_exit_bw, adv_time,
                      num_adv_guards, num_adv_exits, num_guards, gard_expiration, loglevel, path_alg, output_file_path))
    
    """
    os.system("python //home//petr//TorPs//pathsim.py simulate "
              "--nsf_dir //home//petr//TorPs//out//network-state-2019-02 --num_samples 1 "
              "--user_model simple=600 --format normal tor")
    """


if __name__ == '__main__':
    # if len(sys.argv) < 2 or not sys.argv[1].isdigit():
    #     print('We need a numeric argument indicating how many descriptors to make.')
    #    sys.exit(1)

    routers = make_descriptors(1, 5, 1)
    run_simulation()
    paths = parse_out()
    graph_test_generator(routers, paths)
    # generate_graph(routers, paths)
    
    # create_server_descriptors()
    # create_consensus()
