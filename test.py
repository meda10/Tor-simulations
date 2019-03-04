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
    output_file_path = '//home//petr//TorPs//output'
    with open(output_file_path, 'r+') as fh:
        lines = fh.readlines()
        fh.close()
    
    guard_node = ['Guard']
    middle_node = ['Middle']
    exit_node = ['Exit']
    
    for i in range(0, len(lines)):
        if lines[i].split()[2] not in guard_node and not lines[i].split()[2].__eq__('Guard'):
            guard_node.append(lines[i].split()[2])
        if lines[i].split()[3] not in middle_node and not lines[i].split()[3].__eq__('IP'):
            middle_node.append(lines[i].split()[3])
        if lines[i].split()[4] not in exit_node and not lines[i].split()[4].__eq__('Middle'):
            exit_node.append(lines[i].split()[4])
    
    print(guard_node)
    print(middle_node)
    print(exit_node)


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


if __name__ == '__main__':
    # if len(sys.argv) < 2 or not sys.argv[1].isdigit():
    #     print('We need a numeric argument indicating how many descriptors to make.')
    #    sys.exit(1)

    make_descriptors(5, 5, 5)
    parse_out()
    # create_server_descriptors()
    # create_consensus()
