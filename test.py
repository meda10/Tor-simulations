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
    config.read('config.ini')
    print(config.sections())
    for key in config['node0']:
        print(key)
        

def run_simulation_0(guard_nodes=20, middle_nodes=20, exit_nodes=20, n_samples=25, fake_guards=0):
    routers = make_descriptors(guard_nodes, middle_nodes, exit_nodes)
    run_tor_path_simulator(n_samples)
    paths = get_paths()
    generate_large_graph(routers, paths, fake_guards)


def run_simulation_1(guard_nodes=5, middle_nodes=5, exit_nodes=5, n_samples=5):
    routers = make_descriptors(guard_nodes, middle_nodes, exit_nodes)
    run_tor_path_simulator(n_samples)
    paths = get_paths()
    generate_simple_graph(routers, paths)


def run_simulation_2(guard_nodes=1, middle_nodes=20, exit_nodes=20, n_samples=25):
    run_simulation_0(1, middle_nodes, exit_nodes, n_samples, guard_nodes - 1)


def run_simulation_3(guard_nodes=3, middle_nodes=20, exit_nodes=20, n_samples=25):
    run_simulation_0(3, middle_nodes, exit_nodes, n_samples, guard_nodes - 3)


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


def get_paths():
    output_file_path = Path(os.getcwd() + '/torps/out/simulation/output')
    with open(output_file_path, 'r+') as file:
        lines = file.readlines()
    
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
            x = (lines[i].split()[2], lines[i].split()[3], lines[i].split()[4])
            if x not in path:
                path.append(x)
    
    # print(guard_node)
    # print(middle_node)
    # print(exit_node)
    # print(len(path))
    # print(path)
    
    # for g in guard_node:
    # if g in exit_node:
    # print("______{}".format(g))
    
    # for p in path:
    # print(p)
    
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


def make_descriptors(guard_node=0, middle_node=0, exit_node=0, allow_guard_exit=True):
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


def generate_simple_graph(routers, paths):
    guard_node = []
    middle_node = []
    exit_node = []

    colors = ['aquamarine', 'black', 'blue', 'blueviolet', 'brown', 'burlywood', 'cadetblue',
              'chartreuse', 'chocolate', 'coral', 'cornflowerblue', 'crimson', 'cyan', 'darkgoldenrod', 'darkgreen',
              'darkkhaki', 'darkolivegreen', 'darkorange', 'darkorchid', 'darksalmon', 'darkseagreen', 'darkslateblue',
              'darkslategray', 'darkturquoise', 'darkviolet', 'deeppink', 'deepskyblue', 'dimgrey', 'dodgerblue',
              'firebrick', 'forestgreen', 'gold', 'goldenrod', 'green', 'greenyellow', 'hotpink', 'indianred', 'indigo',
              'lawngreen', 'magenta', 'mediumorchid', 'mediumpurple', 'mediumseagreen', 'mediumslateblue',
              'mediumspringgreen', 'mediumturquoise', 'mediumvioletred', 'midnightblue', 'navajowhite', 'olivedrab',
              'orange', 'orangered', 'orchid', 'paleturquoise', 'palevioletred', 'peru', 'plum', 'purple', 'red',
              'saddlebrown', 'salmon', 'sandybrown', 'seagreen', 'sienna', 'slateblue', 'slategrey', 'springgreen',
              'steelblue', 'tan', 'tomato', 'turquoise', 'violet', 'yellowgreen']
    
    graph = Digraph('test', format='svg')

    graph.attr(rankdir='TB')
    graph.attr(fontsize='10')

    if len(paths) > 20:
        graph.attr(overlap="false")
        graph.attr(splines='false')

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
    server_icon_path = "resources//server.svg"
    subgraph_pc.node("PC", label="", shape="none", image=computer_icon_path, fixedsize="true",
                     width="0.6", height="0.6")
    subgraph_server.node("SERVER", label="", shape="none", image=server_icon_path, imagescale="true",
                         width="0.7", height="0.7", margin="20")

    for r in routers:
        if "Guard" in r.flags:
            guard_node.append(r.address)
            subgraph_guards.node(str(r.address), shape='box', fontsize='10', fontname='Verdana')
        elif "Exit" in r.flags:
            exit_node.append(r.address)
            subgraph_exits.node(str(r.address), shape='hexagon', fontsize='10', fontname='Verdana')
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
        color = random.randint(0, 72)
        graph.edge("PC", path[0], color="{}".format(colors[color]), constraint="false", weight='0',
                   layer="path{}".format(index))
        graph.edge(path[0], path[1], color="{}".format(colors[color]), constraint="false", weight='0',
                   layer="path{}".format(index))
        graph.edge(path[1], path[2], color="{}".format(colors[color]), constraint="false", weight='0',
                   layer="path{}".format(index))
        graph.edge(path[2], "SERVER", color="{}".format(colors[color]), constraint="false", weight='0',
                   layer="path{}".format(index))

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
    generate_graph_legend("small")


def generate_large_graph(routers, paths, guards_to_generate):
    guard_node = []
    middle_node = []
    exit_node = []
    
    graph = Digraph('test', format='svg')
    
    graph.attr(layout='twopi')  # neato twopi
    graph.attr(ranksep='4 1.5 1.5')
    graph.attr(root='PC')
    graph.attr(size="6.75,9.25")
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
    server_icon_path = "resources//server.svg"
    graph.node("PC", label="", shape="none", image=computer_icon_path, fixedsize="true", width="1", height="1")
    graph.node("SERVER", label="", shape="none", image=server_icon_path, imagescale="true", width="1.3",
               height="1.3", margin="20")
    
    for index, r in enumerate(routers, start=0):
        if "Guard" in r.flags:
            guard_node.append(r.address)
            subgraph_guards.node(str(r.address), label="", style='filled', fillcolor="coral2", shape='box',
                                 height='0.3', width='0.3')
        elif "Exit" in r.flags:
            exit_node.append(r.address)
            subgraph_exits.node(str(r.address), label="", style='filled', fillcolor="forestgreen", shape='hexagon',
                                height='0.3', width='0.3')
        else:
            middle_node.append(r.address)
            subgraph_middles.node(str(r.address), label="", style='filled', fillcolor="dodgerblue", shape='ellipse',
                                  height='0.3', width='0.3')

    for i in range(0, guards_to_generate):
        guard_node.append("XX{}".format(i))
        subgraph_guards.node("XX{}".format(i), label="", style='filled', fillcolor="coral2", shape='box',
                             height='0.3', width='0.3')
    
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
    
    if len(exit_node) > len(middle_node):
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
    generate_graph_legend("large")


def generate_graph_legend(graph_type="large"):
    graph = Digraph('test', format='svg')
    
    graph.attr(layout='dot', rankdir="TB", rankstep="0.8", constraint="false")  # neato twopi dot
    
    graph.attr(size="3.5,5")
    
    subgraph_legend = Digraph('cluster_legend')
    guard_l = Digraph('cluster_guard_l')
    mid_l = Digraph('cluster_middle_l')
    exit_l = Digraph('cluster_exit_l')
    gu_mi_l = Digraph('cluster_gu_mi_l')
    gu_ex_l = Digraph('cluster_gu_ex_l')
    
    subgraph_legend.attr(label="Key")
    guard_l.attr(label="Guard", penwidth="0")
    mid_l.attr(label="Middle", penwidth="0")
    exit_l.attr(label="Exit", penwidth="0")
    gu_mi_l.attr(label="Guard\nMiddle", penwidth="0")
    gu_ex_l.attr(label="Guard\nExit", penwidth="0")

    if graph_type is "large":
        # guard_l.node("GU", label="", style='filled', fillcolor="darkorchid1", shape='box', height='0.3', width='0.3')
        gu_mi_l.node("GU_MI", label="", style='filled', fillcolor="coral2", shape='box', height='0.3', width='0.3')
        exit_l.node("EX", label="", style='filled', fillcolor="forestgreen", shape='hexagon', height='0.3', width='0.3')
        mid_l.node("MI", label="", style='filled', fillcolor="dodgerblue", shape='ellipse', height='0.3', width='0.3')
        # gu_ex_l.node("GU_EX", label="", style='filled', fillcolor="lawngreen", shape='box', height='0.3', width='0.3')
    else:
        # guard_l.node("GU", label="", shape='box', height='0.3', width='0.3')
        gu_mi_l.node("GU_MI", label="", shape='box', height='0.3', width='0.3')
        exit_l.node("EX", label="", shape='hexagon', height='0.3', width='0.3')
        mid_l.node("MI", label="", shape='ellipse', height='0.3', width='0.3')
        # gu_ex_l.node("GU_EX", label="", shape='box', height='0.3', width='0.3')
        
    subgraph_legend.subgraph(gu_mi_l)
    subgraph_legend.subgraph(gu_ex_l)
    subgraph_legend.subgraph(exit_l)
    subgraph_legend.subgraph(mid_l)
    subgraph_legend.subgraph(guard_l)
    graph.subgraph(subgraph_legend)

    graph.render('graph/legend.dot', view=False)


def create_html():
    cwd = os.getcwd()
    
    output_file = Path(cwd + '/index.html')
    svg_file = Path(cwd + '/graph/simulation.dot.svg')
    svg_file_legend = Path(cwd + '/graph/legend.dot.svg')
    
    with open(svg_file, 'r') as svg:
        s = svg.read()
        svg.close()

    with open(svg_file_legend, 'r') as svg:
        l = svg.read()
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
                        "<p>Výsledek:</p>\n"
                        "<ul id=\"link-container\">\n"
                        "</ul>\n")
        html_file.write(s)
        html_file.write("<br>\n")
        html_file.write(l)
        html_file.write("</body>\n"
                        "</html>\n")
        html_file.close()


def run_tor_path_simulator(n_samples=5):
    cwd = os.getcwd()
    output_folder = Path(cwd + '/torps/out/network-state-2019-02')
    simulation_folder = Path(cwd + '/torps/out/simulation')
    
    if not output_folder.exists():
        output_folder.mkdir(parents=True)
    
    if not simulation_folder.exists():
        simulation_folder.mkdir(parents=True)
    
    simulation_file = simulation_folder / "output"
    
    xxx = '/home/petr/TorPs'
    
    torps_path = Path(xxx + '/pathsim.py')
    dir_path = output_folder
    output_file_path = simulation_file
    num_samples = n_samples
    tracefile = Path(xxx + '/in/users2-processed.traces.pickle')
    usermodel = 'simple=60000'
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
    in_dir = Path(cwd + '/torps/in')
    out_dir = Path(cwd + '/torps/out')
    initial_descriptors_dir = Path(cwd + '/torps/in/server-descriptors-2019-02')
    
    os.system("python {} process --start_year {} --start_month {} --end_year {} --end_month {} --in_dir {} "
              "--out_dir {} --initial_descriptor_dir {} > /dev/null 2>&1".format(torps_path, start_year, start_month,
                                                                                 end_year, end_month, in_dir, out_dir,
                                                                                 initial_descriptors_dir))
    
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
    # generate_large_graph_legend()
    
    # run_simulation_2(20,3,20,50)
    # run_simulation_1(8,3,5,19)

    run_simulation_0(2, 5, 8, 150)
    create_html()
    
    # todo generate exit/Guard - parse flags
    # todo generate IP
    # todo configfile
