#!/usr/bin/python3
import binascii
import os
import random
import sys
import math
import collections
import getopt
import re
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
    dic = {}

    try:
        dic['remove_duplicate_paths'] = config.getboolean('general', 'remove_duplicate_paths')
        dic['generate_graph'] = config.getboolean('general', 'generate_graph')
        dic['create_html'] = config.getboolean('general', 'create_html')
        dic['path'] = config['general']['path']
        dic['same_bandwidth'] = config.getboolean('general', 'same_bandwidth')
        dic['guard_bandwidth_value'] = None if config['general']['guard_bandwidth_value'] == '' else config.getint('general', 'guard_bandwidth_value')
        dic['exit_bandwidth_value'] = None if config['general']['exit_bandwidth_value'] == '' else config.getint('general', 'exit_bandwidth_value')
        dic['middle_bandwidth_value'] = None if config['general']['middle_bandwidth_value'] == '' else config.getint('general', 'middle_bandwidth_value')
        dic['simulation_type'] = config['general']['simulation_type']
    except KeyError as e:
        print('Key Error: {}'.format(e))
        sys.exit(1)
    except ValueError as e:
        print("Value Error: {}".format(e))
        sys.exit(1)
    except configparser.NoOptionError as e:
        print("Key Error: {}".format(e))
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
            dic['encryption'] = 0
            dic['identification_occurrence'] = 0
            dic['path_selection'] = config['path_simulation']['path_selection']
            dic['simulation_size'] = config['path_simulation']['simulation_size']
        except ValueError as e:
            print("Value Error: {}".format(e))
            sys.exit(1)
        except configparser.NoOptionError as e:
            print("Key Error: {}".format(e))
            sys.exit(1)

        if dic['simulation_size'] == 'small':
            if dic['path_selection'] != 'random':
                print('Value of path_selection have to be: random')

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
            dic['encryption'] = 0
            dic['identification_occurrence'] = 0
            dic['path_selection'] = 'random'
        except ValueError as e:
            print("Value Error: {}".format(e))
            sys.exit(1)
        except configparser.NoOptionError as e:
            print("Key Error: {}".format(e))
            sys.exit(1)
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
            dic['encryption'] = config.getint('attack_simulation', 'encryption')
            dic['identification_occurrence'] = config.getint('attack_simulation', 'identification_occurrence')
        except ValueError as e:
            print("Value Error: {}".format(e))
            sys.exit(1)
        except configparser.NoOptionError as e:
            print("Key Error: {}".format(e))
            sys.exit(1)
    elif config['general']['simulation_type'] == 'exit_attack':
        try:
            dic['guard'] = config.getint('exit_attack', 'guard')
            dic['middle'] = 0
            dic['exit'] = config.getint('exit_attack', 'exit')
            dic['guard_exit'] = 0
            dic['number_of_simulations'] = config.getint('exit_attack', 'number_of_simulations')
            dic['adv_exit'] = config.getint('exit_attack', 'adv_exit')
            dic['adv_guard'] = 0
            dic['adv_guard_bandwidth'] = 0
            dic['adv_exit_bandwidth'] = config.getint('exit_attack', 'adv_exit_bandwidth')
            dic['path_selection'] = 'random'
            dic['encryption'] = config.getint('exit_attack', 'encryption')
            dic['identification_occurrence'] = 0
        except ValueError as e:
            print("Value Error: {}".format(e))
            sys.exit(1)
        except configparser.NoOptionError as e:
            print("Key Error: {}".format(e))
            sys.exit(1)
    elif config['general']['simulation_type'] == 'multiple_sim':
        try:
            dic['number_of_simulations'] = config.getint('attack_simulation', 'number_of_simulations')
            dic['same_bandwidth'] = True
            dic['path_selection'] = 'random'
        except ValueError as e:
            print("Value Error: {}".format(e))
            sys.exit(1)
        except KeyError as e:
            print("Key Error: {}".format(e))
            sys.exit(1)
        except configparser.NoOptionError as e:
            print("Key Error: {}".format(e))
            sys.exit(1)

        try:
            for s in config.sections():
                sim = {}
                if 'sim_' in s:
                    sim['encryption'] = config.getint(s, 'encryption')
                    sim['identification_occurrence'] = config.getint(s, 'identification_occurrence')
                    sim['guard'] = config.getint(s, 'guard')
                    sim['middle'] = 0
                    sim['exit'] = config.getint(s, 'exit')
                    sim['guard_exit'] = 0
                    sim['number_of_simulations'] = config.getint('multiple_sim', 'number_of_simulations')
                    sim['adv_exit'] = config.getint(s, 'adv_exit')
                    sim['adv_guard'] = config.getint(s, 'adv_guard')
                    sim['adv_guard_bandwidth'] = config.getint(s, 'adv_guard_bandwidth')
                    sim['adv_exit_bandwidth'] = config.getint(s, 'adv_exit_bandwidth')
                    sim['friendly_guard_bandwidth'] = config.getint(s, 'friendly_guard_bandwidth')
                    sim['friendly_exit_bandwidth'] = config.getint(s, 'friendly_exit_bandwidth')
                    sim['path_selection'] = 'random'
                    all_sims.append(sim)
        except KeyError as e:
            print('Key Error: {}'.format(e))
            sys.exit(1)
        except ValueError as e:
            print("Value Error: {}".format(e))
            sys.exit(1)
        except configparser.NoOptionError as e:
            print("Key Error: {}".format(e))
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

    if config['general']['simulation_type'] != 'multiple_sim':
        if dic['guard'] < 0 or dic['middle'] < 0 or dic['exit'] < 0:
            print('Number of nodes have to be > 0')
            sys.exit(1)

    conf.append(dic)
    conf.append(all_nodes)
    conf.append(all_sims)
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
                             sim['friendly_guard_bandwidth'], sim['friendly_exit_bandwidth'],
                             0, sim['adv_guard'], sim['adv_exit']))
            run_tor_path_simulator(config[0]['path'], sim['adv_guard'], sim['adv_exit'], sim['adv_guard_bandwidth'],
                                   sim['adv_exit_bandwidth'], sim['number_of_simulations'])
            circuits_output = get_circuits(config[0]['remove_duplicate_paths'], routers, sim['adv_guard_bandwidth'],
                                           sim['adv_exit_bandwidth'], config[0]['simulation_type'], loop_count,
                                           sim['encryption'], sim['friendly_guard_bandwidth'],
                                           sim['friendly_exit_bandwidth'], sim['identification_occurrence'],
                                           sim['adv_guard'], sim['adv_exit'])
            output_from_all_sims.append(circuits_output)
            loop_count += 1
        if config[0]['generate_graph']:
            g = GraphGenerator(sim_type=config[0]['simulation_type'], output_from_all_sims=output_from_all_sims)
            GraphGenerator.generate_graph(g)
    else:
        routers = make_descriptors(check_params(config[0]['path_selection'], config[0]['guard'], config[0]['middle'],
                                                config[0]['exit'], config[0]['guard_exit'], config[0]['same_bandwidth'],
                                                config[1], config[0]['simulation_type'],
                                                config[0]['guard_bandwidth_value'], config[0]['exit_bandwidth_value'],
                                                config[0]['middle_bandwidth_value'], config[0]['adv_guard'],
                                                config[0]['adv_exit']))
        run_tor_path_simulator(config[0]['path'], config[0]['adv_guard'], config[0]['adv_exit'],
                               config[0]['adv_guard_bandwidth'], config[0]['adv_exit_bandwidth'],
                               config[0]['number_of_simulations'])
        circuits_output = get_circuits(config[0]['remove_duplicate_paths'], routers, config[0]['adv_guard_bandwidth'],
                                       config[0]['adv_exit_bandwidth'], config[0]['simulation_type'], loop_count,
                                       config[0]['encryption'], config[0]['guard_bandwidth_value'],
                                       config[0]['exit_bandwidth_value'], config[0]['identification_occurrence'],
                                       config[0]['adv_guard'], config[0]['adv_exit'])

    if config[0]['simulation_type'] == 'hidden_service' and config[0]['generate_graph']:
        g = GraphGenerator(routers=routers, paths=circuits_output[0], sim_type=config[0]['simulation_type'])
        exit_code_graph = GraphGenerator.generate_graph(g)      # todo exit code graph
    elif (config[0]['simulation_type'] == 'attack' or config[0]['simulation_type'] == 'exit_attack') and config[0]['generate_graph']:
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
        create_html(config[0]['simulation_type'])


def write_descriptors(descs, filename):
    cwd = os.getcwd()
    output_folder = Path(cwd + '/torps/in/server-descriptors-2019-02')
    output_file = Path(cwd + '/torps/in/server-descriptors-2019-02/2019-02-23-12-05-01-server-descriptors')

    if not output_folder.exists():
        output_folder.mkdir(parents=True)
    
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
    
    # output_file_desc = output_folder_desc / "2019-02-23-12-05-01-server-descriptors"
    # output_file_cons = output_folder_cons / "2019-02-23-12-00-00-consensus"
    output_file_desc = Path(str(output_folder_desc) + '/2019-02-23-12-05-01-server-descriptors')
    output_file_cons = Path(str(output_folder_cons) + '/2019-02-23-12-00-00-consensus')

    if filename == 'server-descriptors':
        with open(output_file_desc, 'w') as file:
            file.write('@type server-descriptor 1.0\n')
            file.write(str(desc))

    elif filename == 'consensus':
        with open(output_file_cons, 'w') as file:
            file.write('@type network-status-consensus-3 1.0\n')
            file.write(str(desc))


def get_circuits(remove_duplicate_paths, routers, adv_guard_bandwidth, adv_exit_bandwidth, sim_type, loop_count,
                 encryption_percentage, guard_bandwidth, exit_bandwidth, identification_occurrence,
                 adv_guard=None, adv_exit=None):
    circuits = []
    attackers_guards = []
    attackers_exits = []
    attackers_middle = []
    circuit_list = []
    color = {}
    node_usage = collections.Counter()
    id_node_usage = collections.Counter()
    encrypted_node_usage = collections.Counter()
    id_stolen_node_usage = collections.Counter()
    encrypted_attacker_guard = collections.Counter()
    encrypted_attacker_exit = collections.Counter()
    encrypted_attacker_middle = collections.Counter()
    statistic = collections.Counter({'bad_guard_used': 0,
                                     'bad_exit_used': 0,
                                     'bad_circuit': 0,
                                     'bad_node': 0,
                                     'bad_gu_and_ex': 0,
                                     'encrypted': 0,
                                     'id': 0,
                                     'not_encrypted_id': 0,
                                     'not_encrypted_id_stolen': 0,
                                     'bad_guard_encrypt': 0,
                                     'bad_middle_encrypt': 0,
                                     'bad_exit_encrypt': 0,
                                     'bad_gu_and_ex_encrypt': 0,
                                     'adv_guard': adv_guard,
                                     'adv_exit': adv_exit,
                                     'encryption': encryption_percentage,
                                     'identification_occurrence': identification_occurrence,
                                     'adv_guard_bandwidth': adv_guard_bandwidth,
                                     'adv_exit_bandwidth': adv_exit_bandwidth,
                                     'guard_bandwidth': guard_bandwidth,
                                     'exit_bandwidth': exit_bandwidth
                                     })
    output_file_path = Path(os.getcwd() + '/torps/out/simulation/output')
    with open(output_file_path, 'r+') as file:
        lines = file.readlines()

    for i in range(0, len(lines)):
        if not lines[i].split()[2].__eq__('Guard'):
            circuit = (lines[i].split()[2], lines[i].split()[3], lines[i].split()[4])
            if circuit[0][:3] == '10.' or circuit[1][:3] == '10.' or circuit[2][:3] == '10.':
                circuit_entry = {'guard': circuit[0], 'middle': circuit[1], 'exit': circuit[2], 'affiliation': True}
            else:
                circuit_entry = {'guard': circuit[0], 'middle': circuit[1], 'exit': circuit[2], 'affiliation': False}
            circuit_list.append(circuit_entry)
            node_usage.update(circuit)
            if circuit not in circuits and remove_duplicate_paths:
                circuits.append(circuit)
            elif not remove_duplicate_paths:
                circuits.append(circuit)

            # attack nodes
            if sim_type == 'attack' or sim_type == 'exit_attack' or sim_type == 'multiple_sim':
                encrypted = get_encryption(encryption_percentage)
                id_included = get_id(identification_occurrence)
                if encrypted:
                    statistic.update(['encrypted'])
                    encrypted_node_usage.update(circuit)
                if id_included and sim_type == 'attack':
                    statistic.update(['id'])
                    id_node_usage.update(circuit)
                if id_included and not encrypted:
                    statistic.update(['not_encrypted_id'])

                if circuit[0][:3] == '10.':  # guard
                    statistic.update(['bad_guard_used', 'bad_node'])
                    if encrypted:
                        statistic.update(['bad_guard_encrypt'])
                        encrypted_attacker_guard.update(['{}'.format(circuit[0])])
                    attackers_guards.append(circuit[0]) if circuit[0] not in attackers_guards else None
                if circuit[1][:3] == '10.':  # middle
                    statistic.update(['bad_node'])
                    if encrypted:
                        statistic.update(['bad_middle_encrypt'])
                        encrypted_attacker_middle.update(['{}'.format(circuit[1])])
                    attackers_middle.append(circuit[1]) if circuit[1] not in attackers_middle else None
                if circuit[2][:3] == '10.':  # exit
                    statistic.update(['bad_exit_used', 'bad_node'])
                    if encrypted:
                        statistic.update(['bad_exit_encrypt'])
                        encrypted_attacker_exit.update(['{}'.format(circuit[2])])
                    attackers_exits.append(circuit[2]) if circuit[2] not in attackers_exits else None

                if circuit[0][:3] == '10.' or circuit[1][:3] == '10.' or circuit[2][:3] == '10.':
                    if id_included and not encrypted and sim_type == 'attack':
                        statistic.update(['not_encrypted_id_stolen'])
                        id_stolen_node_usage.update(circuit)
                if circuit[0][:3] == '10.' and circuit[1][:3] == '10.' and circuit[2][:3] == '10.':
                    statistic.update(['bad_circuit'])
                elif circuit[2][:3] == '10.' and circuit[0][:3] == '10.':
                    statistic.update(['bad_gu_and_ex'])
                    if encrypted:
                        statistic.update(['bad_gu_and_ex_encrypt'])

    create_output_json(circuit_list)
    create_statistic(loop_count, statistic)
    create_node_statistic(routers, sim_type, adv_guard_bandwidth, adv_exit_bandwidth, node_usage, encrypted_node_usage,
                          attackers_guards, attackers_exits, attackers_middle, id_node_usage, id_stolen_node_usage)

    # calculate color for graph
    if sim_type == 'exit_attack':
        # alpha - % | node usage - node usage max
        # blue - % | encrypted
        dict_max = node_usage[max(node_usage.items(), key=operator.itemgetter(1))[0]]
        for k in node_usage.keys():
            encrypted_usage = (100 * (encrypted_node_usage['{}'.format(k)])) / node_usage[k]
            blue = hex(round((255 * encrypted_usage / 100)))[2:]
            alpha = hex(round((100 * node_usage[k] / dict_max) * 255 / 100))[2:]
            color[k] = (alpha, blue)

    elif sim_type == 'attack':
        # add nodes that were not in enemy circuts
        for node in id_node_usage:
            if node not in id_stolen_node_usage.keys():
                id_stolen_node_usage['{}'.format(node)] = 0  # id_node_usage[node]

        # statistic: enemy nodes - stolen count | friendly nodes - not stolen count
        for node in id_stolen_node_usage.keys():
            if node[:3] != '10.':
                id_stolen_node_usage[node] = id_node_usage[node] - id_stolen_node_usage[node]

        # alpha - % | stolen - stolen max
        try:
            dict_max = id_node_usage[max(id_node_usage.items(), key=operator.itemgetter(1))[0]]
        except ValueError:
            dict_max = 1
        for k in node_usage.keys():
            alpha = hex(round((100 * id_stolen_node_usage['{}'.format(k)] / dict_max) * 255 / 100))[2:]
            color[k] = (alpha, '0')

    data = [circuits, color, statistic, node_usage]
    return data


def create_output_json(circuit_list):
    cwd = os.getcwd()
    output_file_path_json = Path(cwd + '/torps/out/simulation/output.json')

    with open(output_file_path_json, 'w') as file:
        json.dump(circuit_list, file, indent=4, sort_keys=True)


def create_statistic(loop_count, statistic):
    cwd = os.getcwd()
    output_folder = Path(cwd + '/torps/out/simulation')
    statistic_file = Path(cwd + '/torps/out/simulation/statistic.json')

    if not output_folder.exists():
        output_folder.mkdir(parents=True)

    if loop_count == 0:
        with open(statistic_file, 'w') as file:
            json.dump(statistic, file, indent=4, sort_keys=True)
    else:
        with open(statistic_file, 'a') as file:
            json.dump(statistic, file, indent=4, sort_keys=True)


def parse_statistics(bandwidth, ip, node_usage, id_node_usage, encrypted_node_usage, id_stolen_node_usage, node_statistics):
    # node_statistics = {IP: (USAGE, BANDWIDTH MB/s, encryption %, id_usage, id_stolen)}
    bandwidth = round(bandwidth / math.pow(10, 6), 3)
    usage = node_usage['{}'.format(ip)]
    id_usage = id_node_usage['{}'.format(ip)]

    if usage != 0 and id_usage != 0:
        encrypted_usage = (100 * (encrypted_node_usage['{}'.format(ip)])) / usage
        id_stolen_percentage = (100 * (id_stolen_node_usage['{}'.format(ip)])) / id_usage
        node_statistics['{}'.format(ip)] = (usage, bandwidth, round(encrypted_usage), round(id_stolen_percentage), id_usage)
    elif usage != 0:
        encrypted_usage = (100 * (encrypted_node_usage['{}'.format(ip)])) / usage
        node_statistics['{}'.format(ip)] = (usage, bandwidth, round(encrypted_usage), 0, id_usage)
    elif id_usage != 0:
        id_stolen_percentage = (100 * (id_stolen_node_usage['{}'.format(ip)])) / id_usage
        node_statistics['{}'.format(ip)] = (usage, bandwidth, 0, round(id_stolen_percentage), id_usage)

    return node_statistics


def create_node_statistic(routers, sim_type, adv_guard_bandwidth, adv_exit_bandwidth, node_usage, encrypted_node_usage,
                          attackers_guards, attackers_exits, attackers_middle, id_node_usage, id_stolen_node_usage):
    node_statistics = {}
    cwd = os.getcwd()
    output_file = Path(cwd + '/torps/out/simulation/usage.json')

    for r in routers:
        node_statistics = parse_statistics(r.bandwidth, r.address, node_usage, id_node_usage, encrypted_node_usage,
                                           id_stolen_node_usage, node_statistics)

    if sim_type == 'attack' or sim_type == 'exit_attack' or sim_type == 'multiple_sim':
        for node in attackers_guards:
            node_statistics = parse_statistics(adv_guard_bandwidth, node, node_usage, id_node_usage,
                                               encrypted_node_usage,id_stolen_node_usage, node_statistics)
        for node in attackers_exits:
            node_statistics = parse_statistics(adv_exit_bandwidth, node, node_usage, id_node_usage,
                                               encrypted_node_usage, id_stolen_node_usage, node_statistics)
        for node in attackers_middle:
            if node not in node_statistics.keys():
                node_statistics = parse_statistics(0, node, node_usage, id_node_usage, encrypted_node_usage,
                                                   id_stolen_node_usage, node_statistics)

    with open(output_file, 'w') as file:
        new_list = []
        for node in node_statistics.keys():
            json_dmp = {'ip': node, 'usage': node_statistics[node][0], 'bandwidth': node_statistics[node][1],
                        'encryption': node_statistics[node][2], 'id_stolen_percentage': node_statistics[node][3],
                        'id': node_statistics[node][4],
                        'affiliation': True if re.match(r"10\.[0-9]{1,3}\.0\.0", node) else False}
            new_list.append(json_dmp)
        json.dump(new_list, file, indent=4, sort_keys=True)
        # json.dump(collections.OrderedDict(sorted(node_statistics.items(), key=lambda kv: kv[1], reverse=True)),
        # file, indent=4, sort_keys=True)


def get_encryption(encryption_percentage):
    probability = random.randint(0, 100)
    if probability < encryption_percentage or encryption_percentage == 100:
        return True
    else:
        return False


def get_id(id_percentage):
    probability = random.randint(0, 100)
    if probability < id_percentage or id_percentage == 100:
        return True
    else:
        return False


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
        bandwidth = "350000000 350000000 350000000"
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
                                                  'reject': '0.0.0.0/8:*\n'
                                                  'accept *:*',
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
                 node_entries=None, sim_type=None, guard_bandwidth_value=None, exit_bandwidth_value=None,
                 middle_bandwidth_value=None, adv_guard_c=0, adv_exit_c=0):
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
    :param guard_bandwidth_value: bandwidth value of gard nodes
    :param exit_bandwidth_value: bandwidth value of exit nodes
    :param middle_bandwidth_value: bandwidth value of middle nodes
    :param adv_guard_c: adversary guard count
    :param adv_exit_c: adversary exit count
    :return: list of nodes to generate, every node is represented as dictionary
    """
    all_names = []
    all_ip = []
    guard_node = []
    middle_node = []
    exit_node = []
    switch = True

    if node_entries is not None:
        for node in node_entries:
            if node['type'] == 'guard':
                validate_node_entries(node, all_names, all_ip, same_bandwidth, guard_bandwidth_value)
                guard_node.append(node)
            if node['type'] == 'exit':
                validate_node_entries(node, all_names, all_ip, same_bandwidth, exit_bandwidth_value)
                exit_node.append(node)
            if node['type'] == 'middle':
                if sim_type != 'attack' and sim_type != 'exit_attack':
                    validate_node_entries(node, all_names, all_ip, same_bandwidth, middle_bandwidth_value)

                    middle_node.append(node)
                else:
                    if switch:
                        node['type'] = 'guard'
                        validate_node_entries(node, all_names, all_ip, same_bandwidth, guard_bandwidth_value)
                        guard_node.append(node)
                        switch = False
                    else:
                        node['type'] = 'exit'
                        validate_node_entries(node, all_names, all_ip, same_bandwidth, exit_bandwidth_value)
                        exit_node.append(node)
                        switch = True

    if guard_exit_c > 0:
        guard_c += guard_exit_c - round(guard_exit_c / 2)
        exit_c += round(guard_exit_c / 2)

    for i in range(0, guard_c):
        guard_node.append(create_node_entries('guard', same_bandwidth, guard_bandwidth_value))
    for i in range(0, middle_c):
        middle_node.append(create_node_entries('middle', same_bandwidth, middle_bandwidth_value))
    for i in range(0, exit_c):
        exit_node.append(create_node_entries('exit', same_bandwidth, exit_bandwidth_value))

    if len(guard_node) + len(middle_node) + len(exit_node) + adv_exit_c + adv_guard_c < 3:
        print('Number of nodes have to be > 3\n')
        sys.exit(1)
    if len(guard_node) + adv_guard_c < 1:
        print('Number of guards have to be > 1')
        sys.exit(1)
    if len(exit_node) + adv_exit_c < 1:
        print('Number of exits have to be > 1')
        # sys.exit(1)

    if path_selection == '1_guard' and sim_type == 'path':
        if len(guard_node) < 1:
            print('Number of guards have to be > 1')
            sys.exit(1)
        for node in guard_node[1:]:
            node['type'] = 'middle'
        middle_node = guard_node[1:] + middle_node
        descriptor_entries = [guard_node[:1], middle_node, exit_node]
        return descriptor_entries
    elif path_selection == '3_guards' and sim_type == 'path':
        if len(guard_node) < 3:
            print('Number of guards have to be > 3')
            sys.exit(1)
        for node in guard_node[3:]:
            node['type'] = 'middle'
        middle_node = guard_node[3:] + middle_node
        descriptor_entries = [guard_node[:3], middle_node, exit_node]
        return descriptor_entries
    else:
        descriptor_entries = [guard_node, middle_node, exit_node]
        return descriptor_entries


def create_html(sim_type):
    cwd = os.getcwd()
    
    output_file = Path(cwd + '/picture.html')
    svg_file = Path(cwd + '/graph/simulation.dot.svg')
    exit_bandwidth_file_path = Path(cwd + '/graph/exit_bandwidth.png')
    guard_bandwidth_file_path = Path(cwd + '/graph/guard_bandwidth.png')
    encryption_file_path = Path(cwd + '/graph/encryption.png')
    svg_file_legend = Path(cwd + '/graph/legend.dot.svg')
    if sim_type != 'multiple_sim':
        try:
            with open(svg_file, 'r') as svg:
                s = svg.read()
                svg.close()
        except (OSError, IOError) as e:
            print("File Error: Can not read file {}".format(svg_file))
            sys.exit(1)
    else:
        if not exit_bandwidth_file_path.exists():
            print("File Error: Can not read file {}".format(exit_bandwidth_file_path))
            sys.exit(1)
        if not guard_bandwidth_file_path.exists():
            print("File Error: Can not read file {}".format(guard_bandwidth_file_path))
            sys.exit(1)
        if not encryption_file_path.exists():
            print("File Error: Can not read file {}".format(encryption_file_path))
            sys.exit(1)
        s = "<div style='display: flex; flex-flow: wrap;'>"\
            "<img src=\"graph/exit_bandwidth.png\" alt=\"Exit bandwidth\">"\
            "<img src=\"graph/guard_bandwidth.png\" alt=\"Guard bandwidth\">"\
            "<img src=\"graph/encryption.png\" alt=\"Encryption\">"\
            "</div>"
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

    # enviromet = "~/PycharmProjects/Generating_Tor_Descriptors/venv_2/bin/python"  # python2.7
    enviromet = "python2"

    # > /dev/null 2>&1
    ret = os.system("{} {} process --start_year {} --start_month {} --end_year {} --end_month {} --in_dir {} "
                    "--out_dir {} --initial_descriptor_dir {} > /dev/null 2>&1".format(enviromet, torps_path, start_year,
                                                                                       start_month, end_year,
                                                                                       end_month, in_dir, out_dir,
                                                                                       initial_descriptors_dir))

    if ret != 0:
        print('Path Simulator requires: Python2.7 and stem. Make sure torps has right permissions')
        sys.exit(1)

    # os.system("python {} simulate -h".format(torps_path))
    
    os.system("{} {} simulate --nsf_dir {} --num_samples {} --trace_file {} --user_model {} --format {} "
              "--adv_guard_cons_bw {} --adv_exit_cons_bw {} --adv_time {} --num_adv_guards {} --num_adv_exits {} "
              "--num_guards {} --guard_expiration {} --loglevel {} {} > {}".format(enviromet, torps_path, dir_path, num_samples,
                                                                                   tracefile, usermodel, format_arg,
                                                                                   adv_guard_bw, adv_exit_bw, adv_time,
                                                                                   num_adv_guards, num_adv_exits,
                                                                                   num_guards, gard_expiration,
                                                                                   loglevel, path_alg,
                                                                                   output_file_path))


if __name__ == '__main__':
    input_file = 'conf/config.ini'
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
                print('Invalid file {}'.format(arg))
                sys.exit(1)

    run_simulation(input_file)

    # todo grapph size in config file
    # todo ip generate function
    # todo 3 graph layout
