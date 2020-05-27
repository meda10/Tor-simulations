<?php

# -----------------------------------------------------------------
# author:	Teoman Soygul https://stackoverflow.com/users/628273/teoman-soygul
# Source:	Stack Overflow https://stackoverflow.com/questions/5695145/how-to-read-and-write-to-an-ini-file-with-php
# -----------------------------------------------------------------
function write_ini_file($file, $array = []) {
    if (!is_string($file)) {
        throw new \InvalidArgumentException('Function argument 1 must be a string.');
    }

    if (!is_array($array)) {
        throw new \InvalidArgumentException('Function argument 2 must be an array.');
    }

    $data = array();
    foreach ($array as $key => $val) {
        if (is_array($val)) {
            $data[] = "[$key]";
            foreach ($val as $skey => $sval) {
                if (is_array($sval)) {
                    foreach ($sval as $_skey => $_sval) {
                        if (is_numeric($_skey)) {
                            $data[] = $skey.'[] = '.(is_numeric($_sval) ? $_sval : (ctype_upper($_sval) ? $_sval : $_sval));
                        } else {
                            $data[] = $skey.'['.$_skey.'] = '.(is_numeric($_sval) ? $_sval : (ctype_upper($_sval) ? $_sval : $_sval));
                        }
                    }
                } else {
                    $data[] = $skey.' = '.(is_numeric($sval) ? $sval : (ctype_upper($sval) ? $sval : $sval));
                }
            }
        } else {
            $data[] = $key.' = '.(is_numeric($val) ? $val : (ctype_upper($val) ? $val : $val));
        }
        $data[] = null;
    }

    $fp = fopen($file, 'w');
    $retries = 0;
    $max_retries = 100;

    if (!$fp) {
        return false;
    }

    do {
        if ($retries > 0) {
            usleep(rand(1, 5000));
        }
        $retries += 1;
    } while (!flock($fp, LOCK_EX) && $retries <= $max_retries);

    if ($retries == $max_retries) {
        return false;
    }

    fwrite($fp, implode(PHP_EOL, $data).PHP_EOL);

    flock($fp, LOCK_UN);
    fclose($fp);

    return true;
}


function parse_arguments($arr, $number_of_user_nodes, $number_of_user_simulations){
    $cwd = getcwd();
    $config = parse_ini_file($cwd.'/conf/config.ini', true, INI_SCANNER_RAW);

    $i = 0;
    while ($config['node'.$i] != NULL){
        unset($config['node'.$i]);
        $i++;
    }

    $config['general']['simulation_type'] = $arr['simulation_type'];
    $config['general']['remove_duplicate_paths'] = $arr['remove_duplicate_paths'];
    $config['general']['same_bandwidth'] = $arr['same_bandwidth'];
    $config['general']['guard_bandwidth_value'] = $arr['guard_bandwidth_value'];
    $config['general']['middle_bandwidth_value'] = $arr['middle_bandwidth_value'];
    $config['general']['exit_bandwidth_value'] = $arr['exit_bandwidth_value'];
    $config['general']['generate_graph'] = 'True';
    $config['general']['create_html'] = 'True';
    $config['general']['path'] = '/var/www/html/torps';

    if($arr['simulation_type'] == 'path'){
        $config['path_simulation']['guard'] = $arr['guard'];
        $config['path_simulation']['middle'] = $arr['middle'];
        $config['path_simulation']['exit'] = $arr['exit'];
        $config['path_simulation']['guard_exit'] = $arr['guard_exit'];
        $config['path_simulation']['number_of_simulations'] = $arr['number_of_simulations'];
        $config['path_simulation']['simulation_size'] = $arr['simulation_size'];
        $config['path_simulation']['path_selection'] = $arr['path_selection'];
    } else if ($arr['simulation_type']  == 'hidden_service'){
        $config['hiden_service_simulation']['nodes'] = $arr['nodes_hs'];
    } else if ($arr['simulation_type']  == 'attack'){
        $config['attack_simulation']['encryption'] = $arr['encryption_attack'];
        $config['attack_simulation']['guard'] = $arr['guard_attack'];
        $config['attack_simulation']['exit'] = $arr['exit_attack'];
        $config['attack_simulation']['number_of_simulations'] = $arr['number_of_simulations_attack'];
        $config['attack_simulation']['adv_guard'] = $arr['adv_guard'];
        $config['attack_simulation']['adv_exit'] = $arr['adv_exit'];
        $config['attack_simulation']['adv_guard_bandwidth'] = $arr['adv_guard_bandwidth'];
        $config['attack_simulation']['adv_exit_bandwidth'] = $arr['adv_exit_bandwidth'];
    } else if ($arr['simulation_type']  == 'exit_attack'){
        $config['exit_attack']['encryption'] = $arr['encryption_exit_attack'];
        $config['exit_attack']['identification_occurrence'] = $arr['identification_occurrence_exit_attack'];
        $config['exit_attack']['guard'] = $arr['guard_exit_attack'];
        $config['exit_attack']['exit'] = $arr['exit_exit_attack'];
        $config['exit_attack']['number_of_simulations'] = $arr['number_of_simulations_exit_attack'];
        $config['exit_attack']['adv_exit'] = $arr['adv_exit_exit_attack'];
        $config['exit_attack']['adv_exit_bandwidth'] = $arr['adv_exit_bandwidth_exit_attack'];
    } else if($arr['simulation_type']  == 'multiple_sim'){

        $config['multiple_sim']['number_of_simulations'] = $arr['number_of_simulations_multiple_sim'];

        for($i = 0; $i < $number_of_user_simulations; $i++){
            $config['sim_'.$i]['encryption'] = $arr['sim_'.$i]['encryption'];
            $config['sim_'.$i]['identification_occurrence'] = $arr['sim_'.$i]['identification_occurrence'];
            $config['sim_'.$i]['guard'] = $arr['sim_'.$i]['guard'];
            $config['sim_'.$i]['exit'] = $arr['sim_'.$i]['exit'];
            $config['sim_'.$i]['adv_guard'] = $arr['sim_'.$i]['adv_guard'];
            $config['sim_'.$i]['adv_exit'] = $arr['sim_'.$i]['adv_exit'];
            $config['sim_'.$i]['friendly_guard_bandwidth'] = $arr['sim_'.$i]['friendly_guard_bandwidth'];
            $config['sim_'.$i]['friendly_exit_bandwidth'] = $arr['sim_'.$i]['friendly_exit_bandwidth'];
            $config['sim_'.$i]['adv_guard_bandwidth'] = $arr['sim_'.$i]['adv_guard_bandwidth'];
            $config['sim_'.$i]['adv_exit_bandwidth'] = $arr['sim_'.$i]['adv_exit_bandwidth'];
        }

    }

    if($arr['simulation_type']  == 'exit_attack' || $arr['simulation_type']  == 'attack' || $arr['simulation_type'] == 'path'){

        for($i = 0; $i < $number_of_user_nodes; $i++){
            $config['node'.$i]['type'] = $arr['node'.$i]['type'];
            $config['node'.$i]['name'] = $arr['node'.$i]['name'];
            $config['node'.$i]['ip'] = $arr['node'.$i]['ip'];
            $config['node'.$i]['port'] = 413;
            $config['node'.$i]['bandwidth'] = $arr['node'.$i]['bandwidth'];;
        }
    }

    $return_code = write_ini_file('conf/config.ini', $config);
    if($return_code != true){
        echo "Wrong permissions: can not write to .ini file\n";
    }
    return $config;
}


function show_graph($config, $number_of_user_simulations){
    $encryption = [];
    $identification_occurrence = [];
    $guard = [];
    $exit = [];
    $adv_guard = [];
    $adv_exit = [];
    $friendly_guard_bandwidth = [];
    $friendly_exit_bandwidth = [];
    $adv_guard_bandwidth = [];
    $adv_exit_bandwidth = [];

    $grapshs = [];

    for($i = 0; $i < $number_of_user_simulations; $i++){
        array_push($encryption, $config['sim_'.$i]['encryption']);
        array_push($identification_occurrence, $config['sim_'.$i]['identification_occurrence']);
        array_push($guard, $config['sim_'.$i]['guard']);
        array_push($exit, $config['sim_'.$i]['exit']);
        array_push($adv_guard, $config['sim_'.$i]['adv_guard']);
        array_push($adv_exit, $config['sim_'.$i]['adv_exit']);
        array_push($friendly_guard_bandwidth, $config['sim_'.$i]['friendly_guard_bandwidth'] );
        array_push($friendly_exit_bandwidth, $config['sim_'.$i]['friendly_exit_bandwidth']);
        array_push($adv_guard_bandwidth, $config['sim_'.$i]['adv_guard_bandwidth']);
        array_push($adv_exit_bandwidth, $config['sim_'.$i]['adv_exit_bandwidth']);
    }

    if(count(array_unique($encryption)) > 1){
        array_push($grapshs, 'encryption');
        array_push($grapshs, 'id_encryption');
        array_push($grapshs, 'exit_encryption');
    }
    if(count(array_unique($identification_occurrence)) > 1){

    }
    if(count(array_unique($guard)) > 1){

    }
    if(count(array_unique($exit)) > 1){
        #array_push($grapshs, 'correlation_attack_exit');
        #array_push($grapshs, 'id_number_of_exits');
        #array_push($grapshs, 'exit_nodes_node_usage');
    }
    if(count(array_unique($adv_guard)) > 1){
        array_push($grapshs, 'correlation_attack_guard');
        array_push($grapshs, 'guard_nodes_node_usage');
        # array_push($grapshs, 'id_number_of_guards');
    }
    if(count(array_unique($adv_exit)) > 1){
        array_push($grapshs, 'correlation_attack_exit');
        array_push($grapshs, 'id_number_of_exits');
        array_push($grapshs, 'exit_nodes_node_usage');
    }
    if(count(array_unique($friendly_guard_bandwidth)) > 1){

    }
    if(count(array_unique($friendly_exit_bandwidth)) > 1){

    }
    if(count(array_unique($adv_guard_bandwidth)) > 1){
        array_push($grapshs, 'guard_bandwidth');
        array_push($grapshs, 'correlation_attack_guard_bandwidth');
        # array_push($grapshs, 'id_guard_bandwidth');
    }
    if(count(array_unique($adv_exit_bandwidth)) > 1){
        array_push($grapshs, 'exit_bandwidth');
        array_push($grapshs, 'id_exit_bandwidth');
        array_push($grapshs, 'correlation_attack_exit_bandwidth');
    }
    return $grapshs;
}

function error($message){
    echo "<h3>Error 1</h3>";
    echo "<p>There was an error, you can find more information in  error.log</p>";
    echo $message;
    exit(0);
}

function create_zip($type){
    $zip = new ZipArchive;
    $res = $zip->open('simulation.zip', ZipArchive::CREATE);
    if ($res === TRUE) {
        if($type == 'path'){
            $zip->addFile('picture.html', 'graph.html');
            $zip->addFile('graph/simulation.dot.svg', 'simulation.svg');
            $zip->addFile('graph/legend.dot.svg', 'legend.svg');
            $zip->addFile('resources/animation.css');
            $zip->addFile('resources/animation.js');
            $zip->close();
        }
        if($type == 'attack'){
            $zip->addFile('picture.html', 'graph.html');
            $zip->addFile('graph/simulation.dot.svg', 'simulation.svg');
            # $zip->addFile('graph/legend.dot.svg', 'legend.svg');
            $zip->addFile('resources/animation.css');
            $zip->addFile('resources/animation.js');
            $zip->close();
        }
        if($type == 'multiple_sim'){
            $zip->addFile('picture.html', 'graph.html');
            $zip->addFile('graph/guard_bandwidth.png', 'guard_bandwidth.png');
            $zip->addFile('graph/nodes_gu_ex_usage.png', 'nodes_gu_ex_usage.png');
            $zip->addFile('graph/correlation_attack_exit.png', 'correlation_attack_exit.png');
            $zip->addFile('graph/correlation_attack_guard.png', 'correlation_attack_guard.png');
            $zip->addFile('graph/encryption.png', 'encryption.png');
            $zip->addFile('graph/id_encryption.png', 'id_encryption.png');
            $zip->addFile('graph/id_exit_bandwidth.png', 'id_exit_bandwidth.png');
            $zip->addFile('graph/id_guard_bandwidth.png', 'id_guard_bandwidth.png');
            $zip->addFile('graph/id_number_of_exits.png', 'id_number_of_exits.png');
            $zip->addFile('graph/id_number_of_guards.png', 'id_number_of_guards.png');
            $zip->addFile('graph/exit_bandwidth.png', 'exit_bandwidth.png');
            $zip->addFile('graph/correlation_attack_exit_bandwidth.png', 'correlation_attack_exit_bandwidth.png');
            $zip->addFile('graph/correlation_attack_guard_bandwidth.png', 'correlation_attack_guard_bandwidth.png');
            $zip->addFile('graph/exit_encryption.png', 'exit_encryption.png');
            $zip->addFile('graph/exit_nodes_node_usage.png', 'exit_nodes_node_usage.png');
            $zip->addFile('graph/guard_nodes_node_usage.png', 'guard_nodes_node_usage.png');
            $zip->close();
        }
        if($type == 'exit_attack'){
            $zip->addFile('picture.html', 'graph.html');
            $zip->addFile('graph/simulation.dot.svg', 'simulation.svg');
            # $zip->addFile('graph/legend.dot.svg', 'legend.svg');
            $zip->addFile('resources/animation.css');
            $zip->addFile('resources/animation.js');
            $zip->close();
        }
        if($type == 'hidden_service'){
            $zip->addFile('picture.html', 'graph.html');
            $zip->addFile('graph/simulation.dot.svg', 'simulation.svg');
            $zip->addFile('graph/legend.dot.svg', 'legend.svg');
            $zip->addFile('resources/animation.css');
            $zip->addFile('resources/animation.js');
            $zip->close();
        }

    }
}

function unlink_file($file_name){
    if (file_exists("conf/" . $file_name)) {
        unlink("conf/" . $file_name);
    }
}

function create_graph_page($sim_type, $graph_names){
    $cwd = getcwd();
    //$graph_file = fopen($cwd."/graph/simulation.dot.svg", "r") or die("Unable to open simulaton file!");
    //$legend_file = fopen($cwd."/graph/legend.dot.svg", "r") or die("Unable to open legend file!");
    if($sim_type == 'multiple_sim'){
        $graph = "<div style='display: flex; flex-flow: wrap;'>";
        for($i = 0; $i < count($graph_names); $i++){
            $graph = $graph."<img src=\"graph/".$graph_names[$i].".png\" alt=\"\">";
        }
        $graph = $graph."</div>";
/*
        $graph = "<div style='display: flex; flex-flow: wrap;'>
                  <img src=\"graph/exit_bandwidth.png\" alt=\"Exit bandwidth\">
                  <img src=\"graph/guard_bandwidth.png\" alt=\"Guard bandwidth\">
                  <img src=\"graph/nodes_gu_ex_usage.png\" alt=\"\">
                  <img src=\"graph/correlation_attack_exit.png\" alt=\"\">
                  <img src=\"graph/correlation_attack_guard.png\" alt=\"\">
                  <img src=\"graph/encryption.png\" alt=\"Encryption\">
                  <img src=\"graph/id_encryption.png\" alt=\"\">
                  <img src=\"graph/id_exit_bandwidth.png\" alt=\"\">
                  <img src=\"graph/id_guard_bandwidth.png\" alt=\"\">
                  <img src=\"graph/id_number_of_exits.png\" alt=\"\">
                  <img src=\"graph/id_number_of_guards.png\" alt=\"\">
                  </div>
                 ";
*/
        $nav = "<li class=\"nav-item\">
                    <a class=\"nav-link\" id=\"statistic_tab\" data-toggle=\"tab\" href=\"#statistic\" role=\"tab\" aria-controls=\"statistic\" aria-selected=\"false\">Statistic</a>
                </li>";

        $statistic_table = "";
    }else{
        $graph = file_get_contents($cwd."/graph/simulation.dot.svg");
        $nav = "<li class=\"nav-item\">
                    <a class=\"nav-link\" id=\"path_tab\" data-toggle=\"tab\" href=\"#path\" role=\"tab\" aria-controls=\"path\" aria-selected=\"false\">Paths</a>
                </li>
                <li class=\"nav-item\">
                    <a class=\"nav-link\" id=\"usage_tab\" data-toggle=\"tab\" href=\"#usage\" role=\"tab\" aria-controls=\"usage\" aria-selected=\"false\">Usage</a>
                </li>
                <li class=\"nav-item\">
                    <a class=\"nav-link\" id=\"statistic_tab\" data-toggle=\"tab\" href=\"#statistic\" role=\"tab\" aria-controls=\"statistic\" aria-selected=\"false\">Statistic</a>
                </li>";
    }

    $output_table = "<th data-field=\"guard\" data-sortable=\"true\" scope=\"col\">Guard</th>
                     <th data-field=\"middle\" data-sortable=\"true\" scope=\"col\">Middle</th>
                     <th data-field=\"exit\" data-sortable=\"true\" scope=\"col\">Exit</th>";
    
    if($sim_type == 'attack'){
        $usage_table = "<th data-field=\"ip\" data-sortable=\"true\" scope=\"col\">IP</th>
                        <th data-field=\"bandwidth\" data-sortable=\"true\" scope=\"col\">KB/s</th>
                        <th data-field=\"usage\" data-sortable=\"true\" scope=\"col\">Usage</th>
                        <th data-field=\"encryption\" data-sortable=\"true\" scope=\"col\">Encryp %</th>";
        $legend = file_get_contents($cwd."/graph/attack_legend.svg");

    }else if($sim_type == 'hidden_service' || $sim_type == 'path') {
        $usage_table = "<th data-field=\"ip\" data-sortable=\"true\" scope=\"col\">IP</th>
                        <th data-field=\"bandwidth\" data-sortable=\"true\" scope=\"col\">KB/s</th>
                        <th data-field=\"usage\" data-sortable=\"true\" scope=\"col\">Usage</th>";
        $legend = file_get_contents($cwd."/graph/legend.dot.svg");
    }else{
        $usage_table = "<th data-field=\"ip\" data-sortable=\"true\" scope=\"col\">IP</th>
                        <th data-field=\"bandwidth\" data-sortable=\"true\" scope=\"col\">KB/s</th>
                        <th data-field=\"id\" data-sortable=\"true\" scope=\"col\">ID's</th>
                        <th data-field=\"id_stolen_node_usage\" data-sortable=\"true\" scope=\"col\">Stolen</th>
                        <th data-field=\"id_stolen_percentage\" data-sortable=\"true\" scope=\"col\">Stolen %</th>";
        $legend = file_get_contents($cwd."/graph/exit_legend.svg");
    }
    $paths_table = "<th data-field=\"count\" data-sortable=\"true\" scope=\"col\">N</th>
                        <th data-field=\"guard\" data-sortable=\"true\" scope=\"col\">Guard</th>
                        <th data-field=\"middle\" data-sortable=\"true\" scope=\"col\">Middle</th>
                        <th data-field=\"exit\" data-sortable=\"true\" scope=\"col\">Exit</th>";

    if($sim_type == 'multiple_sim'){
        $legend = "";
    }

    if($sim_type == 'hidden_service'){
        $info = "<h5>How It works</h5>
        <ol style=\"padding-left: 20px;\">
            <li>
                <p>An onion service needs to advertise its existence in the Tor network before clients will be able to contact it.
                Service randomly picks some relays, builds circuits to them, and asks them to act as introduction points
                by telling them its public key (Introduction points does not know server's location - IP address).
                </p>
            </li>
            <li>
                <p>The onion service assembles an onion service descriptor, containing its public key and a summary of
                each introduction points, and signs this descriptor with its private key.</p>
            </li>
            <li>
                <p>A client that wants to contact an onion service needs to learn about its onion address from directory
                 server. Client  obtains the set of introduction points and the right public key to use.</p>
            </li>
            <li>
                <p>Client creates a circuit to another randomly picked relay and asks it to act as rendezvous point by
                telling it a one-time secret.</p>
            </li>
            <li>
                <p>Client assembles an introduction message (encrypted to the onion service's public key) including the
                address of the rendezvous point and the one-time secret. The client sends this message to one of the
                introduction points.</p>
            </li>
            <li>
                <p>Introduction point delivers message to the onion service.</p>
            </li>
            <li>
                <p>Onion service decrypts the client's message and gets the address of the rendezvous point and the
                one-time secret. The service creates a circuit to the rendezvous point and sends the one-time secret
                to it in a rendezvous message. The rendezvous point notifies the client about successful connection </p>
            </li>
            <li>
                <p>The rendezvous point now relays messages from client to onion service and vice versa.</p>
            </li>
        </ol>";
    } else if ($sim_type == 'path'){
        $info = "<h5>How It works</h5>
        <p>In Tor network, traffic is forwarded through randomly selected relays. Message is wrapped with multiple layers of encryption
        to maintain unlinkability. When message is sent, every relay unwraps one layer of encryption and forwards the message to the next relay in the circuit.
        Each relay only knows the previous and the next relay in the path, therefore, the first relay, the guard node,
        is the only one that knows the source of the stream and and the last relay, the exit node, is the only one that knows
        the destination of the client. The onion router(s) in between only exchange encrypted information. A circuit
        usually consists of three relays. </p>
        <h5>Entry guards</h5>
        <p>
         The first relay in circuit is called an \"entry guard\" or \"guard\".
         It is a fast and stable relay that remains the first one in circuit for 2-3 months as a protection against
         a known anonymity-breaking attack. The rest of the circuit changes with every new website that is visited.
        </p>
        <h5>History</h5>
        <p>
        In the past Tor network used random selection for every node, later entry guards were introduced and 3 or 4 were used.
        Nowadays Tor network uses 1 guard for every circuit.
        </p>
        ";
    } else if ($sim_type == 'attack'){
        $info = "<h5>How It works</h5>
        <p>Correlation attacks are de-anonymization attacks. It is assumed that the attacker controls both the entry
        node and the exit node of the circuit between the client and the server. The attacker is looking for a correlation
        in traffic between the entry node and the exit node, because then he can conclude that the entry node and the
        exit node participate in the circuit. The entry node knows the client, the exit node knows the server, so the
        attacker can confirm that the client and the server are communicating.
        </p>
        ";
    } else if ($sim_type == 'exit_attack'){
        $info = "<h5>How It works</h5>
        <p> Tor prevents eavesdroppers from learning sites that you visit. However, eavesdroppers can still intercept
        unencrypted communication. For encrypting your communication it is important to use end-to-end encryption,
        for example HTTPS protocol. If user does not use proper protocol these data could be visible: </p>
        <h5>Visible data</h5>
            <ol>
                <li>Visited sites</li>
                <li>Username and password</li>
                <li>Data</li>
                <li>Public IP address</li>
            </ol>
        ";
    }


    $html_start = "<!DOCTYPE html>
    <html lang=\"en\">
    <head>
        <meta charset=\"utf-8\">
        <meta content=\"width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no\" name=\"viewport\">
        <link rel=\"stylesheet\" href=\"resources/animation.css\">
        <link href=\"css/style.css\" rel=\"stylesheet\" type=\"text/css\">
        
        <!-- 
        <link rel=\"stylesheet\" href=\"https://cdnjs.cloudflare.com/ajax/libs/bootstrap-table/1.10.1/bootstrap-table.min.css\">
        <script src=\"https://cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js\"></script>
        <script src=\"https://cdnjs.cloudflare.com/ajax/libs/twitter-bootstrap/3.3.6/js/bootstrap.min.js\"></script>
        <script src=\"https://cdnjs.cloudflare.com/ajax/libs/bootstrap-table/1.10.1/bootstrap-table.min.js\"></script>  
        -->
        <!-- Boodstrap 4
        <link rel=\"stylesheet\" href=\"https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/css/bootstrap.min.css\" integrity=\"sha384-ggOyR0iXCbMQv3Xipma34MD+dH/1fQ784/j6cY/iJTQUOhcWr7x9JvoRxT2MZw1T\" crossorigin=\"anonymous\">
        <link rel=\"stylesheet\" href=\"https://use.fontawesome.com/releases/v5.6.3/css/all.css\" integrity=\"sha384-UHRtZLI+pbxtHCWp1t77Bi1L4ZtiqrqD80Kn4Z8NTSRyMA2Fd33n5dQ8lWUE00s/\" crossorigin=\"anonymous\">
        <link rel=\"stylesheet\" href=\"https://unpkg.com/bootstrap-table@1.15.5/dist/bootstrap-table.min.css\">
        
        <script src=\"https://code.jquery.com/jquery-3.3.1.min.js\" integrity=\"sha256-FgpCb/KJQlLNfOu91ta32o/NMZxltwRo8QtmkMRdAu8=\" crossorigin=\"anonymous\"></script>
        <script src=\"https://cdnjs.cloudflare.com/ajax/libs/popper.js/1.14.7/umd/popper.min.js\" integrity=\"sha384-UO2eT0CpHqdSJQ6hJty5KVphtPhzWj9WO1clHTMGa3JDZwrnQq4sF86dIHNDz0W1\" crossorigin=\"anonymous\"></script>
        <script src=\"https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/js/bootstrap.min.js\" integrity=\"sha384-JjSmVgyd0p3pXB1rRibZUAYoIIy6OrQ6VrjIEaFf/nJGzIxFDsf4x0xIM+B07jRM\" crossorigin=\"anonymous\"></script>
        <script src=\"https://unpkg.com/bootstrap-table@1.15.5/dist/bootstrap-table.min.js\"></script>
        -->
    
        <link rel=\"stylesheet\" href=\"https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/css/bootstrap.min.css\" integrity=\"sha384-ggOyR0iXCbMQv3Xipma34MD+dH/1fQ784/j6cY/iJTQUOhcWr7x9JvoRxT2MZw1T\" crossorigin=\"anonymous\">
        <link rel=\"stylesheet\" href=\"https://use.fontawesome.com/releases/v5.6.3/css/all.css\" integrity=\"sha384-UHRtZLI+pbxtHCWp1t77Bi1L4ZtiqrqD80Kn4Z8NTSRyMA2Fd33n5dQ8lWUE00s/\" crossorigin=\"anonymous\">
        <link rel=\"stylesheet\" href=\"https://unpkg.com/bootstrap-table@1.15.5/dist/bootstrap-table.min.css\">
        <!-- 
        <link rel=\"stylesheet\" href=\"https://cdnjs.cloudflare.com/ajax/libs/bootstrap-table/1.10.1/bootstrap-table.min.css\">
        -->
       
        <title>Simulator</title>
    </head>
    <body>
    <div class=\"wrap_header\">
        <div class=\"header\">
            <h1><a href=\"index.html\">Simulator</a></h1>
            <div id=\"small_menu\">
                <ul class=\"nav nav-tabs\" id=\"menu_tabs\" role=\"tablist\">
                    <li class=\"nav-item active\">
                        <a class=\"nav-link\" id=\"home\" href=\"index.html\" aria-selected=\"false\">Home</a>
                    </li>
                    <li class=\"nav-item active\">
                        <a class=\"nav-link\" id=\"how_to\" href=\"how_to.html\" aria-selected=\"false\">How to use</a>
                    </li>
                    <li class=\"nav-item\">
                        <a class=\"nav-link\" id=\"example_file\" href=\"example.html\" aria-selected=\"false\">Example config file</a>
                    </li>
                    <li class=\"nav-item\">
                        <a class=\"nav-link\" id=\"ccc\" href=\"about_tor.html\" aria-selected=\"false\">About Tor</a>
                    </li>
                </ul>
            </div>
        </div>
    </div>
    <div class=\"wrap\">
        <div class=\"content_graph\">
            <div class=\"left\">
                <div class=\"left_header\">
                    <legend>Graph</legend>
                    <ul id=\"link-container\">
                        <h3 id=\"current_num\"></h3>
                        <button id=\"button_prev\" type=\"button\" class=\"btn btn-primary\" disabled>Prev</button>
                        <button id=\"button_next\" type=\"button\" class=\"btn btn-primary\" disabled>Next</button>
                    </ul>
                </div>
                <div class=\"graph\">
                ".$graph."
                </div>
            </div>
            <div class=\"right\">
                <div id=\"tabs_graph\" class=\"tabs_graph\">
                    <ul class=\"nav nav-tabs\" id=\"my_tab\" role=\"tablist\">
                        <li class=\"nav-item active\">
                            <a class=\"nav-link active\" id=\"info_tab\" data-toggle=\"tab\" href=\"#info\" role=\"tab\" aria-controls=\"info\" aria-selected=\"true\" aria-expanded=\"true\">Info</a>
                        </li>
                        ".$nav."
                    </ul>
                    <div class=\"tab-content\" id=\"my_tab_content\">
                        <div class=\"tab-pane fade show active in\" id=\"info\" role=\"tabpanel\" aria-labelledby=\"info-info_tab\">
                            <div class=\"legend\">
                            ".$legend."
                            </div>
                            <div class=\"download\">
                                <h5>Download Zip</h5>
                                <form method='post' action='parse_form.php'>
                                    <input type=\"hidden\" id=\"type\" name=\"type\" value=\"$sim_type\">
                                    <input class=\"btn btn-primary button\" name=\"download\" type=\"submit\" value=\"Download\">
                                </form>
                            </div>
                            ".$info."
                        </div>
                        <div class=\"tab-pane fade\" id=\"path\" role=\"tabpanel\" aria-labelledby=\"path_tab\">
                            <div style='margin-top: 10px'>
                                <label for=\"filter_checkbox_output\">Show only enemy nodes</label>
                                <input id=\"filter_checkbox_output\" type=\"checkbox\">
                                <label for=\"filter_checkbox_v2\">Show correlation</label>
                                <input id=\"filter_checkbox_v2\" type=\"checkbox\">
                            </div>
                            <table id=\"output_table_sorted\"                        
                                   class=\"table\"
                                   data-toggle=\"table\"
                                   data-toolbar=\".toolbar\"
                                   
                                   data-sortable=\"true\"
                                   data-search=\"true\"
                                   data-search-align=\"left\"
                                   data-row-style=\"rowStyle\"
                                   data-url=\"torps/out/simulation/output.json\">
                                <thead>
                                <tr>
                                    ".$paths_table."
                                </tr>
                                </thead>
                            </table>
                        </div>
                        <div class=\"tab-pane fade\" id=\"usage\" role=\"tabpanel\" aria-labelledby=\"usage_tab\">
                            <div style='margin-top: 10px'>
                                <label for=\"filter_checkbox\">Show only enemy nodes</label>
                                <input id=\"filter_checkbox\" type=\"checkbox\">                        
                            </div>
                            <table id=\"usage_table_sorted\" 
                                    class=\"table\" 
                                    data-toggle=\"table\" 
                                    data-toolbar=\".toolbar\" 
                                    data-sortable=\"true\"
                                    data-search=\"true\"
                                    data-search-align=\"left\"
                                    data-row-style=\"rowStyle\"
                                    data-url=\"torps/out/simulation/usage.json\">
                                <thead>
                                <tr>
                                    ".$usage_table."
                                </tr>
                                </thead>
                            </table>
                        </div>
                        <div class=\"tab-pane fade\" id=\"statistic\" role=\"tabpanel\" aria-labelledby=\"statistic_tab\">    
                            <table id=\"statistic_table\"
                                   class=\"table\"
                                   data-toggle=\"table\"
                                   data-pagination=\"true\"
                                   data-pagination-h-align=\"left\"
                                   data-pagination-detail-h-align=\"right\"
                                   data-page-size=\"1\"
                                   data-url=\"torps/out/simulation/statistic.json\">
                                <thead>
                                    <tr>
                                        <th data-field=\"adv_exit\" scope=\"col\">ADV Exit</th>
                                        <th data-field=\"adv_guard\" scope=\"col\">ADV Guard</th>
                                        <th data-field=\"adv_exit_bandwidth\" scope=\"col\">ADV Exit: bandwidth (Kb/s)</th>
                                        <th data-field=\"adv_guard_bandwidth\" scope=\"col\">ADV Guard: bandwidth (Kb/s)</th>
                                        <th data-field=\"exit_bandwidth\" scope=\"col\">Exit: bandwidth (Kb/s)</th>
                                        <th data-field=\"guard_bandwidth\" scope=\"col\">Guard: bandwidth (Kb/s)</th>
                                        <th data-field=\"encryption\" scope=\"col\">Encryption (%)</th>
                                        <th data-field=\"identification_occurrence\" scope=\"col\">Occurrence of ID (%)</th>
                                        <th data-field=\"number_of_simulations\" scope=\"col\">All circuits</th>
                                        <th  scope=\"col\">-------</th>
                                        <th data-field=\"bad_node\" scope=\"col\">ADV nodes used</th>
                                        <th data-field=\"bad_guard_used\" scope=\"col\">ADV as guard</th>
                                        <th data-field=\"bad_middle_used\" scope=\"col\">ADV as middle</th>
                                        <th data-field=\"bad_exit_used\" scope=\"col\">ADV as exit</th>
                                        <th data-field=\"bad_gu_and_ex\" scope=\"col\">ADV correlation</th>
                                        <th  scope=\"col\">-------</th>
                                        <th data-field=\"not_encrypted\" scope=\"col\">Circuits not encrypted</th>
                                        <th data-field=\"encrypted\" scope=\"col\">Circuits encrypted</th>
                                        <th data-field=\"bad_exit_encrypt\" scope=\"col\">ADV exit: encrypted communication</th>
                                        <th data-field=\"bad_exit_unencrypt\" scope=\"col\">ADV exit: unencrypted communication</th>
                                        <th data-field=\"bad_gu_and_ex_encrypt\" scope=\"col\">ADV correlation: encrypted communication</th>
                                        <th data-field=\"bad_gu_and_ex_unencrypt\" scope=\"col\">ADV correlation: uncrypted communication</th>
                                        <th  scope=\"col\">-------</th>
                                        <th data-field=\"total_id\" scope=\"col\">Total number of ID</th>
                                        <th data-field=\"not_encrypted_id\" scope=\"col\">Unencrypted ID</th>
                                        <th data-field=\"not_encrypted_id_stolen\" scope=\"col\">Unencrypted ID stolen</th>
                                    </tr>
                                </thead>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    <script src=\"https://code.jquery.com/jquery-3.3.1.min.js\" integrity=\"sha256-FgpCb/KJQlLNfOu91ta32o/NMZxltwRo8QtmkMRdAu8=\" crossorigin=\"anonymous\"></script>
    <script src = \"https://cdnjs.cloudflare.com/ajax/libs/popper.js/1.14.7/umd/popper.min.js\" integrity = \"sha384-UO2eT0CpHqdSJQ6hJty5KVphtPhzWj9WO1clHTMGa3JDZwrnQq4sF86dIHNDz0W1\" crossorigin = \"anonymous\" ></script >
    <script src = \"https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/js/bootstrap.min.js\" integrity = \"sha384-JjSmVgyd0p3pXB1rRibZUAYoIIy6OrQ6VrjIEaFf/nJGzIxFDsf4x0xIM+B07jRM\" crossorigin = \"anonymous\" ></script >
    <script src = \"https://unpkg.com/bootstrap-table@1.15.5/dist/bootstrap-table.min.js\" ></script >
    <script src = \"js/show.js\" ></script >
    <script src = \"js/table_filter.js\" ></script >
    <script defer = \"\" src = \"resources/animation.js\" ></script >
    <script >
        $( document ) . ready(function () {
            $('#output_table_sorted') . removeClass('table-hover');
            $('#output_table_sorted') . removeClass('table-bordered');
            $('table') . removeClass('table-bordered');
            $('#usage_table_sorted') . removeClass('table-hover');
            $('#usage_table_sorted') . removeClass('table-bordered');
            $('#statistic_table') . removeClass('table-bordered');
            $('#statistic_table') . removeClass('table-hover');

        });
    </script >
    <script >
        function rowStyle(row) {
            if (row . affiliation === true) {
                return {
                    classes:
                    'red'
                }
            }
            return {
            }
        }
    </script >
    <!--
    <script src = \"https://cdnjs.cloudflare.com/ajax/libs/bootstrap-table/1.10.1/bootstrap-table.min.js\" ></script >
    -->
    </body>
    </html>";

    $html_file = fopen("graph.html", "w") or die("Unable to open html file!");
    fwrite($html_file, $html_start);
    fclose($html_file);
}


