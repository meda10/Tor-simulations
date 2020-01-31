<?php

# https://stackoverflow.com/questions/5695145/how-to-read-and-write-to-an-ini-file-with-php
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
    $config = parse_ini_file('/conf/config.ini', true, INI_SCANNER_RAW);

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
    $config['general']['path'] = '/home/petr/torps';

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
        $config['attack_simulation']['identification_occurrence'] = $arr['identification_occurrence_attack'];
        $config['attack_simulation']['guard'] = $arr['guard_attack'];
        $config['attack_simulation']['exit'] = $arr['exit_attack'];
        $config['attack_simulation']['number_of_simulations'] = $arr['number_of_simulations_attack'];
        $config['attack_simulation']['adv_guard'] = $arr['adv_guard'];
        $config['attack_simulation']['adv_exit'] = $arr['adv_exit'];
        $config['attack_simulation']['adv_guard_bandwidth'] = $arr['adv_guard_bandwidth'];
        $config['attack_simulation']['adv_exit_bandwidth'] = $arr['adv_exit_bandwidth'];
    } else if ($arr['simulation_type']  == 'exit_attack'){
        $config['exit_attack']['encryption'] = $arr['encryption_exit_attack'];
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
}


function create_zip(){
    $zip = new ZipArchive;
    $res = $zip->open('simulation.zip', ZipArchive::CREATE);
    if ($res === TRUE) {
        $zip->addFile('picture.html', 'graph.html');
        $zip->addFile('graph/simulation.dot.svg', 'simulation.svg');
        $zip->addFile('graph/legend.dot.svg', 'legend.svg');
        $zip->addFile('resources/animation.css');
        $zip->addFile('resources/animation.js');
        $zip->close();
    }
}

function create_graph_page($sim_type){
    $cwd = getcwd();
    //$graph_file = fopen($cwd."/graph/simulation.dot.svg", "r") or die("Unable to open simulaton file!");
    //$legend_file = fopen($cwd."/graph/legend.dot.svg", "r") or die("Unable to open legend file!");
    if($sim_type == 'multiple_sim'){
        $graph = "<div style='display: flex; flex-flow: wrap;'>
                  <img src=\"graph/exit_bandwidth.png\" alt=\"Exit bandwidth\">
                  <img src=\"graph/guard_bandwidth.png\" alt=\"Guard bandwidth\">
                  <img src=\"graph/encryption.png\" alt=\"Encryption\">
                  </div>
                 ";
    }else{
        $graph = file_get_contents($cwd."/graph/simulation.dot.svg");
    }

    $output_table = "<th data-field=\"guard\" data-sortable=\"true\" scope=\"col\">Guard</th>
                     <th data-field=\"middle\" data-sortable=\"true\" scope=\"col\">Middle</th>
                     <th data-field=\"exit\" data-sortable=\"true\" scope=\"col\">Exit</th>";
    
    if($sim_type == 'attack'){
        $usage_table = "<th data-field=\"ip\" data-sortable=\"true\" scope=\"col\">IP</th>
                        <th data-field=\"bandwidth\" data-sortable=\"true\" scope=\"col\">MB/s</th>
                        <th data-field=\"id\" data-sortable=\"true\" scope=\"col\">ID's</th>
                        <th data-field=\"id_stolen_percentage\" data-sortable=\"true\" scope=\"col\">Stolen %</th>";
    }else{
        $usage_table = "<th data-field=\"ip\" data-sortable=\"true\" scope=\"col\">IP</th>
                        <th data-field=\"bandwidth\" data-sortable=\"true\" scope=\"col\">MB/s</th>
                        <th data-field=\"usage\" data-sortable=\"true\" scope=\"col\">Usage</th>
                        <th data-field=\"encryption\" data-sortable=\"true\" scope=\"col\">Encryp.</th>";
    }
    $legend = file_get_contents($cwd."/graph/legend.dot.svg");
    /*
                    <link rel=\"stylesheet\" href=\"resources//animation.css\">
                    <script defer=\"\" src=\"resources//animation.js\"></script>
                    <link href=\"css/style.css\" rel=\"stylesheet\" type=\"text/css\">
                    <link href=\"css/bootstrap.min.css\" rel=\"stylesheet\" type=\"text/css\">
                    <script src=\"https://ajax.googleapis.com/ajax/libs/jquery/3.4.0/jquery.min.js\"></script>
                    <script src=\"https://maxcdn.bootstrapcdn.com/bootstrap/3.4.0/js/bootstrap.min.js\"></script>
                    <script src=\"js/show.js\"></script>
     */
/*

                    <link href=\"https://cdn.datatables.net/1.10.20/css/jquery.dataTables.min.css\" rel=\"stylesheet\" type=\"text/css\">
                    <link href=\"https://cdnjs.cloudflare.com/ajax/libs/twitter-bootstrap/4.1.3/css/bootstrap.css\" rel=\"stylesheet\" type=\"text/css\">
                    <link href=\"https://maxcdn.bootstrapcdn.com/font-awesome/4.7.0/css/font-awesome.min.css\" rel=\"stylesheet\">

                    <link href=\"https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css\" rel=\"stylesheet\">
                    <script src=\"https://cdnjs.cloudflare.com/ajax/libs/moment.js/2.15.2/moment.min.js\"></script>


                    <link href=\"https://cdn.datatables.net/1.10.20/css/dataTables.bootstrap4.min.css\" rel=\"stylesheet\" type=\"text/css\">
                    <link href=\"https://cdn.datatables.net/1.10.20/css/jquery.dataTables.min.css\" rel=\"stylesheet\" type=\"text/css\">

                    <link href=\"https://cdn.datatables.net/1.10.20/css/jquery.dataTables.min.css\" rel=\"stylesheet\" type=\"text/css\">

 */
    $html_start = "<!DOCTYPE html>
                <html lang=\"en\">
                <head>
                    <meta charset=\"utf-8\">
                    <meta content=\"width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no\" name=\"viewport\">
                    <link rel=\"stylesheet\" href=\"resources//animation.css\">
                    <script defer=\"\" src=\"resources//animation.js\"></script>
                    <link href=\"css/style.css\" rel=\"stylesheet\" type=\"text/css\">
                    <link href=\"css/bootstrap.min.css\" rel=\"stylesheet\" type=\"text/css\">
                    <link rel=\"stylesheet\" href=\"https://cdnjs.cloudflare.com/ajax/libs/bootstrap-table/1.10.1/bootstrap-table.min.css\">
                    <script src=\"https://cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js\"></script>
                    <script src=\"https://cdnjs.cloudflare.com/ajax/libs/twitter-bootstrap/3.3.6/js/bootstrap.min.js\"></script>
                    <script src=\"https://cdnjs.cloudflare.com/ajax/libs/bootstrap-table/1.10.1/bootstrap-table.min.js\"></script>
                    <!-- Boodstrap 4
                    <link rel=\"stylesheet\" href=\"https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/css/bootstrap.min.css\" integrity=\"sha384-ggOyR0iXCbMQv3Xipma34MD+dH/1fQ784/j6cY/iJTQUOhcWr7x9JvoRxT2MZw1T\" crossorigin=\"anonymous\">
                    <link rel=\"stylesheet\" href=\"https://use.fontawesome.com/releases/v5.6.3/css/all.css\" integrity=\"sha384-UHRtZLI+pbxtHCWp1t77Bi1L4ZtiqrqD80Kn4Z8NTSRyMA2Fd33n5dQ8lWUE00s/\" crossorigin=\"anonymous\">
                    <link rel=\"stylesheet\" href=\"https://unpkg.com/bootstrap-table@1.15.5/dist/bootstrap-table.min.css\">
                    
                    <script src=\"https://code.jquery.com/jquery-3.3.1.min.js\" integrity=\"sha256-FgpCb/KJQlLNfOu91ta32o/NMZxltwRo8QtmkMRdAu8=\" crossorigin=\"anonymous\"></script>
                    <script src=\"https://cdnjs.cloudflare.com/ajax/libs/popper.js/1.14.7/umd/popper.min.js\" integrity=\"sha384-UO2eT0CpHqdSJQ6hJty5KVphtPhzWj9WO1clHTMGa3JDZwrnQq4sF86dIHNDz0W1\" crossorigin=\"anonymous\"></script>
                    <script src=\"https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/js/bootstrap.min.js\" integrity=\"sha384-JjSmVgyd0p3pXB1rRibZUAYoIIy6OrQ6VrjIEaFf/nJGzIxFDsf4x0xIM+B07jRM\" crossorigin=\"anonymous\"></script>
                    <script src=\"https://unpkg.com/bootstrap-table@1.15.5/dist/bootstrap-table.min.js\"></script>
                    -->
                    <script src=\"js/show.js\"></script>
                    <script src=\"js/table_filter.js\"></script>
                    <title>Simulator</title>
                </head>
                <body>
                <div class=\"wrap\">
                    <div class=\"header\">
                        <h1><a href=\"index.html\">Simulator</a></h1>
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
                ";

    $html_middle = "
            </div>
        </div>
        <div class=\"right\">
            <div id=\"tabs_graph\" class=\"tabs_graph\">
                <ul class=\"nav nav-tabs\" id=\"my_tab\" role=\"tablist\">
                    <li class=\"nav-item active\">
                        <a class=\"nav-link active\" id=\"info_tab\" data-toggle=\"tab\" href=\"#info\" role=\"tab\" aria-controls=\"info\" aria-selected=\"true\" aria-expanded=\"true\">Info</a>
                    </li>
                    <li class=\"nav-item\">
                        <a class=\"nav-link\" id=\"path_tab\" data-toggle=\"tab\" href=\"#path\" role=\"tab\" aria-controls=\"path\" aria-selected=\"false\">Paths</a>
                    </li>
                    <li class=\"nav-item\">
                        <a class=\"nav-link\" id=\"usage_tab\" data-toggle=\"tab\" href=\"#usage\" role=\"tab\" aria-controls=\"usage\" aria-selected=\"false\">Usage</a>
                    </li>
                </ul>
                <div class=\"tab-content\" id=\"my_tab_content\">
                    <div class=\"tab-pane fade show active in\" id=\"info\" role=\"tabpanel\" aria-labelledby=\"info-info_tab\">
                        <div class=\"legend\">";
    $html_end = "                        </div>
                        <div class=\"download\">
                            <h1>Download Zip</h1>
                            <form method='post' action='backend.php'>
                                <input class=\"btn btn-primary button\" name=\"download\" type=\"submit\" value=\"Download\">
                            </form>
                        </div>
                    </div>
                    <div class=\"tab-pane fade\" id=\"path\" role=\"tabpanel\" aria-labelledby=\"path_tab\">
                        <label><input id=\"filter_checkbox_output\" type=\"checkbox\">Show only enemy nodes</label>    
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
                                ".$output_table."
                            </tr>
                            </thead>
                        </table>
                    </div>
                    <div class=\"tab-pane fade\" id=\"usage\" role=\"tabpanel\" aria-labelledby=\"usage_tab\">
                        <label><input id=\"filter_checkbox\" type=\"checkbox\">Show only enemy nodes</label>    
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
                </div>
            </div>
        </div>
        <script>
            function rowStyle(row) {
                if (row.affiliation === true) {
                    return {
                        classes: 'red'
                    }
                }
                return {}
            }
            $( \"usage_table_sorted\" ).removeClass( \"table-hover\" );
            $( \"output_table_sorted\" ).removeClass( \"table-hover\" );
        </script>
    </div>";

    $html_file = fopen("graph.html", "w") or die("Unable to open html file!");
    fwrite($html_file, $html_start);
    fwrite($html_file, $graph);
    fwrite($html_file, $html_middle);
    fwrite($html_file, $legend);
    fwrite($html_file, $html_end);
    fwrite($html_file, "</div></body></html>");
    fclose($html_file);
}


