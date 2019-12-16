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


function parse_arguments($arr, $number_of_user_nodes){
    $config = parse_ini_file('config.ini', true, INI_SCANNER_RAW);

    $i = 0;
    while ($config['node'.$i] != NULL){
        unset($config['node'.$i]);
        $i++;
    }

    $config['general']['simulation_type'] = $arr['simulation_type'];
    $config['general']['remove_duplicate_paths'] = $arr['remove_duplicate_paths'];
    $config['general']['same_bandwidth'] = $arr['same_bandwidth'];
    $config['general']['bandwidth_value'] = $arr['bandwidth_value'];
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

        for($i = 0; $i < $number_of_user_nodes; $i++){
            $config['node'.$i]['type'] = $arr['node'.$i]['type'];
            $config['node'.$i]['name'] = $arr['node'.$i]['name'];
            $config['node'.$i]['ip'] = $arr['node'.$i]['ip'];
            $config['node'.$i]['port'] = 413;
            $config['node'.$i]['bandwidth'] = $arr['node'.$i]['bandwidth'];;
        }

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
        $config['exit_attack']['guard'] = $arr['guard_exit_attack'];
        $config['exit_attack']['exit'] = $arr['exit_exit_attack'];
        $config['exit_attack']['number_of_simulations'] = $arr['number_of_simulations_exit_attack'];
        $config['exit_attack']['adv_exit'] = $arr['adv_exit_exit_attack'];
        $config['exit_attack']['adv_exit_bandwidth'] = $arr['adv_exit_bandwidth_exit_attack'];
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

function create_table(){
    $table = "";
    $cwd = getcwd();
    $output = file_get_contents($cwd . "/torps//out/simulation/output");
    $i = 0;
    foreach (preg_split("/((\r?\n)|(\r\n?))/", $output) as $line) {
        if (!empty($line)) {
            if ($i >= 1) {
                $parts = preg_split('/\s+/', $line);
                $x = $i - 1;

                if(preg_match('/10.\d{1,3}.0.0/', $parts[2]) && preg_match('/10.\d{1,3}.0.0/', $parts[4])){
                    $html = "<tr style='background-color: #ff7569'>
                        <th style='background-color: #ff7569'>" . $x . "</th>
                        <td style='background-color: #ff7569'>" . $parts[2] . "</td>
                        <td style='background-color: #ff7569'>" . $parts[3] . "</td>
                        <td style='background-color: #ff7569'>" . $parts[4] . "</td>
                     </tr>";
                }else{
                    $html = "<tr>
                        <th>" . $x . "</th>
                        <td>" . $parts[2] . "</td>
                        <td>" . $parts[3] . "</td>
                        <td>" . $parts[4] . "</td>
                     </tr>";
                }
                $table = $table . $html;
            }
        }
        $i++;
    }
    return $table;
}

function create_usage_table(){
    $table = "";
    $cwd = getcwd();
    $output = file_get_contents($cwd . "/torps/out/simulation/usage.json");

    $arr = json_decode($output, true);
    foreach ($arr as $key => $value){
        if(preg_match('/10.\d{1,3}.0.0/', $key)){
            $html = "<tr class='red' style='background-color: #ff7569'>
                     <td class='red' style='background-color: #ff7569'>" . $key . "</td>
                     <td class='red' style='background-color: #ff7569'>" . $value[0] . "</td>
                     <td class='red' style='background-color: #ff7569'>" . $value[1] . "</td>
                     <td class='red' style='background-color: #ff7569'>" . $value[2] . "</td>
                     </tr>";
        }else{
            $html = "<tr>
                     <td>" . $key . "</td>
                     <td>" . $value[0] . "</td>
                     <td>" . $value[1] . "</td>
                     <td>" . $value[2] . "</td>
                     </tr>";
        }
        $table = $table . $html;
    }

    return $table;
}

function create_graph_page(){
    $cwd = getcwd();
    //$graph_file = fopen($cwd."/graph/simulation.dot.svg", "r") or die("Unable to open simulaton file!");
    //$legend_file = fopen($cwd."/graph/legend.dot.svg", "r") or die("Unable to open legend file!");
    $graph = file_get_contents($cwd."/graph/simulation.dot.svg");
    $legend = file_get_contents($cwd."/graph/legend.dot.svg");
    //fclose($graph_file);
    //fclose($legend_file);
    $html_table = create_table();
    $usage_table = create_usage_table();

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
                        <table class=\"table table-striped\">
                            <thead>
                            <tr>
                                <th scope=\"col\">#</th>
                                <th scope=\"col\">Guard</th>
                                <th scope=\"col\">Middle</th>
                                <th scope=\"col\">Exit</th>
                            </tr>
                            </thead>
                            <tbody>
                                " . $html_table . "
                            </tbody>
                        </table>
                    </div>
                    <div class=\"tab-pane fade\" id=\"usage\" role=\"tabpanel\" aria-labelledby=\"usage_tab\">
                        <table id=\"usage_table_sorted\" class=\"table table-striped\" data-toggle=\"table\" data-toolbar=\".toolbar\" data-sortable=\"true\">
                            <thead>
                            <tr>
                                <th data-field=\"0\" data-sortable=\"true\" scope=\"col\">IP</th>
                                <th data-field=\"1\" data-sortable=\"true\" scope=\"col\">Usage</th>
                                <th data-field=\"2\" data-sortable=\"true\" scope=\"col\">MB/s</th>
                                <th data-field=\"3\" data-sortable=\"true\" scope=\"col\">Encryp. %</th>
                            </tr>
                            </thead>
                            <tbody>
                                " .$usage_table. "
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>
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


