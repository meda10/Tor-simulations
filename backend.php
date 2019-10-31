<?php

if ( isset( $_GET['submit'] ) ) {
    $firstname = $_GET['name']; $lastname = $_GET['address'];
    echo '<h3>Form GET Method</h3>';
    echo 'Your name is ' . $lastname . ' ' . $firstname; exit;
}

$simulation_type = $remove_duplicate_paths = $same_bandwidth = "";
$generate_graph = $create_html  = "";

if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['download'])){
    create_zip();
    $filename = "simulation.zip";
    if (file_exists($filename)) {
        header('Content-Type: application/zip');
        header('Content-Disposition: attachment; filename="'.basename($filename).'"');
        header('Content-Length: ' . filesize($filename));
        header("Pragma: no-cache");
        header("Expires: 0");

        flush();
        readfile($filename);
        unlink($filename);
    }
} elseif ($_SERVER["REQUEST_METHOD"] == "POST") {
    $arr = array();
    $number_of_user_nodes = 0;

    if (!empty($_POST['simulation_type'])) {
        $simulation_type = $_POST['simulation_type'];
        $arr['simulation_type'] = $simulation_type;
    }

    if (!empty($_POST['remove_duplicate_paths'])) {
        $remove_duplicate_paths = "True";
        $arr['remove_duplicate_paths'] = $remove_duplicate_paths;
    } else{
        $remove_duplicate_paths = "False";
        $arr['remove_duplicate_paths'] = $remove_duplicate_paths;
    }

    if (!empty($_POST['same_bandwidth'])) {
        $same_bandwidth = "True";
        $arr['same_bandwidth'] = $same_bandwidth;
    } else{
        $same_bandwidth = "False";
        $arr['same_bandwidth'] = $same_bandwidth;
    }

    if (!empty($_POST['bandwidth_value'])) {
        $bandwidth_value = $_POST['bandwidth_value'];
        $arr['bandwidth_value'] = $bandwidth_value * pow(10,6);
    } else{
        $arr['bandwidth_value'] = 'None';
    }

    if($simulation_type == 'path'){
        if (!empty($_POST['guard'])) {
            $guard = $_POST['guard'];
            $arr['guard'] = $guard;
        } else{
            $arr['guard'] = '0';
        }

        if (!empty($_POST['middle'])) {
            $middle = $_POST['middle'];
            $arr['middle'] = $middle;
        } else{
            $arr['middle'] = "0";
        }

        if (!empty($_POST['exit'])) {
            $exit = $_POST['exit'];
            $arr['exit'] = $exit;
        } else{
            $arr['exit'] = "0";
        }

        if (!empty($_POST['guard_exit'])) {
            $guard_exit = $_POST['guard_exit'];
            $arr['guard_exit'] = $guard_exit;
        } else{
            $arr['guard_exit'] = "0";
        }

        if (!empty($_POST['number_of_simulations'])) {
            $number_of_simulations = $_POST['number_of_simulations'];
            $arr['number_of_simulations'] = $number_of_simulations;
        } else{
            $arr['number_of_simulations'] = "1";
        }

        if (!empty($_POST['simulation_size'])) {
            $simulation_size = $_POST['simulation_size'];
            $arr['simulation_size'] = $simulation_size;
        }

        if (!empty($_POST['path_selection'])) {
            $path_selection = $_POST['path_selection'];
            $arr['path_selection'] = $path_selection;
        }


        $number = count($_POST['name']);
        $number_of_user_nodes = $number;
        if($number > 0) {
            for($i = 0; $i < $number; $i++) {
                if(trim($_POST['name'][$i] != '')) {
                    $arr['node'.$i]['type'] = $_POST['type'][$i];
                    $arr['node'.$i]['name'] = $_POST['name'][$i];
                    $arr['node'.$i]['ip'] = $_POST['ip'][$i];
                    $arr['node'.$i]['bandwidth'] = $_POST['bandwidth'][$i] * pow(10,6);
                }
            }
        }

    }else if ($simulation_type == 'hidden_service'){
        if (!empty($_POST['nodes_hs'])) {
            $nodes_hs = $_POST['nodes_hs'];
            $arr['nodes_hs'] = $nodes_hs;
        } else{
            $arr['nodes_hs'] = "0";
        }
    }else {
        if (!empty($_POST['nodes_attack'])) {
            $nodes_attack = $_POST['nodes_attack'];
            $arr['nodes_attack'] = $nodes_attack;
        } else{
            $arr['nodes_attack'] = "0";
        }

        if (!empty($_POST['number_of_simulations_attack'])) {
            $number_of_simulations_attack = $_POST['number_of_simulations_attack'];
            $arr['number_of_simulations_attack'] = $number_of_simulations_attack;
        } else{
            $arr['number_of_simulations_attack'] = "0";
        }

        if (!empty($_POST['adv_guard'])) {
            $adv_guard = $_POST['adv_guard'];
            $arr['adv_guard'] = $adv_guard;
        } else{
            $arr['adv_guard'] = "0";
        }

        if (!empty($_POST['adv_exit'])) {
            $adv_exit = $_POST['adv_exit'];
            $arr['adv_exit'] = $adv_exit;
        } else{
            $arr['adv_exit'] = "0";
        }

        if (!empty($_POST['adv_guard_bandwidth'])) {
            $adv_guard_bandwidth = $_POST['adv_guard_bandwidth'];
            $arr['adv_guard_bandwidth'] = $adv_guard_bandwidth * pow(10,6);
        } else{
            $arr['adv_guard_bandwidth'] = "0";
        }

        if (!empty($_POST['adv_exit_bandwidth'])) {
            $adv_exit_bandwidth = $_POST['adv_exit_bandwidth'];
            $arr['adv_exit_bandwidth'] = $adv_exit_bandwidth * pow(10,6);
        } else{
            $arr['adv_exit_bandwidth'] = "0";
        }
    }

    parse_arguments($arr, $number_of_user_nodes);
    $cwd = getcwd();
    chdir($cwd);
    //echo getcwd();
    $log = "";
    //$command = escapeshellcmd("python3.6 ./sim.py 1> $log 2>&1");

    $command = escapeshellcmd('./sim.py');
    //$output = shell_exec($command);
    exec($command, $op, $ret);
    if($ret != 0) {
        # echo "Error: xx\n";
        foreach ($op as $item) {
            echo $item;
            echo "<br>";
        }
        # echo $ret;
    }else{
        create_graph_page();
        header('Location:graph.html');
    }
}


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
    }else{
        $config['attack_simulation']['nodes'] = $arr['nodes_attack'];
        $config['attack_simulation']['number_of_simulations'] = $arr['number_of_simulations_attack'];
        $config['attack_simulation']['adv_guard'] = $arr['adv_guard'];
        $config['attack_simulation']['adv_exit'] = $arr['adv_exit'];
        $config['attack_simulation']['adv_guard_bandwidth'] = $arr['adv_guard_bandwidth'];
        $config['attack_simulation']['adv_exit_bandwidth'] = $arr['adv_exit_bandwidth'];
    }

    $return_code = write_ini_file('config.ini', $config);
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
                        <th scope=\"row\">" . $x . "</th>
                        <td>" . $parts[2] . "</td>
                        <td>" . $parts[3] . "</td>
                        <td>" . $parts[4] . "</td>
                     </tr>";
                }else{
                    $html = "<tr>
                        <th scope=\"row\">" . $x . "</th>
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
    $output = file_get_contents($cwd . "/torps/out/simulation/usage");

    $arr = json_decode($output, true);
    foreach ($arr as $key => $value){
        $html = "<tr>
                 <td>" . $key . "</td>
                 <td>" . $value[0] . "</td>
                 <td>" . $value[1] . "</td>
                 </tr>";
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

    $html_start = "<!DOCTYPE html>
                <html lang=\"en\">
                <head>
                    <meta charset=\"utf-8\">
                    <meta content=\"width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no\" name=\"viewport\">
                    <link rel=\"stylesheet\" href=\"resources//animation.css\">
                    <script defer=\"\" src=\"resources//animation.js\"></script>
                    <link href=\"css/style.css\" rel=\"stylesheet\" type=\"text/css\">
                    <link href=\"css/bootstrap.min.css\" rel=\"stylesheet\" type=\"text/css\">
                    <script src=\"https://ajax.googleapis.com/ajax/libs/jquery/3.4.0/jquery.min.js\"></script>
                    <script src=\"https://maxcdn.bootstrapcdn.com/bootstrap/3.4.0/js/bootstrap.min.js\"></script>
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
                        <table class=\"table table-striped\">
                            <thead>
                            <tr>
                                <th scope=\"col\">IP</th>
                                <th scope=\"col\">Usage</th>
                                <th scope=\"col\">MB/s</th>
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


