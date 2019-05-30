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

    if (!empty($_POST['generate_graph'])) {
        $generate_graph = "True";
        $arr['generate_graph'] = $generate_graph;
    } else{
        $generate_graph = "False";
        $arr['generate_graph'] = $generate_graph;
    }

    if (!empty($_POST['create_html'])) {
        $create_html = "True";
        $arr['create_html'] = $create_html;
    } else{
        $create_html = "False";
        $arr['create_html'] = $create_html;
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
            $arr['adv_guard_bandwidth'] = $adv_guard_bandwidth;
        } else{
            $arr['adv_guard_bandwidth'] = "0";
        }

        if (!empty($_POST['adv_exit_bandwidth'])) {
            $adv_exit_bandwidth = $_POST['adv_exit_bandwidth'];
            $arr['adv_exit_bandwidth'] = $adv_exit_bandwidth;
        } else{
            $arr['adv_exit_bandwidth'] = "0";
        }
    }

    parse_arguments($arr);
    chdir('/opt/lampp/htdocs/bp_web');
    //echo getcwd();
    //$command = escapeshellcmd('python3.6 ./test.py');
    $command = escapeshellcmd('./test.py');
    $output = shell_exec($command);
    //$output = exec($command);
    create_graph_page();
    //header('Location:index.html');
    header('Location:graph.html');
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


function parse_arguments($arr){
    $config = parse_ini_file('config.ini', true, INI_SCANNER_RAW);


    $config['general']['simulation_type'] = $arr['simulation_type'];
    $config['general']['remove_duplicate_paths'] = $arr['remove_duplicate_paths'];
    $config['general']['same_bandwidth'] = $arr['same_bandwidth'];
    $config['general']['generate_graph'] = $arr['generate_graph'];
    $config['general']['create_html'] = $arr['create_html'];

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
    }else{
        $config['attack_simulation']['nodes'] = $arr['nodes_attack'];
        $config['attack_simulation']['number_of_simulations'] = $arr['number_of_simulations_attack'];
        $config['attack_simulation']['adv_guard'] = $arr['adv_guard'];
        $config['attack_simulation']['adv_exit'] = $arr['adv_exit'];
        $config['attack_simulation']['adv_guard_bandwidth'] = $arr['adv_guard_bandwidth'];
        $config['attack_simulation']['adv_exit_bandwidth'] = $arr['adv_exit_bandwidth'];
    }

    write_ini_file('config.ini', $config);
}


function create_zip(){
    $zip = new ZipArchive;
    $res = $zip->open('simulation.zip', ZipArchive::CREATE);
    if ($res === TRUE) {
        $zip->addFile('index.html', 'graph.html');
        $zip->addFile('graph/simulation.dot.svg', 'simulation.svg');
        $zip->addFile('graph/legend.dot.svg', 'legend.svg');
        $zip->addFile('resources/animation.css');
        $zip->addFile('resources/animation.js');
        $zip->close();
    }
}


function create_graph_page(){
    $cwd = getcwd();
    //$graph_file = fopen($cwd."/graph/simulation.dot.svg", "r") or die("Unable to open simulaton file!");
    //$legend_file = fopen($cwd."/graph/legend.dot.svg", "r") or die("Unable to open legend file!");
    $graph = file_get_contents($cwd."/graph/simulation.dot.svg");
    $legend = file_get_contents($cwd."/graph/legend.dot.svg");
    //fclose($graph_file);
    //fclose($legend_file);


    $txt = "<!DOCTYPE html>
            <html lang=\"en\">
            <head>
            <meta charset=\"UTF-8\">
            <link rel=\"stylesheet\" href=\"resources//animation.css\">
            <script defer=\"\" src=\"resources//animation.js\"></script>
            <meta name=\"viewport\" content=\"width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no\">
            <link rel=\"stylesheet\" type=\"text/css\" href=\"css/style.css\">
            <link rel=\"stylesheet\" type=\"text/css\" href=\"css/bootstrap.min.css\">
            <title>Simulator</title>
            </head>
            <body>
            <div class=\"content\">
                <div class=\"header\">
                    <h1>Simulator</h1>
                </div>
            </div>
            <div class=\"content\">
                <ul id=\"link-container\">
                </ul>
            ";

    $html_file = fopen("graph.html", "w") or die("Unable to open html file!");
    fwrite($html_file, $txt);
    fwrite($html_file, $graph);
    fwrite($html_file, "<br>");
    fwrite($html_file, $legend);
    fwrite($html_file, "<div class='container'>
                                <h1>Download Zip</h1>
                                <form method='post' action='backend.php'>
                                    <input type='submit' name='download' value='Download'>
                                 </form>
                             </div>");
    fwrite($html_file, "</div></body></html>");
    fclose($html_file);
}


