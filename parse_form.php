<?php

include 'backend.php';

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
        $arr['bandwidth_value'] = '';
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
    }else if ($simulation_type == 'attack'){
        if (!empty($_POST['encryption_attack'])) {
            $encryption_attack = $_POST['encryption_attack'];
            $arr['encryption_attack'] = $encryption_attack;
        } else{
            $arr['encryption_attack'] = "0";
        }

        if (!empty($_POST['guard_attack'])) {
            $guard_attack = $_POST['guard_attack'];
            $arr['guard_attack'] = $guard_attack;
        } else{
            $arr['guard_attack'] = "0";
        }

        if (!empty($_POST['exit_attack'])) {
            $exit_attack = $_POST['exit_attack'];
            $arr['exit_attack'] = $exit_attack;
        } else{
            $arr['exit_attack'] = "0";
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
    }else if ($simulation_type == 'exit_attack'){
        if (!empty($_POST['encryption_exit_attack'])) {
            $encryption_exit_attack = $_POST['encryption_exit_attack'];
            $arr['encryption_exit_attack'] = $encryption_exit_attack;
        } else{
            $arr['encryption_exit_attack'] = "0";
        }

        if (!empty($_POST['guard_exit_attack'])) {
            $guard_exit_attack = $_POST['guard_exit_attack'];
            $arr['guard_exit_attack'] = $guard_exit_attack;
        } else{
            $arr['guard_exit_attack'] = "0";
        }

        if (!empty($_POST['exit_exit_attack'])) {
            $exit_exit_attack = $_POST['exit_exit_attack'];
            $arr['exit_exit_attack'] = $exit_exit_attack;
        } else{
            $arr['exit_exit_attack'] = "0";
        }

        if (!empty($_POST['number_of_simulations_exit_attack'])) {
            $number_of_simulations_exit_attack = $_POST['number_of_simulations_exit_attack'];
            $arr['number_of_simulations_exit_attack'] = $number_of_simulations_exit_attack;
        } else{
            $arr['number_of_simulations_exit_attack'] = "0";
        }

        if (!empty($_POST['adv_exit_exit_attack'])) {
            $adv_exit_exit_attack = $_POST['adv_exit_exit_attack'];
            $arr['adv_exit_exit_attack'] = $adv_exit_exit_attack;
        } else{
            $arr['adv_exit_exit_attack'] = "0";
        }

        if (!empty($_POST['adv_exit_bandwidth_exit_attack'])) {
            $adv_exit_bandwidth_exit_attack = $_POST['adv_exit_bandwidth_exit_attack'];
            $arr['adv_exit_bandwidth_exit_attack'] = $adv_exit_bandwidth_exit_attack * pow(10,6);
        } else{
            $arr['adv_exit_bandwidth_exit_attack'] = "0";
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
    exec($command.' 2> error.log', $op, $ret);
    if($ret != 0) {
        # echo "Error: xx\n";
        echo "<h3>Error</h3>";
        echo "<p>There was an error, you can find more information in  error.log</p>";
        foreach ($op as $item) {
            echo $item;
            echo "<br>";
        }
        # echo $ret;
        return 0;
    }else{
        create_graph_page($arr['simulation_type']);
        header('Location:graph.html');
    }
}

