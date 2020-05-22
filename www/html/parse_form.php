<?php

include 'backend.php';

if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['download'])){

    if (!empty($_POST['type'])) {
        $type = $_POST['type'];
        create_zip($type);
    } else{
        $type = 'path';
        create_zip($type);
    }



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
    $number_of_user_simulations = 0;

    if (!empty($_POST['simulation_type'])) {
        $arr['simulation_type'] = $_POST['simulation_type'];
        $simulation_type = $arr['simulation_type'];
    }

    if (!empty($_POST['remove_duplicate_paths'])) {
        $arr['remove_duplicate_paths'] = "True";
    } else{
        $arr['remove_duplicate_paths'] = "False";
    }

    if (!empty($_POST['same_bandwidth'])) {
        $arr['same_bandwidth'] = "True";;
    } else{
        $arr['same_bandwidth'] = "False";
    }

    if (!empty($_POST['guard_bandwidth_value'])) {
        $arr['guard_bandwidth_value'] = $_POST['guard_bandwidth_value'] * pow(10,6);
    } else{
        $arr['guard_bandwidth_value'] = '';
    }

    if (!empty($_POST['middle_bandwidth_value'])) {
        $arr['middle_bandwidth_value'] = $_POST['middle_bandwidth_value'] * pow(10,6);
    } else{
        $arr['middle_bandwidth_value'] = '';
    }

    if (!empty($_POST['exit_bandwidth_value'])) {
        $arr['exit_bandwidth_value'] = $_POST['bandwidth_value'] * pow(10,6);
    } else{
        $arr['exit_bandwidth_value'] = '';
    }

    if($simulation_type == 'path'){
        if ($_POST['guard'] != "") {
            $arr['guard'] = $_POST['guard'];
        } else{
            error('Required field was not field: Guard');
        }

        if ($_POST['middle'] != "") {
            $arr['middle'] = $_POST['middle'];
        } else{
            error('Required field was not field: Middle');
        }

        if ($_POST['exit'] != "") {
            $arr['exit'] = $_POST['exit'];
        } else{
            error('Required field was not field: Exit');
        }

        if ($_POST['guard_exit'] != "") {
            $arr['guard_exit'] = $_POST['guard_exit'];
        } else{
            $arr['guard_exit'] = "0";
        }

        if ($_POST['number_of_simulations'] != "") {
            $arr['number_of_simulations'] = $_POST['number_of_simulations'];
        } else{
            error('Required field was not field: Number of simulations');
        }

        if (!empty($_POST['simulation_size'])) {
            $arr['simulation_size'] = $_POST['simulation_size'];
        }

        if (!empty($_POST['path_selection'])) {
            $arr['path_selection'] = $_POST['path_selection'];
        }

        $number = count($_POST['name']);
        $number_of_user_nodes = $number;
        if($number > 0) {
            for($i = 0; $i < $number; $i++) {
                if(trim($_POST['name'][$i] != '')) {
                    $arr['node'.$i]['type'] = $_POST['type'][$i];
                    $arr['node'.$i]['name'] = $_POST['name'][$i];
                    $arr['node'.$i]['ip'] = $_POST['ip'][$i];
                    if(is_numeric($_POST['bandwidth'][$i])){
                        $arr['node'.$i]['bandwidth'] = $_POST['bandwidth'][$i] * pow(10,6);
                    }else{
                        echo "<h3>Error 5</h3>";
                        echo "<p>There was an error, while loading arguents. Check your custom nodes.</p>";
                        return 5;
                    }
                }
            }
        }

    }else if ($simulation_type == 'hidden_service'){
        if ($_POST['nodes_hs'] != "") {
            $arr['nodes_hs'] = $_POST['nodes_hs'];
        } else{
            error('Required field was not field: Nodes');
        }
    }else if ($simulation_type == 'attack'){
        if ($_POST['encryption_attack'] != "") {
            $arr['encryption_attack'] = $_POST['encryption_attack'];
        } else{
            error('Required field was not field: Encryption %');
        }

        if ($_POST['guard_attack'] != "") {
            $arr['guard_attack'] = $_POST['guard_attack'];
        } else{
            error('Required field was not field: Guard');
        }

        if ($_POST['exit_attack'] != "") {
            $arr['exit_attack'] = $_POST['exit_attack'];
        } else{
            error('Required field was not field: Exit');
        }

        if ($_POST['number_of_simulations_attack'] != "") {
            $arr['number_of_simulations_attack'] = $_POST['number_of_simulations_attack'];
        } else{
            error('Required field was not field: number od simulations');
        }

        if ($_POST['adv_guard'] != "") {
            $arr['adv_guard'] = $_POST['adv_guard'];
        } else{
            error('Required field was not field: ADV guard');
        }

        if ($_POST['adv_exit'] != "") {
            $arr['adv_exit'] = $_POST['adv_exit'];
        } else{
            error('Required field was not field: ADV euard');
        }

        if ($_POST['adv_guard_bandwidth'] != "") {
            $arr['adv_guard_bandwidth'] = $_POST['adv_guard_bandwidth'] * pow(10,6);
        } else{
            error('Required field was not field: ADV guard bandwidth');
        }

        if ($_POST['adv_exit_bandwidth'] != "") {
            $arr['adv_exit_bandwidth'] = $_POST['adv_exit_bandwidth'] * pow(10,6);
        } else{
            error('Required field was not field: ADV exit bandwidth');
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

    }else if ($simulation_type == 'exit_attack'){
        if ($_POST['encryption_exit_attack'] != "") {
            $arr['encryption_exit_attack'] = $_POST['encryption_exit_attack'];
        } else{
            error('Required field was not field: Encryption');
        }

        if ($_POST['identification_occurrence_exit_attack'] != "") {
            $arr['identification_occurrence_exit_attack'] = $_POST['identification_occurrence_exit_attack'];
        } else{
            error('Required field was not field: ID occurrence');
        }

        if ($_POST['guard_exit_attack'] != "") {
            $arr['guard_exit_attack'] = $_POST['guard_exit_attack'];
        } else{
            error('Required field was not field: Guard');
        }

        if ($_POST['exit_exit_attack'] != "") {
            $arr['exit_exit_attack'] = $_POST['exit_exit_attack'];
        } else{
            error('Required field was not field: Exit');
        }

        if ($_POST['number_of_simulations_exit_attack'] != "") {
            $arr['number_of_simulations_exit_attack'] = $_POST['number_of_simulations_exit_attack'];
        } else{
            error('Required field was not field: Number of simulations');
        }

        if ($_POST['adv_exit_exit_attack'] != "") {
            $arr['adv_exit_exit_attack'] = $_POST['adv_exit_exit_attack'];
        } else{
            error('Required field was not field: ADV exit');
        }

        if ($_POST['adv_exit_bandwidth_exit_attack'] != "") {
            $arr['adv_exit_bandwidth_exit_attack'] = $_POST['adv_exit_bandwidth_exit_attack'] * pow(10,6);
        } else{
            error('Required field was not field: ADV exit bandwidth');
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
    } else if ($simulation_type == 'multiple_sim'){

        if (!empty($_POST['number_of_simulations_multiple_sim'])) {
            $number_of_simulations_multiple_sim = $_POST['number_of_simulations_multiple_sim'];
            $arr['number_of_simulations_multiple_sim'] = $number_of_simulations_multiple_sim;
        } else{
            error('Required field was not field: Number of simulations');
        }

        # echo "Number of simulations: ".$number_of_simulations_multiple_sim;

        $n = count($_POST['m_s_guard']);
        $number_of_user_simulations = $n;
        # echo "n ".$n;
        if($n > 0) {
            for($i = 0; $i < $n; $i++) {
                if($_POST['m_s_encryption'][$i] != NULL){
                    $arr['sim_'.$i]['encryption'] = $_POST['m_s_encryption'][$i];
                }else{
                    error('All fields have to be filled, missing field: Encryption');
                }
                if($_POST['m_s_identification_occurrence'][$i] != NULL){
                    $arr['sim_'.$i]['identification_occurrence'] = $_POST['m_s_identification_occurrence'][$i];
                }else{
                    error('All fields have to be filled, missing field: ID occurrence');
                }
                if($_POST['m_s_guard'][$i] != NULL){
                    $arr['sim_'.$i]['guard'] = $_POST['m_s_guard'][$i];
                }else{
                    error('All fields have to be filled, missing field: Guard');
                }
                if($_POST['m_s_exit'][$i] != NULL){
                    $arr['sim_'.$i]['exit'] = $_POST['m_s_exit'][$i];
                }else{
                    error('All fields have to be filled, missing field: exit');
                }
                if($_POST['m_s_adv_guard'][$i] != NULL){
                    $arr['sim_'.$i]['adv_guard'] = $_POST['m_s_adv_guard'][$i];
                }else{
                    error('All fields have to be filled, missing field: ADV guard');
                }
                if($_POST['m_s_adv_exit'][$i] != NULL){
                    $arr['sim_'.$i]['adv_exit'] = $_POST['m_s_adv_exit'][$i];
                }else{
                    error('All fields have to be filled, missing field: ADV Exit');
                }
                if($_POST['m_s_friendly_guard_bandwidth'][$i] != NULL){
                    $arr['sim_'.$i]['friendly_guard_bandwidth'] = $_POST['m_s_friendly_guard_bandwidth'][$i] * pow(10,6);
                }else{
                    error('All fields have to be filled, missing field: Guard bandwidth');
                }
                if($_POST['m_s_friendly_exit_bandwidth'][$i] != NULL){
                    $arr['sim_'.$i]['friendly_exit_bandwidth'] = $_POST['m_s_friendly_exit_bandwidth'][$i] * pow(10,6);
                }else{
                    error('All fields have to be filled, missing field: Exit bandwidth');
                }
                if($_POST['m_s_adv_guard_bandwidth'][$i]  != NULL){
                    $arr['sim_'.$i]['adv_guard_bandwidth'] = $_POST['m_s_adv_guard_bandwidth'][$i] * pow(10,6);
                }else{
                    error('All fields have to be filled, missing field: ADV guard bandwidth');
                }
                if($_POST['m_s_adv_exit_bandwidth'][$i] != NULL){
                    $arr['sim_'.$i]['adv_exit_bandwidth'] = $_POST['m_s_adv_exit_bandwidth'][$i] * pow(10,6);
                }else{
                    error('All fields have to be filled, missing field: ADV exit bandwidth');
                }
            }
        }
    }

    $config = parse_arguments($arr, $number_of_user_nodes, $number_of_user_simulations);
    # print_r($arr);
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
        echo "<h3>Error 0</h3>";
        echo "<p>There was an error, you can find more information in  error.log</p>";
        foreach ($op as $item) {
            echo $item;
            echo "<br>";
        }
        # echo $ret;
        return 0;
    }else{
        if($config['general']['simulation_type'] == 'multiple_sim'){
            $graph = show_graph($config, $number_of_user_simulations);
        }else{
            $graph = NULL;
        }
        create_graph_page($arr['simulation_type'], $graph);
        header('Location:graph.html');
    }
}