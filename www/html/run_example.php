<?php

include 'backend.php';

if (isset($_POST['btn'])) {
    switch ($_POST['btn']) {
        case 'path_example_1':
            run_sim("path_example_1.ini");
            break;
        case 'path_example_2':
            run_sim("path_example_2.ini");
            break;
        case 'path_example_3':
            run_sim("path_example_3.ini");
            break;
        case 'path_example_4':
            run_sim("path_example_4.ini");
            break;
        case 'hidden_service_example_1':
            run_sim("hidden_service_example_1.ini");
            break;
        case 'hidden_service_example_2':
            run_sim("hidden_service_example_2.ini");
            break;
        case 'attack_example_1':
            run_sim("attack_example_1.ini");
            break;
        case 'attack_example_2':
            run_sim("attack_example_2.ini");
            break;
        case 'attack_example_3':
            run_sim("attack_example_3.ini");
            break;
        case 'exit_attack_example_1':
            run_sim("exit_attack_example_1.ini");
            break;
        case 'exit_attack_example_2':
            run_sim("exit_attack_example_2.ini");
            break;
        case 'exit_attack_example_3':
            run_sim("exit_attack_example_3.ini");
            break;
        case 'multiple_sim_example_1':
            run_sim("multiple_sim_example_1.ini");
            break;
        case 'multiple_sim_example_2':
            run_sim("multiple_sim_example_2.ini");
            break;
    }
}

function run_sim($config_file){
    $cwd = getcwd();
    chdir($cwd);

    $command = escapeshellcmd('./sim.py -i "/conf/examples/'.$config_file.'"');
    exec($command.' 2> error.log', $op, $ret);
    if ($ret != 0) {
        echo "<h3>Error</h3>";
        echo "<p>There was an error, you can find more information in  error.log</p>";
        foreach ($op as $item) {
            echo $item;
            echo "<br>";
        }
        return 1;
    } else {
        $config = parse_ini_file($cwd.'/conf/examples/'.$config_file, true, INI_SCANNER_RAW);
        if($config['general']['simulation_type'] == 'multiple_sim'){
            $graph = show_graph($config, count($config) - 2);
        }else{
            $graph = NULL;
        }
        create_graph_page($config['general']['simulation_type'], $graph);
        header('Location:graph.html');
    }
    return 0;
}



