<?php

include 'backend.php';

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $arr = array();
    $number_of_user_nodes = 0;

    if (isset($_FILES['file_to_upload'])) {
        $errors = array();
        $file_name = $_FILES['file_to_upload']['name'];
        $file_size = $_FILES['file_to_upload']['size'];
        $file_tmp = $_FILES['file_to_upload']['tmp_name'];
        $file_type = $_FILES['file_to_upload']['type'];

        $file_ext = strtolower(end(explode('.', $_FILES['file_to_upload']['name'])));

        $extensions = array("ini");

        if (in_array($file_ext, $extensions) === false) {
            $errors[] = "Please select .ini file";
        }

        if ($file_size > 2097152) {
            $errors[] = 'File size must be max 2 MB';
        }

        unlink_file($file_name);

        if (empty($errors) == true) {
            move_uploaded_file($file_tmp, "conf/" . $file_name);

            $cwd = getcwd();
            chdir($cwd);
            //$arg = escapeshellarg('-i conf/'.$file_name);
            $command = escapeshellcmd('./sim.py -i "/conf/'.$file_name.'"');
            exec($command.' 2> error.log', $op, $ret);
            if ($ret != 0) {
                # echo "Error: xx\n";
                echo "<h3>Error</h3>";
                echo "<p>There was an error, you can find more information in  error.log</p>";
                foreach ($op as $item) {
                    echo $item;
                    echo "<br>";
                }
                # echo $ret;
                return 0;
            } else {
                $config = parse_ini_file($cwd.'/conf/'.$file_name, true, INI_SCANNER_RAW);
                unlink_file($file_name);
                if($config['general']['simulation_type'] == 'multiple_sim'){
                    $graph = show_graph($config, count($config) - 2);
                }else{
                    $graph = NULL;
                }
                create_graph_page($config['general']['simulation_type'], $graph);
                header('Location:graph.html');
            }

            return;
        } else {
            print_r($errors);
        }
    }
}