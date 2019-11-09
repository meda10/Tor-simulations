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
            $errors[] = 'File size must be excately 2 MB';
        }

        if (file_exists("conf/" . $file_name)) {
            unlink("conf/" . $file_name);
        }

        if (empty($errors) == true) {
            move_uploaded_file($file_tmp, "conf/" . $file_name);

            $cwd = getcwd();
            chdir($cwd);

            $command = escapeshellcmd('./sim.py -i conf/' . $file_name);
            exec($command, $op, $ret);
            if ($ret != 0) {
                # echo "Error: xx\n";
                foreach ($op as $item) {
                    echo $item;
                    echo "<br>";
                }
                # echo $ret;
            } else {
                create_graph_page();
                header('Location:graph.html');
            }

            return;
        } else {
            print_r($errors);
        }
    }
}