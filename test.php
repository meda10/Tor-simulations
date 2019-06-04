<?php

function create_zip(){
    print_r(get_loaded_extensions ());
    echo phpversion();
    $zip = new ZipArchive;
    if ($zip->open('simulation.zip', ZipArchive::CREATE) === TRUE) {
        $zip->addFile('index.html', 'graph.html');

        $zip->addFile('graph/simulation.dot.svg', 'simulation.svg');
        $zip->addFile('graph/legend.dot.svg', 'legend.svg');
        $zip->addFile('resources/animation.css');
        $zip->addFile('resources/animation.js');

        $zip->close();
    }
}


function write_table()
{
    $table = "";
    $cwd = getcwd();
    $output = file_get_contents($cwd . "/torps//out/simulation/output");
    $i = 0;
    foreach (preg_split("/((\r?\n)|(\r\n?))/", $output) as $line) {
        if (!empty($line)) {
            if ($i >= 1) {
                $parts = preg_split('/\s+/', $line);
                $x = $i - 1;
                $html = "<tr>
                        <th scope=\"row\">" . $x . "</th>
                        <td>" . $parts[2] . "</td>
                        <td>" . $parts[3] . "</td>
                        <td>" . $parts[4] . "</td>
                     </tr>";
                $table = $table . $html;
            }
        }
        $i++;
    }
    return $table;
}


$x = write_table();
echo $x;

