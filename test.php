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

//create_zip();

$cwd = getcwd();
$graph_file = fopen($cwd."/graph/simulation.dot.svg", "r") or die("Unable to open simulaton file!");
$legend_file = fopen($cwd."/graph/legend.dot.svg", "r") or die("Unable to open legend file!");
$graph = file_get_contents($cwd."/graph/simulation.dot.svg");
$legend = file_get_contents($legend_file);
echo $graph;
fclose($graph_file);
fclose($legend_file);



