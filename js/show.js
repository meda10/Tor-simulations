function show(aval) {
    if (aval === "path") {
        hidden_div_path.style.display = 'inline-block';
        hidden_div_hs.style.display = 'none';
        hidden_div_attack.style.display = 'none';
        hidden_div_exit_attack.style.display = 'none';
        hidden_div_multiple_sim.style.display = 'none';
        $('#example_path').show();
        $('#example_hidden_service').hide();
        $('#example_attack').hide();
        $('#example_exit_attack').hide();
        $('#info_path').show();
        $('#info_hidden_service').hide();
        $('#info_attack').hide();
        $('#info_exit_attack').hide();
        add_nodes_path.style.display = 'block';
        multiple_sim_add.style.display = 'none';
        not_path_submit.style.display = 'none';
        tabs.style.maxHeight = '650px';
        //Form.fileURL.focus();
    } else {
        hidden_div_path.style.display = 'none';
    }

    if (aval === "hidden_service") {
        hidden_div_path.style.display = 'none';
        hidden_div_hs.style.display = 'inline-block';
        hidden_div_attack.style.display = 'none';
        hidden_div_exit_attack.style.display = 'none';
        hidden_div_multiple_sim.style.display = 'none';
        $('#example_path').hide();
        $('#example_hidden_service').show();
        $('#example_attack').hide();
        $('#example_exit_attack').hide();
        $('#info_path').hide();
        $('#info_hidden_service').show();
        $('#info_attack').hide();
        $('#info_exit_attack').hide();
        add_nodes_path.style.display = 'none';
        multiple_sim_add.style.display = 'none';
        not_path_submit.style.display = 'unset';
        tabs.style.maxHeight = '650px';
        //Form.fileURL.focus();
    } else {
        hidden_div_hs.style.display = 'none';
    }

    if (aval === "attack") {
        hidden_div_path.style.display = 'none';
        hidden_div_hs.style.display = 'none';
        hidden_div_attack.style.display = 'inline-block';
        hidden_div_exit_attack.style.display = 'none';
        hidden_div_multiple_sim.style.display = 'none';
        $('#example_path').hide();
        $('#example_hidden_service').hide();
        $('#example_attack').show();
        $('#example_exit_attack').hide();
        $('#info_path').hide();
        $('#info_hidden_service').hide();
        $('#info_attack').show();
        $('#info_exit_attack').hide();
        add_nodes_path.style.display = 'block';
        multiple_sim_add.style.display = 'none';
        not_path_submit.style.display = 'none';
        tabs.style.maxHeight = '650px';
        //Form.fileURL.focus();
    } else {
        hidden_div_attack.style.display = 'none';
    }

    if (aval === "exit_attack") {
        hidden_div_path.style.display = 'none';
        hidden_div_hs.style.display = 'none';
        hidden_div_attack.style.display = 'none';
        hidden_div_exit_attack.style.display = 'inline-block';
        hidden_div_multiple_sim.style.display = 'none';
        $('#example_path').hide();
        $('#example_hidden_service').hide();
        $('#example_attack').hide();
        $('#example_exit_attack').show();
        $('#info_path').hide();
        $('#info_hidden_service').hide();
        $('#info_attack').hide();
        $('#info_exit_attack').show();
        add_nodes_path.style.display = 'block';
        multiple_sim_add.style.display = 'none';
        not_path_submit.style.display = 'none';
        tabs.style.maxHeight = '650px';
        //Form.fileURL.focus();
    } else {
        hidden_div_exit_attack.style.display = 'none';
    }


    if (aval === "multiple_sim") {
        hidden_div_path.style.display = 'none';
        hidden_div_hs.style.display = 'none';
        hidden_div_attack.style.display = 'none';
        hidden_div_exit_attack.style.display = 'none';
        hidden_div_multiple_sim.style.display = 'inline-block';
        $('#example_path').hide();
        $('#example_hidden_service').hide();
        $('#example_attack').hide();
        $('#example_exit_attack').hide();
        $('#info_path').hide();
        $('#info_hidden_service').hide();
        $('#info_attack').hide();
        $('#info_exit_attack').hide();
        add_nodes_path.style.display = 'none';
        not_path_submit.style.display = 'none';
        multiple_sim_add.style.display = 'block';
        tabs.style.maxHeight = '450px';
    } else {
        hidden_div_multiple_sim.style.display = 'none';
    }
}

function show_bandwidth() {
    if ($('#same_bandwidth').is(":checked")) {
        bandwidth_value_div.style.display = 'block';
    } else {
        bandwidth_value_div.style.display = 'none';
    }
}