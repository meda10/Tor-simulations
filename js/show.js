function show(aval) {
    if (aval === "path") {
        hidden_div_path.style.display = 'inline-block';
        hidden_div_hs.style.display = 'none';
        hidden_div_attack.style.display = 'none';
        $('#example_path').show();
        $('#example_hidden_service').hide();
        $('#example_attack').hide();
        $('#info_path').show();
        $('#info_hidden_service').hide();
        $('#info_attack').hide();
        add_nodes_path.style.display = 'block';
        not_path_submit.style.display = 'none';
        //Form.fileURL.focus();
    } else {
        hidden_div_path.style.display = 'none';
    }

    if (aval === "hidden_service") {
        hidden_div_path.style.display = 'none';
        hidden_div_hs.style.display = 'inline-block';
        hidden_div_attack.style.display = 'none';
        $('#example_path').hide();
        $('#example_hidden_service').show();
        $('#example_attack').hide();
        $('#info_path').hide();
        $('#info_hidden_service').show();
        $('#info_attack').hide();
        add_nodes_path.style.display = 'none';
        not_path_submit.style.display = 'unset';
        //Form.fileURL.focus();
    } else {
        hidden_div_hs.style.display = 'none';
    }


    if (aval === "attack") {
        hidden_div_path.style.display = 'none';
        hidden_div_hs.style.display = 'none';
        hidden_div_attack.style.display = 'inline-block';
        $('#example_path').hide();
        $('#example_hidden_service').hide();
        $('#example_attack').show();
        $('#info_path').hide();
        $('#info_hidden_service').hide();
        $('#info_attack').show();
        add_nodes_path.style.display = 'none';
        not_path_submit.style.display = 'unset';
        //Form.fileURL.focus();
    } else {
        hidden_div_attack.style.display = 'none';
    }
}