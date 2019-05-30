function show(aval) {
    if (aval == "path") {
        hidden_div_path.style.display = 'inline-block';
        hidden_div_hs.style.display = 'none';
        hidden_div_attack.style.display = 'none';
        Form.fileURL.focus();
    } else {
        hidden_div_path.style.display = 'none';
    }

    if (aval == "hidden_service") {
        hidden_div_path.style.display = 'none';
        hidden_div_hs.style.display = 'inline-block';
        hidden_div_attack.style.display = 'none';
        Form.fileURL.focus();
    } else {
        hidden_div_hs.style.display = 'none';
    }


    if (aval == "attack") {
        hidden_div_path.style.display = 'none';
        hidden_div_hs.style.display = 'none';
        hidden_div_attack.style.display = 'inline-block';
        Form.fileURL.focus();
    } else {
        hidden_div_attack.style.display = 'none';
    }
}