// https://www.webslesson.info/2016/02/dynamically-add-remove-input-fields-in-php-with-jquery-ajax.html

$(document).ready(function(){
    var i=1;
    $('#add').click(function(){
        i++;
        $('#dynamic_field').append('<div class="path_node_item" id="row'+i+'">\
                        <div class="form-row">\
                            <div class="col-md-2 mb-2 mt-2">\
                                <select class="form-control second_row" name="type[]">\
                                    <option value="guard">Guard</option>\
                                    <option value="middle">Middle</option>\
                                    <option value="exit">Exit</option>\
                                </select>\
                            </div>\
                            <div class="col-md-3 mb-2 mt-2">\
                                <input type="text" name="name[]" placeholder="Name" class="form-control">\
                            </div>\
                            <div class="col-md-3 mb-2 mt-2">\
                                <input type="text" name="ip[]" placeholder="IP" class="form-control name_list">\
                            </div>\
                            <div class="col-md-3 mb-2 mt-2">\
                                <input type="text" name="bandwidth[]" placeholder="Bandwidth MB/s" class="form-control name_list">\
                            </div>\
                            <div class="col-md-0 mb-2 mt-2">\
                                <button type="button" name="remove" id="'+i+'" class="btn btn-danger btn_remove">X</button>\
                            </div>\
                        </div>');
    });
    $(document).on('click', '.btn_remove', function(){
        var button_id = $(this).attr("id");
        $('#row'+button_id+'').remove();
    });
    $('#submit').click(function(){
        $.ajax({
            url:"name.php",
            method:"POST",
            data:$('#add_name').serialize(),
            success:function(data)
            {
                alert(data);
                $('#add_name')[0].reset();
            }
        });
    });
});

$(document).ready(function(){
    var i=1;
    $('#add_multiple_sim').click(function(){
        i++;
        $('#dynamic_field_multiple_sim').append('<div class="dynamic_field_multiple_sim border_bottom" id="m_s_row'+i+'">\
                            <div class="form-row">\
                                <div class="col-md-2 mb-2 mt-2">\
                                    <input type="text" name="m_s_guard[]" placeholder="F - Guard" class="form-control form-control-sm name_list">\
                                </div>\
                                <div class="col-md-2 mb-2 mt-2">\
                                    <input type="text" name="m_s_exit[]" placeholder="F - Exit" class="form-control form-control-sm name_list">\
                                </div>\
                                <div class="col-md-2 mb-2 mt-2">\
                                    <input type="text" name="m_s_adv_guard[]" placeholder="ADV - Guard" class="form-control form-control-sm name_list">\
                                </div>\
                                <div class="col-md-2 mb-2 mt-2">\
                                    <input type="text" name="m_s_adv_exit[]" placeholder="ADV - Exit" class="form-control form-control-sm name_list">\
                                </div>\
                                <div class="col-md-2 mb-2 mt-2">\
                                    <input type="text" name="m_s_encryption[]" placeholder="Encription %" class="form-control form-control-sm name_list">\
                                </div>\
                            </div>\
                            <div class="form-row">\
                                <div class="col-md-2 mb-2 mt-2">\
                                    <input type="text" name="m_s_friendly_guard_bandwidth[]" placeholder="F - guard Bandwidth MB/s" class="form-control form-control-sm name_list">\
                                </div>\
                                <div class="col-md-2 mb-2 mt-2">\
                                    <input type="text" name="m_s_friendly_exit_bandwidth[]" placeholder="F - exit Bandwidth MB/s" class="form-control form-control-sm name_list">\
                                </div>\
                                <div class="col-md-2 mb-2 mt-2">\
                                    <input type="text" name="m_s_adv_guard_bandwidth[]" placeholder="A - Guard Bandwidth MB/s" class="form-control form-control-sm name_list">\
                                </div>\
                                <div class="col-md-2 mb-2 mt-2">\
                                    <input type="text" name="m_s_adv_exit_bandwidth[]" placeholder="A - Exit Bandwidth MB/s" class="form-control form-control-sm name_list">\
                                </div>\
                                <div class="col-md-2 mb-2 mt-2">\
                                    <input type="text" name="m_s_identification_occurrence[]" placeholder="ID occurence %" class="form-control form-control-sm name_list">\
                                </div>\
                                <div class="col-md-0 mb-2 mt-2">\
                                    <button type="button" name="remove" id="'+i+'" class="btn-sm btn-danger btn_remove">X</button></div>\
                                </div>\
                            </div>');
                });
    $(document).on('click', '.btn_remove', function(){
        var button_id = $(this).attr("id");
        $('#m_s_row'+button_id+'').remove();
    });
    $('#submit').click(function(){
        $.ajax({
            url:"name.php",
            method:"POST",
            data:$('#add_name').serialize(),
            success:function(data)
            {
                alert(data);
                $('#add_name')[0].reset();
            }
        });
    });
});