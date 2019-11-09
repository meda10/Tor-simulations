// https://www.webslesson.info/2016/02/dynamically-add-remove-input-fields-in-php-with-jquery-ajax.html

$(document).ready(function(){
    var i=1;
    $('#add').click(function(){
        i++;
        $('#dynamic_field').append('<div class="path_node_item" id="row'+i+'">\
            <div class="part_1">\
            <select class="second_row" name="type[]">\
            <option value="guard">Guard</option>\
            <option value="middle">Middle</option>\
            <option value="exit">Exit</option>\
            </select>\
            <input type="text" name="name[]" placeholder="Name" class="form-control name_list">\
            </div>\
            <div class="part_2">\
            <input type="text" name="ip[]" placeholder="IP" class="form-control name_list">\
            <input type="text" name="bandwidth[]" placeholder="Bandwidth MB/s" class="form-control name_list">\
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