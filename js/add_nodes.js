// https://www.webslesson.info/2016/02/dynamically-add-remove-input-fields-in-php-with-jquery-ajax.html

$(document).ready(function(){
    var i=1;
    $('#add').click(function(){
        i++;
        $('#dynamic_field').append('<tr id="row'+i+'">\
            <td>\
            <select class="second_row" name="type[]">\
            <option value="guard">Guard</option>\
            <option value="middle">Middle</option>\
            <option value="exit">Exit</option>\
            </select>\
            </td>\
            <td><input type="text" name="name[]" placeholder="Name" class="form-control name_list" /></td>\
            <td><input type="text" name="ip[]" placeholder="IP" class="form-control name_list" /></td>\
            <td><input type="text" name="bandwidth[]" placeholder="Bandwidth" class="form-control name_list" /></td>\
            <td><button type="button" name="remove" id="'+i+'" class="btn btn-danger btn_remove">X</button></td>\
        </tr>');
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