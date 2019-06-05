$(function() {
    $("#path_example_1").click(function() {
        $("#guard").val(55);
        $("#remove_duplicate_paths").prop('checked', true);
        $("#simulation_size").val('large');

    });
});