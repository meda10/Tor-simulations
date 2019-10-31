$(function() {
    $("#path_example_1").click(function() {
        $("#simulation_type").val('path');
        $("#guard").val(5);
        $("#middle").val(5);
        $("#exit").val(4);
        $("#guard_exit").val(3);
        $("#number_of_simulations").val(20);
        $("#simulation_size").val('small');
        $("#path_selection").val('random');
    });

    $("#path_example_2").click(function () {
        $("#simulation_type").val('path');
        $("#guard").val(20);
        $("#middle").val(30);
        $("#exit").val(20);
        $("#guard_exit").val(16);
        $("#number_of_simulations").val(30);
        $("#simulation_size").val('large');
        $("#path_selection").val('random');

    });

    $("#path_example_3").click(function () {
        $("#simulation_type").val('path');
        $("#guard").val(15);
        $("#middle").val(20);
        $("#exit").val(5);
        $("#guard_exit").val(20);
        $("#number_of_simulations").val(30);
        $("#simulation_size").val('large');
        $("#path_selection").val('3_guards');

    });

    $("#path_example_4").click(function () {
        $("#simulation_type").val('path');
        $("#guard").val(40);
        $("#middle").val(0);
        $("#exit").val(20);
        $("#guard_exit").val(30);
        $("#number_of_simulations").val(30);
        $("#simulation_size").val('large');
        $("#path_selection").val('random');

    });

    $("#hs_example_1").click(function () {
        $("#simulation_type").val('hidden_service');
        $("#nodes_hs").val(180);
    });

    $("#hs_example_2").click(function () {
        $("#simulation_type").val('hidden_service');
        $("#nodes_hs").val(250);
    });

    $("#attack_example_1").click(function () {
        $("#simulation_type").val('attack');
        $("#nodes_attack").val(150);
        $("#number_of_simulations_attack").val(800);
        $("#adv_guard").val(50);
        $("#adv_exit").val(80);
        $("#adv_guard_bandwidth").val(1662668109);
        $("#adv_exit_bandwidth").val(1662668109);
    });

    $("#attack_example_2").click(function () {
        $("#simulation_type").val('attack');
        $("#nodes_attack").val(300);
        $("#number_of_simulations_attack").val(1200);
        $("#adv_guard").val(60);
        $("#adv_exit").val(60);
        $("#adv_guard_bandwidth").val(1662668109);
        $("#adv_exit_bandwidth").val(1662668109);
    });
});


