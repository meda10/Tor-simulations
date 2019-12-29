$(document).ready(function () {

    var $table = $('#usage_table_sorted');

    $(function() {
        $('#filter_checkbox').on('change', function(){
            if(this.checked){
                $table.bootstrapTable('refreshOptions', {
                    filterOptions: {
                        filterAlgorithm: "and"
                    }
                });
                $table.bootstrapTable('filterBy', {
                    affiliation: true
                })
            }else {
                $table.bootstrapTable('refreshOptions', {
                    filterOptions: {
                        filterAlgorithm: "and"
                    }
                });
                $table.bootstrapTable('filterBy', {

                })
            }

        })
    });

    /*
    (function ($) {

        $('#filter').keyup(function () {

            var rex = new RegExp($(this).val(), 'i');
            $('.searchable tr').hide();
            $('.searchable tr').filter(function () {
                return rex.test($(this).text());
            }).show();

        });


        $('#filter_checkbox').on('change', function(){

            if(this.checked){
                $('.searchable tr').hide();
                $('.searchable tr').filter(function() {
                    var regex = /10\.[0-9]{1,3}\.0\.0/;
                    return regex.test($(this).find('td').eq(0).text());
                }).show();
            }else{
                $('.searchable tr').show();
            }


        });

        $(function() {
            $('.toolbar input').change(function () {
                var queryParamsType = $('.toolbar input:checked').next().text()

                $table.bootstrapTable('refreshOptions', {
                    queryParamsType: queryParamsType
                })
            })
        })

    }(jQuery));
    */
});