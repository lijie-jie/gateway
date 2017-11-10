$(function(){
	// 菜单点击事件
    $('.dropMenu a').click(function() {
    	console.log($(this).hasClass('disabled'))
        if ($(this).hasClass('disabled')) {
            // 展开菜单
            var id = $(this).data('id');
            $('.dropMenu a.nt-item').addClass('hidden');
            $('.dropMenu a.nt-item[data-pid='+id+']').removeClass('hidden');
            if ($('.dropMenu a.nt-item.active[data-pid='+id+']').length === 0) {
                $('.dropMenu a.nt-item[data-pid='+id+']').first().trigger('click');
            }
        } else {
            // 打开页面
            $(this).addClass('active').siblings('a').removeClass('active');
            var url = $(this).data('url');
            $('.js-mainframe').attr('src',url);
        }
    });
    // 初始化打开第一个
    $('.dropMenu a:first').trigger('click');
    // 下拉菜单
	$(document).on('click','.dropMenu li > a',function(e){
		$(this).siblings('ul').find('li').eq(0).find('ul').show();
		$(this).parents('li').siblings('li').find('.onemenu').slideUp();
		$(this).siblings('ul').slideToggle();
    	e.stopPropagation();
	});
	// 关闭菜单
	$(document).on("click", function(){
        $(".onemenu").slideUp();
        $('.dropMenu li > a').siblings('ul').find('li').eq(0).find('ul').show();
    });
    // 关闭菜单
	$(document).on("click",'.twomenu a', function(){
        $(".onemenu").slideUp();
        $('.dropMenu li > a').siblings('ul').find('li').eq(0).find('ul').show();
    });
});