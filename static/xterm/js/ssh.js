var window_width = $(window).width();
var window_height = $(window).height();
var term = new Terminal(
    {
        cols : Math.floor(window_width/9),     //列数
        rows : Math.floor(window_height/18),   //行数
        convertEol : true,  //启用时，光标将设置为下一行的开头
        cursorBlink: true, //光标闪烁
        rendererType: "canvas",  //渲染类型
    }
          );
$(function () {
    b = "{% url 'linux_connect' newlinux.id %}"
    // document.write(b);
    a = ("ws://" + window.location.host + "{% url 'linux_connect' newlinux.id %}");
    // document.write(a)
    var sock = new WebSocket("ws://" + window.location.host + "{% url 'linux_connect' newlinux.id %}");
    // 打开webssh页面就打开web终端，并且打开websocket通道
    sock.addEventListener("open",function () {
        term.open(document.getElementById('terminal'));
        term.writeln('等待10s，出现命令行表示连接成功，没有出现则表示连接失败（检查参数跟网络）。');//这里连接失败是表示ssh连接失败.
    });
    //获取从ssh通道获取的outdata
    sock.addEventListener("message",function (recv) {
        term.write(recv.data);
        });
    //输入shelldata并发送到后台
    term.on("data",function (data) {
        sock.send(data)
        });
    window.sock=sock;
});