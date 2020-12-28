#coding-utf-8
import paramiko
import subprocess
# 增加webssh功能
from dwebsocket.decorators import accept_websocket
from threading import Thread


from django.shortcuts import render, redirect
from django.http import HttpResponse
from django.core.paginator import Paginator, PageNotAnInteger, EmptyPage, InvalidPage
from .forms import LinuxPostForm
from .models import NewLinux
from django.core.mail import send_mail    # 导入django发送邮件模块

# Create your views here.


def linux_create(request):
    # 判断用户是否提交数据
    # 必须先实例化表单
    linux = NewLinux.objects.all()
    if request.method == "POST":
        # 将提交的数据赋值到表单实例中
        linux_form = LinuxPostForm(request.POST)
        # 判断提交的数据是否满足模型的要求
        if linux_form.is_valid():
            linux_form.save()
            return redirect("linux_detail")
        else:
            return HttpResponse("输入有误，请重新输入")
    else:
        form = NewLinux()
        # header.html跳转到url.py，然后跳转到view.py。
        content = {'linux': linux, 'form': form}
        return render(request, "linux/create.html", content)


def linux_update(request, id):
    # 获取需要修改的具体文章对象
    linux = NewLinux.objects.get(id=id)
    if request.method == "POST":
        # 将提交的数据赋值到表单实例中
        linux_info = LinuxPostForm(request.POST)
        if linux_info.is_valid():
            # 将更改的数据保存到数据库
            linux.linux_name = request.POST["linux_name"]
            linux.linux_ip = request.POST["linux_ip"]
            linux.linux_hostname = request.POST["linux_hostname"]
            linux.linux_port = request.POST["linux_port"]
            linux.linux_user = request.POST["linux_user"]
            linux.linux_passwd = request.POST["linux_passwd"]
            linux.linux_app = request.POST["linux_app"]
            linux.save()
            return redirect("linux_detail")
        else:
            return HttpResponse("输入错误，请重新输入")
    else:
        # 将数据回填到界面
        content = {'linux': linux, }
        return render(request, 'linux/update.html', content)


def linux_copy(request):
    if request.method == "POST":
        linux_form = LinuxPostForm(request.POST)
        if linux_form.is_valid():
            linux_form.save()
            return HttpResponse("复制成功")
        else:
            return HttpResponse("输入有误，请重新输入")



def linux_delete(request, id):
    # 根据 id 获取需要删除的文章
    linux = NewLinux.objects.get(id=id)
    # 调用.delete()方法删除文章
    linux.delete()
    return redirect('linux_detail')


def linux_list_app(request, id):
    linux = NewLinux.objects.get(id=id)
    content = {'linux': linux}
    return render(request, 'linux/linux_app.html', content)


def linux_detail(request):
    # 根据form的id去取值
    newlinux = NewLinux.objects.all()
    paginator = Paginator(newlinux, 8)
    if request.method == "GET":
        # 获取 url 后面的 page 参数的值, 首页不显示 page 参数, 默认值是 1
        page = request.GET.get('page')
        try:
            pages = paginator.page(page)
        # todo: 注意捕获异常
        except PageNotAnInteger:
            # 如果请求的页数不是整数, 返回第一页。
            pages = paginator.page(1)
        except InvalidPage:
            # 如果请求的页数不存在, 重定向页面
            return HttpResponse('找不到页面的内容')
        except EmptyPage:
            # 如果请求的页数不在合法的页数范围内，返回结果的最后一页。
            pages = paginator.page(paginator.num_pages)
    pagenum = (pages.number - 1) * 8
    # 增加主机总数
    sum = NewLinux.objects.all().count()
    content = {'newlinux': newlinux, "pages": pages, "pagenum": pagenum,"sum": sum}
    return render(request, 'linux/detail.html', content)


def linux_list_detail(request, id):
    # 取出对应id的linux信息
    newlinux = NewLinux.objects.get(id=id)
    REMOTE_HOST = newlinux.linux_ip
    REMOTE_PORT = newlinux.linux_port
    REMOTE_USER = newlinux.linux_user
    REMOTE_PWD = newlinux.linux_passwd
    ssh = paramiko.SSHClient()
    ssh.load_system_host_keys()
    try:
        # 账号密码登录选项，避免服务器拒绝连接
        # 当远程服务器没有本地主机的密钥时自动添加到本地，这样不用在建立连接的时候输入yes或no进行确认
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(hostname=REMOTE_HOST, port=REMOTE_PORT, username=REMOTE_USER, password=REMOTE_PWD, compress=True, timeout=8)
        # 系统版本
        re_cmd = 'cat /etc/redhat-release'
        ke_cmd = "uname -a |awk '{print $3}'"
        # 远端执行shell
        stdin, stdout, stderr = ssh.exec_command(re_cmd)
        # decode()去掉多余的双引号和\n
        release = stdout.read().decode()
        # 远端执行shell
        stdin, stdout, stderr = ssh.exec_command(ke_cmd)
        # decode()去掉多余的双引号和\n
        kernel = stdout.read().decode()

        # 系统cpu
        cmd_cpu = "lscpu |grep '^CPU(s)' |awk '{print $2}'"
        # 远端执行shell
        stdin, stdout, stderr = ssh.exec_command(cmd_cpu)
        # decode()去掉多余的双引号和\n
        cpu = stdout.read().decode()

        # 系统内存
        total_cmd = "free -h |grep Mem |awk '{print $2}'"
        used_cmd = "free -h |grep Mem |awk '{print $3}'"
        free_cmd = "free -h |grep Mem |awk '{print $4}'"
        available_cmd = "free -h |grep Mem |awk '{print $7}'"
        # 远端执行shell
        stdin, stdout, stderr = ssh.exec_command(total_cmd)
        # decode()去掉多余的双引号和\n
        total_mem = stdout.read().decode()
        # 远端执行shell
        stdin, stdout, stderr = ssh.exec_command(used_cmd)
        # decode()去掉多余的双引号和\n
        used_mem = stdout.read().decode()
        # 远端执行shell
        stdin, stdout, stderr = ssh.exec_command(free_cmd)
        # decode()去掉多余的双引号和\n
        free_mem = stdout.read().decode()
        # 远端执行shell
        stdin, stdout, stderr = ssh.exec_command(available_cmd)
        # decode()去掉多余的双引号和\n
        available_mem = stdout.read().decode()

        # 系统IP
        intranet_cmd = "ip addr |grep eth0 |awk -F '/' 'NR == 2 {print $1}'|awk '{print $2}'"
        # 远端执行shell
        stdin, stdout, stderr = ssh.exec_command(intranet_cmd)
        # decode()去掉多余的双引号和\n
        intranet_ip = stdout.read().decode()

        # 系统磁盘
        total_cmd = "df -h |awk 'NR==2{print $2}'"
        used_cmd = "df -h |awk 'NR==2{print $3}'"
        available_cmd = "df -h |awk 'NR==2{print $4}'"
        # 远端执行shell
        stdin, stdout, stderr = ssh.exec_command(total_cmd)
        # decode()去掉多余的双引号和\n
        total_disk = stdout.read().decode()
        # 远端执行shell
        stdin, stdout, stderr = ssh.exec_command(used_cmd)
        # decode()去掉多余的双引号和\n
        used_disk = stdout.read().decode()
        # 远端执行shell
        stdin, stdout, stderr = ssh.exec_command(available_cmd)
        # decode()去掉多余的双引号和\n
        available_disk = stdout.read().decode()
    except Exception as e:
        return HttpResponse("ssh连接有问题，请检查")
    finally:
        ssh.close()
    content = {'newlinux': newlinux,
               'total_mem': total_mem,
               'used_mem': used_mem,
               'free_mem': free_mem,
               'available_mem': available_mem,
               'cpu': cpu,
               'release': release,
               'kernel': kernel,
               'intranet_ip': intranet_ip,
               'total_disk': total_disk,
               'used_disk': used_disk,
               'available_disk': available_disk
               }
    return render(request, 'linux/list_detail.html', content)


def connect_test(request):
    if request.method == "POST":
        linux_form = LinuxPostForm(request.POST)
        if linux_form.is_valid():
            ip = request.POST.get('linux_ip')
            port = request.POST.get('linux_port')
            user = request.POST.get('linux_user')
            passwd = request.POST.get('linux_passwd')
            ssh = paramiko.SSHClient()
            ssh.load_system_host_keys()
            try:
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(hostname=ip, port=port, username=user, password=passwd, compress=True)
            except Exception as e:
                # return HttpResponse('{"status": "fail"}, {"message": "测试连接失败，请检查账号or密码orIPor端口"}')
                return HttpResponse("测试连接失败，请检查账号,密码,IP,端口")
            else:
                # return HttpResponse('{"status": "success"},{"message":"测试连接成功"}')
                return HttpResponse("测试连接成功")
            finally:
                ssh.close()
        else:
            return HttpResponse("输入有误，重新输入")
    else:
        return HttpResponse("请求非post")


@accept_websocket  # 用于websocket连接的修饰器
def linux_connect(request, id):
    print(id)
    newlinux = NewLinux.objects.get(id=id)
    if request.is_websocket():  # 判断websocket连接
        # 打开ssh通道，建立长连接
        # 如果是websocket连接就创建ssh连接，使用paramiko模块创建
        Host = newlinux.linux_ip
        Prot = newlinux.linux_port
        User = newlinux.linux_user
        Pwd = newlinux.linux_passwd
        client = paramiko.SSHClient()   # 创建连接对象
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy)  # 设置自动添加主机名及主机密钥到本地HostKeys对象，不依赖load_system_host_key的配置。即新建立ssh连接时不需要再输入yes或no进行确认
        try:   # 用异常抛出判定主机是否成功连接ssh
            client.connect(hostname=Host, port=Prot, username=User, password=Pwd)  # connect为连接函数
            mess = f'主机{Prot}连接成功！'
        except:
            mess = f'主机{Prot}连接失败！'

        sshsession = client.get_transport().open_session()  # 成功连接后获取ssh通道
        sshsession.get_pty()  # 获取一个终端
        sshsession.invoke_shell()  # 激活终端
        for i in range(2):   # 激活终端后会有信息流，一般都是lastlogin与bath目录，并获取其数据
            messa = sshsession.recv(1024)
            request.websocket.send(messa)
    else:
        return render(request, 'linux/connect.html', {'newlinux': newlinux})

    # 从ssh通道获取输出data，并发送到前端
    def srecv():
        while True:
            sshmess = sshsession.recv(2048)
            if not len(sshmess):
                # print('退出监听发送循环')
                return
            request.websocket.send(sshmess)
            # print('ssh回复的信息：' + sshmess.decode('utf-8'))

    # 获取前端的shelldata并且发送到服务器执行
    for shell in request.websocket:
        deshell = shell.decode('utf-8')
        # print('deshell:'+deshell)
        # stdin,stdout,stderr = client.exec_command(deshell)
        # request.websocket.send(stdout.read())
        # request.websocket.send(stderr.read())
        sshsession.send(deshell)
        # while True:
        #     sshmess = sshsession.recv(2048)
        #     request.websocket.send(sshmess)
        #     print('ssh回复的信息：'+sshmess.decode('utf-8'))
        sshrecvthre = Thread(target=srecv, args=()).start()   # 启用线程监听ssh通道获取输出data，并发送到前端