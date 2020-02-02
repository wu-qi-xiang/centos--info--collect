import paramiko
import subprocess

from django.shortcuts import render, redirect
from django.http import HttpResponse
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
            print(request.POST.get('linux_ip'))
            print(request.POST.get('linux_name'))
            linux_form.save()
            return redirect("linux")
        else:
        # try:
            send_mail('你好', '你好2020', '774727549@qq.com', ['1306833742@qq.com'], fail_silently=False,)
        # except Exception as e:
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
            linux.save()
            return redirect("linux_detail")
        else:
            return HttpResponse("输入错误，请重新输入")
    else:
        # 将数据回填到界面
        content = {'linux': linux, }
        return render(request, 'linux/update.html', content)


def linux_delete(request, id):
    # 根据 id 获取需要删除的文章
    linux = NewLinux.objects.get(id=id)
    # 调用.delete()方法删除文章
    linux.delete()
    return redirect('linux_detail')


def linux_detail(request):
    # 根据form的id去取值
    newlinux = NewLinux.objects.all()
    content = {'newlinux': newlinux, }
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
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(hostname=REMOTE_HOST, port=REMOTE_PORT, username=REMOTE_USER, password=REMOTE_PWD, compress=True)
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
        pass
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
                return HttpResponse("测试连接失败，请检查账号or密码orIPor端口")
            else:
                # return HttpResponse('{"status": "success"},{"message":"测试连接成功"}')
                return HttpResponse("测试连接成功")
            finally:
                ssh.close()
        else:
            return HttpResponse("输入有误，重新输入")
    else:
        return HttpResponse("请求非post")

