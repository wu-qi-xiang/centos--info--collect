import paramiko
import time

from PyLinux.settings import EMAIL_HOST_USER
from .models import Monitor
from RemoteLinux.models import NewLinux
from django.http import HttpResponse
from django.core.mail import send_mail    # 导入django发送邮件模块


def monitor_send_email():
    # 测试
    # localtime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    # linux_info = NewLinux.objects.all()
    # for linux in linux_info:
    #     monitor_data = Monitor.objects.all()
    #     for monitor in monitor_data:
    #         monitor_email = monitor.monitor_email
    #         subject = "服务器告警信息"
    #         message = "告警时间：%s ,主机%s,请重点关注"%(localtime, linux.linux_name)
    #         print("%s, %s, %s"%(localtime, linux.linux_name, monitor_email))
    #         # send_mail(subject, message, EMAIL_HOST_USER, [monitor_email], fail_silently=False,)

    # 获取告警设定值
    monitor_data = Monitor.objects.all()
    for monitor in monitor_data:
        monitor_email = monitor.monitor_email
        monitor_cpu = float(monitor.monitor_cpu.strip('%'))/100.0
        monitor_mem = float(monitor.monitor_men.strip('%'))/100.0
        monitor_disk = float(monitor.monitor_disk.strip('%'))/100.0

    # 获取远端主机的IP，账号，密码
    linux_info = NewLinux.objects.all()
    for linux in linux_info:
        REMOTE_HOST = linux.linux_ip
        REMOTE_PORT = linux.linux_port
        REMOTE_USER = linux.linux_user
        REMOTE_PWD = linux.linux_passwd
        ssh = paramiko.SSHClient()
        ssh.load_system_host_keys()
        try:
            # 账号密码登录选项，避免服务器拒绝连接
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(hostname=REMOTE_HOST, port=REMOTE_PORT, username=REMOTE_USER, password=REMOTE_PWD, compress=True)
            cpu_cmd = "vmstat |awk 'NR==3{print $15}'"
            mem_cmd_use = "free |grep Mem|awk '{print $7}'"
            mem_cmd_total = "free |grep Mem|awk '{print $2}'"
            disk_cmd = "df |grep '^/dev'|awk '{print $5}'"
            # 执行远端shell命令，获取服务器信息
            stdin, stdout, stderr = ssh.exec_command(cpu_cmd)
            # decode().strip("\n") 编码，去掉换行符，不然强制转换有问题
            remote_cpu_1 = float(stdout.read().decode().strip("\n"))
            remote_cpu_2 = remote_cpu_1/100
            remote_cpu_3 = 1.0 - remote_cpu_2
            remote_cpu = float('%.2f' % remote_cpu_3)

            stdin, stdout, stderr = ssh.exec_command(mem_cmd_use)
            remote_mem_use_1 = float(stdout.read().decode().strip("\n"))
            remote_mem_use = float('%.2f' % remote_mem_use_1)

            stdin, stdout, stderr = ssh.exec_command(mem_cmd_total)
            remote_mem_total_1 = float(stdout.read().decode().strip("\n"))
            remote_mem_total = float('%.2f' % remote_mem_total_1)

            stdin, stdout, stderr = ssh.exec_command(disk_cmd)
            remote_disk_all_1 = float(stdout.read().decode().strip("%\n"))
            remote_disk_all = float('%.2f' % remote_disk_all_1)

            remote_disk_1 = remote_disk_all / 100.0
            remote_disk = float('%.2f' % remote_disk_1)
            # 获取内存的百分百值
            remote_mem_1 = remote_mem_use / remote_mem_total
            remote_mem = float('%.2f' % remote_mem_1)

            # 比较告警值，判断是否发送邮件
            subject = "LINUX服务器告警信息"
            if remote_cpu >= monitor_cpu:
                localtime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
                message = "告警时间：%s \n主机%s的CPU使用率高达%s,已经超过设定的告警阈值，请重点关注"%(localtime, linux.linux_name, remote_cpu)
                send_mail(subject, message, EMAIL_HOST_USER, [monitor_email], fail_silently=False, )
            else:
                print("CPU显示正常")

            if remote_mem >= monitor_mem:
                localtime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
                message = "告警时间：%s \n主机%s的内存使用率高达%s,已经超过设定的告警阈值，请重点关注"%(localtime, linux.linux_name, remote_mem)
                send_mail(subject, message, EMAIL_HOST_USER, [monitor_email], fail_silently=False, )
            else:
                print("MEM显示正常")

            if remote_disk >= monitor_disk:
                localtime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
                message = "告警时间：%s \n主机%s的CPU使用率高达%s,已经超过设定的告警阈值，请重点关注"%(localtime, linux.linux_name, remote_disk)
                send_mail(subject, message, EMAIL_HOST_USER, [monitor_email], fail_silently=False, )
            else:
                print("disk显示正常")
        except Exception as e:
            print("远程连接失败，请先测试连接")
        finally:
            ssh.close()



