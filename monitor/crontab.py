import time

from PyLinux.settings import EMAIL_HOST_USER
from .models import Monitor
from devops.models import AlertEvent
from devops.services import cleanup_metric_samples, record_alert, record_metric_sample, resolve_alert
from RemoteLinux.models import NewLinux
from RemoteLinux.collectors import collect_remote_usage
from RemoteLinux.ssh_utils import create_host_ssh_client, describe_ssh_error
from django.core.mail import send_mail    # 导入django发送邮件模块


def parse_percent(value, default=None):
    if value in (None, ''):
        return default
    try:
        number = float(str(value).strip().strip('%'))
    except (TypeError, ValueError):
        return default
    if number > 1:
        number = number / 100.0
    if number < 0 or number > 1:
        return default
    return number


def create_alert(host, metric, message, level=AlertEvent.LEVEL_WARNING):
    return record_alert(host, metric, message, level)


def send_threshold_alert(host, metric, value, threshold, monitor_email, subject):
    if value is None:
        print("%s 未获取到 %s 使用率" % (host.linux_name, metric))
        return
    record_metric_sample(host, metric, value)
    if value < threshold:
        resolve_alert(host, metric, '%s 使用率恢复正常：%s' % (metric, value))
        print("%s %s 显示正常" % (host.linux_name, metric))
        return
    localtime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    metric_names = {
        'cpu': 'CPU',
        'memory': '内存',
        'disk': '磁盘',
    }
    metric_label = metric_names.get(metric, metric)
    message = "告警时间：%s \n主机%s的%s使用率高达%s,已经超过设定的告警阈值，请重点关注" % (
        localtime,
        host.linux_name,
        metric_label,
        value,
    )
    alert, created = create_alert(host, metric, message)
    if EMAIL_HOST_USER and monitor_email and alert.status != AlertEvent.STATUS_SILENCED and created:
        send_mail(subject, message, EMAIL_HOST_USER, [monitor_email], fail_silently=False, )


def record_collection_failure(host, exc):
    message = "主机%s监控采集失败：%s" % (host.linux_name or host.linux_ip, describe_ssh_error(exc))
    return record_alert(host, 'collector', message, AlertEvent.LEVEL_CRITICAL)


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

    # 获取告警设定值，当前系统只使用第一条配置。
    monitor = Monitor.objects.first()
    if not monitor:
        print("未配置告警阈值，跳过本次监控")
        return

    monitor_email = monitor.monitor_email
    monitor_cpu = parse_percent(monitor.monitor_cpu)
    monitor_mem = parse_percent(monitor.monitor_men)
    monitor_disk = parse_percent(monitor.monitor_disk)
    if monitor_cpu is None or monitor_mem is None or monitor_disk is None:
        print("告警阈值格式错误，跳过本次监控")
        return

    # 获取远端主机的IP，账号，密码
    linux_info = NewLinux.objects.all()
    for linux in linux_info:
        ssh = None
        try:
            # 账号密码登录选项，避免服务器拒绝连接
            ssh = create_host_ssh_client(linux)
            usage = collect_remote_usage(ssh)
            resolve_alert(linux, 'collector', '监控采集恢复正常')
            subject = "LINUX服务器告警信息"
            send_threshold_alert(linux, 'cpu', usage.get('cpu'), monitor_cpu, monitor_email, subject)
            send_threshold_alert(linux, 'memory', usage.get('memory'), monitor_mem, monitor_email, subject)
            send_threshold_alert(linux, 'disk', usage.get('disk'), monitor_disk, monitor_email, subject)
        except Exception as e:
            record_collection_failure(linux, e)
            print("远程连接或采集失败：%s，主机：%s" % (describe_ssh_error(e), linux.linux_name))
        finally:
            if ssh:
                ssh.close()
    cleanup_metric_samples()
