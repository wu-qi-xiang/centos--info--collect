import os
import re
import subprocess
import urllib.request


def clean_metric(value, fallback='未获取'):
	value = (value or '').strip()
	error_markers = (
		'command not found',
		'No such file or directory',
		'not found',
		'Operation not permitted',
	)
	if not value or any(marker in value for marker in error_markers):
		return fallback
	return value


def run_local_command(command, fallback='未获取'):
	return clean_metric(subprocess.getoutput(command), fallback)


def first_non_empty(*values):
	for value in values:
		value = (value or '').strip()
		if value and value != '未获取':
			return value
	return ''


def first_token(value):
	value = (value or '').strip()
	return value.split()[0] if value.split() else ''


def fetch_public_ip(timeout=2):
	if os.environ.get('ENABLE_PUBLIC_IP_LOOKUP', '').lower() not in ('1', 'true', 'yes', 'on'):
		return []
	try:
		response = urllib.request.urlopen('https://api.ipify.org', timeout=timeout)
		text = response.read().decode('utf-8')
	except Exception:
		return []
	return re.findall(r'\d+\.\d+\.\d+\.\d+', text)


def collect_local_detail(public_ip_lookup=None):
	public_ip_lookup = fetch_public_ip if public_ip_lookup is None else public_ip_lookup
	release = first_non_empty(
		run_local_command(". /etc/os-release 2>/dev/null && echo \"$PRETTY_NAME\""),
		run_local_command('cat /etc/redhat-release 2>/dev/null'),
		run_local_command('uname -s'),
	)
	intranet_ip = first_token(first_non_empty(
		run_local_command("hostname -I 2>/dev/null | awk '{print $1}'"),
		run_local_command("ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i==\"src\") {print $(i+1); exit}}'"),
		run_local_command("ip -o -4 addr show scope global 2>/dev/null | awk '{split($4,a,\"/\"); print a[1]; exit}'"),
	))
	return {
		'cpu': first_non_empty(
			run_local_command('nproc 2>/dev/null', '0'),
			run_local_command("lscpu | awk -F: '/^CPU\\(s\\)/ {gsub(/ /,\"\",$2); print $2; exit}'", '0'),
		) or '0',
		'total_mem': run_local_command("free -h | awk '/^Mem:/ {print $2}'", '0'),
		'used_mem': run_local_command("free -h | awk '/^Mem:/ {print $3}'", '0'),
		'free_mem': run_local_command("free -h | awk '/^Mem:/ {print $4}'", '0'),
		'available_mem': run_local_command("free -h | awk '/^Mem:/ {print $7}'", '0'),
		'release': release or '未获取',
		'kernel': run_local_command('uname -r'),
		'outside_ip': public_ip_lookup(),
		'intranet_ip': intranet_ip or '未获取',
		'total_disk': run_local_command("df -hP / | awk 'NR==2 {print $2}'", '0'),
		'used_disk': run_local_command("df -hP / | awk 'NR==2 {print $3}'", '0'),
		'available_disk': run_local_command("df -hP / | awk 'NR==2 {print $4}'", '0'),
	}
