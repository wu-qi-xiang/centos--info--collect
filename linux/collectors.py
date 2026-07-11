import os
import re
import shutil
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
	lower_value = value.lower()
	if not value or any(marker.lower() in lower_value for marker in error_markers):
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


def metric_available(value):
	value = (value or '').strip()
	return bool(value and value != '未获取' and value != '0')


def parse_kb_value(line):
	match = re.search(r'(\d+)', line or '')
	if not match:
		return None
	return int(match.group(1)) * 1024


def bytes_value(value):
	return str(int(value)) if value is not None else '0'


def parse_meminfo(text):
	values = {}
	for line in (text or '').splitlines():
		if ':' not in line:
			continue
		key, value = line.split(':', 1)
		parsed = parse_kb_value(value)
		if parsed is not None:
			values[key] = parsed
	total = values.get('MemTotal')
	if not total:
		return None
	free = values.get('MemFree')
	available = values.get('MemAvailable')
	if available is None:
		available = (
			(free or 0) +
			values.get('Buffers', 0) +
			values.get('Cached', 0) +
			values.get('SReclaimable', 0) -
			values.get('Shmem', 0)
		)
	used = max(total - available, 0)
	return {
		'total_mem': bytes_value(total),
		'used_mem': bytes_value(used),
		'free_mem': bytes_value(free),
		'available_mem': bytes_value(available),
	}


def parse_vm_stat(text, page_size):
	if not page_size:
		match = re.search(r'page size of (\d+) bytes', text or '')
		if match:
			page_size = int(match.group(1))
	if not page_size:
		return {}
	values = {}
	for line in (text or '').splitlines():
		match = re.match(r'([^:]+):\s+(\d+)\.?', line.strip())
		if match:
			values[match.group(1)] = int(match.group(2)) * page_size
	free = values.get('Pages free')
	available = (
		values.get('Pages free', 0) +
		values.get('Pages inactive', 0) +
		values.get('Pages speculative', 0)
	)
	total = sum(values.get(key, 0) for key in (
		'Pages free',
		'Pages active',
		'Pages inactive',
		'Pages speculative',
		'Pages wired down',
		'Pages compressed',
	))
	return {'total': total or None, 'free': free, 'available': available or free}


def parse_df_k_output(text):
	lines = [line for line in (text or '').splitlines() if line.strip()]
	if len(lines) < 2:
		return None
	parts = lines[1].split()
	if len(parts) < 4:
		return None
	try:
		total = int(parts[1]) * 1024
		used = int(parts[2]) * 1024
		available = int(parts[3]) * 1024
	except ValueError:
		return None
	return {
		'total_disk': bytes_value(total),
		'used_disk': bytes_value(used),
		'available_disk': bytes_value(available),
	}


def local_disk_path():
	if os.path.exists('/System/Volumes/Data'):
		return '/System/Volumes/Data'
	return '/'


def first_ipv4(text):
	for address in re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text or ''):
		if not address.startswith('127.'):
			return address
	return ''


def collect_memory_detail():
	memory = {
		'total_mem': run_local_command("free -h | awk '/^Mem:/ {print $2}'", '0'),
		'used_mem': run_local_command("free -h | awk '/^Mem:/ {print $3}'", '0'),
		'free_mem': run_local_command("free -h | awk '/^Mem:/ {print $4}'", '0'),
		'available_mem': run_local_command("free -h | awk '/^Mem:/ {print $7}'", '0'),
	}
	if metric_available(memory.get('total_mem')):
		return memory

	meminfo = parse_meminfo(run_local_command('cat /proc/meminfo 2>/dev/null', ''))
	if meminfo:
		return meminfo

	try:
		total = int(run_local_command('sysctl -n hw.memsize 2>/dev/null', '0'))
	except ValueError:
		total = 0
	try:
		page_size = int(run_local_command('sysctl -n hw.pagesize 2>/dev/null', '0'))
	except ValueError:
		page_size = 0
	vm_values = parse_vm_stat(run_local_command('vm_stat 2>/dev/null', ''), page_size)
	total = total or vm_values.get('total') or 0
	if total:
		available = vm_values.get('available')
		free = vm_values.get('free')
		used = max(total - (available or 0), 0) if available is not None else 0
		return {
			'total_mem': bytes_value(total),
			'used_mem': bytes_value(used),
			'free_mem': bytes_value(free),
			'available_mem': bytes_value(available),
		}

	try:
		page_size = os.sysconf('SC_PAGE_SIZE')
		total_pages = os.sysconf('SC_PHYS_PAGES')
		available_pages = os.sysconf('SC_AVPHYS_PAGES')
	except (AttributeError, OSError, ValueError):
		return memory
	total = page_size * total_pages
	available = page_size * available_pages
	return {
		'total_mem': bytes_value(total),
		'used_mem': bytes_value(max(total - available, 0)),
		'free_mem': bytes_value(available),
		'available_mem': bytes_value(available),
	}


def collect_disk_detail(path=None):
	path = path or local_disk_path()
	disk = {
		'total_disk': run_local_command("df -hP %s | awk 'NR==2 {print $2}'" % path, '0'),
		'used_disk': run_local_command("df -hP %s | awk 'NR==2 {print $3}'" % path, '0'),
		'available_disk': run_local_command("df -hP %s | awk 'NR==2 {print $4}'" % path, '0'),
	}
	if metric_available(disk.get('total_disk')) and not disk.get('total_disk', '').strip().isdigit():
		return disk

	df_k = parse_df_k_output(run_local_command('df -kP %s 2>/dev/null' % path, ''))
	if df_k:
		return df_k

	try:
		usage = shutil.disk_usage(path)
	except OSError:
		return disk
	return {
		'total_disk': bytes_value(usage.total),
		'used_disk': bytes_value(usage.used),
		'available_disk': bytes_value(usage.free),
	}


def fetch_public_ip(timeout=3):
	if os.environ.get('DISABLE_PUBLIC_IP_LOOKUP', '').lower() in ('1', 'true', 'yes', 'on'):
		return []
	for url in (
		'https://api.ipify.org',
		'https://ifconfig.me/ip',
		'https://icanhazip.com',
	):
		try:
			response = urllib.request.urlopen(url, timeout=timeout)
			text = response.read().decode('utf-8')
		except Exception:
			text = run_local_command("curl -4 -s --max-time %s %s" % (timeout, url), '')
		addresses = re.findall(r'\d+\.\d+\.\d+\.\d+', text)
		if addresses:
			return addresses
	return []


def collect_local_detail(public_ip_lookup=None):
	public_ip_lookup = fetch_public_ip if public_ip_lookup is None else public_ip_lookup
	release = first_non_empty(
		run_local_command(". /etc/os-release 2>/dev/null && echo \"$PRETTY_NAME\""),
		run_local_command('cat /etc/redhat-release 2>/dev/null'),
		run_local_command('sw_vers -productVersion 2>/dev/null'),
		run_local_command('uname -s'),
	)
	intranet_ip = first_token(first_non_empty(
		run_local_command("hostname -I 2>/dev/null | awk '{print $1}'"),
		run_local_command("ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i==\"src\") {print $(i+1); exit}}'"),
		run_local_command("ip -o -4 addr show scope global 2>/dev/null | awk '{split($4,a,\"/\"); print a[1]; exit}'"),
		first_ipv4(run_local_command("ifconfig 2>/dev/null | awk '/inet / && $2 != \"127.0.0.1\" {print $2; exit}'", '')),
		first_ipv4(run_local_command("route -n get default 2>/dev/null | awk '/interface:/ {print $2; exit}' | xargs -I{} ifconfig {} 2>/dev/null", '')),
	))
	memory = collect_memory_detail()
	disk = collect_disk_detail()
	detail = {
		'cpu': first_non_empty(
			run_local_command('nproc 2>/dev/null', ''),
			run_local_command("lscpu | awk -F: '/^CPU\\(s\\)/ {gsub(/ /,\"\",$2); print $2; exit}'", ''),
			run_local_command('getconf _NPROCESSORS_ONLN 2>/dev/null', ''),
			run_local_command('sysctl -n hw.ncpu 2>/dev/null', ''),
		) or '0',
		'release': release or '未获取',
		'kernel': run_local_command('uname -r'),
		'outside_ip': public_ip_lookup(),
		'intranet_ip': intranet_ip or '未获取',
	}
	detail.update(memory)
	detail.update(disk)
	return detail
