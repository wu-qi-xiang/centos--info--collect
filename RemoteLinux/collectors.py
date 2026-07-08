from .ssh_utils import run_command


def parse_float(value, default=None):
	try:
		return float(str(value).strip().strip('%'))
	except (TypeError, ValueError):
		return default


def ratio(value, digits=2):
	if value is None:
		return None
	return float(('%.' + str(digits) + 'f') % value)


def first_non_empty(*values):
	for value in values:
		value = (value or '').strip()
		if value:
			return value
	return ''


def first_token(value):
	value = (value or '').strip()
	return value.split()[0] if value.split() else ''


def collect_remote_detail(ssh):
	release = first_non_empty(
		run_command(ssh, ". /etc/os-release 2>/dev/null && echo \"$PRETTY_NAME\""),
		run_command(ssh, 'lsb_release -ds 2>/dev/null'),
		run_command(ssh, 'cat /etc/redhat-release 2>/dev/null'),
		run_command(ssh, 'uname -s'),
	)
	kernel = run_command(ssh, "uname -r")
	cpu = first_non_empty(
		run_command(ssh, "nproc 2>/dev/null"),
		run_command(ssh, "lscpu | awk -F: '/^CPU\\(s\\)/ {gsub(/ /,\"\",$2); print $2; exit}'"),
	)
	total_mem = run_command(ssh, "free -h | awk '/^Mem:/ {print $2}'")
	used_mem = run_command(ssh, "free -h | awk '/^Mem:/ {print $3}'")
	free_mem = run_command(ssh, "free -h | awk '/^Mem:/ {print $4}'")
	available_mem = run_command(ssh, "free -h | awk '/^Mem:/ {print $7}'")
	intranet_ip = first_token(first_non_empty(
		run_command(ssh, "hostname -I 2>/dev/null | awk '{print $1}'"),
		run_command(ssh, "ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i==\"src\") {print $(i+1); exit}}'"),
		run_command(ssh, "ip -o -4 addr show scope global 2>/dev/null | awk '{split($4,a,\"/\"); print a[1]; exit}'"),
	))
	total_disk = run_command(ssh, "df -hP / | awk 'NR==2 {print $2}'")
	used_disk = run_command(ssh, "df -hP / | awk 'NR==2 {print $3}'")
	available_disk = run_command(ssh, "df -hP / | awk 'NR==2 {print $4}'")
	return {
		'release': release,
		'kernel': kernel,
		'cpu': cpu,
		'total_mem': total_mem,
		'used_mem': used_mem,
		'free_mem': free_mem,
		'available_mem': available_mem,
		'intranet_ip': intranet_ip,
		'total_disk': total_disk,
		'used_disk': used_disk,
		'available_disk': available_disk,
	}


def collect_remote_usage(ssh):
	cpu_idle = parse_float(run_command(ssh, "vmstat 1 2 | awk 'NR==4 {print $15}'"))
	if cpu_idle is None:
		cpu_idle = parse_float(run_command(ssh, "vmstat | awk 'NR==3 {print $15}'"))
	cpu = ratio(1.0 - (cpu_idle / 100.0)) if cpu_idle is not None else None

	mem_total = parse_float(run_command(ssh, "free -m | awk '/^Mem:/ {print $2}'"))
	mem_available = parse_float(run_command(ssh, "free -m | awk '/^Mem:/ {print $7}'"))
	memory = None
	if mem_total and mem_available is not None:
		memory = ratio((mem_total - mem_available) / mem_total)

	disk_percent = parse_float(run_command(ssh, "df -P / | awk 'NR==2 {print $5}'"))
	disk = ratio(disk_percent / 100.0) if disk_percent is not None else None

	return {
		'cpu': cpu,
		'memory': memory,
		'disk': disk,
	}
