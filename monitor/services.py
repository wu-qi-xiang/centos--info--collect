import json
import hashlib
import math
import os
import re
import signal
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime

from django.utils import timezone
from django.utils.dateparse import parse_datetime
from django.db.models import Q

from devops.models import AlertEvent
from RemoteLinux.models import NewLinux
from .models import AlertmanagerConfig, AlertNotificationConfig

try:
    from urllib import error as urlerror
    from urllib import parse as urlparse
    from urllib import request as urlrequest
except ImportError:
    import urllib.error as urlerror
    import urllib.parse as urlparse
    import urllib.request as urlrequest

try:
    import certifi
except ImportError:
    certifi = None

try:
    import requests
except ImportError:
    requests = None


PROMETHEUS_TIMEOUT_SECONDS = 5
PROMETHEUS_TABLE_MAX_ROWS = 500
ALERTMANAGER_TIMEOUT_SECONDS = 5
ALERTMANAGER_POLL_MAX_ALERTS = int(os.environ.get('ALERTMANAGER_POLL_MAX_ALERTS', '1'))
PROMETHEUS_INVALID_QUERY_MESSAGE = 'PromQL 查询语句无效，请检查语法后重试'
PROMETHEUS_QUERY_TIMEOUT_MESSAGE = 'Prometheus 查询超时，请简化查询后重试'
PROMETHEUS_QUERY_FORMAT_MESSAGE = 'Prometheus 返回的查询结果格式异常'
PROMETHEUS_TARGETS_FAILURE_MESSAGE = 'Prometheus Targets 查询失败'
PROMETHEUS_TARGETS_FORMAT_MESSAGE = 'Prometheus 返回的 Targets 数据格式异常'
PROMETHEUS_RULES_FAILURE_MESSAGE = 'Prometheus Rules 查询失败'
PROMETHEUS_RULES_FORMAT_MESSAGE = 'Prometheus 返回的 Rules 数据格式异常'
PROMETHEUS_METADATA_FAILURE_MESSAGE = 'Prometheus 查询提示数据获取失败'
PROMETHEUS_METADATA_FORMAT_MESSAGE = 'Prometheus 返回的查询提示数据格式异常'
PROMETHEUS_METADATA_MAX_METRICS = 1000
PROMETHEUS_METADATA_MAX_LABELS = 200
PROMETHEUS_IDENTIFIER_MAX_LENGTH = 256
PROMETHEUS_LABEL_MAX_ITEMS = 50
PROMETHEUS_LABEL_KEY_MAX_LENGTH = 128
PROMETHEUS_LABEL_VALUE_MAX_LENGTH = 256
PROMETHEUS_METADATA_TEXT_MAX_LENGTH = 500
PROMETHEUS_RULE_QUERY_MAX_LENGTH = 2000
ALERTMANAGER_ALERTS_FAILURE_MESSAGE = 'Alertmanager 告警查询失败'
ALERTMANAGER_ALERTS_FORMAT_MESSAGE = 'Alertmanager 返回的告警数据格式异常'
ALERTMANAGER_ALERTS_MAX_ROWS = 500
PROMETHEUS_DASHBOARD_MAX_ROWS = 500

# Dashboard queries are intentionally fixed.  The dashboard must never become a
# second arbitrary PromQL console, because it is loaded automatically on page open.
PROMETHEUS_DASHBOARD_QUERIES = {
    'host_cpu': '100 - (avg by (instance) (rate(node_cpu_seconds_total{mode="idle"}[5m])) * 100)',
    'host_memory': '100 * (1 - (node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes))',
    'host_disk': 'max by (instance) (100 * (1 - (node_filesystem_avail_bytes{fstype!~"tmpfs|overlay"} / node_filesystem_size_bytes{fstype!~"tmpfs|overlay"})))',
    'host_cpu_total': 'count by (instance) (node_cpu_seconds_total{mode="idle"})',
    'host_memory_total': 'node_memory_MemTotal_bytes',
    'host_memory_available': 'node_memory_MemAvailable_bytes',
    'host_disk_total': 'sum by (instance) (node_filesystem_size_bytes{fstype!~"tmpfs|overlay"})',
    'host_disk_available': 'sum by (instance) (node_filesystem_avail_bytes{fstype!~"tmpfs|overlay"})',
    'host_io_read': 'sum by (instance) (rate(node_disk_read_bytes_total[5m]))',
    'host_io_write': 'sum by (instance) (rate(node_disk_written_bytes_total[5m]))',
    'host_load_one': 'node_load1',
    'host_load_five': 'node_load5',
    'host_load_fifteen': 'node_load15',
    'pod_cpu': 'sum by (cluster, kubernetes_cluster, cluster_name, namespace, pod) (rate(container_cpu_usage_seconds_total{container!=""}[5m])) * 100',
    'pod_memory': '100 * sum by (cluster, kubernetes_cluster, cluster_name, namespace, pod) (container_memory_working_set_bytes{container!=""}) / sum by (cluster, kubernetes_cluster, cluster_name, namespace, pod) (kube_pod_container_resource_limits{resource="memory", unit="byte"})',
    'pod_status': 'max by (cluster, kubernetes_cluster, cluster_name, namespace, pod, phase) (kube_pod_status_phase{phase=~"Pending|Running|Failed|Unknown"})',
}


_SENSITIVE_LABEL_TERMS = {
    'password',
    'passwd',
    'secret',
    'token',
    'key',
    'credential',
    'credentials',
    'authorization',
    'auth',
    'webhook',
    'api_key',
    'apikey',
}
_SENSITIVE_LABEL_SUFFIXES = tuple(
    term.replace('_', '') for term in _SENSITIVE_LABEL_TERMS
)
_PROMETHEUS_LABEL_MATCHER_RE = re.compile(
    r'(?P<prefix>(?P<key>[A-Za-z_][A-Za-z0-9_]*)\s*(?:=~|!~|!=|=)\s*)'
    r'(?P<value>"(?:\\.|[^"\\])*")'
)
_SENSITIVE_VALUE_PARAMETER_RE = re.compile(
    r'(?:^|[?&#;\s])'
    r'(?:api[_-]?key|apikey|token|password|passwd|secret|credential|credentials|'
    r'authorization|auth|webhook|access[_-]?key|client[_-]?secret)\s*=',
    re.IGNORECASE,
)
_PROMETHEUS_METRIC_IDENTIFIER_RE = re.compile(r'^[A-Za-z_:][A-Za-z0-9_:]*$')
_PROMETHEUS_LABEL_IDENTIFIER_RE = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*$')


def _json_object(payload):
    if isinstance(payload, bytes):
        try:
            payload = payload.decode('utf-8')
        except UnicodeDecodeError:
            return None
    if not isinstance(payload, str):
        return None
    try:
        body = json.loads(payload)
    except (TypeError, ValueError):
        return None
    return body if isinstance(body, dict) else None


def _safe_text(value, max_length=PROMETHEUS_METADATA_TEXT_MAX_LENGTH):
    if not isinstance(value, str):
        return ''
    return value.strip()[:max_length]


def _is_sensitive_label_key(key):
    normalized = re.sub(r'([a-z0-9])([A-Z])', r'\1_\2', key.strip()).lower()
    if not normalized:
        return True
    tokens = [item for item in re.split(r'[^a-z0-9]+', normalized) if item]
    compact = ''.join(tokens)
    if normalized in _SENSITIVE_LABEL_TERMS or compact in _SENSITIVE_LABEL_TERMS:
        return True
    if any(item in _SENSITIVE_LABEL_TERMS for item in tokens):
        return True
    return any(compact.endswith(item) for item in _SENSITIVE_LABEL_SUFFIXES)


def _is_sensitive_label_value(value):
    if not isinstance(value, str):
        return False
    text = value.strip()
    if not text:
        return False
    if _SENSITIVE_VALUE_PARAMETER_RE.search(text):
        return True
    try:
        parsed = urlparse.urlparse(text)
    except ValueError:
        return False
    is_web_url = (
        parsed.scheme.lower() in ('http', 'https') and bool(parsed.netloc)
    ) or (text.startswith('//') and bool(parsed.netloc))
    if not is_web_url:
        return False
    try:
        has_userinfo = bool(parsed.username or parsed.password)
    except ValueError:
        has_userinfo = True
    return bool(has_userinfo or parsed.query or parsed.fragment)


def _safe_label_value(value):
    if isinstance(value, bool):
        text = 'true' if value else 'false'
    elif isinstance(value, int):
        text = str(value)
    elif isinstance(value, float):
        if not math.isfinite(value):
            return None
        text = str(value)
    elif isinstance(value, str):
        if _is_sensitive_label_value(value):
            return None
        text = value
    else:
        return None
    return text[:PROMETHEUS_LABEL_VALUE_MAX_LENGTH]


def _safe_prometheus_labels(labels):
    if not isinstance(labels, dict):
        return {}
    candidates = []
    for key, value in labels.items():
        if not isinstance(key, str):
            continue
        key = key.strip()
        if (
                not key
                or len(key) > PROMETHEUS_LABEL_KEY_MAX_LENGTH
                or _is_sensitive_label_key(key)):
            continue
        safe_value = _safe_label_value(value)
        if safe_value is None:
            continue
        candidates.append((key, safe_value))
    candidates.sort(key=lambda item: item[0])
    return dict(candidates[:PROMETHEUS_LABEL_MAX_ITEMS])


def _prometheus_target_name(labels):
    for key in ('name', 'pod', 'node', 'service', 'endpoint', 'instance', 'job'):
        value = labels.get(key)
        if value:
            return value
    return ''


def _safe_nonnegative_seconds(value):
    if isinstance(value, bool):
        return None
    if value is None or value == '':
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(number) or number < 0:
        return None
    return number


def _safe_prometheus_sample_timestamp(value):
    timestamp = _safe_nonnegative_seconds(value)
    if timestamp is None:
        return ''
    try:
        return datetime.utcfromtimestamp(timestamp).isoformat() + 'Z'
    except (OverflowError, OSError, ValueError):
        return ''


def _safe_rule_query(value):
    if not isinstance(value, str):
        return ''

    def redact_match(match):
        matcher_value = match.group('value')[1:-1]
        if (
                not _is_sensitive_label_key(match.group('key'))
                and not _is_sensitive_label_value(matcher_value)):
            return match.group(0)
        return '%s"<redacted>"' % match.group('prefix')

    redacted = _PROMETHEUS_LABEL_MATCHER_RE.sub(redact_match, value.strip())
    return redacted[:PROMETHEUS_RULE_QUERY_MAX_LENGTH]


def _prometheus_query_error(body=None, status_code=None):
    body = body if isinstance(body, dict) else {}
    error_type = body.get('errorType')
    if status_code in (401, 403):
        return {'ok': False, 'message': 'Prometheus 拒绝访问，请检查对接权限'}
    if error_type == 'bad_data' or status_code in (400, 422):
        return {
            'ok': False,
            'message': PROMETHEUS_INVALID_QUERY_MESSAGE,
            'error_kind': 'invalid_query',
        }
    if error_type in ('timeout', 'canceled'):
        return {'ok': False, 'message': PROMETHEUS_QUERY_TIMEOUT_MESSAGE}
    if status_code == 404:
        return {'ok': False, 'message': 'Prometheus 查询接口不可用，请检查对接地址'}
    if status_code == 429:
        return {'ok': False, 'message': 'Prometheus 查询过于频繁，请稍后重试'}
    if status_code and status_code >= 500:
        return {'ok': False, 'message': 'Prometheus 服务暂时不可用，请稍后重试'}
    return {'ok': False, 'message': 'Prometheus 查询失败'}


def _prometheus_http_error(path, error):
    try:
        payload = error.read()
    except Exception:
        payload = None
    body = _json_object(payload)
    status_code = getattr(error, 'code', None)
    if path == '/api/v1/query':
        return _prometheus_query_error(body, status_code)
    if status_code in (401, 403):
        message = 'Prometheus 拒绝访问，请检查对接权限'
    elif status_code == 404:
        message = 'Prometheus 接口不可用，请检查对接地址'
    elif status_code == 429:
        message = 'Prometheus 请求过于频繁，请稍后重试'
    elif status_code and status_code >= 500:
        message = 'Prometheus 服务暂时不可用，请稍后重试'
    else:
        message = 'Prometheus 请求失败，请检查地址和网络'
    return {'ok': False, 'message': message}


def prometheus_url(config, path, params=None):
    base = (getattr(config, 'prometheus_url', '') or '').rstrip('/')
    query = ''
    if params:
        query = '?' + urlparse.urlencode(params)
    return '%s%s%s' % (base, path, query)


def prometheus_get_json(
        config, path, params=None, timeout=PROMETHEUS_TIMEOUT_SECONDS, require_enabled=True):
    if (
            not config
            or not getattr(config, 'prometheus_url', '')
            or (require_enabled and not getattr(config, 'enabled', False))):
        return {'ok': False, 'message': 'Prometheus 未配置或未启用'}
    request = urlrequest.Request(prometheus_url(config, path, params), headers={'Accept': 'application/json'})
    try:
        response = urlrequest.urlopen(request, timeout=timeout)
        response_body = response.read()
    except urlerror.HTTPError as error:
        return _prometheus_http_error(path, error)
    except Exception:
        return {'ok': False, 'message': 'Prometheus 请求失败，请检查地址和网络'}
    body = _json_object(response_body)
    if body is None:
        return {'ok': False, 'message': 'Prometheus 返回格式异常'}
    return {'ok': True, 'body': body}


def test_prometheus_connection(config):
    result = prometheus_get_json(config, '/api/v1/status/buildinfo', require_enabled=False)
    if not result.get('ok'):
        return result
    body = result.get('body') or {}
    if body.get('status') == 'success':
        return {'ok': True, 'message': 'Prometheus 连接正常'}
    return {'ok': False, 'message': 'Prometheus 返回状态异常'}


def query_prometheus(config, query):
    result = prometheus_get_json(config, '/api/v1/query', {'query': query})
    if not isinstance(result, dict):
        return {'ok': False, 'message': 'Prometheus 查询失败'}
    if not result.get('ok'):
        safe_messages = (
            'Prometheus 未配置或未启用',
            'Prometheus 请求失败，请检查地址和网络',
            'Prometheus 返回格式异常',
            PROMETHEUS_INVALID_QUERY_MESSAGE,
            PROMETHEUS_QUERY_TIMEOUT_MESSAGE,
            'Prometheus 拒绝访问，请检查对接权限',
            'Prometheus 查询接口不可用，请检查对接地址',
            'Prometheus 查询过于频繁，请稍后重试',
            'Prometheus 服务暂时不可用，请稍后重试',
        )
        message = result.get('message')
        if message not in safe_messages:
            message = 'Prometheus 查询失败'
        failure = {'ok': False, 'message': message}
        if result.get('error_kind') == 'invalid_query' and message == PROMETHEUS_INVALID_QUERY_MESSAGE:
            failure['error_kind'] = 'invalid_query'
        return failure
    body = result.get('body')
    if not isinstance(body, dict):
        return {'ok': False, 'message': PROMETHEUS_QUERY_FORMAT_MESSAGE}
    status = body.get('status')
    if status == 'error':
        return _prometheus_query_error(body)
    if status != 'success':
        return {'ok': False, 'message': PROMETHEUS_QUERY_FORMAT_MESSAGE}
    data = body.get('data')
    if not isinstance(data, dict):
        return {'ok': False, 'message': PROMETHEUS_QUERY_FORMAT_MESSAGE}
    result_type = data.get('resultType')
    query_result = data.get('result')
    if result_type in ('vector', 'matrix'):
        valid_result = isinstance(query_result, list)
    elif result_type in ('scalar', 'string'):
        valid_result = isinstance(query_result, (list, tuple)) and len(query_result) >= 2
    else:
        valid_result = False
    if not valid_result:
        return {'ok': False, 'message': PROMETHEUS_QUERY_FORMAT_MESSAGE}
    return {'ok': True, 'body': body}


def empty_prometheus_table(result_type=''):
    return {
        'result_type': result_type,
        'label_columns': [],
        'rows': [],
        'total_rows': 0,
        'truncated': False,
    }


def normalize_prometheus_result(body):
    """Flatten an instant-query response into a deterministic table payload."""
    data = body.get('data') if isinstance(body, dict) else None
    if not isinstance(data, dict):
        return empty_prometheus_table()

    result_type = data.get('resultType') or ''
    result = data.get('result')
    rows = []
    label_columns = set()
    total_rows = 0

    def add_row(metric, sample):
        nonlocal total_rows
        labels = metric if isinstance(metric, dict) else {}
        label_columns.update(labels.keys())
        total_rows += 1
        if len(rows) >= PROMETHEUS_TABLE_MAX_ROWS:
            return
        sample = sample if isinstance(sample, (list, tuple)) else []
        rows.append({
            'labels': labels,
            'timestamp': sample[0] if len(sample) > 0 else None,
            'value': sample[1] if len(sample) > 1 else '',
        })

    if result_type == 'vector' and isinstance(result, list):
        for item in result:
            if isinstance(item, dict):
                add_row(item.get('metric'), item.get('value'))
    elif result_type == 'matrix' and isinstance(result, list):
        for item in result:
            if not isinstance(item, dict):
                continue
            values = item.get('values')
            if not isinstance(values, list):
                continue
            for sample in values:
                add_row(item.get('metric'), sample)
    elif result_type in ('scalar', 'string') and isinstance(result, (list, tuple)):
        add_row({}, result)

    columns = sorted(label_columns, key=lambda key: (key != '__name__', key))
    for row in rows:
        labels = row['labels']
        row['labels'] = {column: labels[column] for column in columns if column in labels}
    return {
        'result_type': result_type,
        'label_columns': columns,
        'rows': rows,
        'total_rows': total_rows,
        'truncated': total_rows > len(rows),
    }


def _dashboard_metric_rows(body, label_keys, optional_label_keys=()):
    """Return bounded, safe instant-vector samples keyed by the requested labels."""
    data = body.get('data') if isinstance(body, dict) else None
    result = data.get('result') if isinstance(data, dict) else None
    if not isinstance(result, list):
        return []
    rows = []
    for item in result:
        if len(rows) >= PROMETHEUS_DASHBOARD_MAX_ROWS:
            break
        if not isinstance(item, dict):
            continue
        labels = _safe_prometheus_labels(item.get('metric'))
        values = item.get('value')
        if not isinstance(values, (list, tuple)) or len(values) < 2:
            continue
        try:
            value = float(values[1])
        except (TypeError, ValueError):
            continue
        if not math.isfinite(value):
            continue
        row = {}
        for key in label_keys:
            text = _safe_text(labels.get(key), PROMETHEUS_LABEL_VALUE_MAX_LENGTH)
            if not text:
                if key in optional_label_keys:
                    continue
                break
            row[key] = text
        else:
            row['value'] = value
            if 'phase' in labels:
                row['phase'] = _safe_text(labels.get('phase'), 32)
            rows.append(row)
    return rows


def _dashboard_percent(value):
    if value is None or not math.isfinite(value):
        return None
    return round(max(0.0, min(100.0, value)), 2)


def _dashboard_capacity(total=None, remaining=None, percent=None):
    """Build a stable total/used/remaining capacity object from safe samples."""
    if total is None or not math.isfinite(total) or total < 0:
        return {'total': None, 'used': None, 'remaining': None}
    total = round(total, 2)
    if remaining is not None and math.isfinite(remaining):
        remaining = round(max(0.0, min(total, remaining)), 2)
        used = round(total - remaining, 2)
    elif percent is not None:
        used = round(total * _dashboard_percent(percent) / 100.0, 2)
        remaining = round(total - used, 2)
    else:
        used = None
        remaining = None
    return {'total': total, 'used': used, 'remaining': remaining}


def _dashboard_cluster(row, fallback):
    for key in ('cluster', 'kubernetes_cluster', 'cluster_name'):
        value = row.get(key)
        if value:
            return value
    return fallback


def query_prometheus_dashboard(config):
    """Collect a safe, bounded host and pod summary from fixed Prometheus queries."""
    samples = {}
    errors = []
    query_labels = {
        'host_cpu': ('instance',), 'host_memory': ('instance',), 'host_disk': ('instance',),
        'host_cpu_total': ('instance',), 'host_memory_total': ('instance',),
        'host_memory_available': ('instance',), 'host_disk_total': ('instance',),
        'host_disk_available': ('instance',),
        'host_io_read': ('instance',), 'host_io_write': ('instance',),
        'host_load_one': ('instance',), 'host_load_five': ('instance',),
        'host_load_fifteen': ('instance',),
        'pod_cpu': ('namespace', 'pod', 'cluster', 'kubernetes_cluster', 'cluster_name'),
        'pod_memory': ('namespace', 'pod', 'cluster', 'kubernetes_cluster', 'cluster_name'),
        'pod_status': ('namespace', 'pod', 'cluster', 'kubernetes_cluster', 'cluster_name'),
    }
    error_labels = {
        'host_cpu': '主机 CPU', 'host_memory': '主机内存', 'host_disk': '主机磁盘',
        'host_cpu_total': '主机 CPU 容量', 'host_memory_total': '主机内存总量',
        'host_memory_available': '主机内存剩余量', 'host_disk_total': '主机磁盘总量',
        'host_disk_available': '主机磁盘剩余量',
        'host_io_read': '主机磁盘读取', 'host_io_write': '主机磁盘写入',
        'host_load_one': '主机 1 分钟负载', 'host_load_five': '主机 5 分钟负载',
        'host_load_fifteen': '主机 15 分钟负载',
        'pod_cpu': 'Pod CPU', 'pod_memory': 'Pod 内存', 'pod_status': 'Pod 状态',
    }
    for key, query in PROMETHEUS_DASHBOARD_QUERIES.items():
        result = query_prometheus(config, query)
        if not isinstance(result, dict) or not result.get('ok'):
            errors.append('%s 指标暂时不可用' % error_labels[key])
            samples[key] = []
            continue
        samples[key] = _dashboard_metric_rows(
            result.get('body') or {},
            query_labels[key],
            optional_label_keys=('cluster', 'kubernetes_cluster', 'cluster_name'),
        )

    hosts = {}
    for key, metric_name in (('host_cpu', 'cpu'), ('host_memory', 'memory'), ('host_disk', 'disk'),
                             ('host_cpu_total', 'cpu_total'), ('host_memory_total', 'memory_total'),
                             ('host_memory_available', 'memory_available'), ('host_disk_total', 'disk_total'),
                             ('host_disk_available', 'disk_available'), ('host_io_read', 'io_read'),
                             ('host_io_write', 'io_write'), ('host_load_one', 'load_one'),
                             ('host_load_five', 'load_five'), ('host_load_fifteen', 'load_fifteen')):
        for row in samples[key]:
            host = hosts.setdefault(row['instance'], {'instance': row['instance']})
            host[metric_name] = _dashboard_percent(row['value']) if metric_name in ('cpu', 'memory', 'disk') else row['value']
    for host in hosts.values():
        host['capacity'] = {
            'cpu': _dashboard_capacity(host.get('cpu_total'), percent=host.get('cpu')),
            'memory': _dashboard_capacity(host.get('memory_total'), remaining=host.get('memory_available')),
            'disk': _dashboard_capacity(host.get('disk_total'), remaining=host.get('disk_available')),
        }
        host['load'] = {
            'one': host.pop('load_one', None),
            'five': host.pop('load_five', None),
            'fifteen': host.pop('load_fifteen', None),
        }
        for key in ('cpu_total', 'memory_total', 'memory_available', 'disk_total', 'disk_available'):
            host.pop(key, None)

    pods = {}
    fallback_cluster = _safe_text(getattr(config, 'name', ''), PROMETHEUS_LABEL_VALUE_MAX_LENGTH) or 'Prometheus'
    for key, metric_name in (('pod_cpu', 'cpu'), ('pod_memory', 'memory')):
        for row in samples[key]:
            cluster = _dashboard_cluster(row, fallback_cluster)
            identity = (cluster, row['namespace'], row['pod'])
            pod = pods.setdefault(identity, {
                'cluster': cluster, 'namespace': row['namespace'], 'pod': row['pod'],
            })
            pod[metric_name] = _dashboard_percent(row['value'])
    for row in samples['pod_status']:
        if row['value'] != 1:
            continue
        cluster = _dashboard_cluster(row, fallback_cluster)
        identity = (cluster, row['namespace'], row['pod'])
        pod = pods.setdefault(identity, {
            'cluster': cluster, 'namespace': row['namespace'], 'pod': row['pod'],
        })
        pod['status'] = row.get('phase') or 'Unknown'

    host_rows = [hosts[name] for name in sorted(hosts)[:PROMETHEUS_DASHBOARD_MAX_ROWS]]
    pod_rows = [pods[key] for key in sorted(pods)[:PROMETHEUS_DASHBOARD_MAX_ROWS]]
    return {'ok': True, 'hosts': host_rows, 'pods': pod_rows, 'errors': errors}


def _query_prometheus_collection(
        config, path, params, data_key, failure_message, format_message):
    result = prometheus_get_json(config, path, params)
    if not isinstance(result, dict) or not result.get('ok'):
        return {'ok': False, 'message': failure_message}
    body = result.get('body')
    if not isinstance(body, dict):
        return {'ok': False, 'message': format_message}
    if body.get('status') == 'error':
        return {'ok': False, 'message': failure_message}
    if body.get('status') != 'success':
        return {'ok': False, 'message': format_message}
    data = body.get('data')
    if not isinstance(data, dict) or not isinstance(data.get(data_key), list):
        return {'ok': False, 'message': format_message}
    return {'ok': True, 'body': body}


def query_prometheus_targets(config):
    result = _query_prometheus_collection(
        config,
        '/api/v1/targets',
        {'state': 'active'},
        'activeTargets',
        PROMETHEUS_TARGETS_FAILURE_MESSAGE,
        PROMETHEUS_TARGETS_FORMAT_MESSAGE,
    )
    if not result.get('ok'):
        return result
    body = result.get('body') or {}
    data = body.get('data') if isinstance(body, dict) else None
    if data.get('activeTargets'):
        return result

    fallback = query_prometheus(config, 'up')
    if not fallback.get('ok'):
        return {'ok': False, 'message': PROMETHEUS_TARGETS_FAILURE_MESSAGE}
    fallback_body = _prometheus_up_targets_body(fallback.get('body'))
    if fallback_body is None:
        return {'ok': False, 'message': PROMETHEUS_TARGETS_FORMAT_MESSAGE}
    return {'ok': True, 'body': fallback_body}


def _prometheus_up_targets_body(body):
    data = body.get('data') if isinstance(body, dict) else None
    if not isinstance(data, dict) or data.get('resultType') != 'vector':
        return None
    query_rows = data.get('result')
    if not isinstance(query_rows, list):
        return None

    targets = []
    for item in query_rows:
        if not isinstance(item, dict):
            continue
        labels = _safe_prometheus_labels(item.get('metric'))
        sample = item.get('value')
        sample = sample if isinstance(sample, (list, tuple)) else []
        last_scrape = _safe_prometheus_sample_timestamp(
            sample[0] if sample else None
        )
        value = _safe_nonnegative_seconds(sample[1] if len(sample) > 1 else None)
        if value == 1:
            health = 'up'
        elif value is None:
            health = 'unknown'
        else:
            health = 'down'
        targets.append({
            'labels': labels,
            'scrapePool': labels.get('job', ''),
            'health': health,
            'lastScrape': last_scrape,
        })
    return {
        'status': 'success',
        'data': {'activeTargets': targets},
    }


def query_prometheus_rules(config):
    return _query_prometheus_collection(
        config,
        '/api/v1/rules',
        None,
        'groups',
        PROMETHEUS_RULES_FAILURE_MESSAGE,
        PROMETHEUS_RULES_FORMAT_MESSAGE,
    )


def _normalize_prometheus_identifiers(values, pattern, limit, filter_sensitive=False):
    if not isinstance(values, list):
        return None
    identifiers = set()
    for value in values:
        if not isinstance(value, str):
            continue
        if value != value.strip():
            continue
        if (
                not value
                or len(value) > PROMETHEUS_IDENTIFIER_MAX_LENGTH
                or not pattern.match(value)
                or (filter_sensitive and _is_sensitive_label_key(value))):
            continue
        identifiers.add(value)
    return sorted(identifiers)[:limit]


def _query_prometheus_identifier_values(config, path, pattern, limit, filter_sensitive=False):
    result = prometheus_get_json(config, path)
    if not isinstance(result, dict) or not result.get('ok'):
        return {'ok': False, 'message': PROMETHEUS_METADATA_FAILURE_MESSAGE}
    body = result.get('body')
    if not isinstance(body, dict):
        return {'ok': False, 'message': PROMETHEUS_METADATA_FORMAT_MESSAGE}
    if body.get('status') == 'error':
        return {'ok': False, 'message': PROMETHEUS_METADATA_FAILURE_MESSAGE}
    if body.get('status') != 'success':
        return {'ok': False, 'message': PROMETHEUS_METADATA_FORMAT_MESSAGE}
    identifiers = _normalize_prometheus_identifiers(
        body.get('data'), pattern, limit, filter_sensitive=filter_sensitive,
    )
    if identifiers is None:
        return {'ok': False, 'message': PROMETHEUS_METADATA_FORMAT_MESSAGE}
    return {'ok': True, 'values': identifiers}


def query_prometheus_metadata(config):
    metrics_result = _query_prometheus_identifier_values(
        config,
        '/api/v1/label/__name__/values',
        _PROMETHEUS_METRIC_IDENTIFIER_RE,
        PROMETHEUS_METADATA_MAX_METRICS,
    )
    if not metrics_result.get('ok'):
        return metrics_result
    labels_result = _query_prometheus_identifier_values(
        config,
        '/api/v1/labels',
        _PROMETHEUS_LABEL_IDENTIFIER_RE,
        PROMETHEUS_METADATA_MAX_LABELS,
        filter_sensitive=True,
    )
    if not labels_result.get('ok'):
        return labels_result
    return {
        'ok': True,
        'metrics': metrics_result['values'],
        'labels': labels_result['values'],
    }


def empty_prometheus_targets():
    return {
        'rows': [],
        'summary': {
            'total': 0,
            'up': 0,
            'down': 0,
            'unknown': 0,
            'with_errors': 0,
        },
        'total_rows': 0,
        'truncated': False,
    }


def normalize_prometheus_targets(body):
    data = body.get('data') if isinstance(body, dict) else None
    targets = data.get('activeTargets') if isinstance(data, dict) else None
    if not isinstance(targets, list):
        return empty_prometheus_targets()

    payload = empty_prometheus_targets()
    rows = payload['rows']
    summary = payload['summary']
    for target in targets:
        if not isinstance(target, dict):
            continue
        labels = _safe_prometheus_labels(target.get('labels'))
        health = _safe_text(target.get('health'), 32).lower()
        if health not in ('up', 'down'):
            health = 'unknown'
        has_error = bool(target.get('lastError'))
        summary['total'] += 1
        summary[health] += 1
        if has_error:
            summary['with_errors'] += 1
        if len(rows) >= PROMETHEUS_TABLE_MAX_ROWS:
            continue
        rows.append({
            'name': _prometheus_target_name(labels),
            'instance': labels.get('instance', ''),
            'job': labels.get('job', ''),
            'scrape_pool': _safe_text(target.get('scrapePool')),
            'health': health,
            'last_scrape': _safe_text(target.get('lastScrape')),
            'last_scrape_duration': _safe_nonnegative_seconds(target.get('lastScrapeDuration')),
            'labels': labels,
            'has_error': has_error,
        })
    payload['total_rows'] = summary['total']
    payload['truncated'] = summary['total'] > len(rows)
    return payload


def empty_prometheus_rules():
    return {
        'rows': [],
        'summary': {
            'total': 0,
            'alerting': 0,
            'recording': 0,
            'unhealthy': 0,
            'firing': 0,
            'pending': 0,
        },
        'total_rows': 0,
        'truncated': False,
    }


def normalize_prometheus_rules(body):
    data = body.get('data') if isinstance(body, dict) else None
    groups = data.get('groups') if isinstance(data, dict) else None
    if not isinstance(groups, list):
        return empty_prometheus_rules()

    payload = empty_prometheus_rules()
    rows = payload['rows']
    summary = payload['summary']
    for group in groups:
        if not isinstance(group, dict) or not isinstance(group.get('rules'), list):
            continue
        group_name = _safe_text(group.get('name'))
        group_last_evaluation = group.get('lastEvaluation')
        group_evaluation_time = group.get('evaluationTime')
        for rule in group.get('rules'):
            if not isinstance(rule, dict):
                continue
            rule_type = _safe_text(rule.get('type'), 32).lower()
            if rule_type not in ('alerting', 'recording'):
                rule_type = 'unknown'
            health = _safe_text(rule.get('health'), 32).lower()
            if health not in ('ok', 'err'):
                health = 'unknown'
            state = _safe_text(rule.get('state'), 32).lower()
            if state not in ('firing', 'pending', 'inactive'):
                state = ''
            last_evaluation = rule.get('lastEvaluation')
            if last_evaluation is None:
                last_evaluation = group_last_evaluation
            evaluation_time = rule.get('evaluationTime')
            if evaluation_time is None:
                evaluation_time = group_evaluation_time
            alerts = rule.get('alerts')
            active_alerts = len(alerts) if isinstance(alerts, list) else 0
            has_error = bool(rule.get('lastError'))

            summary['total'] += 1
            if rule_type in ('alerting', 'recording'):
                summary[rule_type] += 1
            if health != 'ok':
                summary['unhealthy'] += 1
            if state in ('firing', 'pending'):
                summary[state] += 1
            if len(rows) >= PROMETHEUS_TABLE_MAX_ROWS:
                continue
            rows.append({
                'group': group_name,
                'name': _safe_text(rule.get('name')),
                'type': rule_type,
                'health': health,
                'state': state,
                'query': _safe_rule_query(rule.get('query')),
                'duration': _safe_nonnegative_seconds(rule.get('duration')),
                'labels': _safe_prometheus_labels(rule.get('labels')),
                'last_evaluation': _safe_text(last_evaluation),
                'evaluation_time': _safe_nonnegative_seconds(evaluation_time),
                'active_alerts': active_alerts,
                'has_error': has_error,
            })
    payload['total_rows'] = summary['total']
    payload['truncated'] = summary['total'] > len(rows)
    return payload


def alertmanager_url(config, path, params=None):
    base = (getattr(config, 'alertmanager_url', '') or '').rstrip('/')
    query = ''
    if params:
        query = '?' + urlparse.urlencode(params)
    return '%s%s%s' % (base, path, query)


def _run_curl(args, input_data=None, timeout=ALERTMANAGER_TIMEOUT_SECONDS):
    if 'test' in sys.argv or not shutil.which('curl'):
        return None
    process = None
    output_file = None
    try:
        output_file = tempfile.TemporaryFile()
        process = subprocess.Popen(
            args,
            stdin=subprocess.PIPE if input_data is not None else None,
            stdout=output_file,
            stderr=subprocess.DEVNULL,
        )
        if input_data is not None:
            process.stdin.write(input_data)
            process.stdin.close()
        deadline = time.monotonic() + max(float(timeout), 1.0)
        while process.poll() is None and time.monotonic() < deadline:
            time.sleep(0.1)
        if process.poll() is None:
            process.kill()
            return {'ok': False, 'message': 'timeout'}
        output_file.seek(0)
        output = output_file.read()
        return {'ok': True, 'returncode': process.returncode, 'output': output}
    except Exception:
        if process is not None and process.poll() is None:
            process.kill()
        return None
    finally:
        if output_file is not None:
            output_file.close()


def _get_json_with_curl(url, timeout):
    result = _run_curl(
        [
            'curl',
            '-sS',
            '--connect-timeout',
            str(min(int(timeout), 3)),
            '--max-time',
            str(max(int(timeout), 1)),
            '-H',
            'Accept: application/json',
            url,
        ],
        timeout=timeout,
    )
    if result is None:
        return None
    if not result.get('ok'):
        return {'ok': False, 'message': 'Alertmanager 请求超时，请检查地址和网络'}
    if result.get('returncode') != 0:
        return {'ok': False, 'message': 'Alertmanager 请求失败，请检查地址和网络'}
    body = _json_object(result.get('output'))
    if body is None:
        try:
            body = json.loads((result.get('output') or b'').decode('utf-8'))
        except (TypeError, ValueError):
            body = None
    if not isinstance(body, (dict, list)):
        return {'ok': False, 'message': 'Alertmanager 返回格式异常'}
    return {'ok': True, 'body': body}


def alertmanager_get_json(
        config, path, params=None, timeout=ALERTMANAGER_TIMEOUT_SECONDS, require_enabled=True):
    if (
            not config
            or not getattr(config, 'alertmanager_url', '')
            or (require_enabled and not getattr(config, 'enabled', False))):
        return {'ok': False, 'message': 'Alertmanager 未配置或未启用'}
    url = alertmanager_url(config, path, params)
    curl_result = _get_json_with_curl(url, timeout)
    if isinstance(curl_result, dict):
        return curl_result
    request = urlrequest.Request(url, headers={'Accept': 'application/json'})
    try:
        response = urlrequest.urlopen(request, timeout=timeout)
        response_body = response.read().decode('utf-8')
    except Exception:
        return {'ok': False, 'message': 'Alertmanager 请求失败，请检查地址和网络'}
    try:
        body = json.loads(response_body)
    except (TypeError, ValueError):
        return {'ok': False, 'message': 'Alertmanager 返回格式异常'}
    if not isinstance(body, (dict, list)):
        return {'ok': False, 'message': 'Alertmanager 返回格式异常'}
    return {'ok': True, 'body': body}


def test_alertmanager_connection(config):
    result = alertmanager_get_json(config, '/api/v2/status', require_enabled=False)
    if not result.get('ok'):
        return result
    if isinstance(result.get('body'), dict):
        return {'ok': True, 'message': 'Alertmanager 连接正常'}
    return {'ok': False, 'message': 'Alertmanager 返回格式异常'}


def query_alertmanager_alerts(config):
    result = alertmanager_get_json(config, '/api/v2/alerts')
    if not isinstance(result, dict) or not result.get('ok'):
        return {'ok': False, 'message': ALERTMANAGER_ALERTS_FAILURE_MESSAGE}
    if not isinstance(result.get('body'), list):
        return {'ok': False, 'message': ALERTMANAGER_ALERTS_FORMAT_MESSAGE}
    return {'ok': True, 'body': result.get('body')}


def _safe_alertmanager_timestamp(value):
    if not isinstance(value, str):
        return ''
    parsed = parse_datetime(value.strip())
    if not parsed:
        return ''
    try:
        return parsed.isoformat()
    except (TypeError, ValueError):
        return ''


def normalize_alertmanager_alerts(alerts):
    if not isinstance(alerts, list):
        return {'rows': [], 'summary': {'total': 0, 'firing': 0, 'resolved': 0, 'other': 0}, 'total_rows': 0, 'truncated': False}
    rows = []
    summary = {'total': 0, 'firing': 0, 'resolved': 0, 'other': 0}
    for alert in alerts:
        if not isinstance(alert, dict):
            continue
        summary['total'] += 1
        status = _alertmanager_status({}, alert)
        if status not in ('firing', 'resolved'):
            status = 'unknown'
        summary[status if status in ('firing', 'resolved') else 'other'] += 1
        if len(rows) >= ALERTMANAGER_ALERTS_MAX_ROWS:
            continue
        labels = _safe_prometheus_labels(alert.get('labels'))
        annotations = _safe_prometheus_labels(alert.get('annotations'))
        name = _safe_text(labels.get('alertname') or annotations.get('summary') or 'Alertmanager 告警', 240)
        rows.append({
            'name': name,
            'status': status,
            'starts_at': _safe_alertmanager_timestamp(alert.get('startsAt')),
            'updated_at': _safe_alertmanager_timestamp(alert.get('updatedAt')),
            'ends_at': _safe_alertmanager_timestamp(alert.get('endsAt')),
            'labels': labels,
            'annotations': annotations,
        })
    return {
        'rows': rows,
        'summary': summary,
        'total_rows': summary['total'],
        'truncated': summary['total'] > len(rows),
    }


def _alertmanager_status(payload, alert):
    status = ''
    if isinstance(alert, dict):
        raw_status = alert.get('status')
        if isinstance(raw_status, dict):
            status = (raw_status.get('state') or '').strip().lower()
        elif isinstance(raw_status, str):
            status = raw_status.strip().lower()
    if not status and isinstance(payload, dict):
        raw_status = payload.get('status')
        if isinstance(raw_status, dict):
            status = (raw_status.get('state') or '').strip().lower()
        elif isinstance(raw_status, str):
            status = raw_status.strip().lower()
    if status == 'active':
        return 'firing'
    return status


def _alertmanager_alert_text(alert, key):
    value = alert.get(key) if isinstance(alert, dict) else ''
    return value if isinstance(value, str) else ''


def _alertmanager_normalized_alert(payload, alert):
    labels = alert.get('labels') if isinstance(alert, dict) and isinstance(alert.get('labels'), dict) else {}
    annotations = alert.get('annotations') if isinstance(alert, dict) and isinstance(alert.get('annotations'), dict) else {}
    alert_name = labels.get('alertname') or annotations.get('summary') or 'Alertmanager 告警'
    instance = labels.get('instance') or labels.get('pod') or labels.get('node') or labels.get('job') or ''
    message = annotations.get('description') or annotations.get('summary') or alert_name
    return {
        'status': _alertmanager_status(payload, alert),
        'metric': alert_name,
        'message': message,
        'host_name': instance,
        'instance': instance,
        'startsAt': _alertmanager_alert_text(alert, 'startsAt'),
        'timestamp': _alertmanager_alert_text(alert, 'startsAt') or _alertmanager_alert_text(alert, 'updatedAt'),
        'fingerprint': _alertmanager_alert_text(alert, 'fingerprint'),
        'labels': labels,
        'annotations': annotations,
    }


def _alertmanager_alerts_from_payload(payload):
    if isinstance(payload, list):
        alerts = payload
    elif isinstance(payload, dict):
        alerts = payload.get('alerts')
        if not isinstance(alerts, list):
            alerts = [payload]
    else:
        alerts = []
    return [
        _alertmanager_normalized_alert(payload, alert)
        for alert in alerts
        if isinstance(alert, dict)
    ]


def _alertmanager_fingerprint(alertmanager, alert):
    raw = alert.get('fingerprint')
    if not raw:
        payload = {
            'labels': alert.get('labels') or {},
            'startsAt': alert.get('startsAt') or '',
            'metric': alert.get('metric') or '',
        }
        raw = hashlib.sha256(json.dumps(payload, sort_keys=True).encode('utf-8')).hexdigest()
    return 'alertmanager:%s:%s' % (alertmanager.id, raw[:80])


def _alertmanager_notification_content(alertmanager, config, alert):
    title = '告警通知：%s' % (
        config.alert_name or alert.get('metric') or config.name or 'Alertmanager 告警'
    )
    content_lines = [
        ('告警名称', config.alert_name or alert.get('metric')),
        ('通知渠道', config.name or '企业微信'),
        ('Alertmanager', alertmanager.name),
        ('主机', alert.get('host_name') or alert.get('instance')),
        ('状态', 'firing'),
        ('时间', alert.get('timestamp')),
        ('内容', alert.get('message')),
    ]
    content = '\n'.join('%s：%s' % (label, value) for label, value in content_lines if value)
    return title, content


def _alertmanager_alert_sort_key(alert):
    for key in ('timestamp', 'startsAt'):
        value = alert.get(key)
        if not value:
            continue
        parsed = parse_datetime(value)
        if parsed:
            return parsed
    return timezone.datetime.min.replace(tzinfo=timezone.utc)


def _alertmanager_matching_host(alert):
    """Find a managed host for an Alertmanager instance label, when unambiguous."""
    instance = _safe_text(alert.get('instance'), 100)
    if not instance:
        return None
    candidates = [instance]
    # node_exporter commonly reports an IPv4/DNS instance as host:port.
    if instance.count(':') == 1:
        hostname, port = instance.rsplit(':', 1)
        if hostname and port.isdigit():
            candidates.append(hostname)
    return NewLinux.objects.filter(
        Q(linux_name__in=candidates)
        | Q(linux_hostname__in=candidates)
        | Q(linux_ip__in=candidates)
    ).order_by('id').first()


def _alertmanager_is_silenced_for_maintenance(host, now=None):
    """Keep external alert delivery available when the maintenance lookup fails."""
    if host is None:
        return False
    try:
        from devops.services import active_maintenance_windows_for_host
        return active_maintenance_windows_for_host(host, now=now).exists()
    except Exception:
        return False


def _silence_alertmanager_event(event, now=None):
    if event.status == AlertEvent.STATUS_SILENCED:
        return event
    from devops.services import update_alert_status
    return update_alert_status(
        event,
        AlertEvent.STATUS_SILENCED,
        handler='system',
        remark='命中维护窗口',
    )


def push_alertmanager_firing_alerts(alertmanager, payload, dedupe=False):
    alerts = _alertmanager_alerts_from_payload(payload)
    firing_alerts = [alert for alert in alerts if alert.get('status') == 'firing']
    pushable_alerts = sorted(firing_alerts, key=_alertmanager_alert_sort_key, reverse=True)
    if dedupe and ALERTMANAGER_POLL_MAX_ALERTS > 0:
        pushable_alerts = pushable_alerts[:ALERTMANAGER_POLL_MAX_ALERTS]
    configs = AlertNotificationConfig.objects.filter(
        alertmanager=alertmanager,
        provider=AlertNotificationConfig.PROVIDER_WECOM,
        enabled=True,
        webhook_url__gt='',
    )
    config_count = configs.count()
    if config_count == 0:
        return {
            'received': len(alerts),
            'firing': len(firing_alerts),
            'attempted': 0,
            'matched_notifications': 0,
            'pushed': 0,
            'skipped': 0,
            'silenced': 0,
            'results': [],
        }
    results = []
    skipped = 0
    silenced = 0
    now = timezone.now()
    active_statuses = [
        AlertEvent.STATUS_OPEN,
        AlertEvent.STATUS_PROCESSING,
        AlertEvent.STATUS_SILENCED,
    ]
    for alert in pushable_alerts:
        event = None
        fingerprint = ''
        host = _alertmanager_matching_host(alert)
        maintenance_silenced = _alertmanager_is_silenced_for_maintenance(host, now=now)
        if dedupe:
            fingerprint = _alertmanager_fingerprint(alertmanager, alert)
            event = AlertEvent.objects.filter(
                fingerprint=fingerprint,
                status__in=active_statuses,
            ).first()
            if event:
                event.repeat_count += 1
                event.last_seen_at = now
                event.message = alert.get('message') or event.message
                if maintenance_silenced:
                    _silence_alertmanager_event(event, now=now)
                    silenced += 1
                event.save(update_fields=['repeat_count', 'last_seen_at', 'message', 'updated_at'])
                skipped += 1
                continue
        if maintenance_silenced:
            if dedupe:
                AlertEvent.objects.create(
                    host=host,
                    level=AlertEvent.LEVEL_WARNING,
                    metric=alert.get('metric') or 'alertmanager',
                    message=alert.get('message') or 'Alertmanager firing 告警',
                    status=AlertEvent.STATUS_SILENCED,
                    fingerprint=fingerprint,
                    first_seen_at=now,
                    last_seen_at=now,
                    remark='命中维护窗口',
                )
            silenced += 1
            continue
        alert_result_start = len(results)
        for config in configs:
            title, content = _alertmanager_notification_content(alertmanager, config, alert)
            result = send_alert_notification(config, title, content)
            result_item = {
                'notification_id': config.id,
                'ok': bool(result.get('ok')),
                'message': result.get('message') or '',
            }
            if event:
                result_item['alert_event_id'] = event.id
            results.append(result_item)
        if dedupe and any(item.get('ok') for item in results[alert_result_start:]):
            event = AlertEvent.objects.create(
                host=host,
                level=AlertEvent.LEVEL_WARNING,
                metric=alert.get('metric') or 'alertmanager',
                message=alert.get('message') or 'Alertmanager firing 告警',
                status=AlertEvent.STATUS_OPEN,
                fingerprint=fingerprint,
                first_seen_at=now,
                last_seen_at=now,
                remark='Alertmanager：%s' % alertmanager.name,
            )
            for item in results[alert_result_start:]:
                item['alert_event_id'] = event.id
    return {
        'received': len(alerts),
        'firing': len(firing_alerts),
        'attempted': len(pushable_alerts),
        'matched_notifications': config_count,
        'pushed': len(results),
        'skipped': skipped,
        'silenced': silenced,
        'results': results,
    }


def poll_alertmanager_firing_alerts():
    summary = {'alertmanagers': 0, 'received': 0, 'firing': 0, 'attempted': 0, 'pushed': 0, 'skipped': 0, 'errors': []}
    configs = AlertmanagerConfig.objects.filter(enabled=True, alertmanager_url__gt='').order_by('id')
    for config in configs:
        summary['alertmanagers'] += 1
        result = alertmanager_get_json(config, '/api/v2/alerts')
        if not result.get('ok'):
            summary['errors'].append({'alertmanager_id': config.id, 'message': result.get('message') or 'Alertmanager 查询失败'})
            continue
        push_result = push_alertmanager_firing_alerts(config, result.get('body'), dedupe=True)
        summary['received'] += push_result.get('received', 0)
        summary['firing'] += push_result.get('firing', 0)
        summary['attempted'] += push_result.get('attempted', 0)
        summary['pushed'] += push_result.get('pushed', 0)
        summary['skipped'] += push_result.get('skipped', 0)
    return summary


def alert_notification_payload(provider, title, content):
    text = '%s\n%s' % (title, content)
    if provider == 'feishu':
        return {'msg_type': 'text', 'content': {'text': text}}
    return {'msgtype': 'text', 'text': {'content': text}}


def _alert_notification_ssl_context(url):
    if urlparse.urlsplit(url).scheme.lower() != 'https':
        return None
    if certifi is not None:
        return ssl.create_default_context(cafile=certifi.where())
    return ssl.create_default_context()


def _alert_notification_alarm_handler(signum, frame):
    raise socket.timeout()


def _enable_alert_notification_alarm(timeout):
    if (
            not hasattr(signal, 'SIGALRM')
            or threading.current_thread() is not threading.main_thread()):
        return None
    previous_handler = signal.getsignal(signal.SIGALRM)
    signal.signal(signal.SIGALRM, _alert_notification_alarm_handler)
    signal.setitimer(signal.ITIMER_REAL, max(float(timeout), 1.0))
    return previous_handler


def _disable_alert_notification_alarm(previous_handler):
    if previous_handler is None:
        return
    signal.setitimer(signal.ITIMER_REAL, 0)
    signal.signal(signal.SIGALRM, previous_handler)


def _alert_notification_provider_label(provider):
    if provider == 'feishu':
        return '飞书'
    if provider == 'wecom':
        return '企业微信'
    return provider or '告警通知'


def _alert_notification_response_result(provider, status_code, response_text, success_message):
    if status_code and status_code >= 400:
        return {'ok': False, 'message': '通知发送失败，请检查通知配置和网络'}
    body = _json_object(response_text)
    if body:
        code = None
        if provider == 'wecom' and 'errcode' in body:
            code = body.get('errcode')
        elif provider == 'feishu':
            if 'StatusCode' in body:
                code = body.get('StatusCode')
            elif 'code' in body:
                code = body.get('code')
        if code is not None:
            try:
                code_ok = int(code) == 0
            except (TypeError, ValueError):
                code_ok = False
            if not code_ok:
                return {'ok': False, 'message': '通知平台返回失败，请检查通知配置'}
    return {'ok': True, 'message': success_message}


def _send_alert_notification_with_curl(url, data, timeout):
    result = _run_curl(
        [
            'curl',
            '-sS',
            '--connect-timeout',
            str(min(int(timeout), 3)),
            '--max-time',
            str(max(int(timeout), 1)),
            '-H',
            'Content-Type: application/json',
            '-X',
            'POST',
            '--data-binary',
            '@-',
            '-w',
            '\n%{http_code}',
            url,
        ],
        input_data=data,
        timeout=timeout,
    )
    if result is None:
        return None
    if not result.get('ok'):
        return {'ok': False, 'message': 'timeout'}
    output = result.get('output').decode('utf-8', 'replace')
    response_text, _, status_text = output.rpartition('\n')
    try:
        status_code = int(status_text.strip())
    except (TypeError, ValueError):
        status_code = 0
    if result.get('returncode') != 0 and not response_text:
        return {'ok': False, 'message': 'timeout' if result.get('returncode') == 28 else 'failed'}
    return {'ok': True, 'status_code': status_code, 'response_text': response_text[:300]}


def _send_alert_notification_with_requests(url, data, timeout):
    if 'test' in sys.argv or requests is None:
        return None
    try:
        response = requests.post(
            url,
            data=data,
            headers={'Content-Type': 'application/json'},
            timeout=(min(float(timeout), 3.0), float(timeout)),
        )
        return {
            'ok': True,
            'status_code': response.status_code,
            'response_text': (response.text or '')[:300],
        }
    except requests.exceptions.Timeout:
        return {'ok': False, 'message': 'timeout'}
    except requests.exceptions.RequestException:
        return {'ok': False, 'message': 'failed'}


def send_alert_notification(config, title='告警通知测试', content='这是一条告警通知测试消息。', timeout=PROMETHEUS_TIMEOUT_SECONDS):
    url = getattr(config, 'decrypted_webhook_url', '') or ''
    if not url:
        return {'ok': False, 'message': 'Webhook 地址为空或解密失败'}
    is_test_message = title == '告警通知测试' and content == '这是一条告警通知测试消息。'
    payload = alert_notification_payload(config.provider, title, content)
    data = json.dumps(payload, ensure_ascii=False).encode('utf-8')
    curl_result = _send_alert_notification_with_curl(url, data, timeout)
    if isinstance(curl_result, dict):
        if not curl_result.get('ok'):
            message = '测试通知发送超时，请检查 Webhook 地址和网络' if is_test_message else '通知发送超时，请检查通知配置和网络'
            return {'ok': False, 'message': message}
        success_message = '测试通知发送成功' if is_test_message else '告警通知发送成功'
        return _alert_notification_response_result(
            config.provider,
            curl_result.get('status_code'),
            curl_result.get('response_text') or '',
            success_message,
        )
    requests_result = _send_alert_notification_with_requests(url, data, timeout)
    if isinstance(requests_result, dict):
        if not requests_result.get('ok'):
            message = '测试通知发送超时，请检查 Webhook 地址和网络' if requests_result.get('message') == 'timeout' and is_test_message else ''
            if not message:
                message = '测试通知发送失败，请检查 Webhook 地址和网络' if is_test_message else '通知发送失败，请检查通知配置和网络'
            if requests_result.get('message') == 'timeout' and not is_test_message:
                message = '通知发送超时，请检查通知配置和网络'
            return {'ok': False, 'message': message}
        success_message = '测试通知发送成功' if is_test_message else '告警通知发送成功'
        return _alert_notification_response_result(
            config.provider,
            requests_result.get('status_code'),
            requests_result.get('response_text') or '',
            success_message,
        )
    request = urlrequest.Request(
        url,
        data=data,
        headers={'Content-Type': 'application/json'},
        method='POST',
    )
    old_timeout = socket.getdefaulttimeout()
    old_alarm_handler = None
    response = None
    try:
        socket.setdefaulttimeout(timeout)
        old_alarm_handler = _enable_alert_notification_alarm(timeout)
        context = _alert_notification_ssl_context(url)
        if context is not None:
            response = urlrequest.urlopen(request, timeout=timeout, context=context)
        else:
            response = urlrequest.urlopen(request, timeout=timeout)
        response_text = response.read().decode('utf-8')[:300]
        status_code = getattr(response, 'status', None) or getattr(response, 'code', 0)
        success_message = '测试通知发送成功' if is_test_message else '告警通知发送成功'
        return _alert_notification_response_result(
            config.provider,
            status_code,
            response_text,
            success_message,
        )
    except ssl.SSLError:
        return {'ok': False, 'message': 'HTTPS 证书校验失败，请检查运行环境 CA 证书配置'}
    except urlerror.URLError as error:
        reason = getattr(error, 'reason', None)
        if isinstance(reason, ssl.SSLError):
            return {'ok': False, 'message': 'HTTPS 证书校验失败，请检查运行环境 CA 证书配置'}
        message = '测试通知发送失败，请检查 Webhook 地址和网络' if is_test_message else '通知发送失败，请检查通知配置和网络'
        return {'ok': False, 'message': message}
    except socket.timeout:
        message = '测试通知发送超时，请检查 Webhook 地址和网络' if is_test_message else '通知发送超时，请检查通知配置和网络'
        return {'ok': False, 'message': message}
    except Exception:
        message = '测试通知发送失败，请检查 Webhook 地址和网络' if is_test_message else '通知发送失败，请检查通知配置和网络'
        return {'ok': False, 'message': message}
    finally:
        _disable_alert_notification_alarm(old_alarm_handler)
        socket.setdefaulttimeout(old_timeout)
        if response is not None and hasattr(response, 'close'):
            response.close()


def _alert_value(alert, key):
    if isinstance(alert, dict):
        return alert.get(key)
    return getattr(alert, key, None)


def _alert_host_name(alert):
    host = _alert_value(alert, 'host')
    if isinstance(host, dict):
        return host.get('linux_name') or host.get('name') or host.get('host') or host.get('hostname')
    if host:
        return getattr(host, 'linux_name', None) or getattr(host, 'name', None) or str(host)
    return (
        _alert_value(alert, 'host_name')
        or _alert_value(alert, 'hostname')
        or _alert_value(alert, 'instance')
    )


def _alert_timestamp(alert):
    for key in ('timestamp', 'last_seen_at', 'updated_at', 'created_at', 'first_seen_at'):
        value = _alert_value(alert, key)
        if value:
            if hasattr(value, 'strftime'):
                return value.strftime('%Y-%m-%d %H:%M:%S')
            return value
    return ''


def _alert_display_value(alert):
    for key in ('value', 'current_value', 'usage', 'metric_value'):
        value = _alert_value(alert, key)
        if value is not None and value != '':
            return value
    return ''


def _alert_threshold(alert):
    for key in ('threshold', 'limit', 'threshold_value'):
        value = _alert_value(alert, key)
        if value is not None and value != '':
            return value
    return ''


def _format_alert_notification_message(config, alert, status):
    provider_label = _alert_notification_provider_label(getattr(config, 'provider', ''))
    alert_name = (
        getattr(config, 'alert_name', '')
        or getattr(config, 'name', '')
        or provider_label
    )
    status = status or _alert_value(alert, 'status') or '-'
    fields = [
        ('告警名称', alert_name),
        ('通知渠道', getattr(config, 'name', '') or provider_label),
        ('主机', _alert_host_name(alert)),
        ('指标', _alert_value(alert, 'metric')),
        ('状态', status),
        ('时间', _alert_timestamp(alert)),
        ('当前值', _alert_display_value(alert)),
        ('阈值', _alert_threshold(alert)),
    ]
    lines = ['%s：%s' % (label, value) for label, value in fields if value not in (None, '')]
    message = None
    if status == 'resolved':
        message = _alert_value(alert, 'remark')
    message = message or _alert_value(alert, 'message') or _alert_value(alert, 'content') or _alert_value(alert, 'description')
    if message:
        lines.append('内容：%s' % message)
    title = '告警通知：%s' % alert_name
    return title, '\n'.join(lines)


def send_alert_event_notifications(alert, status=None, timeout=PROMETHEUS_TIMEOUT_SECONDS):
    from .models import AlertNotificationConfig

    configs = AlertNotificationConfig.objects.filter(
        enabled=True,
        webhook_url__gt='',
        provider__in=[
            AlertNotificationConfig.PROVIDER_FEISHU,
            AlertNotificationConfig.PROVIDER_WECOM,
        ],
    )
    results = []
    for config in configs:
        channel = getattr(config, 'name', '') or _alert_notification_provider_label(config.provider)
        try:
            if not (getattr(config, 'decrypted_webhook_url', '') or ''):
                result = {'ok': False, 'message': 'Webhook 地址为空或解密失败'}
            else:
                title, content = _format_alert_notification_message(config, alert, status)
                result = send_alert_notification(config, title, content, timeout=timeout)
        except Exception:
            result = {'ok': False, 'message': '通知发送失败，请检查通知配置和网络'}
        results.append({
            'provider': config.provider,
            'channel': channel,
            'ok': bool(result.get('ok')),
            'message': result.get('message') or '',
        })
    success_count = len([item for item in results if item.get('ok')])
    failed_count = len(results) - success_count
    return {
        'ok': failed_count == 0,
        'total': len(results),
        'success': success_count,
        'failed': failed_count,
        'results': results,
    }
