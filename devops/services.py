import base64
from decimal import Decimal, InvalidOperation
import hashlib
import hmac
import json
import os
import re
import subprocess
import tempfile
import time
import posixpath
import shlex
from threading import Thread
try:
    from urllib import parse as urlparse
except ImportError:
    import urllib.parse as urlparse
try:
    from urllib import request as urlrequest
except ImportError:
    import urllib.request as urlrequest

from django.conf import settings
from django.core.cache import cache
from django.db import models
from django.utils import timezone
try:
    import requests
except ImportError:
    class _UrlLibResponse(object):
        def __init__(self, response):
            self.status_code = response.getcode()
            self.text = response.read().decode('utf-8', errors='ignore')

    class _UrlLibRequests(object):
        @staticmethod
        def post(url, json=None, timeout=5):
            data = None
            if json is not None:
                data = globals()['json_module'].dumps(json).encode('utf-8')
            req = urlrequest.Request(
                url,
                data=data,
                headers={'Content-Type': 'application/json'},
            )
            return _UrlLibResponse(urlrequest.urlopen(req, timeout=timeout))

    requests = _UrlLibRequests()
json_module = json

from RemoteLinux.ssh_utils import create_host_ssh_client, describe_ssh_error
from .models import (
    AlertEvent,
    AlertHistory,
    AlertSilence,
    ApprovalRequest,
    AuditLog,
    BatchTask,
    BatchTaskResult,
    CommandExecution,
    CommandPolicy,
    DeploymentRelease,
    DeploymentResult,
    DevOpsHostScope,
    DevOpsModulePermission,
    DevOpsRole,
    FileDistribution,
    FileDistributionResult,
    MetricSample,
    K8sCluster,
    NotificationChannel,
    NotificationLog,
    ComplianceBaseline,
    ComplianceResult,
)
from RemoteLinux.models import NewLinux


DANGEROUS_COMMANDS = (
    'mkfs',
    'dd if=',
    ':(){',
)

SYSTEM_POWER_COMMANDS = ('shutdown', 'reboot', 'halt', 'poweroff')

COMMAND_ALLOWED = 'allow'
COMMAND_BLOCKED = 'blocked'
COMMAND_ADMIN_REQUIRED = 'admin_required'


ROLE_RANKS = {
    DevOpsRole.ROLE_VIEWER: 1,
    DevOpsRole.ROLE_OPERATOR: 2,
    DevOpsRole.ROLE_ADMIN: 3,
}


K8S_PRIMARY_RESOURCE_KEYS = (
    'deployments', 'statefulsets', 'daemonsets', 'jobs', 'cronjobs',
)
K8S_RELATED_RESOURCE_KEYS = (
    'pods', 'services', 'configmaps', 'secrets', 'persistentvolumeclaims',
)
K8S_SAFE_RESOURCE_FIELDS = (
    'kind', 'name', 'status', 'replicas', 'namespace', 'created_at', 'detail',
    'labels', 'annotations', 'ip_address',
)
K8S_NAMESPACE_PATTERN = re.compile(r'^[a-z0-9]([-a-z0-9]*[a-z0-9])?$')
K8S_DETAIL_CACHE_TIMEOUT_DEFAULT = 86400
K8S_DETAIL_CACHE_SCHEMA_VERSION = 'v4'


def _k8s_detail_cache_timeout():
    try:
        timeout = int(getattr(
            settings,
            'K8S_DETAIL_CACHE_TIMEOUT_SECONDS',
            K8S_DETAIL_CACHE_TIMEOUT_DEFAULT,
        ))
    except (TypeError, ValueError):
        return K8S_DETAIL_CACHE_TIMEOUT_DEFAULT
    return timeout if timeout > 0 else K8S_DETAIL_CACHE_TIMEOUT_DEFAULT


def safe_k8s_namespace(value, fallback=''):
    namespace = (value or '').strip().lower()
    if namespace and len(namespace) <= 63 and K8S_NAMESPACE_PATTERN.match(namespace):
        return namespace
    return fallback


def _safe_k8s_error(exc, fallback='Kubernetes API 请求失败'):
    error_type = exc.__class__.__name__[:60]
    status = getattr(exc, 'status', None)
    reason = getattr(exc, 'reason', '')
    reason = re.sub(r'[\r\n\t]+', ' ', str(reason or '')).strip()
    if re.search(r'(?i)(token|certificate|authorization|kubeconfig|password|secret)', reason):
        reason = ''
    parts = [fallback]
    if status:
        parts.append('状态码 %s' % str(status)[:12])
    if reason:
        parts.append(reason[:120])
    elif error_type:
        parts.append(error_type)
    return '：'.join(parts)[:260]


def _k8s_temp_config(kubeconfig_text):
    descriptor, path = tempfile.mkstemp(prefix='devops-kube-', suffix='.yaml')
    os.chmod(path, 0o600)
    try:
        with os.fdopen(descriptor, 'w') as handle:
            handle.write(kubeconfig_text)
    except Exception:
        try:
            os.close(descriptor)
        except OSError:
            pass
        try:
            os.unlink(path)
        except OSError:
            pass
        raise
    return path


def _k8s_created_at(item):
    value = getattr(getattr(item, 'metadata', None), 'creation_timestamp', None)
    return value.strftime('%Y/%m/%d %H:%M:%S') if value else '-'


def _k8s_name(item):
    return getattr(getattr(item, 'metadata', None), 'name', None) or '-'


def _k8s_namespace(item, default='-'):
    return getattr(getattr(item, 'metadata', None), 'namespace', None) or default


def _k8s_labels(item):
    labels = getattr(getattr(item, 'metadata', None), 'labels', None) or {}
    parts = []
    for key, value in sorted(labels.items()):
        safe_key = re.sub(r'[\r\n\t]+', ' ', str(key or '')).strip()[:160]
        safe_value = re.sub(r'[\r\n\t]+', ' ', str(value or '')).strip()[:160]
        if safe_key:
            parts.append('%s=%s' % (safe_key, safe_value) if safe_value else safe_key)
    return ', '.join(parts) or '-'


def _k8s_annotations(item):
    annotations = getattr(getattr(item, 'metadata', None), 'annotations', None) or {}
    parts = []
    for key, value in sorted(annotations.items()):
        safe_key = re.sub(r'[\r\n\t]+', ' ', str(key or '')).strip()[:160]
        safe_value = re.sub(r'[\r\n\t]+', ' ', str(value or '')).strip()[:500]
        if safe_key:
            parts.append('%s=%s' % (safe_key, safe_value) if safe_value else safe_key)
    return ', '.join(parts) or '-'


def _k8s_node_ip(item):
    addresses = getattr(getattr(item, 'status', None), 'addresses', None) or []
    address_map = {
        getattr(address, 'type', ''): getattr(address, 'address', '')
        for address in addresses
        if getattr(address, 'address', '')
    }
    return address_map.get('InternalIP') or address_map.get('ExternalIP') or address_map.get('Hostname') or '-'


def _k8s_image(template):
    spec = getattr(template, 'spec', None)
    containers = getattr(spec, 'containers', None) or []
    return getattr(containers[0], 'image', None) or '-' if containers else '-'


def _k8s_cronjob_image(item):
    job_template = getattr(getattr(item, 'spec', None), 'job_template', None)
    job_spec = getattr(job_template, 'spec', None)
    return _k8s_image(getattr(job_spec, 'template', None))


def _k8s_cpu_millicores(value):
    text = str(value or '0').strip()
    multipliers = {'n': Decimal('0.000001'), 'u': Decimal('0.001'), 'm': Decimal('1')}
    suffix = text[-1:] if text else ''
    try:
        if suffix in multipliers:
            return Decimal(text[:-1] or '0') * multipliers[suffix]
        return Decimal(text) * Decimal('1000')
    except (InvalidOperation, ValueError):
        return Decimal('0')


def _k8s_memory_bytes(value):
    text = str(value or '0').strip()
    units = {
        'Ki': Decimal(1024), 'Mi': Decimal(1024 ** 2), 'Gi': Decimal(1024 ** 3),
        'Ti': Decimal(1024 ** 4), 'K': Decimal(1000), 'M': Decimal(1000 ** 2),
        'G': Decimal(1000 ** 3), 'T': Decimal(1000 ** 4),
    }
    try:
        for suffix, multiplier in units.items():
            if text.endswith(suffix):
                return Decimal(text[:-len(suffix)] or '0') * multiplier
        return Decimal(text)
    except (InvalidOperation, ValueError):
        return Decimal('0')


def _format_k8s_cpu(millicores):
    cores = Decimal(millicores or 0) / Decimal('1000')
    return ('%.2f' % cores).rstrip('0').rstrip('.') + ' 核'


def _format_k8s_memory(byte_count):
    gib = Decimal(byte_count or 0) / Decimal(1024 ** 3)
    return ('%.2f' % gib).rstrip('0').rstrip('.') + ' GiB'


def summarize_k8s_nodes(items):
    cpu_capacity = Decimal('0')
    cpu_allocatable = Decimal('0')
    memory_capacity = Decimal('0')
    memory_allocatable = Decimal('0')
    ready_nodes = 0
    nodes = list(items or [])
    for item in nodes:
        status = getattr(item, 'status', None)
        capacity = getattr(status, 'capacity', None) or {}
        allocatable = getattr(status, 'allocatable', None) or {}
        cpu_capacity += _k8s_cpu_millicores(capacity.get('cpu'))
        cpu_allocatable += _k8s_cpu_millicores(allocatable.get('cpu'))
        memory_capacity += _k8s_memory_bytes(capacity.get('memory'))
        memory_allocatable += _k8s_memory_bytes(allocatable.get('memory'))
        conditions = getattr(status, 'conditions', None) or []
        if any(getattr(condition, 'type', '') == 'Ready' and str(getattr(condition, 'status', '')).lower() == 'true' for condition in conditions):
            ready_nodes += 1
    return {
        'node_count': len(nodes),
        'ready_nodes': ready_nodes,
        'cpu_capacity': _format_k8s_cpu(cpu_capacity),
        'cpu_allocatable': _format_k8s_cpu(cpu_allocatable),
        'memory_capacity': _format_k8s_memory(memory_capacity),
        'memory_allocatable': _format_k8s_memory(memory_allocatable),
    }


def safe_k8s_resource(resource):
    return {key: resource.get(key) for key in K8S_SAFE_RESOURCE_FIELDS if key in resource}


def normalize_k8s_resource_name(name, strip_generated_suffixes=True):
    normalized = re.sub(r'[^a-z0-9]+', '-', (name or '').lower()).strip('-')
    if not strip_generated_suffixes:
        return normalized
    parts = [part for part in normalized.split('-') if part]
    while len(parts) > 1:
        suffix = parts[-1]
        if suffix.isdigit() or (len(suffix) == 5 and re.search(r'[a-z]', suffix) and re.search(r'\d', suffix)):
            parts.pop()
            continue
        if re.match(r'^[a-f0-9]{8,12}$', suffix):
            parts.pop()
            continue
        break
    return '-'.join(parts)


def _k8s_resources_match(primary, related, related_key):
    primary_namespace = (primary.get('namespace') or '-').strip()
    related_namespace = (related.get('namespace') or '-').strip()
    if related_namespace != '-' and primary_namespace != related_namespace:
        return False
    primary_name = normalize_k8s_resource_name(primary.get('name'), False)
    related_name = normalize_k8s_resource_name(related.get('name'), related_key == 'pods')
    if not primary_name or not related_name:
        return False
    if primary_name == related_name:
        return True
    if related_key == 'services':
        return related_name.startswith(primary_name + '-')
    return related_name.startswith(primary_name + '-') or primary_name.startswith(related_name + '-')


def build_k8s_resource_matches(resources):
    resources = resources or {}
    groups = []
    for primary_key in K8S_PRIMARY_RESOURCE_KEYS:
        for primary_resource in resources.get(primary_key, []) or []:
            primary = safe_k8s_resource(primary_resource)
            related_groups = {}
            for related_key in K8S_RELATED_RESOURCE_KEYS:
                related_groups[related_key] = [
                    safe_k8s_resource(item)
                    for item in resources.get(related_key, []) or []
                    if _k8s_resources_match(primary, item, related_key)
                ]
            search_parts = list(primary.values())
            for items in related_groups.values():
                for item in items:
                    search_parts.extend(item.values())
            groups.append({
                'name': primary.get('name') or '-',
                'namespace': primary.get('namespace') or '-',
                'status': primary.get('status') or '-',
                'primary': primary,
                'resources': related_groups,
                'resource_count': 1 + sum(len(items) for items in related_groups.values()),
                'search_text': ' '.join(str(value) for value in search_parts if value).lower(),
            })
    return groups


def load_k8s_namespaces(kubeconfig_text, timeout=5):
    result = {'ok': False, 'message': '', 'namespaces': []}
    if not kubeconfig_text:
        result['message'] = 'kubeconfig 无法解密或为空'
        return result
    try:
        from kubernetes import client, config
    except ImportError:
        result['message'] = '缺少 kubernetes Python 依赖，无法读取命名空间'
        return result
    path = ''
    try:
        path = _k8s_temp_config(kubeconfig_text)
        api_client = config.new_client_from_config(config_file=path)
        response = client.CoreV1Api(api_client).list_namespace(_request_timeout=timeout)
        for item in getattr(response, 'items', []) or []:
            name = safe_k8s_namespace(_k8s_name(item))
            if name:
                result['namespaces'].append({
                    'name': name,
                    'status': getattr(getattr(item, 'status', None), 'phase', None) or '-',
                    'labels': _k8s_labels(item),
                    'created_at': _k8s_created_at(item),
                })
        result['namespaces'].sort(key=lambda item: item['name'])
        result['ok'] = True
        result['message'] = '命名空间读取成功'
    except Exception as exc:
        result['message'] = _safe_k8s_error(exc, '命名空间读取失败')
    finally:
        if path:
            try:
                os.unlink(path)
            except OSError:
                pass
    return result


def load_k8s_cluster_overview(kubeconfig_text, namespace='default', timeout=5):
    namespace = safe_k8s_namespace(namespace, 'default')
    overview = {
        'ok': False, 'message': '', 'version': '', 'namespace': namespace,
        'resources': {}, 'resource_errors': {}, 'resource_matches': [],
        'cluster_capacity': summarize_k8s_nodes([]),
    }
    if not kubeconfig_text:
        overview['message'] = 'kubeconfig 无法解密或为空'
        return overview
    try:
        from kubernetes import client, config
    except ImportError:
        overview['message'] = '缺少 kubernetes Python 依赖，无法读取集群信息'
        return overview
    path = ''
    try:
        path = _k8s_temp_config(kubeconfig_text)
        api_client = config.new_client_from_config(config_file=path)
        version = client.VersionApi(api_client).get_code(_request_timeout=timeout)
        overview['version'] = getattr(version, 'git_version', '') or 'unknown'
        apps_api = client.AppsV1Api(api_client)
        batch_api = client.BatchV1Api(api_client)
        cron_api_class = getattr(client, 'BatchV1beta1Api', client.BatchV1Api)
        cron_api = cron_api_class(api_client)
        core_api = client.CoreV1Api(api_client)
        networking_api_class = getattr(client, 'NetworkingV1Api', None) or getattr(client, 'ExtensionsV1beta1Api', None)
        networking_api = networking_api_class(api_client) if networking_api_class else None
        storage_api_class = getattr(client, 'StorageV1Api', None)
        storage_api = storage_api_class(api_client) if storage_api_class else None

        def add_resource(key, loader, mapper):
            try:
                response = loader()
                overview['resources'][key] = [safe_k8s_resource(mapper(item)) for item in getattr(response, 'items', []) or []]
            except Exception as exc:
                overview['resources'][key] = []
                overview['resource_errors'][key] = _safe_k8s_error(exc, '%s 读取失败' % key)

        def replica_workload(item, kind):
            spec = getattr(item, 'spec', None)
            status = getattr(item, 'status', None)
            desired = getattr(spec, 'replicas', None) or 0
            ready = getattr(status, 'ready_replicas', None) or 0
            return with_workload_metadata({'kind': kind, 'name': _k8s_name(item), 'status': '运行中' if desired > 0 and ready == desired else '异常', 'replicas': '%s / %s' % (ready, desired), 'namespace': _k8s_namespace(item, namespace), 'created_at': _k8s_created_at(item), 'detail': _k8s_image(getattr(spec, 'template', None))}, item)

        def with_workload_metadata(resource, item):
            resource['labels'] = _k8s_labels(item)
            resource['annotations'] = _k8s_annotations(item)
            return resource

        add_resource('deployments', lambda: apps_api.list_namespaced_deployment(namespace=namespace, _request_timeout=timeout), lambda item: replica_workload(item, 'Deployment'))
        add_resource('statefulsets', lambda: apps_api.list_namespaced_stateful_set(namespace=namespace, _request_timeout=timeout), lambda item: replica_workload(item, 'StatefulSet'))
        add_resource('daemonsets', lambda: apps_api.list_namespaced_daemon_set(namespace=namespace, _request_timeout=timeout), lambda item: with_workload_metadata({'kind': 'DaemonSet', 'name': _k8s_name(item), 'status': '运行中' if (getattr(item.status, 'desired_number_scheduled', 0) or 0) > 0 and (getattr(item.status, 'number_ready', 0) or 0) == (getattr(item.status, 'desired_number_scheduled', 0) or 0) else '异常', 'replicas': '%s / %s' % (getattr(item.status, 'number_ready', 0) or 0, getattr(item.status, 'desired_number_scheduled', 0) or 0), 'namespace': _k8s_namespace(item, namespace), 'created_at': _k8s_created_at(item), 'detail': _k8s_image(getattr(item.spec, 'template', None))}, item))
        add_resource('jobs', lambda: batch_api.list_namespaced_job(namespace=namespace, _request_timeout=timeout), lambda item: with_workload_metadata({'kind': 'Job', 'name': _k8s_name(item), 'status': '完成' if getattr(item.status, 'succeeded', 0) else ('运行中' if getattr(item.status, 'active', 0) else '异常'), 'replicas': '%s / %s' % (getattr(item.status, 'succeeded', 0) or 0, getattr(item.spec, 'completions', 0) or 1), 'namespace': _k8s_namespace(item, namespace), 'created_at': _k8s_created_at(item), 'detail': _k8s_image(getattr(getattr(item, 'spec', None), 'template', None))}, item))
        add_resource('cronjobs', lambda: cron_api.list_namespaced_cron_job(namespace=namespace, _request_timeout=timeout), lambda item: with_workload_metadata({'kind': 'CronJob', 'name': _k8s_name(item), 'status': '暂停' if getattr(item.spec, 'suspend', False) else '启用', 'replicas': '-', 'namespace': _k8s_namespace(item, namespace), 'created_at': _k8s_created_at(item), 'detail': _k8s_cronjob_image(item)}, item))
        add_resource('pods', lambda: core_api.list_namespaced_pod(namespace=namespace, _request_timeout=timeout), lambda item: {'kind': 'Pod', 'name': _k8s_name(item), 'status': getattr(item.status, 'phase', None) or '-', 'replicas': '-', 'namespace': _k8s_namespace(item, namespace), 'created_at': _k8s_created_at(item), 'detail': getattr(item.spec, 'node_name', None) or '-'})
        try:
            node_response = core_api.list_node(_request_timeout=timeout)
            node_items = list(getattr(node_response, 'items', []) or [])
            overview['cluster_capacity'] = summarize_k8s_nodes(node_items)

            def node_resource(item):
                metadata = getattr(item, 'metadata', None)
                labels = getattr(metadata, 'labels', None) or {}
                roles = sorted(filter(None, [
                    key.split('node-role.kubernetes.io/', 1)[1] or 'worker'
                    for key in labels
                    if key.startswith('node-role.kubernetes.io/')
                ])) or ['worker']
                status = getattr(item, 'status', None)
                conditions = getattr(status, 'conditions', None) or []
                ready = any(getattr(condition, 'type', '') == 'Ready' and str(getattr(condition, 'status', '')).lower() == 'true' for condition in conditions)
                node_info = getattr(status, 'node_info', None)
                kubelet = getattr(node_info, 'kubelet_version', None) or '-'
                return {
                    'kind': 'Node', 'name': _k8s_name(item), 'status': 'Ready' if ready else 'NotReady',
                    'replicas': '-', 'namespace': '-', 'created_at': _k8s_created_at(item),
                    'ip_address': _k8s_node_ip(item),
                    'detail': '%s | Kubelet %s' % (', '.join(roles), kubelet),
                }

            overview['resources']['nodes'] = [safe_k8s_resource(node_resource(item)) for item in node_items]
        except Exception as exc:
            overview['resources']['nodes'] = []
            overview['resource_errors']['nodes'] = _safe_k8s_error(exc, 'nodes 读取失败')
        add_resource('services', lambda: core_api.list_namespaced_service(namespace=namespace, _request_timeout=timeout), lambda item: {'kind': 'Service', 'name': _k8s_name(item), 'status': getattr(item.spec, 'type', None) or '-', 'replicas': '-', 'namespace': _k8s_namespace(item, namespace), 'created_at': _k8s_created_at(item), 'detail': getattr(item.spec, 'cluster_ip', None) or '-'})
        add_resource('ingresses', lambda: networking_api.list_namespaced_ingress(namespace=namespace, _request_timeout=timeout), lambda item: {'kind': 'Ingress', 'name': _k8s_name(item), 'status': '可用' if getattr(item.spec, 'rules', None) else '-', 'replicas': '-', 'namespace': _k8s_namespace(item, namespace), 'created_at': _k8s_created_at(item), 'detail': ', '.join(filter(None, [getattr(rule, 'host', None) for rule in (getattr(item.spec, 'rules', None) or [])])) or '-'})
        add_resource('configmaps', lambda: core_api.list_namespaced_config_map(namespace=namespace, _request_timeout=timeout), lambda item: {'kind': 'ConfigMap', 'name': _k8s_name(item), 'status': '-', 'replicas': '-', 'namespace': _k8s_namespace(item, namespace), 'created_at': _k8s_created_at(item), 'detail': '%s keys' % len(getattr(item, 'data', None) or {})})
        add_resource('secrets', lambda: core_api.list_namespaced_secret(namespace=namespace, _request_timeout=timeout), lambda item: {'kind': 'Secret', 'name': _k8s_name(item), 'status': getattr(item, 'type', None) or '-', 'replicas': '-', 'namespace': _k8s_namespace(item, namespace), 'created_at': _k8s_created_at(item), 'detail': '受保护数据'})
        add_resource('persistentvolumeclaims', lambda: core_api.list_namespaced_persistent_volume_claim(namespace=namespace, _request_timeout=timeout), lambda item: {'kind': 'PVC', 'name': _k8s_name(item), 'status': getattr(item.status, 'phase', None) or '-', 'replicas': '-', 'namespace': _k8s_namespace(item, namespace), 'created_at': _k8s_created_at(item), 'detail': getattr(item.spec, 'storage_class_name', None) or '-'})
        add_resource('persistentvolumes', lambda: core_api.list_persistent_volume(_request_timeout=timeout), lambda item: {'kind': 'PV', 'name': _k8s_name(item), 'status': getattr(getattr(item, 'status', None), 'phase', None) or '-', 'replicas': '-', 'namespace': '-', 'created_at': _k8s_created_at(item), 'detail': getattr(getattr(item, 'spec', None), 'storage_class_name', None) or '-'})
        add_resource('storageclasses', lambda: storage_api.list_storage_class(_request_timeout=timeout), lambda item: {'kind': 'StorageClass', 'name': _k8s_name(item), 'status': '可用', 'replicas': '-', 'namespace': '-', 'created_at': _k8s_created_at(item), 'detail': getattr(item, 'provisioner', None) or '-'})
        overview['resource_matches'] = build_k8s_resource_matches(overview['resources'])
        overview['ok'] = True
        overview['message'] = '集群信息读取成功'
    except Exception as exc:
        overview['message'] = _safe_k8s_error(exc, '集群信息读取失败')
    finally:
        if path:
            try:
                os.unlink(path)
            except OSError:
                pass
    return overview


def k8s_detail_cache_key(cluster_id, kubeconfig_text, schema_version=None):
    fingerprint = hashlib.sha256((kubeconfig_text or '').encode('utf-8')).hexdigest()
    return 'devops:k8s-detail:%s:%s:%s' % (
        schema_version or K8S_DETAIL_CACHE_SCHEMA_VERSION,
        cluster_id,
        fingerprint,
    )


def clear_k8s_detail_cache(cluster_id, kubeconfig_text):
    cache.delete(k8s_detail_cache_key(cluster_id, kubeconfig_text))
    cache.delete(k8s_detail_cache_key(cluster_id, kubeconfig_text, 'v3'))


def load_cached_k8s_cluster_detail(cluster_id, kubeconfig_text, namespace='default', refresh=False, timeout=5):
    selected = safe_k8s_namespace(namespace, 'default')
    key = k8s_detail_cache_key(cluster_id, kubeconfig_text)
    cached = cache.get(key)
    if not isinstance(cached, dict):
        cached = None
    legacy_cached = cache.get(k8s_detail_cache_key(cluster_id, kubeconfig_text, 'v3'))
    if not isinstance(legacy_cached, dict):
        legacy_cached = None
    cached_namespace_result = (cached or {}).get('namespace_result') or {}
    legacy_namespace_result = (legacy_cached or {}).get('namespace_result') or {}
    if not cached_namespace_result.get('ok') and legacy_namespace_result.get('ok'):
        cached_namespace_result = legacy_namespace_result
    namespace_cache_valid = bool(
        isinstance(cached_namespace_result, dict)
        and cached_namespace_result.get('ok')
        and isinstance(cached_namespace_result.get('namespaces'), list)
    )
    current_overviews = dict((cached or {}).get('overviews') or {})
    overviews = dict((legacy_cached or {}).get('overviews') or {})
    overviews.update(current_overviews)
    cluster_scope_source = next((
        item for item in overviews.values()
        if 'cluster_capacity' in item and 'nodes' in (item.get('resources') or {})
    ), None)
    if cluster_scope_source:
        source_resources = cluster_scope_source.get('resources') or {}
        for overview_namespace, overview_item in list(overviews.items()):
            merged_overview = dict(overview_item)
            merged_resources = dict(merged_overview.get('resources') or {})
            for resource_key in ('nodes', 'persistentvolumes', 'storageclasses'):
                if resource_key not in merged_resources and resource_key in source_resources:
                    merged_resources[resource_key] = source_resources[resource_key]
            merged_overview['resources'] = merged_resources
            if 'cluster_capacity' not in merged_overview:
                merged_overview['cluster_capacity'] = cluster_scope_source['cluster_capacity']
            overviews[overview_namespace] = merged_overview
    cached_overview = overviews.get(selected) or {}
    cached_workload_rows = [
        row
        for resource_key in K8S_PRIMARY_RESOURCE_KEYS
        for row in (cached_overview.get('resources') or {}).get(resource_key, []) or []
    ]
    workload_metadata_valid = all(
        'labels' in row and 'annotations' in row
        for row in cached_workload_rows
    )
    overview_cache_valid = bool(
        cached_overview.get('ok')
        and workload_metadata_valid
        and (
            selected in current_overviews
            or (
                'cluster_capacity' in cached_overview
                and 'nodes' in (cached_overview.get('resources') or {})
            )
        )
    )
    if not refresh and namespace_cache_valid and overview_cache_valid:
        return {
            'overview': overviews[selected],
            'namespace_result': cached_namespace_result,
            'from_cache': True,
        }

    if refresh or not namespace_cache_valid:
        loaded_namespace_result = load_k8s_namespaces(kubeconfig_text, timeout=timeout)
        namespace_result = (
            loaded_namespace_result if loaded_namespace_result.get('ok')
            else cached_namespace_result or loaded_namespace_result
        )
    else:
        namespace_result = cached_namespace_result
    if refresh or not overview_cache_valid:
        loaded_overview = load_k8s_cluster_overview(kubeconfig_text, selected, timeout=timeout)
        if loaded_overview.get('ok') or not cached_overview.get('ok'):
            overviews[selected] = loaded_overview
        else:
            preserved_overview = dict(cached_overview)
            preserved_overview['ok'] = False
            preserved_overview['message'] = loaded_overview.get('message') or '集群信息刷新失败，继续显示已有缓存'
            overviews[selected] = preserved_overview
    cache.set(
        key,
        {'namespace_result': namespace_result, 'overviews': overviews},
        _k8s_detail_cache_timeout(),
    )
    return {
        'overview': overviews[selected],
        'namespace_result': namespace_result,
        'from_cache': False,
    }


def _k8s_pod_quantity(pod, field, resource_name, parser):
    spec = getattr(pod, 'spec', None)

    def container_value(container):
        resources = getattr(container, 'resources', None)
        values = getattr(resources, field, None) or {}
        return parser(values.get(resource_name))

    regular_total = sum(
        (container_value(container) for container in (getattr(spec, 'containers', None) or [])),
        Decimal('0'),
    )
    init_values = [
        container_value(container)
        for container in (getattr(spec, 'init_containers', None) or [])
    ]
    init_max = max(init_values) if init_values else Decimal('0')
    return max(regular_total, init_max)


def k8s_node_detail_cache_key(cluster_id, kubeconfig_text, node_name):
    fingerprint = hashlib.sha256((kubeconfig_text or '').encode('utf-8')).hexdigest()
    node_fingerprint = hashlib.sha256((node_name or '').encode('utf-8')).hexdigest()[:24]
    return 'devops:k8s-node-detail:v1:%s:%s:%s' % (cluster_id, fingerprint, node_fingerprint)


def load_k8s_node_detail(kubeconfig_text, node_name, timeout=8):
    result = {
        'ok': False,
        'message': '',
        'metrics_message': '',
        'node': {},
        'summary': {},
        'pods': [],
    }
    if not kubeconfig_text:
        result['message'] = 'kubeconfig 无法解密或为空'
        return result
    try:
        from kubernetes import client, config
    except ImportError:
        result['message'] = '缺少 kubernetes Python 依赖，无法读取节点详情'
        return result
    path = ''
    try:
        path = _k8s_temp_config(kubeconfig_text)
        api_client = config.new_client_from_config(config_file=path)
        core_api = client.CoreV1Api(api_client)
        node = core_api.read_node(name=node_name, _request_timeout=timeout)
        pod_response = core_api.list_pod_for_all_namespaces(
            field_selector='spec.nodeName=%s' % node_name,
            _request_timeout=timeout,
        )
        pods = list(getattr(pod_response, 'items', []) or [])
        status = getattr(node, 'status', None)
        capacity = getattr(status, 'capacity', None) or {}
        allocatable = getattr(status, 'allocatable', None) or {}
        conditions = getattr(status, 'conditions', None) or []
        ready = any(
            getattr(condition, 'type', '') == 'Ready'
            and str(getattr(condition, 'status', '')).lower() == 'true'
            for condition in conditions
        )
        metadata = getattr(node, 'metadata', None)
        labels = getattr(metadata, 'labels', None) or {}
        roles = sorted(filter(None, [
            key.split('node-role.kubernetes.io/', 1)[1] or 'worker'
            for key in labels
            if key.startswith('node-role.kubernetes.io/')
        ])) or ['worker']
        node_info = getattr(status, 'node_info', None)

        cpu_requests = Decimal('0')
        cpu_limits = Decimal('0')
        memory_requests = Decimal('0')
        memory_limits = Decimal('0')
        pod_rows = []
        for pod in pods:
            pod_cpu_request = _k8s_pod_quantity(pod, 'requests', 'cpu', _k8s_cpu_millicores)
            pod_cpu_limit = _k8s_pod_quantity(pod, 'limits', 'cpu', _k8s_cpu_millicores)
            pod_memory_request = _k8s_pod_quantity(pod, 'requests', 'memory', _k8s_memory_bytes)
            pod_memory_limit = _k8s_pod_quantity(pod, 'limits', 'memory', _k8s_memory_bytes)
            cpu_requests += pod_cpu_request
            cpu_limits += pod_cpu_limit
            memory_requests += pod_memory_request
            memory_limits += pod_memory_limit
            pod_status = getattr(pod, 'status', None)
            pod_rows.append({
                'name': _k8s_name(pod),
                'namespace': _k8s_namespace(pod),
                'status': getattr(pod_status, 'phase', None) or '-',
                'pod_ip': getattr(pod_status, 'pod_ip', None) or '-',
                'created_at': _k8s_created_at(pod),
                'cpu_request': _format_k8s_cpu(pod_cpu_request),
                'cpu_limit': _format_k8s_cpu(pod_cpu_limit),
                'memory_request': _format_k8s_memory(pod_memory_request),
                'memory_limit': _format_k8s_memory(pod_memory_limit),
            })

        cpu_usage = None
        memory_usage = None
        try:
            metrics_api = client.CustomObjectsApi(api_client)
            metrics = metrics_api.get_cluster_custom_object(
                group='metrics.k8s.io',
                version='v1beta1',
                plural='nodes',
                name=node_name,
                _request_timeout=timeout,
            )
            usage = (metrics or {}).get('usage') or {}
            cpu_usage = _k8s_cpu_millicores(usage.get('cpu'))
            memory_usage = _k8s_memory_bytes(usage.get('memory'))
        except Exception as exc:
            result['metrics_message'] = _safe_k8s_error(exc, '节点实时使用量读取失败')

        result['node'] = {
            'name': _k8s_name(node),
            'status': 'Ready' if ready else 'NotReady',
            'ip_address': _k8s_node_ip(node),
            'roles': ', '.join(roles),
            'created_at': _k8s_created_at(node),
            'kubelet_version': getattr(node_info, 'kubelet_version', None) or '-',
            'container_runtime': getattr(node_info, 'container_runtime_version', None) or '-',
            'os_image': getattr(node_info, 'os_image', None) or '-',
            'kernel_version': getattr(node_info, 'kernel_version', None) or '-',
            'architecture': getattr(node_info, 'architecture', None) or '-',
        }
        result['summary'] = {
            'cpu_total': _format_k8s_cpu(_k8s_cpu_millicores(capacity.get('cpu'))),
            'cpu_allocatable': _format_k8s_cpu(_k8s_cpu_millicores(allocatable.get('cpu'))),
            'cpu_usage': _format_k8s_cpu(cpu_usage) if cpu_usage is not None else '-',
            'cpu_request': _format_k8s_cpu(cpu_requests),
            'cpu_limit': _format_k8s_cpu(cpu_limits),
            'memory_total': _format_k8s_memory(_k8s_memory_bytes(capacity.get('memory'))),
            'memory_allocatable': _format_k8s_memory(_k8s_memory_bytes(allocatable.get('memory'))),
            'memory_usage': _format_k8s_memory(memory_usage) if memory_usage is not None else '-',
            'memory_request': _format_k8s_memory(memory_requests),
            'memory_limit': _format_k8s_memory(memory_limits),
            'pod_total': len(pod_rows),
        }
        result['pods'] = sorted(pod_rows, key=lambda item: (item['namespace'], item['name']))
        result['ok'] = True
        result['message'] = '节点详情读取成功'
    except Exception as exc:
        result['message'] = _safe_k8s_error(exc, '节点详情读取失败')
    finally:
        if path:
            try:
                os.unlink(path)
            except OSError:
                pass
    return result


def load_cached_k8s_node_detail(cluster_id, kubeconfig_text, node_name, refresh=False, timeout=8):
    key = k8s_node_detail_cache_key(cluster_id, kubeconfig_text, node_name)
    cached = cache.get(key)
    if not refresh and isinstance(cached, dict) and cached.get('ok'):
        result = dict(cached)
        result['from_cache'] = True
        return result

    loaded = load_k8s_node_detail(kubeconfig_text, node_name, timeout=timeout)
    if loaded.get('ok'):
        cache.set(key, loaded, _k8s_detail_cache_timeout())
        result = dict(loaded)
    elif isinstance(cached, dict) and cached.get('ok'):
        result = dict(cached)
        result['ok'] = False
        result['message'] = loaded.get('message') or '节点详情刷新失败，继续显示已有缓存'
    else:
        result = loaded
    result['from_cache'] = False
    return result


def test_k8s_cluster_connection(cluster, timeout=8):
    kubeconfig = cluster.decrypted_kubeconfig
    checked_at = timezone.now()
    if not kubeconfig:
        cluster.status = K8sCluster.STATUS_OFFLINE
        cluster.last_error = 'Kubeconfig 无法解密或为空'
        cluster.last_checked_at = checked_at
        cluster.save(update_fields=['status', 'last_error', 'last_checked_at', 'updated_at'])
        return False, cluster.last_error

    path = ''
    try:
        descriptor, path = tempfile.mkstemp(prefix='devops-kube-', suffix='.yaml')
        os.chmod(path, 0o600)
        with os.fdopen(descriptor, 'w') as handle:
            handle.write(kubeconfig)
        command = [
            'kubectl',
            '--kubeconfig', path,
            '--namespace', cluster.default_namespace or 'default',
            '--request-timeout=5s',
            'get',
            '--raw=/version',
        ]
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            timeout=timeout,
            check=False,
        )
        if result.returncode == 0:
            success = True
            message = ''
        else:
            success = False
            message = 'Kubectl 连接失败（退出码 %s）' % result.returncode
    except FileNotFoundError:
        success = False
        message = '未找到 kubectl 命令'
    except subprocess.TimeoutExpired:
        success = False
        message = 'Kubernetes 连接测试超时'
    except (OSError, ValueError):
        success = False
        message = 'Kubernetes 连接测试执行失败'
    finally:
        if path:
            try:
                os.unlink(path)
            except OSError:
                pass

    cluster.status = K8sCluster.STATUS_ONLINE if success else K8sCluster.STATUS_OFFLINE
    cluster.last_error = message[:300]
    cluster.last_checked_at = checked_at
    cluster.save(update_fields=['status', 'last_error', 'last_checked_at', 'updated_at'])
    return success, message


def claim_pending_work(model_class, obj, running_status):
    updated = model_class.objects.filter(
        id=obj.id,
        status=model_class.STATUS_PENDING,
    ).update(status=running_status)
    obj.refresh_from_db()
    return bool(updated)


def claim_running_deployment_if_empty(release, action):
    if release.status != DeploymentRelease.STATUS_RUNNING:
        return False
    has_results = DeploymentResult.objects.filter(release=release, action=action).exists()
    if has_results:
        return False
    release.refresh_from_db()
    return release.status == DeploymentRelease.STATUS_RUNNING


def claim_deployment_rollback(release):
    rollbackable_statuses = (
        DeploymentRelease.STATUS_SUCCESS,
        DeploymentRelease.STATUS_PARTIAL,
        DeploymentRelease.STATUS_FAILED,
    )
    updated = DeploymentRelease.objects.filter(
        id=release.id,
        status__in=rollbackable_statuses,
    ).update(status=DeploymentRelease.STATUS_RUNNING)
    release.refresh_from_db()
    return bool(updated)


def enqueue_background_job(target, *args, **kwargs):
    if getattr(settings, 'DEVOPS_SYNC_TASKS', False):
        return target(*args, **kwargs)
    thread = Thread(target=run_background_job, args=(target, args, kwargs))
    thread.daemon = True
    thread.start()
    return thread


def mark_background_failure(target, args, exc):
    message = '后台任务异常：%s' % exc
    target_name = getattr(target, '__name__', str(target))
    obj = args[0] if args else None
    AuditLog.objects.create(
        user='system',
        action='后台任务异常',
        target_type=obj.__class__.__name__ if obj else target_name,
        target_id=str(getattr(obj, 'id', '') or ''),
        detail='%s: %s' % (target_name, message),
    )
    if isinstance(obj, CommandExecution):
        obj.status = CommandExecution.STATUS_FAILED
        obj.error = message
        obj.finished_at = timezone.now()
        obj.save(update_fields=['status', 'error', 'finished_at'])
        return
    if isinstance(obj, BatchTask):
        obj.status = BatchTask.STATUS_FAILED
        obj.summary = message[:300]
        obj.finished_at = timezone.now()
        obj.save(update_fields=['status', 'summary', 'finished_at'])
        return
    if isinstance(obj, FileDistribution):
        obj.status = FileDistribution.STATUS_FAILED
        obj.summary = message[:300]
        obj.finished_at = timezone.now()
        obj.save(update_fields=['status', 'summary', 'finished_at'])
        return
    if isinstance(obj, DeploymentRelease):
        obj.status = DeploymentRelease.STATUS_FAILED
        obj.summary = message[:300]
        obj.finished_at = timezone.now()
        obj.save(update_fields=['status', 'summary', 'finished_at'])
        return


def run_background_job(target, args, kwargs):
    try:
        return target(*args, **kwargs)
    except Exception as exc:
        mark_background_failure(target, args, exc)
        print('后台任务执行失败：%s' % exc)


def client_ip(request):
    forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if forwarded_for:
        return forwarded_for.split(',')[0].strip()
    return request.META.get('REMOTE_ADDR', '')


def audit(request, action, target_type='', target_id='', detail=''):
    AuditLog.objects.create(
        user=request.session.get('user_name', ''),
        action=action,
        target_type=target_type,
        target_id=str(target_id or ''),
        detail=detail,
        ip_address=client_ip(request),
    )


def cleanup_audit_logs(retention_days=None):
    days = retention_days
    if days is None:
        days = int(getattr(settings, 'AUDIT_LOG_RETENTION_DAYS', 0) or 0)
    days = int(days or 0)
    if days <= 0:
        return 0
    cutoff = timezone.now() - timezone.timedelta(days=days)
    deleted, details = AuditLog.objects.filter(created_at__lt=cutoff).delete()
    return deleted


def user_role(request):
	user_id = request.session.get('user_id')
	if not user_id:
		return DevOpsRole.ROLE_VIEWER
	try:
		return DevOpsRole.objects.get(user_id=user_id).role
	except DevOpsRole.DoesNotExist:
		return DevOpsRole.ROLE_ADMIN if not DevOpsRole.objects.exists() else DevOpsRole.ROLE_OPERATOR


def module_role(request, module=''):
	base_role = user_role(request)
	user_id = request.session.get('user_id')
	if not user_id or not module:
		return base_role
	try:
		return DevOpsModulePermission.objects.get(user_id=user_id, module=module).role
	except DevOpsModulePermission.DoesNotExist:
		return base_role


def has_role(request, minimum_role, module=''):
	if request.session.get('user_id') and not has_configured_role(request):
		return ROLE_RANKS.get(DevOpsRole.ROLE_OPERATOR, 0) >= ROLE_RANKS.get(minimum_role, 0)
	return ROLE_RANKS.get(module_role(request, module), 0) >= ROLE_RANKS.get(minimum_role, 0)


def host_scope_for_request(request):
    user_id = request.session.get('user_id')
    if not user_id:
        return None
    try:
        return DevOpsHostScope.objects.get(user_id=user_id)
    except DevOpsHostScope.DoesNotExist:
        return None


def has_explicit_admin_role(request):
	user_id = request.session.get('user_id')
	if not user_id:
		return False
	try:
		return DevOpsRole.objects.get(user_id=user_id).role == DevOpsRole.ROLE_ADMIN
	except DevOpsRole.DoesNotExist:
		return not DevOpsRole.objects.exists()


def has_configured_role(request):
	user_id = request.session.get('user_id')
	if not user_id:
		return False
	return DevOpsRole.objects.filter(user_id=user_id).exists()


def visible_hosts_for_request(request):
	scope = host_scope_for_request(request)
	if not scope:
		if has_explicit_admin_role(request):
			return NewLinux.objects.all()
		if not has_configured_role(request):
			return NewLinux.objects.all()
		return NewLinux.objects.none()
	group_ids = list(scope.groups.values_list('id', flat=True))
	tag_ids = list(scope.tags.values_list('id', flat=True))
	if not group_ids and not tag_ids:
		return NewLinux.objects.none()
	query = models.Q()
	if group_ids:
		query |= models.Q(hostgroup__id__in=group_ids)
	if tag_ids:
		query |= models.Q(hosttag__id__in=tag_ids)
	return NewLinux.objects.filter(query).distinct()


def can_access_host(request, host):
    if not host:
        return True
    return visible_hosts_for_request(request).filter(id=host.id).exists()


def can_access_hosts(request, hosts):
    host_ids = [host.id for host in hosts]
    if not host_ids:
        return True
    allowed_ids = set(visible_hosts_for_request(request).filter(id__in=host_ids).values_list('id', flat=True))
    return set(host_ids).issubset(allowed_ids)


def evaluate_command_policy(command, role=DevOpsRole.ROLE_OPERATOR):
    normalized = ' '.join(command.strip().lower().split())
    policies = CommandPolicy.objects.filter(enabled=True)
    for policy in policies:
        if policy.pattern.lower() in normalized:
            if policy.action == CommandPolicy.ACTION_ALLOW:
                return COMMAND_ALLOWED, policy
            if policy.action == CommandPolicy.ACTION_REQUIRE_ADMIN and role != DevOpsRole.ROLE_ADMIN:
                return COMMAND_ADMIN_REQUIRED, policy
            if policy.action == CommandPolicy.ACTION_BLOCK:
                return COMMAND_BLOCKED, policy

    if matches_default_dangerous_command(normalized):
        return COMMAND_BLOCKED, None
    return COMMAND_ALLOWED, None


def matches_default_dangerous_command(normalized_command):
    for pattern in DANGEROUS_COMMANDS:
        if pattern in normalized_command:
            return True
    try:
        tokens = shlex.split(normalized_command)
    except ValueError:
        tokens = normalized_command.split()
    if tokens and tokens[0] == 'sudo':
        tokens = tokens[1:]
    if not tokens:
        return False
    command_name = tokens[0].split('/')[-1]
    if command_name in SYSTEM_POWER_COMMANDS:
        return True
    if command_name == 'rm':
        flags = ''.join(token[1:] for token in tokens[1:] if token.startswith('-') and not token.startswith('--'))
        targets = [token for token in tokens[1:] if not token.startswith('-')]
        if 'r' in flags and 'f' in flags and any(target in ('/', '/*') for target in targets):
            return True
    return False


def command_denied_message(decision, policy=None):
    if decision == COMMAND_ADMIN_REQUIRED:
        reason = policy.reason if policy and policy.reason else '该命令需要管理员权限'
        return '命令需要管理员权限：%s' % reason
    reason = policy.reason if policy and policy.reason else '命令包含高危操作'
    return '%s，已被平台拦截' % reason


def is_dangerous_command(command):
    decision, policy = evaluate_command_policy(command)
    return decision in (COMMAND_BLOCKED, COMMAND_ADMIN_REQUIRED)


def task_retry_count():
    return max(0, int(getattr(settings, 'DEVOPS_TASK_RETRY_COUNT', 0) or 0))


def ssh_connect_timeout():
    return max(1, int(getattr(settings, 'DEVOPS_SSH_CONNECT_TIMEOUT_SECONDS', 10) or 10))


def command_timeout():
    return max(1, int(getattr(settings, 'DEVOPS_COMMAND_TIMEOUT_SECONDS', 60) or 60))


def command_output_max_bytes():
    return max(1, int(getattr(settings, 'DEVOPS_COMMAND_OUTPUT_MAX_BYTES', 204800) or 204800))


def read_limited_stream(stream, limit):
    data = stream.read()
    truncated = False
    if len(data) > limit:
        data = data[:limit]
        truncated = True
    text = data.decode(errors='ignore')
    if truncated:
        text += '\n[输出已截断，最多保留 %s 字节]' % limit
    return text


def execute_command_record(record, role=DevOpsRole.ROLE_OPERATOR):
    if not claim_pending_work(CommandExecution, record, CommandExecution.STATUS_RUNNING):
        return record

    decision, policy = evaluate_command_policy(record.command, role)
    if decision in (COMMAND_BLOCKED, COMMAND_ADMIN_REQUIRED):
        record.status = CommandExecution.STATUS_BLOCKED
        record.error = command_denied_message(decision, policy)
        record.finished_at = timezone.now()
        record.save()
        return record

    started = time.time()
    attempts = task_retry_count() + 1
    last_error = ''
    for attempt in range(1, attempts + 1):
        client = None
        try:
            client = create_host_ssh_client(record.host, timeout=ssh_connect_timeout())
            stdin, stdout, stderr = client.exec_command(record.command, timeout=command_timeout())
            output_limit = command_output_max_bytes()
            record.output = read_limited_stream(stdout, output_limit)
            record.error = read_limited_stream(stderr, output_limit)
            record.status = (
                CommandExecution.STATUS_FAILED
                if record.error and not record.output
                else CommandExecution.STATUS_SUCCESS
            )
            if record.status == CommandExecution.STATUS_SUCCESS:
                break
            last_error = record.error
        except Exception as exc:
            record.status = CommandExecution.STATUS_FAILED
            last_error = describe_ssh_error(exc)
            record.error = last_error
        finally:
            if client:
                client.close()
        if attempt < attempts:
            record.error = '%s，准备重试 %s/%s' % (last_error, attempt, attempts - 1)
            record.save(update_fields=['error', 'status'])
    if record.status == CommandExecution.STATUS_FAILED and attempts > 1 and last_error:
        record.error = '%s（已尝试 %s 次）' % (last_error, attempts)
    record.duration_ms = int((time.time() - started) * 1000)
    record.finished_at = timezone.now()
    record.save()
    return record


def execute_batch_task(task, role=DevOpsRole.ROLE_OPERATOR):
    if not claim_pending_work(BatchTask, task, BatchTask.STATUS_RUNNING):
        return task

    decision, policy = evaluate_command_policy(task.command, role)
    if decision != COMMAND_ALLOWED:
        task.status = BatchTask.STATUS_BLOCKED
        task.summary = command_denied_message(decision, policy)
        task.finished_at = timezone.now()
        task.save()
        for host in task.hosts.all():
            BatchTaskResult.objects.create(
                task=task,
                host=host,
                status=CommandExecution.STATUS_BLOCKED,
                error=task.summary,
            )
        return task

    success_count = 0
    failed_count = 0
    for host in task.hosts.all():
        record = CommandExecution.objects.create(
            host=host,
            command=task.command,
            created_by=task.created_by,
        )
        execute_command_record(record, role)
        BatchTaskResult.objects.create(
            task=task,
            host=host,
            command_execution=record,
            status=record.status,
            output=record.output,
            error=record.error,
            duration_ms=record.duration_ms,
        )
        if record.status == CommandExecution.STATUS_SUCCESS:
            success_count += 1
        else:
            failed_count += 1
    if success_count and failed_count:
        task.status = BatchTask.STATUS_PARTIAL
    elif success_count:
        task.status = BatchTask.STATUS_SUCCESS
    else:
        task.status = BatchTask.STATUS_FAILED
    task.summary = '成功 %s 台，失败 %s 台' % (success_count, failed_count)
    task.finished_at = timezone.now()
    task.save()
    return task


def service_command(action, service_name):
    return 'systemctl %s %s' % (action, service_name)


def alert_fingerprint(host, metric):
    host_id = host.id if host else 'none'
    return '%s:%s' % (host_id, metric or 'general')


def is_alert_silenced(host, metric, now=None):
    now = now or timezone.now()
    silences = AlertSilence.objects.filter(starts_at__lte=now, ends_at__gte=now)
    return silences.filter(host=host, metric__in=[metric, '']).exists() or silences.filter(host__isnull=True, metric__in=[metric, '']).exists()


def record_alert(host, metric, message, level=AlertEvent.LEVEL_WARNING):
    now = timezone.now()
    fingerprint = alert_fingerprint(host, metric)
    active_statuses = [
        AlertEvent.STATUS_OPEN,
        AlertEvent.STATUS_PROCESSING,
        AlertEvent.STATUS_SILENCED,
    ]
    alert = AlertEvent.objects.filter(fingerprint=fingerprint, status__in=active_statuses).first()
    if alert:
        alert.repeat_count += 1
        alert.last_seen_at = now
        alert.message = message
        if is_alert_silenced(host, metric):
            alert.status = AlertEvent.STATUS_SILENCED
            alert.remark = '命中静默规则'
        alert.save(update_fields=['repeat_count', 'last_seen_at', 'message', 'status', 'remark', 'updated_at'])
        return alert, False

    status = AlertEvent.STATUS_SILENCED if is_alert_silenced(host, metric) else AlertEvent.STATUS_OPEN
    alert = AlertEvent.objects.create(
        host=host,
        level=level,
        metric=metric,
        message=message,
        status=status,
        fingerprint=fingerprint,
        first_seen_at=now,
        last_seen_at=now,
        remark='命中静默规则' if status == AlertEvent.STATUS_SILENCED else '',
    )
    if alert.status != AlertEvent.STATUS_SILENCED:
        notify_alert(alert)
    return alert, True


def resolve_alert(host, metric, message='指标已恢复正常'):
    fingerprint = alert_fingerprint(host, metric)
    active_statuses = [
        AlertEvent.STATUS_OPEN,
        AlertEvent.STATUS_PROCESSING,
        AlertEvent.STATUS_SILENCED,
    ]
    alert = AlertEvent.objects.filter(fingerprint=fingerprint, status__in=active_statuses).first()
    if not alert:
        return None
    alert = update_alert_status(
        alert,
        AlertEvent.STATUS_RESOLVED,
        handler='system',
        remark=message,
    )
    try:
        from monitor.services import send_alert_event_notifications
        send_alert_event_notifications(alert, status=AlertEvent.STATUS_RESOLVED)
    except Exception:
        pass
    return alert


def compliance_metric(baseline):
    return 'compliance:%s' % baseline.id


def compliance_scan_command(baseline):
    if baseline.baseline_type == ComplianceBaseline.TYPE_SERVICE_ACTIVE:
        if not re.match(r'^[A-Za-z0-9_.@:-]+$', baseline.service_name or ''):
            return None, ''
        return 'systemctl is-active -- %s' % shlex.quote(baseline.service_name), 'active'
    path = baseline.file_path or ''
    sha = (baseline.expected_sha256 or '').lower()
    if (baseline.baseline_type != ComplianceBaseline.TYPE_FILE_SHA256 or not path.startswith('/')
            or '\x00' in path or '\n' in path or '\r' in path
            or posixpath.normpath(path) != path or not re.match(r'^[a-f0-9]{64}$', sha)):
        return None, ''
    return 'sha256sum -- %s' % shlex.quote(path), sha


def scan_compliance_baseline(baseline):
    """Scan a fixed, validated baseline without accepting arbitrary commands."""
    scanned = 0
    command, expected = compliance_scan_command(baseline)
    for host in baseline.hosts.all():
        client = None
        state = ComplianceResult.STATE_ERROR
        actual_value = ''
        try:
            if not command:
                raise ValueError('invalid compliance baseline')
            client = create_host_ssh_client(host, timeout=ssh_connect_timeout())
            stdin, stdout, stderr = client.exec_command(command, timeout=command_timeout())
            output = (stdout.read() or b'').decode('utf-8', 'ignore').strip()
            if baseline.baseline_type == ComplianceBaseline.TYPE_FILE_SHA256:
                actual_value = output.split()[0].lower() if output else ''
                if not re.match(r'^[a-f0-9]{64}$', actual_value):
                    actual_value = ''
            else:
                actual_value = output[:100]
            state = ComplianceResult.STATE_COMPLIANT if actual_value == expected else ComplianceResult.STATE_DRIFT
        except Exception:
            state = ComplianceResult.STATE_ERROR
        finally:
            if client:
                client.close()
        ComplianceResult.objects.update_or_create(
            baseline=baseline, host=host,
            defaults={'state': state, 'actual_value': actual_value},
        )
        if state == ComplianceResult.STATE_DRIFT:
            record_alert(host, compliance_metric(baseline), '合规基线“%s”存在漂移' % baseline.name, AlertEvent.LEVEL_WARNING)
        elif state == ComplianceResult.STATE_COMPLIANT:
            resolve_alert(host, compliance_metric(baseline), '合规基线“%s”已恢复' % baseline.name)
        scanned += 1
    return scanned


def scan_compliance_baselines():
    return sum(scan_compliance_baseline(baseline) for baseline in ComplianceBaseline.objects.prefetch_related('hosts'))


def dingtalk_signed_url(url, secret):
    if not secret:
        return url
    timestamp = str(int(time.time() * 1000))
    string_to_sign = '%s\n%s' % (timestamp, secret)
    digest = hmac.new(
        secret.encode('utf-8'),
        string_to_sign.encode('utf-8'),
        hashlib.sha256,
    ).digest()
    sign = urlparse.quote_plus(base64.b64encode(digest))
    separator = '&' if '?' in url else '?'
    return '%s%stimestamp=%s&sign=%s' % (url, separator, timestamp, sign)


def notification_payload(channel, event_type, title, content):
    if channel.channel_type in (NotificationChannel.TYPE_WECOM, NotificationChannel.TYPE_DINGTALK):
        return {
            'msgtype': 'text',
            'text': {
                'content': '%s\n%s' % (title, content),
            },
        }
    return {
        'event_type': event_type,
        'title': title,
        'content': content,
    }


def send_notification_channel(channel, event_type, title, content):
    dedup_seconds = getattr(settings, 'NOTIFICATION_DEDUP_SECONDS', 300)
    if dedup_seconds:
        since = timezone.now() - timezone.timedelta(seconds=dedup_seconds)
        recent = NotificationLog.objects.filter(
            channel=channel,
            event_type=event_type,
            title=title,
            content=content,
            created_at__gte=since,
        ).exists()
        if recent:
            return NotificationLog.objects.create(
                channel=channel,
                event_type=event_type,
                title=title,
                content=content,
                status=NotificationLog.STATUS_SUCCESS,
                response='deduped: %s秒内重复通知已跳过' % dedup_seconds,
            )

    url = channel.decrypted_webhook_url
    if not url:
        return NotificationLog.objects.create(
            channel=channel,
            event_type=event_type,
            title=title,
            content=content,
            status=NotificationLog.STATUS_FAILED,
            response='Webhook URL 为空或解密失败',
        )

    if channel.channel_type == NotificationChannel.TYPE_DINGTALK:
        url = dingtalk_signed_url(url, channel.decrypted_secret)

    payload = notification_payload(channel, event_type, title, content)
    attempts = max(1, int(getattr(settings, 'NOTIFICATION_RETRY_COUNT', 0) or 0) + 1)
    timeout = max(1, int(getattr(settings, 'NOTIFICATION_TIMEOUT_SECONDS', 5) or 5))
    status = NotificationLog.STATUS_FAILED
    response_message = ''
    for attempt in range(1, attempts + 1):
        try:
            response = requests.post(url, json=payload, timeout=timeout)
            response_text = response.text[:1000]
            response_message = 'HTTP %s %s' % (response.status_code, response_text)
            status = NotificationLog.STATUS_SUCCESS if response.status_code < 400 else NotificationLog.STATUS_FAILED
        except Exception as exc:
            response_message = str(exc)
            status = NotificationLog.STATUS_FAILED
        if status == NotificationLog.STATUS_SUCCESS:
            break
    if attempts > 1:
        response_message = '%s（已尝试 %s 次）' % (response_message, attempt)
    return NotificationLog.objects.create(
        channel=channel,
        event_type=event_type,
        title=title,
        content=content,
        status=status,
        response=response_message,
    )


def send_notifications(event_type, title, content):
    channels = NotificationChannel.objects.filter(enabled=True)
    if event_type == NotificationLog.EVENT_ALERT:
        channels = channels.filter(notify_alert=True)
    elif event_type == NotificationLog.EVENT_APPROVAL:
        channels = channels.filter(notify_approval=True)
    elif event_type == NotificationLog.EVENT_DEPLOYMENT:
        channels = channels.filter(notify_deployment=True)
    logs = []
    for channel in channels:
        logs.append(send_notification_channel(channel, event_type, title, content))
    return logs


def notify_alert(alert):
    host_name = alert.host.linux_name if alert.host else '-'
    title = '告警通知：%s %s' % (host_name, alert.metric or 'general')
    content = '级别：%s\n状态：%s\n内容：%s' % (
        alert.get_level_display() if hasattr(alert, 'get_level_display') else alert.level,
        alert.get_status_display() if hasattr(alert, 'get_status_display') else alert.status,
        alert.message,
    )
    logs = send_notifications(NotificationLog.EVENT_ALERT, title, content)
    try:
        from monitor.services import send_alert_event_notifications
        send_alert_event_notifications(alert, status=alert.status)
    except Exception:
        pass
    return logs


def notify_approval(approval, action):
    title = '审批%s：%s' % (action, approval.title)
    content = '类型：%s\n状态：%s\n申请人：%s\n审批人：%s\n原因：%s\n意见：%s' % (
        approval.get_request_type_display(),
        approval.get_status_display(),
        approval.requester or '-',
        approval.approver or '-',
        approval.reason or '-',
        approval.comment or '-',
    )
    return send_notifications(NotificationLog.EVENT_APPROVAL, title, content)


def notify_deployment(release, action='发布结果'):
    title = '%s：%s %s' % (action, release.app.name, release.version)
    content = '状态：%s\n摘要：%s\n提交人：%s' % (
        release.get_status_display(),
        release.summary or '-',
        release.created_by or '-',
    )
    return send_notifications(NotificationLog.EVENT_DEPLOYMENT, title, content)


def update_alert_status(alert, to_status, handler='', remark='', from_status=None):
    from_status = from_status if from_status is not None else alert.status
    alert.status = to_status
    alert.handler = handler
    alert.remark = remark
    alert.save()
    AlertHistory.objects.create(
        alert=alert,
        from_status=from_status,
        to_status=to_status,
        handler=handler,
        remark=remark,
    )
    return alert


def record_metric_sample(host, metric, value, collected_at=None, unit='percent'):
    return MetricSample.objects.create(
        host=host,
        metric=metric,
        value=float(value),
        unit=unit,
        collected_at=collected_at or timezone.now(),
    )


def cleanup_metric_samples(retention_days=None, now=None):
    days = retention_days
    if days is None:
        days = int(getattr(settings, 'METRIC_SAMPLE_RETENTION_DAYS', 0) or 0)
    days = int(days or 0)
    if days <= 0:
        return 0
    cutoff = (now or timezone.now()) - timezone.timedelta(days=days)
    deleted, details = MetricSample.objects.filter(collected_at__lt=cutoff).delete()
    return deleted


def latest_metric_map(hosts=None):
    hosts = hosts or []
    host_ids = [host.id for host in hosts]
    samples = MetricSample.objects.filter(host_id__in=host_ids) if host_ids else MetricSample.objects.none()
    result = {}
    for sample in samples.order_by('host_id', 'metric', '-collected_at'):
        key = (sample.host_id, sample.metric)
        if key not in result:
            result[key] = sample
    return result


def deployment_risk_preview(hosts, now=None):
    """Return read-only deployment risk data for the selected hosts."""
    hosts = list(hosts)
    host_ids = [host.id for host in hosts]
    if not host_ids:
        return {
            'hosts': hosts,
            'active_alerts': AlertEvent.objects.none(),
            'recent_releases': DeploymentRelease.objects.none(),
            'pending_approvals': ApprovalRequest.objects.none(),
            'host_metrics': [],
        }

    cutoff = (now or timezone.now()) - timezone.timedelta(hours=24)
    active_alerts = AlertEvent.objects.filter(
        host_id__in=host_ids,
        status__in=(AlertEvent.STATUS_OPEN, AlertEvent.STATUS_PROCESSING),
    ).select_related('host')
    recent_releases = DeploymentRelease.objects.filter(
        hosts__in=host_ids,
        created_at__gte=cutoff,
    ).select_related('app').distinct()
    pending_approvals = ApprovalRequest.objects.filter(
        request_type__in=(ApprovalRequest.TYPE_DEPLOYMENT, ApprovalRequest.TYPE_ROLLBACK),
        status=ApprovalRequest.STATUS_PENDING,
        deployment_release__hosts__in=host_ids,
    ).select_related('deployment_release__app').distinct()
    metrics = latest_metric_map(hosts)
    host_metrics = []
    for host in hosts:
        host_metrics.append({
            'host': host,
            'cpu': metrics.get((host.id, MetricSample.METRIC_CPU)),
            'memory': metrics.get((host.id, MetricSample.METRIC_MEMORY)),
            'disk': metrics.get((host.id, MetricSample.METRIC_DISK)),
        })
    return {
        'hosts': hosts,
        'active_alerts': active_alerts,
        'recent_releases': recent_releases,
        'pending_approvals': pending_approvals,
        'host_metrics': host_metrics,
    }


def validate_remote_path(remote_path):
    if not remote_path or not remote_path.startswith('/'):
        return False, '远端路径必须是绝对路径'
    normalized = posixpath.normpath(remote_path)
    if normalized in ('/', '.', ''):
        return False, '不能分发到根目录'
    if '..' in remote_path.split('/'):
        return False, '远端路径不能包含 ..'
    return True, normalized


def execute_file_distribution(distribution):
    if not claim_pending_work(FileDistribution, distribution, FileDistribution.STATUS_RUNNING):
        return distribution

    valid, normalized_path = validate_remote_path(distribution.remote_path)
    if not valid:
        distribution.status = FileDistribution.STATUS_BLOCKED
        distribution.summary = normalized_path
        distribution.finished_at = timezone.now()
        distribution.save()
        for host in distribution.hosts.all():
            FileDistributionResult.objects.create(
                distribution=distribution,
                host=host,
                status=CommandExecution.STATUS_BLOCKED,
                message=normalized_path,
            )
        return distribution

    distribution.remote_path = normalized_path
    distribution.save(update_fields=['remote_path'])
    success_count = 0
    failed_count = 0
    local_path = distribution.source_file.path
    for host in distribution.hosts.all():
        started = time.time()
        status = CommandExecution.STATUS_SUCCESS
        message = '分发成功'
        attempts = task_retry_count() + 1
        last_message = ''
        for attempt in range(1, attempts + 1):
            client = None
            try:
                client = create_host_ssh_client(host, timeout=ssh_connect_timeout())
                sftp = client.open_sftp()
                try:
                    sftp.put(local_path, normalized_path)
                finally:
                    sftp.close()
                status = CommandExecution.STATUS_SUCCESS
                message = '分发成功'
                break
            except Exception as exc:
                status = CommandExecution.STATUS_FAILED
                last_message = describe_ssh_error(exc)
                message = last_message
            finally:
                if client:
                    client.close()
            if status == CommandExecution.STATUS_FAILED and attempt < attempts:
                message = '%s，准备重试 %s/%s' % (last_message, attempt, attempts - 1)
        if status == CommandExecution.STATUS_FAILED and attempts > 1 and last_message:
            message = '%s（已尝试 %s 次）' % (last_message, attempts)
        if status == CommandExecution.STATUS_SUCCESS:
            success_count += 1
        else:
            failed_count += 1
        FileDistributionResult.objects.create(
            distribution=distribution,
            host=host,
            status=status,
            message=message,
            duration_ms=int((time.time() - started) * 1000),
        )

    if success_count and failed_count:
        distribution.status = FileDistribution.STATUS_PARTIAL
    elif success_count:
        distribution.status = FileDistribution.STATUS_SUCCESS
    else:
        distribution.status = FileDistribution.STATUS_FAILED
    distribution.summary = '成功 %s 台，失败 %s 台' % (success_count, failed_count)
    distribution.finished_at = timezone.now()
    distribution.save()
    return distribution


def create_deployment_result(release, host, action, record):
    return DeploymentResult.objects.create(
        release=release,
        host=host,
        action=action,
        command_execution=record,
        status=record.status,
        output=record.output,
        error=record.error,
        duration_ms=record.duration_ms,
    )


def execute_deployment_release(release, role=DevOpsRole.ROLE_OPERATOR):
    claimed = claim_pending_work(DeploymentRelease, release, DeploymentRelease.STATUS_RUNNING)
    if not claimed and not claim_running_deployment_if_empty(release, DeploymentResult.ACTION_DEPLOY):
        return release

    decision, policy = evaluate_command_policy(release.deploy_script, role)
    if decision != COMMAND_ALLOWED:
        message = command_denied_message(decision, policy)
        release.status = DeploymentRelease.STATUS_BLOCKED
        release.summary = message
        release.finished_at = timezone.now()
        release.save()
        for host in release.hosts.all():
            DeploymentResult.objects.create(
                release=release,
                host=host,
                action=DeploymentResult.ACTION_DEPLOY,
                status=CommandExecution.STATUS_BLOCKED,
                error=message,
            )
        notify_deployment(release)
        return release

    success_count = 0
    failed_count = 0
    for host in release.hosts.all():
        record = CommandExecution.objects.create(
            host=host,
            command=release.deploy_script,
            created_by=release.created_by,
        )
        execute_command_record(record, role)
        create_deployment_result(release, host, DeploymentResult.ACTION_DEPLOY, record)
        if record.status == CommandExecution.STATUS_SUCCESS:
            success_count += 1
        else:
            failed_count += 1

    if success_count and failed_count:
        release.status = DeploymentRelease.STATUS_PARTIAL
    elif success_count:
        release.status = DeploymentRelease.STATUS_SUCCESS
    else:
        release.status = DeploymentRelease.STATUS_FAILED
    release.summary = '成功 %s 台，失败 %s 台' % (success_count, failed_count)
    release.finished_at = timezone.now()
    release.save()
    notify_deployment(release)
    return release


def execute_deployment_rollback(release, role=DevOpsRole.ROLE_OPERATOR):
    claimed = claim_deployment_rollback(release)
    if not claimed and not claim_running_deployment_if_empty(release, DeploymentResult.ACTION_ROLLBACK):
        return release

    if not release.rollback_script.strip():
        release.status = DeploymentRelease.STATUS_FAILED
        release.summary = '未配置回滚脚本'
        release.finished_at = timezone.now()
        release.save(update_fields=['status', 'summary', 'finished_at'])
        notify_deployment(release, '回滚结果')
        return release

    decision, policy = evaluate_command_policy(release.rollback_script, role)
    if decision != COMMAND_ALLOWED:
        message = command_denied_message(decision, policy)
        release.status = DeploymentRelease.STATUS_FAILED
        release.summary = message
        release.finished_at = timezone.now()
        release.save(update_fields=['status', 'summary', 'finished_at'])
        for host in release.hosts.all():
            DeploymentResult.objects.create(
                release=release,
                host=host,
                action=DeploymentResult.ACTION_ROLLBACK,
                status=CommandExecution.STATUS_BLOCKED,
                error=message,
            )
        notify_deployment(release, '回滚结果')
        return release

    success_count = 0
    failed_count = 0
    for host in release.hosts.all():
        record = CommandExecution.objects.create(
            host=host,
            command=release.rollback_script,
            created_by=release.created_by,
        )
        execute_command_record(record, role)
        create_deployment_result(release, host, DeploymentResult.ACTION_ROLLBACK, record)
        if record.status == CommandExecution.STATUS_SUCCESS:
            success_count += 1
        else:
            failed_count += 1
    release.status = DeploymentRelease.STATUS_ROLLED_BACK if success_count else DeploymentRelease.STATUS_FAILED
    release.summary = '回滚成功 %s 台，失败 %s 台' % (success_count, failed_count)
    release.finished_at = timezone.now()
    release.save()
    notify_deployment(release, '回滚结果')
    return release


def create_command_approval(host, command, requester='', reason=''):
    approval = ApprovalRequest.objects.create(
        request_type=ApprovalRequest.TYPE_COMMAND,
        title='命令执行审批：%s' % host,
        host=host,
        command=command,
        requester=requester,
        reason=reason,
    )
    notify_approval(approval, '创建')
    return approval


def create_deployment_approval(release, requester='', reason=''):
    approval = ApprovalRequest.objects.create(
        request_type=ApprovalRequest.TYPE_DEPLOYMENT,
        title='发布审批：%s %s' % (release.app.name, release.version),
        deployment_release=release,
        requester=requester,
        reason=reason,
    )
    notify_approval(approval, '创建')
    return approval


def create_rollback_approval(release, requester='', reason=''):
    approval = ApprovalRequest.objects.create(
        request_type=ApprovalRequest.TYPE_ROLLBACK,
        title='回滚审批：%s %s' % (release.app.name, release.version),
        deployment_release=release,
        requester=requester,
        reason=reason,
    )
    notify_approval(approval, '创建')
    return approval


def execute_approval_request(approval, role=DevOpsRole.ROLE_ADMIN):
    if approval.request_type == ApprovalRequest.TYPE_COMMAND:
        record = CommandExecution.objects.create(
            host=approval.host,
            command=approval.command,
            created_by=approval.requester,
        )
        execute_command_record(record, role)
        approval.command_execution = record
        approval.status = ApprovalRequest.STATUS_EXECUTED if record.status != CommandExecution.STATUS_FAILED else ApprovalRequest.STATUS_FAILED
        approval.executed_at = timezone.now()
        approval.save()
        notify_approval(approval, '执行')
        return approval

    if approval.request_type == ApprovalRequest.TYPE_DEPLOYMENT and approval.deployment_release:
        execute_deployment_release(approval.deployment_release, role)
        approval.status = ApprovalRequest.STATUS_EXECUTED
        if approval.deployment_release.status == DeploymentRelease.STATUS_FAILED:
            approval.status = ApprovalRequest.STATUS_FAILED
        approval.executed_at = timezone.now()
        approval.save()
        notify_approval(approval, '执行')
        return approval

    if approval.request_type == ApprovalRequest.TYPE_ROLLBACK and approval.deployment_release:
        execute_deployment_rollback(approval.deployment_release, role)
        approval.status = ApprovalRequest.STATUS_EXECUTED
        if approval.deployment_release.status == DeploymentRelease.STATUS_FAILED:
            approval.status = ApprovalRequest.STATUS_FAILED
        approval.executed_at = timezone.now()
        approval.save()
        notify_approval(approval, '执行')
        return approval

    approval.status = ApprovalRequest.STATUS_FAILED
    approval.comment = '审批目标不存在'
    approval.executed_at = timezone.now()
    approval.save()
    notify_approval(approval, '执行')
    return approval
