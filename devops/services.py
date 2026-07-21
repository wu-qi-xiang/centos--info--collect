import base64
from datetime import timedelta
from decimal import Decimal, InvalidOperation
import hashlib
import hmac
import json
import math
import os
import re
import subprocess
import tempfile
import time
import posixpath
import shlex
try:
    import yaml
except ImportError:
    yaml = None
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
from django.db import models, transaction
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
    Incident,
    IncidentTimeline,
    AlertSilence,
    ApprovalRequest,
    AuditLog,
    BatchTask,
    BatchTaskResult,
    BackgroundJob,
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
    NotificationTemplate,
    AlertNotificationEscalation,
    ComplianceBaseline,
    ComplianceResult,
    DevOpsProject,
    DeploymentApp,
    HostGroup,
    HostTag,
    IntegrationHealthEvent,
    MaintenanceWindow,
    ServiceCatalog,
    ServiceSlo,
    RunbookTemplate,
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
PROMETHEUS_RULE_GROUP = 'monitoring.coreos.com'
PROMETHEUS_RULE_VERSION = 'v1'
PROMETHEUS_RULE_PLURAL = 'prometheusrules'
PROMETHEUS_RULE_KIND = 'PrometheusRule'
PROMETHEUS_RULE_API_VERSION = '%s/%s' % (
    PROMETHEUS_RULE_GROUP,
    PROMETHEUS_RULE_VERSION,
)
PROMETHEUS_RULE_LIST_MAX_PAGES = 1000
K8S_RESOURCE_NAME_PATTERN = re.compile(
    r'^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$'
)


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


def _prometheus_rule_result(ok=False, code='', message='', **values):
    result = {'ok': ok, 'code': code, 'message': message}
    result.update(values)
    return result


def _safe_prometheus_rule_identity(namespace, name):
    namespace = safe_k8s_namespace(namespace)
    name = (name or '').strip()
    if not namespace or not name or len(name) > 253 or not K8S_RESOURCE_NAME_PATTERN.match(name):
        return None, None
    return namespace, name


def _prometheus_rule_custom_objects_api(cluster):
    kubeconfig = getattr(cluster, 'decrypted_kubeconfig', '') or ''
    if not kubeconfig:
        raise ValueError('kubeconfig_unavailable')
    from kubernetes import client, config
    path = _k8s_temp_config(kubeconfig)
    api_client = None
    try:
        api_client = config.new_client_from_config(config_file=path)
        return client.CustomObjectsApi(api_client), api_client, path
    except Exception:
        _close_prometheus_rule_api_client(api_client)
        try:
            os.unlink(path)
        except OSError:
            pass
        raise


def _close_prometheus_rule_api_client(api_client):
    close = getattr(api_client, 'close', None)
    if callable(close):
        try:
            close()
        except Exception:
            pass


def _prometheus_rule_error(exc):
    status = getattr(exc, 'status', None)
    name = exc.__class__.__name__.lower()
    if status == 409:
        return _prometheus_rule_result(False, 'conflict', '规则已被其他操作更新，请刷新后重试。')
    if status == 403:
        return _prometheus_rule_result(False, 'forbidden', '当前集群权限不足，无法操作 PrometheusRule。')
    if status == 404:
        return _prometheus_rule_result(False, 'crd_not_found', '集群未安装 PrometheusRule CRD，或规则不存在。')
    if status in (401,):
        return _prometheus_rule_result(False, 'forbidden', '当前集群认证无效，无法操作 PrometheusRule。')
    if isinstance(exc, (TimeoutError,)) or 'timeout' in name or 'timeouterror' in name:
        return _prometheus_rule_result(False, 'timeout', '连接 Kubernetes 集群超时，请稍后重试。')
    if isinstance(exc, ValueError) and str(exc) == 'kubeconfig_unavailable':
        return _prometheus_rule_result(False, 'offline', '集群 kubeconfig 无法解密或为空。')
    if isinstance(exc, ImportError):
        return _prometheus_rule_result(False, 'dependency_missing', '缺少 kubernetes Python 依赖，无法操作 PrometheusRule。')
    return _prometheus_rule_result(False, 'offline', '无法连接 Kubernetes 集群，请确认集群状态后重试。')


def _validate_prometheus_rule_yaml(yaml_text, namespace, name):
    namespace, name = _safe_prometheus_rule_identity(namespace, name)
    if not namespace or not name:
        return None, _prometheus_rule_result(False, 'invalid_yaml', '规则命名空间或名称无效。')
    if not yaml:
        return None, _prometheus_rule_result(False, 'dependency_missing', '缺少 YAML 解析依赖，无法更新 PrometheusRule。')
    try:
        documents = list(yaml.safe_load_all(yaml_text))
    except Exception:
        return None, _prometheus_rule_result(False, 'invalid_yaml', '规则 YAML 格式无效。')
    if len(documents) != 1 or not isinstance(documents[0], dict):
        return None, _prometheus_rule_result(False, 'invalid_yaml', '规则 YAML 必须且只能包含一个对象。')
    document = documents[0]
    metadata = document.get('metadata')
    if document.get('apiVersion') != PROMETHEUS_RULE_API_VERSION or document.get('kind') != PROMETHEUS_RULE_KIND:
        return None, _prometheus_rule_result(False, 'invalid_yaml', '规则 YAML 必须是 monitoring.coreos.com/v1 PrometheusRule。')
    if not isinstance(metadata, dict):
        return None, _prometheus_rule_result(False, 'invalid_yaml', '规则 YAML 缺少 metadata。')
    document_name = metadata.get('name')
    document_namespace = metadata.get('namespace')
    resource_version = metadata.get('resourceVersion')
    if not all(isinstance(value, str) and value.strip() for value in (document_name, document_namespace, resource_version)):
        return None, _prometheus_rule_result(False, 'invalid_yaml', '规则 YAML 必须包含 metadata.name、metadata.namespace 和 metadata.resourceVersion。')
    if document_name.strip() != name or document_namespace.strip() != namespace:
        return None, _prometheus_rule_result(False, 'invalid_yaml', '规则 YAML 的名称或命名空间与当前选择不一致。')
    metadata['name'] = name
    metadata['namespace'] = namespace
    metadata['resourceVersion'] = resource_version.strip()
    return document, None


def _prometheus_rule_summary(item):
    metadata = item.get('metadata') if isinstance(item, dict) else {}
    metadata = metadata if isinstance(metadata, dict) else {}
    namespace, name = _safe_prometheus_rule_identity(metadata.get('namespace'), metadata.get('name'))
    if not namespace or not name:
        return None
    return {
        'namespace': namespace,
        'name': name,
        'resource_version': str(metadata.get('resourceVersion') or ''),
        'created_at': str(metadata.get('creationTimestamp') or ''),
    }


def list_prometheus_rules(cluster, timeout=8):
    path = ''
    api_client = None
    try:
        api, api_client, path = _prometheus_rule_custom_objects_api(cluster)
        rules = []
        continuation_token = ''
        seen_continuation_tokens = set()
        for _ in range(PROMETHEUS_RULE_LIST_MAX_PAGES):
            request_kwargs = {
                'group': PROMETHEUS_RULE_GROUP,
                'version': PROMETHEUS_RULE_VERSION,
                'plural': PROMETHEUS_RULE_PLURAL,
                '_request_timeout': timeout,
            }
            if continuation_token:
                request_kwargs['_continue'] = continuation_token
            response = api.list_cluster_custom_object(**request_kwargs)
            items = response.get('items', []) if isinstance(response, dict) else []
            rules.extend(summary for summary in (
                _prometheus_rule_summary(item) for item in items
            ) if summary)
            metadata = response.get('metadata', {}) if isinstance(response, dict) else {}
            next_token = metadata.get('continue') or metadata.get('_continue') if isinstance(metadata, dict) else ''
            if not isinstance(next_token, str) or not next_token.strip():
                rules.sort(key=lambda item: (item['namespace'], item['name']))
                return _prometheus_rule_result(True, 'ok', 'PrometheusRule 读取成功。', rules=rules)
            continuation_token = next_token.strip()
            if continuation_token in seen_continuation_tokens:
                return _prometheus_rule_result(False, 'pagination_error', 'PrometheusRule 列表分页令牌异常，请稍后重试。')
            seen_continuation_tokens.add(continuation_token)
        return _prometheus_rule_result(False, 'pagination_error', 'PrometheusRule 列表分页次数超过安全上限，请稍后重试。')
    except Exception as exc:
        return _prometheus_rule_error(exc)
    finally:
        _close_prometheus_rule_api_client(api_client)
        if path:
            try:
                os.unlink(path)
            except OSError:
                pass


def get_prometheus_rule(cluster, namespace, name, timeout=8):
    namespace, name = _safe_prometheus_rule_identity(namespace, name)
    if not namespace or not name:
        return _prometheus_rule_result(False, 'invalid_identity', '规则命名空间或名称无效。')
    path = ''
    api_client = None
    try:
        api, api_client, path = _prometheus_rule_custom_objects_api(cluster)
        rule = api.get_namespaced_custom_object(
            group=PROMETHEUS_RULE_GROUP, version=PROMETHEUS_RULE_VERSION,
            namespace=namespace, plural=PROMETHEUS_RULE_PLURAL, name=name,
            _request_timeout=timeout,
        )
        if not yaml:
            return _prometheus_rule_result(False, 'dependency_missing', '缺少 YAML 解析依赖，无法查看 PrometheusRule。')
        yaml_text = yaml.safe_dump(rule, allow_unicode=True, sort_keys=False)
        return _prometheus_rule_result(True, 'ok', 'PrometheusRule 读取成功。', rule=rule, yaml=yaml_text)
    except Exception as exc:
        return _prometheus_rule_error(exc)
    finally:
        _close_prometheus_rule_api_client(api_client)
        if path:
            try:
                os.unlink(path)
            except OSError:
                pass


def replace_prometheus_rule(cluster, namespace, name, yaml_text, timeout=8):
    rule, error = _validate_prometheus_rule_yaml(yaml_text, namespace, name)
    if error:
        return error
    namespace = rule['metadata']['namespace']
    name = rule['metadata']['name']
    path = ''
    api_client = None
    try:
        api, api_client, path = _prometheus_rule_custom_objects_api(cluster)
        updated = api.replace_namespaced_custom_object(
            group=PROMETHEUS_RULE_GROUP, version=PROMETHEUS_RULE_VERSION,
            namespace=namespace, plural=PROMETHEUS_RULE_PLURAL, name=name,
            body=rule, _request_timeout=timeout,
        )
        return _prometheus_rule_result(True, 'ok', 'PrometheusRule 已同步到集群。', rule=updated)
    except Exception as exc:
        return _prometheus_rule_error(exc)
    finally:
        _close_prometheus_rule_api_client(api_client)
        if path:
            try:
                os.unlink(path)
            except OSError:
                pass


def delete_prometheus_rule(cluster, namespace, name, resource_version, timeout=8):
    namespace, name = _safe_prometheus_rule_identity(namespace, name)
    resource_version = (resource_version or '').strip()
    if not namespace or not name or not resource_version:
        return _prometheus_rule_result(False, 'invalid_identity', '规则命名空间、名称或资源版本无效。')
    path = ''
    api_client = None
    try:
        api, api_client, path = _prometheus_rule_custom_objects_api(cluster)
        api.delete_namespaced_custom_object(
            group=PROMETHEUS_RULE_GROUP, version=PROMETHEUS_RULE_VERSION,
            namespace=namespace, plural=PROMETHEUS_RULE_PLURAL, name=name,
            body={'preconditions': {'resourceVersion': resource_version}},
            _request_timeout=timeout,
        )
        return _prometheus_rule_result(True, 'ok', 'PrometheusRule 已从集群删除。')
    except Exception as exc:
        return _prometheus_rule_error(exc)
    finally:
        _close_prometheus_rule_api_client(api_client)
        if path:
            try:
                os.unlink(path)
            except OSError:
                pass


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
    job_type, target_id, role = background_job_spec(target, args, kwargs)
    return BackgroundJob.objects.create(
        job_type=job_type,
        target_id=target_id,
        role=role,
    )


def background_job_spec(target, args, kwargs):
    """Convert a supported execution call into a safe durable queue reference."""
    if kwargs and set(kwargs) != set(['role']):
        raise ValueError('后台任务仅支持 role 参数')
    if not args:
        raise ValueError('后台任务缺少目标记录')

    obj = args[0]
    role = kwargs.get('role', args[1] if len(args) > 1 else '')
    if len(args) > 2 or (role and not isinstance(role, str)):
        raise ValueError('后台任务参数无效')

    supported = (
        (execute_command_record, CommandExecution, BackgroundJob.TYPE_COMMAND),
        (execute_batch_task, BatchTask, BackgroundJob.TYPE_BATCH_TASK),
        (execute_file_distribution, FileDistribution, BackgroundJob.TYPE_FILE_DISTRIBUTION),
        (execute_deployment_release, DeploymentRelease, BackgroundJob.TYPE_DEPLOYMENT),
        (execute_deployment_rollback, DeploymentRelease, BackgroundJob.TYPE_ROLLBACK),
    )
    for expected_target, model_class, job_type in supported:
        if target is expected_target and isinstance(obj, model_class) and obj.pk:
            if job_type == BackgroundJob.TYPE_FILE_DISTRIBUTION and role:
                raise ValueError('文件分发任务不支持 role 参数')
            return job_type, obj.pk, role
    raise ValueError('不支持的后台任务类型')


def claim_next_background_job():
    """Atomically claim one pending row without holding a transaction for I/O."""
    candidate_ids = BackgroundJob.objects.filter(
        status=BackgroundJob.STATUS_PENDING,
    ).order_by('id').values_list('id', flat=True)[:20]
    now = timezone.now()
    for job_id in candidate_ids:
        updated = BackgroundJob.objects.filter(
            id=job_id,
            status=BackgroundJob.STATUS_PENDING,
        ).update(
            status=BackgroundJob.STATUS_RUNNING,
            attempts=models.F('attempts') + 1,
            started_at=now,
            finished_at=None,
            error='',
        )
        if updated:
            return BackgroundJob.objects.get(id=job_id)
    return None


def background_job_target(job):
    targets = {
        BackgroundJob.TYPE_COMMAND: (CommandExecution, execute_command_record),
        BackgroundJob.TYPE_BATCH_TASK: (BatchTask, execute_batch_task),
        BackgroundJob.TYPE_FILE_DISTRIBUTION: (FileDistribution, execute_file_distribution),
        BackgroundJob.TYPE_DEPLOYMENT: (DeploymentRelease, execute_deployment_release),
        BackgroundJob.TYPE_ROLLBACK: (DeploymentRelease, execute_deployment_rollback),
    }
    model_class, target = targets[job.job_type]
    obj = model_class.objects.filter(id=job.target_id).first()
    if obj is None:
        raise ValueError('后台任务目标不存在')
    return target, obj


def process_background_job(job):
    """Run a claimed job and record the worker result after remote work finishes."""
    try:
        target, obj = background_job_target(job)
        if job.job_type == BackgroundJob.TYPE_FILE_DISTRIBUTION:
            target(obj)
        elif job.role:
            target(obj, job.role)
        else:
            target(obj)
    except Exception as exc:
        mark_background_failure(target if 'target' in locals() else job.job_type, (obj,) if 'obj' in locals() else (), exc)
        if 'obj' in locals() and isinstance(obj, CommandExecution):
            finalize_command_approval(obj)
        message = '后台任务异常：%s' % exc
        BackgroundJob.objects.filter(id=job.id, status=BackgroundJob.STATUS_RUNNING).update(
            status=BackgroundJob.STATUS_FAILED,
            error=message[:500],
            finished_at=timezone.now(),
        )
        return False

    if isinstance(obj, CommandExecution):
        finalize_command_approval(obj)
    BackgroundJob.objects.filter(id=job.id, status=BackgroundJob.STATUS_RUNNING).update(
        status=BackgroundJob.STATUS_SUCCESS,
        finished_at=timezone.now(),
    )
    return True


def fail_timed_out_background_jobs(timeout_seconds):
    """Fail abandoned claims rather than replaying ambiguous remote operations."""
    try:
        timeout_seconds = int(timeout_seconds)
    except (TypeError, ValueError):
        return 0
    if timeout_seconds <= 0:
        return 0
    expired_before = timezone.now() - timedelta(seconds=timeout_seconds)
    jobs = list(BackgroundJob.objects.filter(
        status=BackgroundJob.STATUS_RUNNING,
        started_at__lt=expired_before,
    ).order_by('id')[:100])
    failed = 0
    message = '后台任务超时，未自动重放以避免重复远程操作'
    for job in jobs:
        updated = BackgroundJob.objects.filter(
            id=job.id,
            status=BackgroundJob.STATUS_RUNNING,
        ).update(status=BackgroundJob.STATUS_FAILED, error=message, finished_at=timezone.now())
        if not updated:
            continue
        failed += 1
        try:
            target, obj = background_job_target(job)
        except Exception:
            target, obj = job.job_type, None
        mark_background_failure(target, (obj,) if obj else (), RuntimeError(message))
        if isinstance(obj, CommandExecution):
            finalize_command_approval(obj)
    return failed


BACKGROUND_JOB_DEFAULT_TIMEOUT_SECONDS = 300
BACKGROUND_JOB_RECENT_WINDOW = timedelta(hours=1)
WORKER_ALERT_METRIC_PENDING = 'worker:pending'
WORKER_ALERT_METRIC_FAILURE_RATE = 'worker:failure_rate'
WORKER_ALERT_METRIC_TIMED_OUT = 'worker:timed_out'

WORKER_ALERT_THRESHOLDS = (
    (
        'DEVOPS_WORKER_ALERT_PENDING_THRESHOLD',
        WORKER_ALERT_METRIC_PENDING,
        'pending',
        AlertEvent.LEVEL_WARNING,
        'Worker 待处理任务数',
    ),
    (
        'DEVOPS_WORKER_ALERT_FAILURE_RATE_PERCENT_THRESHOLD',
        WORKER_ALERT_METRIC_FAILURE_RATE,
        'recent_failure_rate_percent',
        AlertEvent.LEVEL_WARNING,
        'Worker 最近一小时任务失败率',
    ),
    (
        'DEVOPS_WORKER_ALERT_TIMED_OUT_THRESHOLD',
        WORKER_ALERT_METRIC_TIMED_OUT,
        'timed_out',
        AlertEvent.LEVEL_WARNING,
        'Worker 超时任务数',
    ),
)


def _positive_worker_alert_threshold(setting_name):
    """Return an enabled numeric worker threshold, otherwise ``None``."""
    try:
        threshold = float(getattr(settings, setting_name, 0))
    except (TypeError, ValueError):
        return None
    return threshold if math.isfinite(threshold) and threshold > 0 else None


def worker_alert_summary_values(summary=None):
    """Return the Worker alert values using public threshold units.

    Queue counts are integers and the rolling failure ratio is converted from
    the internal 0.0--1.0 representation to the configured 0--100 percentage.
    """
    summary = summary if summary is not None else summarize_background_jobs()
    try:
        pending = float(summary['pending'])
        timed_out = float(summary['timed_out'])
        failure_rate_percent = float(summary['recent_failure_rate']) * 100
    except (KeyError, TypeError, ValueError):
        raise ValueError('Worker 汇总缺少有效的阈值告警数值。')
    values = {
        'pending': pending,
        'recent_failure_rate_percent': failure_rate_percent,
        'timed_out': timed_out,
    }
    if not all(math.isfinite(value) for value in values.values()):
        raise ValueError('Worker 汇总缺少有效的阈值告警数值。')
    return values


def summarize_background_jobs(timeout_seconds=None, now=None):
    """Return numeric-only queue health aggregates without changing job state.

    ``recent_*`` values cover completed jobs whose ``finished_at`` is within the
    preceding one-hour window.  Invalid worker timeout configuration falls back
    to 300 seconds so a status read remains available during misconfiguration.
    """
    if timeout_seconds is None:
        timeout_seconds = getattr(
            settings,
            'DEVOPS_WORKER_JOB_TIMEOUT_SECONDS',
            BACKGROUND_JOB_DEFAULT_TIMEOUT_SECONDS,
        )
    try:
        timeout_seconds = int(timeout_seconds)
    except (TypeError, ValueError):
        timeout_seconds = BACKGROUND_JOB_DEFAULT_TIMEOUT_SECONDS
    if timeout_seconds <= 0:
        timeout_seconds = BACKGROUND_JOB_DEFAULT_TIMEOUT_SECONDS

    now = now or timezone.now()
    status_counts = {
        row['status']: row['total']
        for row in BackgroundJob.objects.values('status').annotate(
            total=models.Count('id'),
        )
    }
    expired_before = now - timedelta(seconds=timeout_seconds)
    timed_out = BackgroundJob.objects.filter(
        status=BackgroundJob.STATUS_RUNNING,
        started_at__lt=expired_before,
    ).count()

    recent_counts = {
        row['status']: row['total']
        for row in BackgroundJob.objects.filter(
            status__in=(BackgroundJob.STATUS_SUCCESS, BackgroundJob.STATUS_FAILED),
            finished_at__gte=now - BACKGROUND_JOB_RECENT_WINDOW,
        ).values('status').annotate(total=models.Count('id'))
    }
    recent_completed = sum(recent_counts.values())
    recent_failed = recent_counts.get(BackgroundJob.STATUS_FAILED, 0)

    return {
        'pending': status_counts.get(BackgroundJob.STATUS_PENDING, 0),
        'running': status_counts.get(BackgroundJob.STATUS_RUNNING, 0),
        'success': status_counts.get(BackgroundJob.STATUS_SUCCESS, 0),
        'failed': status_counts.get(BackgroundJob.STATUS_FAILED, 0),
        'timed_out': timed_out,
        'recent_completed': recent_completed,
        'recent_failed': recent_failed,
        'recent_failure_rate': (
            float(recent_failed) / recent_completed if recent_completed else 0.0
        ),
    }


def evaluate_worker_alert_thresholds(summary=None):
    """Record or resolve system Worker alerts from the read-only queue summary.

    A threshold at or below zero (and malformed values) disables that individual
    check.  Failure-rate thresholds use the summary's 0.0--1.0 ratio.
    """
    values = worker_alert_summary_values(summary)
    alerts = {}
    for setting_name, metric, summary_key, level, label in WORKER_ALERT_THRESHOLDS:
        threshold = _positive_worker_alert_threshold(setting_name)
        if threshold is None:
            alerts[metric] = None
            continue
        value = values[summary_key]
        if value >= threshold:
            alert, created = record_alert(
                None,
                metric,
                '%s为 %s，达到阈值 %s。' % (label, value, threshold),
                level,
            )
            alerts[metric] = {'alert': alert, 'created': created, 'triggered': True}
        else:
            alerts[metric] = {
                'alert': resolve_alert(
                    None,
                    metric,
                    '%s已恢复正常：当前值 %s，阈值 %s。' % (label, value, threshold),
                ),
                'created': False,
                'triggered': False,
            }
    return alerts


INTEGRATION_HEALTH_SUMMARIES = {
    IntegrationHealthEvent.CATEGORY_OK: '连接或投递正常',
    IntegrationHealthEvent.CATEGORY_HTTP_ERROR: '远端返回 HTTP 错误',
    IntegrationHealthEvent.CATEGORY_TIMEOUT: '请求超时',
    IntegrationHealthEvent.CATEGORY_REQUEST_ERROR: '请求异常',
    IntegrationHealthEvent.CATEGORY_CONFIGURATION: '配置不可用',
    IntegrationHealthEvent.CATEGORY_VALIDATION_ERROR: '请求校验失败',
    IntegrationHealthEvent.CATEGORY_REJECTED: '请求已拒绝',
    IntegrationHealthEvent.CATEGORY_DUPLICATE: '重复投递已忽略',
    IntegrationHealthEvent.CATEGORY_UNAVAILABLE: '服务暂不可用',
    IntegrationHealthEvent.CATEGORY_INTERNAL_ERROR: '处理异常',
}


def _integration_health_source(source=None, source_id=None, source_name=''):
    """Return a safe configuration/channel reference without serializing values."""
    if source is not None:
        if isinstance(source, int):
            source_id = source
        elif isinstance(source, str):
            source_name = source
        else:
            source_id = getattr(source, 'pk', source_id)
            source_name = getattr(source, 'name', source_name)

    try:
        source_id = int(source_id) if source_id not in (None, '') else None
    except (TypeError, ValueError):
        raise ValueError('集成来源编号无效')
    if source_id is not None and source_id <= 0:
        raise ValueError('集成来源编号无效')

    source_name = str(source_name or '').replace('\n', ' ').replace('\r', ' ').strip()
    # References are labels only. Drop URL-like or query-like input rather than
    # risking an endpoint, token, or other secret entering this audit table.
    if any(marker in source_name for marker in ('://', '/', '?', '&', '=', '@')):
        source_name = ''
    source_name = re.sub(r'[^\w .()#-]', '', source_name).strip()[:100]
    return source_id, source_name


def _integration_health_status(status, category):
    allowed_types = set(item[0] for item in IntegrationHealthEvent.TYPE_CHOICES)
    allowed_statuses = set(item[0] for item in IntegrationHealthEvent.STATUS_CHOICES)
    allowed_categories = set(item[0] for item in IntegrationHealthEvent.CATEGORY_CHOICES)
    if status not in allowed_statuses:
        raise ValueError('集成健康状态无效')
    if not category:
        category = (IntegrationHealthEvent.CATEGORY_OK
                    if status == IntegrationHealthEvent.STATUS_SUCCESS
                    else IntegrationHealthEvent.CATEGORY_INTERNAL_ERROR)
    if category not in allowed_categories:
        raise ValueError('集成健康分类无效')
    if status == IntegrationHealthEvent.STATUS_SUCCESS and category not in (
            IntegrationHealthEvent.CATEGORY_OK,
            IntegrationHealthEvent.CATEGORY_DUPLICATE):
        raise ValueError('成功事件仅支持正常或重复分类')
    return allowed_types, category


def integration_health_summary(category, summary=''):
    """Return a fixed safe message; never persist caller or remote response text."""
    return INTEGRATION_HEALTH_SUMMARIES[category]


def record_integration_health_event(integration_type, source=None,
                                    status=IntegrationHealthEvent.STATUS_SUCCESS,
                                    category='', summary='', occurred_at=None,
                                    source_id=None, source_name=''):
    """Append a safe outcome for a configured external integration.

    ``summary`` is deliberately accepted only for a stable caller signature and
    is discarded.  Categories select the fixed summaries above, so raw response
    bodies, webhook payloads, headers, URLs, and exception messages cannot be
    written to this table.
    """
    allowed_types, category = _integration_health_status(status, category)
    if integration_type not in allowed_types:
        raise ValueError('集成类型无效')
    source_id, source_name = _integration_health_source(source, source_id, source_name)
    return IntegrationHealthEvent.objects.create(
        integration_type=integration_type,
        source_id=source_id,
        source_name=source_name,
        status=status,
        category=category,
        summary=integration_health_summary(category, summary),
        occurred_at=occurred_at or timezone.now(),
    )


def summarize_integration_health(integration_type, source=None, source_id=None,
                                 source_name='', recent_since=None):
    """Return safe status counts and latest outcome for one integration reference."""
    allowed_types, unused_category = _integration_health_status(
        IntegrationHealthEvent.STATUS_SUCCESS, IntegrationHealthEvent.CATEGORY_OK)
    if integration_type not in allowed_types:
        raise ValueError('集成类型无效')
    source_id, source_name = _integration_health_source(source, source_id, source_name)
    events = IntegrationHealthEvent.objects.filter(integration_type=integration_type)
    if source_id is not None:
        events = events.filter(source_id=source_id)
    if source_name:
        events = events.filter(source_name=source_name)

    latest = events.first()
    consecutive_failures = 0
    for event in events.only('status'):
        if event.status != IntegrationHealthEvent.STATUS_FAILED:
            break
        consecutive_failures += 1

    recent_since = recent_since or (timezone.now() - timedelta(hours=24))
    recent_events = events.filter(occurred_at__gte=recent_since)
    recent_event_counts = {
        'total': recent_events.count(),
        IntegrationHealthEvent.STATUS_SUCCESS: recent_events.filter(
            status=IntegrationHealthEvent.STATUS_SUCCESS).count(),
        IntegrationHealthEvent.STATUS_FAILED: recent_events.filter(
            status=IntegrationHealthEvent.STATUS_FAILED).count(),
    }
    current_status = latest.status if latest else 'unknown'
    return {
        'integration_type': integration_type,
        'source_id': source_id,
        'source_name': source_name,
        'current_state': current_status,
        'current_status': current_status,
        'latest_check': latest.occurred_at if latest else None,
        'latest_category': latest.category if latest else '',
        'latest_summary': latest.summary if latest else '',
        'consecutive_failures': consecutive_failures,
        'recent_since': recent_since,
        'recent_event_counts': recent_event_counts,
    }


def process_next_background_job(max_attempts=1):
    job = claim_next_background_job()
    if job is None:
        return None
    try:
        max_attempts = max(1, int(max_attempts))
    except (TypeError, ValueError):
        max_attempts = 1
    if job.attempts > max_attempts:
        message = '后台任务超过最大尝试次数'
        BackgroundJob.objects.filter(id=job.id).update(
            status=BackgroundJob.STATUS_FAILED,
            error=message,
            finished_at=timezone.now(),
        )
        if job.job_type == BackgroundJob.TYPE_COMMAND:
            record = CommandExecution.objects.filter(id=job.target_id).first()
            if record:
                mark_background_failure('process_next_background_job', (record,), RuntimeError(message))
                finalize_command_approval(record)
        return job
    process_background_job(job)
    return job


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


def revoke_module_permission(request, permission):
    """Remove one explicit override and record its return to global-role behavior."""
    permission_id = permission.id
    with transaction.atomic():
        locked_permission = DevOpsModulePermission.objects.select_for_update().select_related('user').filter(
            id=permission_id,
        ).first()
        if not locked_permission:
            return False
        detail = '用户=%s, 模块=%s, 旧角色=%s, 结果=继承全局角色' % (
            locked_permission.user.user,
            locked_permission.module,
            locked_permission.role,
        )
        locked_permission.delete()
        audit(request, '撤销模块权限', 'DevOpsModulePermission', permission_id, detail)
    return True


def clear_module_permissions(request, user):
    """Remove only the selected user's explicit module overrides."""
    with transaction.atomic():
        permissions = list(DevOpsModulePermission.objects.select_for_update().filter(user=user).order_by('module'))
        before = ','.join('%s:%s' % (permission.module, permission.role) for permission in permissions) or '-'
        detail = '用户=%s, 旧模块权限=%s, 结果=继承全局角色' % (user.user, before)
        permission_ids = [permission.id for permission in permissions]
        if permission_ids:
            DevOpsModulePermission.objects.filter(id__in=permission_ids).delete()
        audit(request, '清空模块权限', 'User', user.id, detail)
    return len(permissions)


def create_project_onboarding(request, cleaned_data):
    """Create the project aggregate and its optional catalog records atomically."""
    username = request.session.get('user_name', '')
    with transaction.atomic():
        project = DevOpsProject.objects.create(
            name=cleaned_data['name'],
            owner=cleaned_data.get('owner', ''),
            description=cleaned_data.get('description', ''),
            monitoring_enabled=cleaned_data.get('monitoring_enabled', False),
            monitor_cpu=cleaned_data.get('monitor_cpu', '80%'),
            monitor_memory=cleaned_data.get('monitor_memory', '80%'),
            monitor_disk=cleaned_data.get('monitor_disk', '80%'),
            created_by=username,
        )
        hosts = list(cleaned_data.get('hosts') or [])
        groups = list(cleaned_data.get('groups') or [])
        tags = list(cleaned_data.get('tags') or [])
        services = list(cleaned_data.get('services') or [])
        apps = list(cleaned_data.get('deployment_apps') or [])
        group_name = cleaned_data.get('create_group_name', '')
        if group_name:
            group = HostGroup.objects.create(name=group_name, created_by=username)
            group.hosts.set(hosts)
            groups.append(group)
        tag_name = cleaned_data.get('create_tag_name', '')
        if tag_name:
            tag = HostTag.objects.create(name=tag_name, created_by=username)
            tag.hosts.set(hosts)
            tags.append(tag)
        service_name = cleaned_data.get('create_service_name', '')
        if service_name:
            service = ServiceCatalog.objects.create(name=service_name, owner=project.owner, created_by=username)
            service.hosts.set(hosts)
            services.append(service)
        app_name = cleaned_data.get('create_app_name', '')
        if app_name:
            apps.append(DeploymentApp.objects.create(
                name=app_name,
                repository=cleaned_data.get('create_app_repository') or None,
                created_by=username,
            ))
        project.hosts.set(hosts)
        project.groups.set(groups)
        project.tags.set(tags)
        project.services.set(services)
        project.deployment_apps.set(apps)
        audit(request, '项目接入', 'DevOpsProject', project.id, '项目=%s, 主机=%s, 服务=%s, 应用=%s' % (
            project.name, len(hosts), len(services), len(apps),
        ))
    return project


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


def _permission_cache(request):
	cache = getattr(request, '_devops_permission_cache', None)
	if cache is None:
		cache = {}
		request._devops_permission_cache = cache
	return cache


def user_role(request):
	permission_cache = _permission_cache(request)
	if 'user_role' in permission_cache:
		return permission_cache['user_role']
	user_id = request.session.get('user_id')
	if not user_id:
		permission_cache['user_role'] = DevOpsRole.ROLE_VIEWER
		return permission_cache['user_role']
	try:
		permission_cache['user_role'] = DevOpsRole.objects.get(user_id=user_id).role
	except DevOpsRole.DoesNotExist:
		permission_cache['user_role'] = DevOpsRole.ROLE_ADMIN if not DevOpsRole.objects.exists() else DevOpsRole.ROLE_OPERATOR
	return permission_cache['user_role']


def module_role(request, module=''):
	permission_cache = _permission_cache(request)
	module_roles = permission_cache.setdefault('module_roles', {})
	if module in module_roles:
		return module_roles[module]
	base_role = user_role(request)
	user_id = request.session.get('user_id')
	if not user_id or not module:
		module_roles[module] = base_role
		return module_roles[module]
	try:
		module_roles[module] = DevOpsModulePermission.objects.get(user_id=user_id, module=module).role
	except DevOpsModulePermission.DoesNotExist:
		module_roles[module] = base_role
	return module_roles[module]


def has_role(request, minimum_role, module=''):
	permission_cache = _permission_cache(request)
	role_results = permission_cache.setdefault('role_results', {})
	cache_key = (minimum_role, module)
	if cache_key in role_results:
		return role_results[cache_key]
	resolved_module_role = module_role(request, module)
	if resolved_module_role == DevOpsModulePermission.ROLE_NONE:
		role_results[cache_key] = False
		return False
	if request.session.get('user_id') and not has_configured_role(request):
		role_results[cache_key] = ROLE_RANKS.get(DevOpsRole.ROLE_OPERATOR, 0) >= ROLE_RANKS.get(minimum_role, 0)
		return role_results[cache_key]
	role_results[cache_key] = ROLE_RANKS.get(resolved_module_role, 0) >= ROLE_RANKS.get(minimum_role, 0)
	return role_results[cache_key]


def host_scope_for_request(request):
    user_id = request.session.get('user_id')
    if not user_id:
        return None
    try:
        return DevOpsHostScope.objects.get(user_id=user_id)
    except DevOpsHostScope.DoesNotExist:
        return None


def has_explicit_admin_role(request):
	permission_cache = _permission_cache(request)
	if 'has_explicit_admin_role' in permission_cache:
		return permission_cache['has_explicit_admin_role']
	user_id = request.session.get('user_id')
	if not user_id:
		permission_cache['has_explicit_admin_role'] = False
		return False
	try:
		permission_cache['has_explicit_admin_role'] = DevOpsRole.objects.get(user_id=user_id).role == DevOpsRole.ROLE_ADMIN
	except DevOpsRole.DoesNotExist:
		permission_cache['has_explicit_admin_role'] = not DevOpsRole.objects.exists()
	return permission_cache['has_explicit_admin_role']


def has_configured_role(request):
	permission_cache = _permission_cache(request)
	if 'has_configured_role' in permission_cache:
		return permission_cache['has_configured_role']
	user_id = request.session.get('user_id')
	if not user_id:
		permission_cache['has_configured_role'] = False
		return False
	permission_cache['has_configured_role'] = DevOpsRole.objects.filter(user_id=user_id).exists()
	return permission_cache['has_configured_role']


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


def can_decide_deployment_approval(request, approval):
    """A deployment approval is actionable only when every release host is visible."""
    if approval.request_type == ApprovalRequest.TYPE_COMMAND and approval.host_id:
        return can_access_host(request, approval.host)
    if approval.request_type != ApprovalRequest.TYPE_DEPLOYMENT or not approval.deployment_release_id:
        return True
    return can_access_hosts(request, approval.deployment_release.hosts.all())


def incident_reference_hosts(incident):
    hosts = []
    if incident.host_id:
        hosts.append(incident.host)
    if incident.alert_id and incident.alert.host_id:
        hosts.append(incident.alert.host)
    if incident.command_execution_id and incident.command_execution.host_id:
        hosts.append(incident.command_execution.host)
    if incident.deployment_release_id:
        hosts.extend(list(incident.deployment_release.hosts.all()))
    return hosts


def can_access_incident(request, incident):
    return can_access_hosts(request, incident_reference_hosts(incident))


def create_incident(request, title, severity, description='', host=None, alert=None,
                    deployment_release=None, command_execution=None):
    incident = Incident(
        title=title,
        severity=severity,
        description=description,
        host=host,
        alert=alert,
        deployment_release=deployment_release,
        command_execution=command_execution,
        created_by=request.session.get('user_name', ''),
    )
    if not can_access_incident(request, incident):
        return None
    incident.save()
    audit(request, '创建事件工单', 'Incident', incident.id, incident.title)
    return incident


def update_incident_status(request, incident, status):
    previous_status = incident.status
    incident.status = status
    if status == Incident.STATUS_RESOLVED and not incident.resolved_at:
        incident.resolved_at = timezone.now()
    if status in (Incident.STATUS_OPEN, Incident.STATUS_PROCESSING):
        incident.resolved_at = None
    incident.save()
    audit(request, '更新事件状态', 'Incident', incident.id, '%s -> %s' % (previous_status, status))
    return incident


def add_incident_timeline_note(request, incident, note):
    entry = IncidentTimeline.objects.create(
        incident=incident,
        note=note,
        created_by=request.session.get('user_name', ''),
    )
    audit(request, '追加事件时间线', 'Incident', incident.id, '时间线 #%s' % entry.id)
    return entry


def record_incident_postmortem(request, incident, root_cause, resolution, follow_up):
    incident.root_cause = root_cause
    incident.resolution = resolution
    incident.follow_up = follow_up
    incident.save(update_fields=['root_cause', 'resolution', 'follow_up', 'updated_at'])
    audit(request, '记录事件复盘', 'Incident', incident.id, incident.title)
    return incident


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


def notification_failure(category, attempt_count, summary):
    return {
        'status': NotificationLog.STATUS_FAILED,
        'failure_category': category,
        'attempt_count': attempt_count,
        'response': summary,
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
                attempt_count=0,
            )

    url = channel.decrypted_webhook_url
    if not url:
        return NotificationLog.objects.create(
            channel=channel,
            event_type=event_type,
            title=title,
            content=content,
            **notification_failure('configuration', 0, '渠道配置不可用'),
        )

    if channel.channel_type == NotificationChannel.TYPE_DINGTALK:
        url = dingtalk_signed_url(url, channel.decrypted_secret)

    payload = notification_payload(channel, event_type, title, content)
    attempts = max(1, int(getattr(settings, 'NOTIFICATION_RETRY_COUNT', 0) or 0) + 1)
    timeout = max(1, int(getattr(settings, 'NOTIFICATION_TIMEOUT_SECONDS', 5) or 5))
    status = NotificationLog.STATUS_FAILED
    failure_category = 'request_error'
    response_message = '请求失败'
    for attempt in range(1, attempts + 1):
        try:
            response = requests.post(url, json=payload, timeout=timeout)
            response_message = 'HTTP %s' % response.status_code
            status = NotificationLog.STATUS_SUCCESS if response.status_code < 400 else NotificationLog.STATUS_FAILED
            failure_category = '' if status == NotificationLog.STATUS_SUCCESS else 'http_error'
        except Exception as exc:
            exception_name = exc.__class__.__name__.lower()
            failure_category = 'timeout' if 'timeout' in exception_name else 'request_error'
            response_message = '请求超时' if failure_category == 'timeout' else '请求异常'
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
        failure_category=failure_category,
        attempt_count=attempt,
    )


def render_notification_template(event_type, title, content, values=None):
    template = NotificationTemplate.objects.filter(event_type=event_type).first()
    if not template:
        return title, content
    values = values or {}
    replacements = {
        '{{title}}': title,
        '{{content}}': content,
    }
    for key, value in values.items():
        replacements['{{%s}}' % key] = str(value or '-')

    def replace_fixed(text):
        for placeholder, value in replacements.items():
            text = text.replace(placeholder, value)
        return text

    return (
        replace_fixed(template.title_template) if template.title_template else title,
        replace_fixed(template.content_template) if template.content_template else content,
    )


def alert_level_rank(level):
    return {
        AlertEvent.LEVEL_INFO: 1,
        AlertEvent.LEVEL_WARNING: 2,
        AlertEvent.LEVEL_CRITICAL: 3,
    }.get(level, 0)


def send_notifications(event_type, title, content, template_values=None, escalation_alert=None):
    title, content = render_notification_template(event_type, title, content, template_values)
    channels = NotificationChannel.objects.filter(enabled=True)
    if event_type == NotificationLog.EVENT_ALERT:
        channels = channels.filter(notify_alert=True)
    elif event_type == NotificationLog.EVENT_APPROVAL:
        channels = channels.filter(notify_approval=True)
    elif event_type == NotificationLog.EVENT_DEPLOYMENT:
        channels = channels.filter(notify_deployment=True)
    channels = list(channels)
    if event_type == NotificationLog.EVENT_ALERT and escalation_alert:
        rule = AlertNotificationEscalation.objects.select_related('channel').filter(enabled=True).first()
        if rule and rule.channel and rule.channel.enabled and alert_level_rank(escalation_alert.level) >= alert_level_rank(rule.minimum_level):
            if rule.channel_id not in [channel.id for channel in channels]:
                channels.append(rule.channel)
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
    logs = send_notifications(
        NotificationLog.EVENT_ALERT,
        title,
        content,
        template_values={
            'host': host_name,
            'metric': alert.metric or 'general',
            'level': alert.level,
            'status': alert.status,
            'message': alert.message,
        },
        escalation_alert=alert,
    )
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
    return send_notifications(NotificationLog.EVENT_APPROVAL, title, content, {
        'title': approval.title,
        'status': approval.status,
        'requester': approval.requester,
        'approver': approval.approver,
    })


def notify_deployment(release, action='发布结果'):
    title = '%s：%s %s' % (action, release.app.name, release.version)
    content = '状态：%s\n摘要：%s\n提交人：%s' % (
        release.get_status_display(),
        release.summary or '-',
        release.created_by or '-',
    )
    return send_notifications(NotificationLog.EVENT_DEPLOYMENT, title, content, {
        'app': release.app.name,
        'version': release.version,
        'status': release.status,
        'summary': release.summary,
    })


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


def active_maintenance_windows_for_hosts(hosts, now=None):
    """Return enabled windows that affect the supplied hosts through topology.

    A service-scoped window affects every host associated with that service.  The
    query intentionally returns only window metadata; callers must still enforce
    their own DevOps role and host-scope checks before rendering it.
    """
    host_ids = [host.id for host in hosts if getattr(host, 'id', None)]
    if not host_ids:
        return MaintenanceWindow.objects.none()
    current = now or timezone.now()
    return MaintenanceWindow.objects.filter(
        enabled=True,
        starts_at__lte=current,
        ends_at__gte=current,
    ).filter(
        models.Q(hosts__id__in=host_ids) |
        models.Q(services__hosts__id__in=host_ids)
    ).distinct()


def active_maintenance_windows_for_host(host, now=None):
    return active_maintenance_windows_for_hosts([host], now=now)


def active_maintenance_windows_for_release(release, now=None):
    """Find active host- or service-scoped windows matching a release.

    Services are resolved both from their topology hosts and from the existing
    project-to-deployment-app relation, so an application can be covered before
    its host assignment is populated.
    """
    current = now or timezone.now()
    host_ids = list(release.hosts.values_list('id', flat=True))
    service_ids = list(ServiceCatalog.objects.filter(
        devops_projects__deployment_apps=release.app,
    ).values_list('id', flat=True).distinct())
    if not host_ids and not service_ids:
        return MaintenanceWindow.objects.none()
    matches = models.Q()
    if host_ids:
        matches |= models.Q(hosts__id__in=host_ids)
        matches |= models.Q(services__hosts__id__in=host_ids)
    if service_ids:
        matches |= models.Q(services__id__in=service_ids)
    return MaintenanceWindow.objects.filter(
        enabled=True,
        starts_at__lte=current,
        ends_at__gte=current,
    ).filter(matches).distinct()


@transaction.atomic
def require_deployment_maintenance_approval(release, requester='', now=None):
    """Create or reuse a deployment approval when an active window applies.

    The caller is responsible for deciding whether to execute immediately.  A
    final approval is never reused, which keeps a later maintenance window from
    being silently approved by an earlier completed request.
    """
    # Lock the parent release so concurrent submission retries cannot create two
    # pending approvals for the same maintenance window.
    release = DeploymentRelease.objects.select_for_update().get(pk=release.pk)
    windows = active_maintenance_windows_for_release(release, now=now)
    if not windows.exists():
        return None
    approval = ApprovalRequest.objects.filter(
        request_type=ApprovalRequest.TYPE_DEPLOYMENT,
        deployment_release=release,
        status__in=(ApprovalRequest.STATUS_PENDING, ApprovalRequest.STATUS_APPROVED),
    ).order_by('-created_at').first()
    if approval:
        return approval
    names = list(windows.values_list('name', flat=True)[:5])
    reason = '维护窗口要求审批：%s' % '、'.join(names)
    approval = create_deployment_approval(release, requester=requester, reason=reason[:500])
    return approval


SLO_PROMETHEUS_QUERY_TEMPLATES = {
    ServiceSlo.KIND_AVAILABILITY: 'avg(up{{{selector}}})',
    ServiceSlo.KIND_LATENCY: (
        'histogram_quantile(0.95, sum(rate(http_request_duration_seconds_bucket{{{selector}}}[{window}m])) by (le))'
    ),
    ServiceSlo.KIND_ERROR_RATE: (
        'sum(rate(http_requests_total{{code=~"5..",{selector}}}[{window}m])) / '
        'sum(rate(http_requests_total{{{selector}}}[{window}m]))'
    ),
}


def _service_slo_query(slo):
    """Render only one of the fixed server-owned Prometheus query templates."""
    template = SLO_PROMETHEUS_QUERY_TEMPLATES.get(slo.metric_kind)
    if not template:
        return None
    window = int(slo.window_minutes)
    if window < 1 or window > 10080:
        return None
    # The selector is server-rendered from a bounded catalog identifier; callers
    # cannot supply PromQL or alter the fixed query structure.
    selector = 'service=%s' % json.dumps(slo.service.name)
    return template.format(selector=selector, window=window)


def _service_slo_numeric_result(body):
    try:
        data = body['data']
        result_type = data['resultType']
        result = data['result']
        if result_type in ('scalar', 'string'):
            value = result[1]
        elif result_type == 'vector' and len(result) == 1:
            value = result[0]['value'][1]
        else:
            return None
        value = float(value)
    except (KeyError, TypeError, ValueError, IndexError):
        return None
    return value if math.isfinite(value) else None


def _service_slo_display_value(slo, value):
    if slo.metric_kind == ServiceSlo.KIND_AVAILABILITY:
        return value * 100, '%0.3f%%' % (value * 100)
    if slo.metric_kind == ServiceSlo.KIND_ERROR_RATE:
        return value * 100, '%0.3f%%' % (value * 100)
    if slo.metric_kind == ServiceSlo.KIND_LATENCY:
        return value * 1000, '%0.3f ms' % (value * 1000)
    return None, ''


def evaluate_service_slo(slo, now=None):
    """Evaluate an SLO without retaining raw upstream results or query text."""
    now = now or timezone.now()
    query = _service_slo_query(slo)
    state = ServiceSlo.STATE_UNAVAILABLE
    summary = '指标不可用'
    if query:
        from monitor.models import PrometheusConfig
        from monitor.services import query_prometheus

        config = PrometheusConfig.objects.filter(enabled=True).exclude(prometheus_url='').order_by('id').first()
        result = query_prometheus(config, query) if config else None
        value = _service_slo_numeric_result(result.get('body') if isinstance(result, dict) and result.get('ok') else None)
        if value is not None:
            displayed, label = _service_slo_display_value(slo, value)
            if displayed is not None:
                healthy = displayed >= float(slo.target) if slo.metric_kind == ServiceSlo.KIND_AVAILABILITY else displayed <= float(slo.target)
                state = ServiceSlo.STATE_HEALTHY if healthy else ServiceSlo.STATE_EXHAUSTED
                summary = '%s，目标 %s' % (label, slo.target)
    slo.last_state = state
    slo.last_summary = summary[:200]
    slo.last_evaluated_at = now
    slo.save(update_fields=['last_state', 'last_summary', 'last_evaluated_at', 'updated_at'])
    return {'state': state, 'summary': slo.last_summary}


def deployment_service_slos(release):
    services = ServiceCatalog.objects.filter(
        models.Q(devops_projects__deployment_apps=release.app) |
        models.Q(hosts__in=release.hosts.all())
    ).distinct()
    return ServiceSlo.objects.filter(service__in=services, enabled=True).select_related('service')


def require_deployment_slo_approval(release, requester=''):
    """Require an existing deployment approval when an enabled SLO is exhausted."""
    with transaction.atomic():
        release = DeploymentRelease.objects.select_for_update().get(pk=release.pk)
        slo_count = 0
        exhausted = []
        unavailable_count = 0
        for slo in deployment_service_slos(release):
            slo_count += 1
            try:
                state = evaluate_service_slo(slo)['state']
            except Exception:
                # An unavailable metrics integration must preserve the release path.
                state = ServiceSlo.STATE_UNAVAILABLE
            if state == ServiceSlo.STATE_EXHAUSTED:
                exhausted.append(slo.service.name)
            elif state == ServiceSlo.STATE_UNAVAILABLE:
                unavailable_count += 1
        state = (
            ServiceSlo.STATE_EXHAUSTED if exhausted else
            ServiceSlo.STATE_UNAVAILABLE if unavailable_count else
            ServiceSlo.STATE_HEALTHY
        )
        AuditLog.objects.create(
            user=requester or 'system',
            action='服务SLO发布门禁',
            target_type='DeploymentRelease',
            target_id=str(release.id),
            detail='状态=%s, SLO数量=%s, 耗尽数量=%s' % (state, slo_count, len(exhausted)),
            ip_address='',
        )
        if not exhausted:
            return None
        approval = ApprovalRequest.objects.filter(
            request_type=ApprovalRequest.TYPE_DEPLOYMENT,
            deployment_release=release,
            status__in=(ApprovalRequest.STATUS_PENDING, ApprovalRequest.STATUS_APPROVED),
        ).order_by('-created_at').first()
        if approval:
            return approval
        reason = 'SLO 预算耗尽：%s' % '、'.join(exhausted[:5])
        return create_deployment_approval(release, requester=requester, reason=reason[:500])


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


class RunbookInitiationError(ValueError):
    pass


def initiate_runbook(request, runbook, host):
    """Create a pending command and approval; never invoke SSH from this path."""
    if not has_role(request, DevOpsRole.ROLE_OPERATOR, DevOpsModulePermission.MODULE_COMMAND):
        raise PermissionError('没有命令执行权限')
    if not runbook.enabled:
        raise RunbookInitiationError('运行手册未启用')
    if not runbook.requires_approval:
        raise RunbookInitiationError('运行手册必须经过审批')
    if not can_access_host(request, host):
        raise PermissionError('目标主机不在当前用户授权范围内')
    if not runbook.allowed_hosts.filter(id=host.id).exists():
        raise RunbookInitiationError('目标主机不在运行手册授权范围内')
    if runbook.service_id and not runbook.service.hosts.filter(id=host.id).exists():
        raise RunbookInitiationError('目标主机不属于运行手册关联服务')

    decision, policy = evaluate_command_policy(runbook.command_template, user_role(request))
    if decision == COMMAND_BLOCKED:
        raise RunbookInitiationError(command_denied_message(decision, policy))
    record = CommandExecution.objects.create(
        host=host,
        runbook_template=runbook,
        command=runbook.command_template,
        created_by=request.session.get('user_name', ''),
    )
    approval = create_command_approval(
        host, runbook.command_template, request.session.get('user_name', ''),
        '受控运行手册 #%s v%s' % (runbook.id, runbook.version),
    )
    approval.command_execution = record
    approval.save(update_fields=['command_execution'])
    audit(request, '发起受控运行手册', 'RunbookTemplate', runbook.id, '版本=%s, 主机=%s, 审批=%s' % (
        runbook.version, host.id, approval.id,
    ))
    return record, approval


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


def finalize_command_approval(record):
    """Move a queued runbook approval only after its existing command worker reaches a terminal state."""
    if not record.runbook_template_id:
        return
    if record.status == CommandExecution.STATUS_SUCCESS:
        status = ApprovalRequest.STATUS_EXECUTED
    elif record.status in (CommandExecution.STATUS_FAILED, CommandExecution.STATUS_BLOCKED):
        status = ApprovalRequest.STATUS_FAILED
    else:
        return
    for approval in ApprovalRequest.objects.filter(
            request_type=ApprovalRequest.TYPE_COMMAND,
            command_execution=record,
            status=ApprovalRequest.STATUS_APPROVED):
        approval.status = status
        approval.executed_at = timezone.now()
        approval.save(update_fields=['status', 'executed_at'])
        notify_approval(approval, '执行')


def execute_approval_request(approval, role=DevOpsRole.ROLE_ADMIN):
    if approval.request_type == ApprovalRequest.TYPE_COMMAND:
        if approval.command_execution_id:
            record = approval.command_execution
            enqueue_background_job(execute_command_record, record, role)
            finalize_command_approval(record)
            return approval
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
