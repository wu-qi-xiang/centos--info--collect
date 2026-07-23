"""PrometheusRule YAML validation and Kubernetes custom-resource operations."""

import os
import re
import tempfile

try:
    import yaml
except ImportError:
    yaml = None


PROMETHEUS_RULE_GROUP = 'monitoring.coreos.com'
PROMETHEUS_RULE_VERSION = 'v1'
PROMETHEUS_RULE_PLURAL = 'prometheusrules'
PROMETHEUS_RULE_KIND = 'PrometheusRule'
PROMETHEUS_RULE_API_VERSION = '%s/%s' % (
    PROMETHEUS_RULE_GROUP,
    PROMETHEUS_RULE_VERSION,
)
PROMETHEUS_RULE_LIST_MAX_PAGES = 1000
PROMETHEUS_RULE_RESOURCE_VERSION_MAX_LENGTH = 253
K8S_NAMESPACE_PATTERN = re.compile(r'^[a-z0-9]([-a-z0-9]*[a-z0-9])?$')
K8S_RESOURCE_NAME_PATTERN = re.compile(r'^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$')


def _prometheus_rule_result(ok=False, code='', message='', **values):
    result = {'ok': ok, 'code': code, 'message': message}
    result.update(values)
    return result


def _safe_k8s_namespace(value, fallback=''):
    namespace = (value or '').strip().lower()
    if namespace and len(namespace) <= 63 and K8S_NAMESPACE_PATTERN.match(namespace):
        return namespace
    return fallback


def _safe_prometheus_rule_identity(namespace, name):
    namespace = _safe_k8s_namespace(namespace)
    name = (name or '').strip()
    if not namespace or not name or len(name) > 253 or not K8S_RESOURCE_NAME_PATTERN.match(name):
        return None, None
    return namespace, name


def normalize_prometheus_rule_resource_version(value):
    value = value.strip() if isinstance(value, str) else ''
    if (not value or len(value) > PROMETHEUS_RULE_RESOURCE_VERSION_MAX_LENGTH
            or not value.isprintable()):
        return ''
    return value


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
    if isinstance(exc, TimeoutError) or 'timeout' in name or 'timeouterror' in name:
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
    resource_version = normalize_prometheus_rule_resource_version(metadata.get('resourceVersion'))
    if not all(isinstance(value, str) and value.strip() for value in (document_name, document_namespace)) or not resource_version:
        return None, _prometheus_rule_result(False, 'invalid_yaml', '规则 YAML 必须包含 metadata.name、metadata.namespace 和 metadata.resourceVersion。')
    if document_name.strip() != name or document_namespace.strip() != namespace:
        return None, _prometheus_rule_result(False, 'invalid_yaml', '规则 YAML 的名称或命名空间与当前选择不一致。')
    metadata['name'] = name
    metadata['namespace'] = namespace
    metadata['resourceVersion'] = resource_version
    return document, None


def _validate_prometheus_rule_create_yaml(yaml_text):
    if not yaml:
        return None, _prometheus_rule_result(False, 'dependency_missing', '缺少 YAML 解析依赖，无法创建 PrometheusRule。')
    try:
        documents = list(yaml.safe_load_all(yaml_text))
    except Exception:
        return None, _prometheus_rule_result(False, 'invalid_yaml', '规则 YAML 格式无效。')
    if len(documents) != 1 or not isinstance(documents[0], dict):
        return None, _prometheus_rule_result(False, 'invalid_yaml', '规则 YAML 必须且只能包含一个对象。')
    document = documents[0]
    if document.get('apiVersion') != PROMETHEUS_RULE_API_VERSION or document.get('kind') != PROMETHEUS_RULE_KIND:
        return None, _prometheus_rule_result(False, 'invalid_yaml', '规则 YAML 必须是 monitoring.coreos.com/v1 PrometheusRule。')
    metadata = document.get('metadata')
    if not isinstance(metadata, dict):
        return None, _prometheus_rule_result(False, 'invalid_yaml', '规则 YAML 缺少 metadata。')
    if 'resourceVersion' in metadata:
        return None, _prometheus_rule_result(False, 'invalid_yaml', '创建规则 YAML 不允许包含 metadata.resourceVersion。')
    if not all(isinstance(value, str) for value in (metadata.get('namespace'), metadata.get('name'))):
        return None, _prometheus_rule_result(False, 'invalid_yaml', '规则 YAML 的命名空间或名称无效。')
    namespace, name = _safe_prometheus_rule_identity(metadata.get('namespace'), metadata.get('name'))
    if not namespace or not name:
        return None, _prometheus_rule_result(False, 'invalid_yaml', '规则 YAML 的命名空间或名称无效。')
    metadata['namespace'] = namespace
    metadata['name'] = name
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


def _cleanup_prometheus_rule_client(api_client, path):
    _close_prometheus_rule_api_client(api_client)
    if path:
        try:
            os.unlink(path)
        except OSError:
            pass


def list_prometheus_rules(cluster, timeout=8, api_factory=None):
    path = ''
    api_client = None
    api_factory = api_factory or _prometheus_rule_custom_objects_api
    try:
        api, api_client, path = api_factory(cluster)
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
            rules.extend(summary for summary in (_prometheus_rule_summary(item) for item in items) if summary)
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
        _cleanup_prometheus_rule_client(api_client, path)


def get_prometheus_rule(cluster, namespace, name, timeout=8, api_factory=None):
    namespace, name = _safe_prometheus_rule_identity(namespace, name)
    if not namespace or not name:
        return _prometheus_rule_result(False, 'invalid_identity', '规则命名空间或名称无效。')
    path = ''
    api_client = None
    api_factory = api_factory or _prometheus_rule_custom_objects_api
    try:
        api, api_client, path = api_factory(cluster)
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
        _cleanup_prometheus_rule_client(api_client, path)


def replace_prometheus_rule(cluster, namespace, name, yaml_text, timeout=8, api_factory=None):
    rule, error = _validate_prometheus_rule_yaml(yaml_text, namespace, name)
    if error:
        return error
    namespace = rule['metadata']['namespace']
    name = rule['metadata']['name']
    path = ''
    api_client = None
    api_factory = api_factory or _prometheus_rule_custom_objects_api
    try:
        api, api_client, path = api_factory(cluster)
        updated = api.replace_namespaced_custom_object(
            group=PROMETHEUS_RULE_GROUP, version=PROMETHEUS_RULE_VERSION,
            namespace=namespace, plural=PROMETHEUS_RULE_PLURAL, name=name,
            body=rule, _request_timeout=timeout,
        )
        return _prometheus_rule_result(True, 'ok', 'PrometheusRule 已同步到集群。', rule=updated)
    except Exception as exc:
        return _prometheus_rule_error(exc)
    finally:
        _cleanup_prometheus_rule_client(api_client, path)


def create_prometheus_rule(cluster, yaml_text, timeout=8, api_factory=None):
    rule, error = _validate_prometheus_rule_create_yaml(yaml_text)
    if error:
        return error
    namespace = rule['metadata']['namespace']
    path = ''
    api_client = None
    api_factory = api_factory or _prometheus_rule_custom_objects_api
    try:
        api, api_client, path = api_factory(cluster)
        api.create_namespaced_custom_object(
            group=PROMETHEUS_RULE_GROUP, version=PROMETHEUS_RULE_VERSION,
            namespace=namespace, plural=PROMETHEUS_RULE_PLURAL,
            body=rule, _request_timeout=timeout,
        )
        return _prometheus_rule_result(True, 'ok', 'PrometheusRule 已创建。', rule={
            'namespace': namespace, 'name': rule['metadata']['name'],
        })
    except Exception as exc:
        return _prometheus_rule_error(exc)
    finally:
        _cleanup_prometheus_rule_client(api_client, path)


def delete_prometheus_rule(cluster, namespace, name, resource_version, timeout=8, api_factory=None):
    namespace, name = _safe_prometheus_rule_identity(namespace, name)
    resource_version = normalize_prometheus_rule_resource_version(resource_version)
    if not namespace or not name or not resource_version:
        return _prometheus_rule_result(False, 'invalid_identity', '规则命名空间、名称或资源版本无效。')
    path = ''
    api_client = None
    api_factory = api_factory or _prometheus_rule_custom_objects_api
    try:
        api, api_client, path = api_factory(cluster)
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
        _cleanup_prometheus_rule_client(api_client, path)
