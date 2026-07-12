import json
import math
import re

try:
    from urllib import error as urlerror
    from urllib import parse as urlparse
    from urllib import request as urlrequest
except ImportError:
    import urllib.error as urlerror
    import urllib.parse as urlparse
    import urllib.request as urlrequest


PROMETHEUS_TIMEOUT_SECONDS = 5
PROMETHEUS_TABLE_MAX_ROWS = 500
ALERTMANAGER_TIMEOUT_SECONDS = 5
PROMETHEUS_INVALID_QUERY_MESSAGE = 'PromQL 查询语句无效，请检查语法后重试'
PROMETHEUS_QUERY_TIMEOUT_MESSAGE = 'Prometheus 查询超时，请简化查询后重试'
PROMETHEUS_QUERY_FORMAT_MESSAGE = 'Prometheus 返回的查询结果格式异常'
PROMETHEUS_TARGETS_FAILURE_MESSAGE = 'Prometheus Targets 查询失败'
PROMETHEUS_TARGETS_FORMAT_MESSAGE = 'Prometheus 返回的 Targets 数据格式异常'
PROMETHEUS_RULES_FAILURE_MESSAGE = 'Prometheus Rules 查询失败'
PROMETHEUS_RULES_FORMAT_MESSAGE = 'Prometheus 返回的 Rules 数据格式异常'
PROMETHEUS_LABEL_MAX_ITEMS = 50
PROMETHEUS_LABEL_KEY_MAX_LENGTH = 128
PROMETHEUS_LABEL_VALUE_MAX_LENGTH = 256
PROMETHEUS_METADATA_TEXT_MAX_LENGTH = 500
PROMETHEUS_RULE_QUERY_MAX_LENGTH = 2000


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
    return _query_prometheus_collection(
        config,
        '/api/v1/targets',
        {'state': 'active'},
        'activeTargets',
        PROMETHEUS_TARGETS_FAILURE_MESSAGE,
        PROMETHEUS_TARGETS_FORMAT_MESSAGE,
    )


def query_prometheus_rules(config):
    return _query_prometheus_collection(
        config,
        '/api/v1/rules',
        None,
        'groups',
        PROMETHEUS_RULES_FAILURE_MESSAGE,
        PROMETHEUS_RULES_FORMAT_MESSAGE,
    )


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


def alertmanager_get_json(
        config, path, params=None, timeout=ALERTMANAGER_TIMEOUT_SECONDS, require_enabled=True):
    if (
            not config
            or not getattr(config, 'alertmanager_url', '')
            or (require_enabled and not getattr(config, 'enabled', False))):
        return {'ok': False, 'message': 'Alertmanager 未配置或未启用'}
    request = urlrequest.Request(alertmanager_url(config, path, params), headers={'Accept': 'application/json'})
    try:
        response = urlrequest.urlopen(request, timeout=timeout)
        response_body = response.read().decode('utf-8')
    except Exception:
        return {'ok': False, 'message': 'Alertmanager 请求失败，请检查地址和网络'}
    try:
        body = json.loads(response_body)
    except (TypeError, ValueError):
        return {'ok': False, 'message': 'Alertmanager 返回格式异常'}
    if not isinstance(body, dict):
        return {'ok': False, 'message': 'Alertmanager 返回格式异常'}
    return {'ok': True, 'body': body}


def test_alertmanager_connection(config):
    result = alertmanager_get_json(config, '/api/v2/status', require_enabled=False)
    if not result.get('ok'):
        return result
    if isinstance(result.get('body'), dict):
        return {'ok': True, 'message': 'Alertmanager 连接正常'}
    return {'ok': False, 'message': 'Alertmanager 返回格式异常'}


def alert_notification_payload(provider, title, content):
    text = '%s\n%s' % (title, content)
    if provider == 'feishu':
        return {'msg_type': 'text', 'content': {'text': text}}
    return {'msgtype': 'text', 'text': {'content': text}}


def send_alert_notification(config, title='告警通知测试', content='这是一条告警通知测试消息。', timeout=PROMETHEUS_TIMEOUT_SECONDS):
    url = getattr(config, 'decrypted_webhook_url', '') or ''
    if not url:
        return {'ok': False, 'message': 'Webhook 地址为空或解密失败'}
    payload = alert_notification_payload(config.provider, title, content)
    data = json.dumps(payload, ensure_ascii=False).encode('utf-8')
    request = urlrequest.Request(
        url,
        data=data,
        headers={'Content-Type': 'application/json'},
        method='POST',
    )
    try:
        response = urlrequest.urlopen(request, timeout=timeout)
        response_text = response.read().decode('utf-8')[:300]
        status_code = getattr(response, 'status', None) or getattr(response, 'code', 0)
        if status_code and status_code >= 400:
            return {'ok': False, 'message': 'HTTP %s %s' % (status_code, response_text)}
        return {'ok': True, 'message': '测试通知发送成功'}
    except Exception:
        return {'ok': False, 'message': '测试通知发送失败，请检查 Webhook 地址和网络'}
