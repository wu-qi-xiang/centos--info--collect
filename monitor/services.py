import json

try:
    from urllib import parse as urlparse
    from urllib import request as urlrequest
except ImportError:
    import urllib.parse as urlparse
    import urllib.request as urlrequest


PROMETHEUS_TIMEOUT_SECONDS = 5
PROMETHEUS_TABLE_MAX_ROWS = 500
ALERTMANAGER_TIMEOUT_SECONDS = 5


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
        response_body = response.read().decode('utf-8')
    except Exception:
        return {'ok': False, 'message': 'Prometheus 请求失败，请检查地址和网络'}
    try:
        body = json.loads(response_body)
    except (TypeError, ValueError):
        return {'ok': False, 'message': 'Prometheus 返回格式异常'}
    if not isinstance(body, dict):
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
    if not result.get('ok'):
        return result
    body = result.get('body') or {}
    if body.get('status') != 'success':
        return {'ok': False, 'message': 'Prometheus 查询失败'}
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
