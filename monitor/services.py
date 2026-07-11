import json

try:
    from urllib import parse as urlparse
    from urllib import request as urlrequest
except ImportError:
    import urllib.parse as urlparse
    import urllib.request as urlrequest


PROMETHEUS_TIMEOUT_SECONDS = 5


def prometheus_url(config, path, params=None):
    base = (getattr(config, 'prometheus_url', '') or '').rstrip('/')
    query = ''
    if params:
        query = '?' + urlparse.urlencode(params)
    return '%s%s%s' % (base, path, query)


def prometheus_get_json(config, path, params=None, timeout=PROMETHEUS_TIMEOUT_SECONDS):
    if not config or not getattr(config, 'enabled', False) or not getattr(config, 'prometheus_url', ''):
        return {'ok': False, 'message': 'Prometheus 未配置或未启用'}
    request = urlrequest.Request(prometheus_url(config, path, params), headers={'Accept': 'application/json'})
    try:
        response = urlrequest.urlopen(request, timeout=timeout)
        body = response.read().decode('utf-8')
        return {'ok': True, 'body': json.loads(body)}
    except Exception:
        return {'ok': False, 'message': 'Prometheus 请求失败，请检查地址和网络'}


def test_prometheus_connection(config):
    result = prometheus_get_json(config, '/api/v1/status/runtimeinfo')
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
        return {'ok': False, 'message': body.get('error') or 'Prometheus 查询失败'}
    return {'ok': True, 'body': body}


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
