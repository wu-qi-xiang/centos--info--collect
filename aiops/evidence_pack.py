"""Deterministic, read-only host evidence aggregation for AIOps diagnosis."""

from django.utils import timezone

from devops.models import (
    AlertEvent,
    CIDelivery,
    CommandExecution,
    DeploymentHealthEvaluation,
    Incident,
    MetricSample,
)


MAX_EVIDENCE = 48


def _timestamp(value):
    return timezone.localtime(value).strftime('%Y-%m-%d %H:%M:%S') if value else None


def _batch_contains_host(batch_identity, host_id):
    prefix = 'host_ids='
    if not (batch_identity or '').startswith(prefix):
        return False
    return str(host_id) in set(batch_identity[len(prefix):].split(','))


def _append(rows, item, observed_at):
    item['_observed_at'] = observed_at
    rows.append(item)


def _finish(rows):
    rows.sort(
        key=lambda item: (
            item['_observed_at'], item['kind'], item.get('id', 0),
        ),
        reverse=True,
    )
    result = []
    for item in rows[:MAX_EVIDENCE]:
        item.pop('_observed_at', None)
        result.append(item)
    return result


def build_evidence_pack(selected_host, hosts, window_start, window_end):
    """Return bounded safe evidence for one host already authorized by a caller.

    The caller owns authorization. This helper verifies that the selected host
    is present in the supplied host collection and only queries that host.
    """
    selected_host_id = getattr(selected_host, 'id', selected_host)
    supplied_host_ids = {getattr(host, 'id', host) for host in hosts}
    if not selected_host_id or selected_host_id not in supplied_host_ids:
        raise ValueError('selected host is outside the supplied host scope')
    if not window_start or not window_end or window_start > window_end:
        raise ValueError('invalid evidence window')

    rows = []
    alerts = AlertEvent.objects.filter(
        host_id=selected_host_id,
        updated_at__gte=window_start,
        updated_at__lte=window_end,
    ).order_by('-updated_at', '-id')[:MAX_EVIDENCE]
    for alert in alerts:
        _append(rows, {
            'kind': 'alert', 'id': alert.id, 'level': alert.level,
            'metric': alert.metric, 'status': alert.status,
            'observed_at': _timestamp(alert.updated_at),
        }, alert.updated_at)

    metrics = MetricSample.objects.filter(
        host_id=selected_host_id,
        collected_at__gte=window_start,
        collected_at__lte=window_end,
    ).order_by('-collected_at', '-id')[:MAX_EVIDENCE]
    seen_metrics = set()
    for metric in metrics:
        if metric.metric in seen_metrics:
            continue
        seen_metrics.add(metric.metric)
        _append(rows, {
            'kind': 'metric_state', 'metric': metric.metric,
            'state': 'observed', 'observed_at': _timestamp(metric.collected_at),
        }, metric.collected_at)

    incidents = Incident.objects.filter(
        host_id=selected_host_id,
        updated_at__gte=window_start,
        updated_at__lte=window_end,
    ).order_by('-updated_at', '-id')[:MAX_EVIDENCE]
    for incident in incidents:
        _append(rows, {
            'kind': 'incident', 'id': incident.id, 'status': incident.status,
            'observed_at': _timestamp(incident.updated_at),
        }, incident.updated_at)

    commands = CommandExecution.objects.filter(
        host_id=selected_host_id,
        status=CommandExecution.STATUS_FAILED,
        finished_at__gte=window_start,
        finished_at__lte=window_end,
    ).order_by('-finished_at', '-id')[:MAX_EVIDENCE]
    for command in commands:
        _append(rows, {
            'kind': 'failed_command', 'id': command.id, 'status': command.status,
            'observed_at': _timestamp(command.finished_at),
        }, command.finished_at)

    health_evaluations = DeploymentHealthEvaluation.objects.filter(
        evaluated_at__gte=window_start,
        evaluated_at__lte=window_end,
    ).order_by('-evaluated_at', '-id')[:MAX_EVIDENCE]
    for evaluation in health_evaluations:
        if not _batch_contains_host(evaluation.batch_identity, selected_host_id):
            continue
        _append(rows, {
            'kind': 'deployment_health', 'id': evaluation.id,
            'release_id': evaluation.release_id, 'status': evaluation.status,
            'score': evaluation.score, 'summary': evaluation.summary,
            'observed_at': _timestamp(evaluation.evaluated_at),
        }, evaluation.evaluated_at)

    deliveries = CIDelivery.objects.filter(
        release__hosts__id=selected_host_id,
        received_at__gte=window_start,
        received_at__lte=window_end,
    ).distinct().order_by('-received_at', '-id')[:MAX_EVIDENCE]
    for delivery in deliveries:
        _append(rows, {
            'kind': 'ci_delivery', 'id': delivery.id,
            'release_id': delivery.release_id, 'provider': delivery.provider,
            'status': delivery.status, 'summary': delivery.summary,
            'observed_at': _timestamp(delivery.received_at),
        }, delivery.received_at)

    return {
        'host_id': selected_host_id,
        'window_start': _timestamp(window_start),
        'window_end': _timestamp(window_end),
        'evidence': _finish(rows),
    }
