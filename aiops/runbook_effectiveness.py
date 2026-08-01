"""Safe, host-scoped runbook effectiveness rankings for AIOps."""

from collections import defaultdict

from django.urls import reverse

from devops.models import RunbookEffectivenessFeedback, RunbookTemplate


def build_runbook_effectiveness_suggestions(hosts):
    host_ids = [host.id for host in hosts]
    if not host_ids:
        return []
    counts = defaultdict(lambda: defaultdict(int))
    rows = RunbookEffectivenessFeedback.objects.filter(
        command_execution__host_id__in=host_ids,
        command_execution__runbook_template__enabled=True,
    ).values('command_execution__runbook_template_id', 'classification')
    for row in rows:
        counts[row['command_execution__runbook_template_id']][row['classification']] += 1
    runbooks = RunbookTemplate.objects.filter(
        id__in=counts,
        allowed_hosts__id__in=host_ids,
    ).distinct().order_by('name', '-version', 'id')
    results = []
    for runbook in runbooks:
        result = counts[runbook.id]
        effective = result[RunbookEffectivenessFeedback.CLASSIFICATION_EFFECTIVE]
        partial = result[RunbookEffectivenessFeedback.CLASSIFICATION_PARTIAL]
        ineffective = result[RunbookEffectivenessFeedback.CLASSIFICATION_INEFFECTIVE]
        total = effective + partial + ineffective
        score = int(round((effective * 100 + partial * 50) / total)) if total else 0
        results.append({
            'id': runbook.id,
            'name': runbook.name,
            'version': runbook.version,
            'effective_count': effective,
            'partial_count': partial,
            'ineffective_count': ineffective,
            'effectiveness_score': score,
            'initiate_url': reverse('devops:runbooks'),
        })
    return sorted(
        results,
        key=lambda item: (-item['effectiveness_score'], -(item['effective_count'] + item['partial_count'] + item['ineffective_count']), item['name'], -item['version'], item['id']),
    )
