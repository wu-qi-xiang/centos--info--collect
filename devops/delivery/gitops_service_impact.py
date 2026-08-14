"""Read-only GitOps drift to service-risk mapping."""

from collections import defaultdict

from ..models import GitOpsDriftFinding, K8sWorkloadServiceMapping


def build_gitops_service_impacts(findings, services):
    """Map drifted workloads to caller-authorized services without manifests."""
    services = list(services)
    service_ids = {service.id for service in services}
    if not service_ids:
        return []
    mappings = {
        (item.cluster_id, item.namespace, item.workload_kind, item.workload_name): item.service_id
        for item in K8sWorkloadServiceMapping.objects.filter(service_id__in=service_ids)
    }
    counts = defaultdict(int)
    for finding in findings:
        if finding.status != GitOpsDriftFinding.STATUS_DRIFTED:
            continue
        service_id = mappings.get((
            finding.cluster_id, finding.namespace, finding.resource_kind, finding.resource_name,
        ))
        if service_id:
            counts[service_id] += 1
    rows = []
    for service in services:
        count = counts.get(service.id, 0)
        if not count:
            continue
        critical = service.criticality == service.CRITICALITY_CRITICAL
        rows.append({
            'service': {'id': service.id, 'name': service.name},
            'criticality': service.criticality,
            'drifted_workload_count': count,
            'dependency_count': service.upstream_links.count(),
            'risk': 'critical' if critical else 'elevated',
            'recommendation': (
                '优先核查关键服务的 GitOps 漂移并走受控修订流程'
                if critical else '核查服务工作负载漂移并走受控修订流程'
            ),
        })
    return sorted(rows, key=lambda item: (-item['drifted_workload_count'], item['service']['name'], item['service']['id']))
