"""PrometheusRule database revision workflow.

YAML is deliberately kept in this module and the database only.  API callers
receive revision metadata and a digest, never the desired resource body.
"""
import hashlib

from django.db import transaction
from django.utils import timezone

try:
    import yaml
except ImportError:  # pragma: no cover - the service has the same fallback
    yaml = None

from RemoteLinux.models import User
from ..models import PrometheusRuleRevision, PrometheusRuleRevisionReview
from ..services import (
    create_prometheus_rule,
    delete_prometheus_rule,
    get_prometheus_rule,
    normalize_prometheus_rule_resource_version,
    replace_prometheus_rule,
)

PROMETHEUS_RULE_API_VERSION = 'monitoring.coreos.com/v1'
PROMETHEUS_RULE_KIND = 'PrometheusRule'


def _result(ok=False, code='', message='', **values):
    result = {'ok': ok, 'code': code, 'message': message}
    result.update(values)
    return result


def _identity(namespace, name):
    namespace = (namespace or '').strip().lower()
    name = (name or '').strip()
    if not namespace or len(namespace) > 63 or not name or len(name) > 253:
        return None, None
    # API routing performs the full pattern check. Keep this module safe for
    # direct callers too without accepting path/control characters.
    if not namespace.replace('-', '').isalnum() or not all(c.isalnum() or c in '.-' for c in name):
        return None, None
    return namespace, name


def _yaml_document(yaml_text, namespace, name, action):
    if not isinstance(yaml_text, str) or not yaml_text.strip() or not yaml:
        return None, _result(False, 'invalid_yaml', '规则 YAML 格式或资源身份无效。')
    try:
        documents = list(yaml.safe_load_all(yaml_text))
    except Exception:
        return None, _result(False, 'invalid_yaml', '规则 YAML 格式或资源身份无效。')
    if len(documents) != 1 or not isinstance(documents[0], dict):
        return None, _result(False, 'invalid_yaml', '规则 YAML 格式或资源身份无效。')
    document = documents[0]
    metadata = document.get('metadata')
    if (document.get('apiVersion') != PROMETHEUS_RULE_API_VERSION
            or document.get('kind') != PROMETHEUS_RULE_KIND or not isinstance(metadata, dict)):
        return None, _result(False, 'invalid_yaml', '规则 YAML 格式或资源身份无效。')
    document_namespace, document_name = _identity(metadata.get('namespace'), metadata.get('name'))
    if (not document_namespace or document_namespace != namespace or document_name != name):
        return None, _result(False, 'invalid_yaml', '规则 YAML 格式或资源身份无效。')
    resource_version = normalize_prometheus_rule_resource_version(metadata.get('resourceVersion'))
    if action == PrometheusRuleRevision.ACTION_CREATE:
        if metadata.get('resourceVersion') is not None:
            return None, _result(False, 'invalid_yaml', '创建规则不能包含资源版本。')
    elif not resource_version:
        return None, _result(False, 'invalid_yaml', '更新规则必须包含资源版本。')
    return document, None


def serialize_revision(revision):
    """Safe revision data suitable for lists, audit responses and reviews."""
    return {
        'id': revision.id,
        'cluster_id': revision.cluster_id,
        'namespace': revision.namespace,
        'name': revision.name,
        'action': revision.action,
        'status': revision.status,
        'digest': revision.desired_digest,
        'baseline_resource_version': revision.baseline_resource_version,
        'created_by': revision.created_by.user,
        'created_at': revision.created_at.strftime('%Y-%m-%d %H:%M:%S'),
        'submitted_at': revision.submitted_at.strftime('%Y-%m-%d %H:%M:%S') if revision.submitted_at else None,
        'approved_at': revision.approved_at.strftime('%Y-%m-%d %H:%M:%S') if revision.approved_at else None,
        'published_at': revision.published_at.strftime('%Y-%m-%d %H:%M:%S') if revision.published_at else None,
        'failure_code': revision.failure_code or None,
    }


def create_prometheus_rule_draft(request, cluster, yaml_text, action='create', namespace=None, name=None,
                                 resource_version='', actor=None):
    """Create a revision without contacting Kubernetes.

    This function is the integration boundary used by existing direct-write
    endpoints and new UI/API callers.
    """
    if action not in dict(PrometheusRuleRevision.ACTION_CHOICES):
        return _result(False, 'validation_error', '修订操作无效。')
    user = actor or User.objects.filter(id=request.session.get('user_id')).first()
    if not user:
        return _result(False, 'unauthorized', '未登录。')
    if action == PrometheusRuleRevision.ACTION_DELETE:
        namespace, name = _identity(namespace, name)
        resource_version = normalize_prometheus_rule_resource_version(resource_version)
        if not namespace or not name or not resource_version:
            return _result(False, 'validation_error', '规则命名空间、名称或资源版本无效。')
        # A deletion does not mutate at draft time, but it must retain a
        # server-side desired-state snapshot for auditable restore later.
        current = get_prometheus_rule(cluster, namespace, name)
        if not current.get('ok'):
            return _result(False, current.get('code', 'offline'), '无法读取当前规则以创建删除草稿。')
        rule = current.get('rule') if isinstance(current.get('rule'), dict) else {}
        metadata = rule.get('metadata') if isinstance(rule.get('metadata'), dict) else {}
        current_version = normalize_prometheus_rule_resource_version(metadata.get('resourceVersion'))
        desired_yaml = current.get('yaml') if isinstance(current.get('yaml'), str) else ''
        if not desired_yaml or current_version != resource_version:
            return _result(False, 'conflict', '规则已被其他操作更新，请刷新后重试。')
        digest = hashlib.sha256(desired_yaml.encode('utf-8')).hexdigest()
    else:
        # The create endpoint derives identity from YAML. Existing update
        # routes pass the identity and therefore bind YAML to that resource.
        if action == PrometheusRuleRevision.ACTION_CREATE:
            if not yaml:
                return _result(False, 'invalid_yaml', '规则 YAML 格式或资源身份无效。')
            try:
                documents = list(yaml.safe_load_all(yaml_text))
                metadata = documents[0].get('metadata', {}) if len(documents) == 1 else {}
            except Exception:
                metadata = {}
            namespace, name = _identity(metadata.get('namespace'), metadata.get('name'))
        else:
            namespace, name = _identity(namespace, name)
        if not namespace or not name:
            return _result(False, 'validation_error', '规则命名空间或名称无效。')
        document, error = _yaml_document(yaml_text, namespace, name, action)
        if error:
            return error
        desired_yaml = yaml_text
        digest = hashlib.sha256(yaml_text.encode('utf-8')).hexdigest()
        resource_version = normalize_prometheus_rule_resource_version(
            document.get('metadata', {}).get('resourceVersion'),
        )
    revision = PrometheusRuleRevision.objects.create(
        cluster=cluster,
        namespace=namespace,
        name=name,
        action=action,
        desired_yaml=desired_yaml,
        desired_digest=digest,
        baseline_resource_version=resource_version,
        created_by=user,
    )
    return _result(True, 'ok', 'PrometheusRule 修订草稿已创建。', revision=serialize_revision(revision))


def submit_revision(revision, actor):
    if revision.created_by_id != actor.id:
        return _result(False, 'forbidden', '仅创建人可以提交修订。')
    if revision.status != PrometheusRuleRevision.STATUS_DRAFT:
        return _result(False, 'validation_error', '仅草稿可以提交复核。')
    revision.status = PrometheusRuleRevision.STATUS_SUBMITTED
    revision.submitted_at = timezone.now()
    revision.save(update_fields=['status', 'submitted_at', 'updated_at'])
    return _result(True, 'ok', '修订已提交复核。', revision=serialize_revision(revision))


def review_revision(revision, actor, decision, comment=''):
    if actor.id == revision.created_by_id:
        return _result(False, 'validation_error', '创建人不能复核自己的修订。')
    if revision.status != PrometheusRuleRevision.STATUS_SUBMITTED:
        return _result(False, 'validation_error', '仅待复核修订可以审批。')
    if decision not in (PrometheusRuleRevisionReview.DECISION_APPROVE,
                        PrometheusRuleRevisionReview.DECISION_REJECT):
        return _result(False, 'validation_error', '复核决定无效。')
    if not isinstance(comment, str) or len(comment) > 500:
        return _result(False, 'validation_error', '复核意见无效。')
    PrometheusRuleRevisionReview.objects.create(
        revision=revision, reviewer=actor, decision=decision, comment=comment.strip(),
    )
    if decision == PrometheusRuleRevisionReview.DECISION_APPROVE:
        revision.status = PrometheusRuleRevision.STATUS_APPROVED
        revision.approved_at = timezone.now()
        revision.save(update_fields=['status', 'approved_at', 'updated_at'])
    else:
        revision.status = PrometheusRuleRevision.STATUS_REJECTED
        revision.save(update_fields=['status', 'updated_at'])
    return _result(True, 'ok', '复核决定已记录。', revision=serialize_revision(revision))


def _current_resource_version(cluster, namespace, name):
    current = get_prometheus_rule(cluster, namespace, name)
    if not current.get('ok'):
        return '', current
    rule = current.get('rule') if isinstance(current.get('rule'), dict) else {}
    metadata = rule.get('metadata') if isinstance(rule.get('metadata'), dict) else {}
    return normalize_prometheus_rule_resource_version(metadata.get('resourceVersion')), None


def _fail_revision(revision, code):
    revision.status = PrometheusRuleRevision.STATUS_FAILED
    revision.failure_code = code if code in ('conflict', 'forbidden', 'crd_not_found', 'timeout', 'offline', 'invalid_yaml', 'dependency_missing') else 'offline'
    revision.publish_claimed_at = None
    revision.save(update_fields=['status', 'failure_code', 'publish_claimed_at', 'updated_at'])
    return _result(False, revision.failure_code, 'PrometheusRule 发布失败。', revision=serialize_revision(revision))


def publish_revision(revision_id, actor):
    """Explicitly apply an approved revision with an optimistic RV check."""
    with transaction.atomic():
        revision = (PrometheusRuleRevision.objects.select_for_update().select_related('cluster', 'created_by')
                    .filter(id=revision_id).first())
        if not revision:
            return _result(False, 'not_found', '修订不存在。')
        if actor.id == revision.created_by_id:
            return _result(False, 'validation_error', '创建人不能发布自己的修订。')
        if PrometheusRuleRevisionReview.objects.filter(revision=revision, reviewer_id=actor.id).exists():
            return _result(False, 'validation_error', '复核人不能发布已复核的修订。')
        if revision.status != PrometheusRuleRevision.STATUS_APPROVED:
            return _result(False, 'validation_error', '仅已批准修订可以发布。')
        if revision.publish_claimed_at:
            return _result(False, 'validation_error', '该修订正在发布。')
        revision.publish_claimed_at = timezone.now()
        revision.save(update_fields=['publish_claimed_at', 'updated_at'])

    # Never hold a database transaction open during a Kubernetes network call.
    current_version, current_error = _current_resource_version(revision.cluster, revision.namespace, revision.name)
    if revision.action == PrometheusRuleRevision.ACTION_CREATE:
        if current_error is None:
            result = _result(False, 'conflict')
        elif current_error.get('code') != 'crd_not_found':
            result = current_error
        else:
            result = create_prometheus_rule(revision.cluster, revision.desired_yaml)
    elif current_error:
        result = current_error
    elif not current_version or current_version != revision.baseline_resource_version:
        result = _result(False, 'conflict')
    elif revision.action == PrometheusRuleRevision.ACTION_DELETE:
        result = delete_prometheus_rule(revision.cluster, revision.namespace, revision.name,
                                        revision.baseline_resource_version)
    else:
        result = replace_prometheus_rule(revision.cluster, revision.namespace, revision.name, revision.desired_yaml)
    with transaction.atomic():
        revision = PrometheusRuleRevision.objects.select_for_update().select_related('created_by').get(id=revision_id)
        if not result.get('ok'):
            return _fail_revision(revision, result.get('code'))
        revision.status = PrometheusRuleRevision.STATUS_PUBLISHED
        revision.published_at = timezone.now()
        revision.failure_code = ''
        revision.publish_claimed_at = None
        revision.save(update_fields=['status', 'published_at', 'failure_code', 'publish_claimed_at', 'updated_at'])
        return _result(True, 'ok', 'PrometheusRule 修订已发布。', revision=serialize_revision(revision))


def restore_revision(revision, actor):
    if revision.status != PrometheusRuleRevision.STATUS_PUBLISHED or not revision.desired_yaml:
        return _result(False, 'validation_error', '仅可从已发布且包含期望 YAML 的修订恢复。')
    # Restoring is intentionally only a new draft. It needs a current baseline
    # and goes through the same review and separate-publisher path.
    current_version, current_error = _current_resource_version(revision.cluster, revision.namespace, revision.name)
    if current_error:
        return _result(False, current_error.get('code', 'offline'), '无法读取当前规则以创建恢复草稿。')
    if not current_version:
        return _result(False, 'conflict', '当前规则资源版本无效。')
    try:
        document = yaml.safe_load(revision.desired_yaml)
        document['metadata']['resourceVersion'] = current_version
        yaml_text = yaml.safe_dump(document, allow_unicode=True, sort_keys=False)
    except Exception:
        return _result(False, 'invalid_yaml', '历史修订内容无效，无法恢复。')
    return create_prometheus_rule_draft(
        None, revision.cluster, yaml_text,
        action=PrometheusRuleRevision.ACTION_UPDATE, namespace=revision.namespace, name=revision.name,
        actor=actor,
    )
