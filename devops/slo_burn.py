"""Read-only SLO error-budget burn summaries from local evaluation snapshots."""

from decimal import Decimal, ROUND_HALF_UP

from django.utils import timezone

from .models import ServiceSlo, ServiceSloEvaluation


SHORT_WINDOW = timezone.timedelta(hours=1)
LONG_WINDOW = timezone.timedelta(hours=6)
SUPPORTED_KINDS = frozenset((
    ServiceSlo.KIND_AVAILABILITY,
    ServiceSlo.KIND_ERROR_RATE,
))


def _decimal_text(value):
    if value is None:
        return None
    return str(Decimal(value).quantize(Decimal('0.1'), rounding=ROUND_HALF_UP))


def _recommendation(state):
    if state == 'critical':
        return '暂停扩大发布范围并创建或复用人工审批'
    if state == 'elevated':
        return '持续观察 SLO 燃尽趋势并在发布前复核'
    if state == 'healthy':
        return '当前错误预算燃尽处于可接受范围'
    return '当前 SLO 类型或历史记录不支持错误预算燃尽计算'


def _average(rows):
    values = [row.burn_rate for row in rows if row.burn_rate is not None]
    if not values:
        return None
    return sum(values) / Decimal(len(values))


def build_slo_burn_summary(slo, now=None):
    """Return a bounded safe summary; callers own SLO visibility authorization."""
    now = now or timezone.now()
    result = {
        'slo_id': slo.id,
        'metric_kind': slo.metric_kind,
        'state': 'unavailable',
        'budget_remaining_percent': None,
        'short_window_burn_rate': None,
        'long_window_burn_rate': None,
        'recommendation': _recommendation('unavailable'),
    }
    if slo.metric_kind not in SUPPORTED_KINDS:
        return result
    rows = list(ServiceSloEvaluation.objects.filter(
        slo=slo,
        evaluated_at__gte=now - LONG_WINDOW,
        evaluated_at__lte=now,
        budget_remaining_percent__isnull=False,
        burn_rate__isnull=False,
    ).only('budget_remaining_percent', 'burn_rate', 'evaluated_at'))
    if not rows:
        return result
    short_burn = _average([row for row in rows if row.evaluated_at >= now - SHORT_WINDOW])
    long_burn = _average(rows)
    latest = max(rows, key=lambda row: row.evaluated_at)
    if short_burn is None or long_burn is None:
        return result
    state = 'critical' if short_burn >= Decimal('2') and long_burn >= Decimal('1') else (
        'elevated' if short_burn >= Decimal('1') or long_burn >= Decimal('1') else 'healthy'
    )
    result.update({
        'state': state,
        'budget_remaining_percent': _decimal_text(latest.budget_remaining_percent),
        'short_window_burn_rate': _decimal_text(short_burn),
        'long_window_burn_rate': _decimal_text(long_burn),
        'recommendation': _recommendation(state),
    })
    return result
