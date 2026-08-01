# 发布健康守护 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 在既有发布、CI 门禁和审批流之上，提供确定性的发布后健康评估和分批发布止损，不自动执行回滚。

**Architecture:** `DeploymentHealthEvaluation` 只保存发布、批次、健康状态、分数和经净化的摘要。服务层以目标主机上的发布后严重告警、失败命令和已耗尽 SLO 计算评估；不健康时保留发布为 `blocked`，并复用既有回滚审批。AIOps 仅读取这些证据，且只返回当前用户可见主机的数据。

**Tech Stack:** Django 4.2 ORM migrations, existing DevOps RBAC/host scope, BackgroundJob, Vue 3 static dashboard, mocked SSH/network tests.

---

### Task 1: 发布健康摘要模型与确定性评估

**Files:**
- Modify: `devops/models.py`, `devops/services.py`
- Create: `devops/migrations/0038_deployment_health_guard.py`
- Test: `devops/test_deployment_health_guard.py`

- [ ] **Step 1: 写失败测试**

```python
evaluation = evaluate_deployment_health(release, batch_hosts=[host], now=now)
self.assertEqual(evaluation.status, DeploymentHealthEvaluation.STATUS_UNHEALTHY)
self.assertIn('critical_alert', evaluation.summary)
self.assertNotIn(alert.message, evaluation.summary)
```

- [ ] **Step 2: 运行 RED 测试**

Run: `.venv/bin/python manage.py test devops.test_deployment_health_guard -v 1`
Expected: FAIL because the health model and service do not yet exist.

- [ ] **Step 3: 最小实现**

```python
class DeploymentHealthEvaluation(models.Model):
    release = models.ForeignKey(DeploymentRelease, on_delete=models.CASCADE, related_name='health_evaluations')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES)
    score = models.PositiveSmallIntegerField(default=100)
    summary = models.CharField(max_length=300)
    evaluated_at = models.DateTimeField()
```

`evaluate_deployment_health()` 仅聚合批次主机、发布开始后的严重告警、失败命令和已耗尽 SLO，返回受限摘要。

- [ ] **Step 4: 运行 GREEN 测试**

Run: `.venv/bin/python manage.py test devops.test_deployment_health_guard -v 1`
Expected: PASS.

### Task 2: 分批发布守护与回滚审批

**Files:**
- Modify: `devops/models.py`, `devops/services.py`, `devops/api.py`, `devops/urls.py`
- Test: `devops/test_deployment_health_guard.py`

- [ ] **Step 1: 写失败测试**

```python
release.rollout_batch_size = 1
execute_deployment_release(release)
release.refresh_from_db()
self.assertEqual(release.status, DeploymentRelease.STATUS_BLOCKED)
self.assertTrue(ApprovalRequest.objects.filter(
    deployment_release=release, request_type=ApprovalRequest.TYPE_ROLLBACK,
).exists())
```

- [ ] **Step 2: 运行 RED 测试**

Run: `.venv/bin/python manage.py test devops.test_deployment_health_guard.DeploymentHealthGuardTests.test_unhealthy_batch_blocks_following_hosts -v 1`
Expected: FAIL because releases currently execute every host without health gating.

- [ ] **Step 3: 最小实现**

添加可选 `rollout_batch_size`，默认 `0` 保持旧的一次性发布。批次健康为 `unhealthy` 时停止下一批、创建或复用既有回滚审批、写安全审计和通知；不调用 `execute_deployment_rollback()`。

- [ ] **Step 4: 运行 GREEN 测试**

Run: `.venv/bin/python manage.py test devops.test_deployment_health_guard -v 1`
Expected: PASS.

### Task 3: AIOps 发布效果证据与受控展示

**Files:**
- Modify: `aiops/change_impact.py`, `aiops/views.py`, `static/js/aiops-vue.js`, `templates/aiops/dashboard.html`
- Test: `aiops/test_change_impact.py`

- [ ] **Step 1: 写失败测试**

```python
impacts = build_change_impacts(request, [alert], [], [host])
health = [row for row in impacts[0]['evidence'] if row['kind'] == 'deployment_health'][0]
self.assertEqual(health['status'], 'unhealthy')
self.assertNotIn('private alert message', repr(health))
```

- [ ] **Step 2: 运行 RED 测试**

Run: `.venv/bin/python manage.py test aiops.test_change_impact -v 1`
Expected: FAIL because health evidence is not currently emitted.

- [ ] **Step 3: 最小实现**

在既有变更影响证据中加入健康状态、分数、净化摘要和受控发布详情链接；前端展示“健康/需观察/已止损”，不展示命令、输出、告警原文或审批评论。

- [ ] **Step 4: 运行 GREEN 测试**

Run: `.venv/bin/python manage.py test aiops.test_change_impact -v 1 && node --check static/js/aiops-vue.js`
Expected: PASS.

### Task 4: 集成验证与文档

**Files:**
- Modify: `docs/devops_json_api.md`, `README.md`
- Test: `devops/test_deployment_health_guard.py`, `aiops/test_change_impact.py`

- [ ] **Step 1: 记录 API 与安全边界**

文档仅列出健康状态、分数、摘要、审批行为和“不自动回滚”的约束，不记录命令或外部地址。

- [ ] **Step 2: 运行集成验证**

Run: `.venv/bin/python manage.py test devops aiops && .venv/bin/python manage.py check && .venv/bin/python manage.py makemigrations --check --dry-run && git diff --check`
Expected: all commands pass.
