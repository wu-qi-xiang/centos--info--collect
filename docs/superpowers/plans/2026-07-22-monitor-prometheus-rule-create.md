# Monitor PrometheusRule Create Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Permit an authorized Kubernetes cluster administrator to create one validated PrometheusRule from the monitor alert-settings page.

**Architecture:** The monitor-owned POST view enforces session, cluster viewer, and cluster-admin permissions, then delegates Kubernetes interaction to one new `devops.services` function. The service has a creation-specific YAML validator and reuses the existing temporary-kubeconfig lifecycle and safe Kubernetes error mapping. The monitor page receives only summaries and safe status messages.

**Tech Stack:** Django function views/forms/templates, existing Vue page renderer, PyYAML, Kubernetes CustomObjectsApi, Django unittest mocks.

---

### Task 1: Create-Service YAML Contract

**Files:**
- Modify: `devops/services.py`
- Test: `devops/tests.py`

- [ ] **Step 1: Add failing service tests**

Add tests to `PrometheusRuleServiceTests` that call `create_prometheus_rule(cluster, yaml_text)` and prove that a valid single document invokes `create_namespaced_custom_object` with fixed group/version/plural, the validated namespace, and an object body without `metadata.resourceVersion`. Add invalid inputs for multiple documents, non-PrometheusRule kind, missing name/namespace, malformed or unsafe identity, and any present resourceVersion. Assert the API helper is not called for every invalid input. Add a mocked API exception test proving raw Kubernetes details are omitted and client/temp config cleanup remains intact.

- [ ] **Step 2: Run the new tests red**

Run: `.venv/bin/python manage.py test devops.tests.PrometheusRuleServiceTests`

Expected: the creation tests fail because `create_prometheus_rule` and its create validator do not exist.

- [ ] **Step 3: Implement the smallest creation-specific validator and service**

Implement `_validate_prometheus_rule_create_yaml(yaml_text)` beside the replacement validator. Require exactly one mapping with `apiVersion == PROMETHEUS_RULE_API_VERSION`, `kind == PROMETHEUS_RULE_KIND`, a valid `metadata.name`, and valid `metadata.namespace`; reject any `metadata.resourceVersion` key, including an empty value. Normalize only the name/namespace and retain the submitted `spec`. Implement:

```python
def create_prometheus_rule(cluster, yaml_text, timeout=8):
    rule, error = _validate_prometheus_rule_create_yaml(yaml_text)
    if error:
        return error
    # Open via _prometheus_rule_custom_objects_api, call create_namespaced_custom_object,
    # map exceptions with _prometheus_rule_error, then always close/remove resources.
```

Call `create_namespaced_custom_object(group=..., version=..., namespace=rule['metadata']['namespace'], plural=..., body=rule, _request_timeout=timeout)`. Return the existing bounded result shape, never YAML or connection data.

- [ ] **Step 4: Run service tests green**

Run: `.venv/bin/python manage.py test devops.tests.PrometheusRuleServiceTests`

Expected: PASS.

### Task 2: Monitor Page Context And Create Endpoint

**Files:**
- Modify: `monitor/views.py`
- Modify: `monitor/urls.py`
- Modify: `static/js/ops-vue-pages.js`
- Test: `monitor/tests.py`

- [ ] **Step 1: Add failing monitor tests**

Add tests proving a cluster viewer sees only accessible cluster choices and safe summaries after `?cluster=<id>`, but no creation form; a cluster administrator sees the form; an unprivileged monitor user sees no PrometheusRule section and no service call. Add POST tests for CSRF-backed create success, invalid form/service failure preserving submitted YAML only in the rendered form, safe error rendering, safe audit detail, and no audit for denied/invalid requests.

- [ ] **Step 2: Run the new page tests red**

Run: `.venv/bin/python manage.py test monitor`

Expected: the new UI/route tests fail because the rule payload and create route are absent.

- [ ] **Step 3: Add monitor-owned permission helpers, payload, view, and route**

Import `K8sCluster`, `DevOpsRole`, `DevOpsModulePermission`, `has_role`, `list_prometheus_rules`, `create_prometheus_rule`, `audit`, and a `PrometheusRule` YAML form matching the existing textarea limits. Add one helper that lists/loads rules only for `has_role(request, ROLE_VIEWER, MODULE_CLUSTER)` and records `can_manage` using `ROLE_ADMIN`. Merge its safe payload into `_monitor_payload` / monitor page data, with selected cluster parsed as a bounded integer. Add `prometheus_rule_create(request)`:

```python
@session_login_required
def prometheus_rule_create(request):
    if request.method != 'POST':
        return HttpResponseNotAllowed(['POST'])
    if not has_role(request, DevOpsRole.ROLE_ADMIN, MODULE_CLUSTER):
        return HttpResponseForbidden(...)
    # Validate cluster selection and YAML form, call create_prometheus_rule,
    # audit only fixed safe fields, redirect to monitor_index with cluster on success.
```

Add `path('prometheus-rules/create/', views.prometheus_rule_create, name='prometheus_rule_create')`. Map known service codes to the same safe message/status contract already used by direct management; never render the returned raw message.

- [ ] **Step 4: Render the compact PrometheusRule section in the existing Vue monitor page**

For `kind === 'monitor'`, add the cluster selector, summaries (namespace, name, resource version, creation time), links to `devops:prometheus_rule_detail`, error/empty states, and a CSRF POST textarea form conditioned on `can_manage`. Use server-generated URLs and escape plain text through Vue bindings. Do not add any edit/delete controls to this page.

- [ ] **Step 5: Run monitor tests green**

Run: `.venv/bin/python manage.py test monitor`

Expected: PASS.

### Task 3: Integration Review And Regression Validation

**Files:**
- Review: `devops/services.py`, `devops/tests.py`, `monitor/views.py`, `monitor/urls.py`, `monitor/tests.py`, `static/js/ops-vue-pages.js`

- [ ] **Step 1: Run focused cross-app tests and framework checks**

Run:

```bash
.venv/bin/python manage.py test devops.tests.PrometheusRuleServiceTests monitor
.venv/bin/python manage.py check
node --check static/js/ops-vue-pages.js
git diff --check
```

Expected: all commands exit zero.

- [ ] **Step 2: Review security and compatibility**

Confirm the audit only contains cluster ID, namespace, rule name, `create`, and an allowlisted outcome; no YAML/kubeconfig/raw exception crosses a template or response. Confirm existing DevOps update/delete tests still pass and no existing routes were changed.
