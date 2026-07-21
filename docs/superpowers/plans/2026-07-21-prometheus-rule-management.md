# PrometheusRule Management Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Provide a cluster-selected, cross-namespace PrometheusRule list with safe YAML view, resource-version-protected update, and confirmed delete synchronized directly to Kubernetes.

**Architecture:** Add fixed-GVK Kubernetes helpers in `devops.services`; classic DevOps views and safe JSON endpoints call only those helpers. Kubernetes remains the source of truth, while Django audits only identifiers, outcomes, and resource versions.

**Tech Stack:** Django 4.2.16, Python Kubernetes client `CustomObjectsApi`, PyYAML safe parsing/dumping, Django TestCase with mocked Kubernetes client.

---

## File Map

- `devops/services.py`: fixed PrometheusRule Kubernetes operations, safe errors, YAML validation.
- `devops/views.py`, `devops/api.py`, `devops/urls.py`: classic page and JSON actions with cluster permissions.
- `devops/forms.py`: YAML update and deletion-confirmation forms.
- `templates/devops/prometheus_rules.html`: cluster dropdown, resource table, YAML detail/edit/delete controls.
- `devops/tests.py`: mocked Kubernetes, authorization, conflict, audit, and UI regressions.
- `docs/devops_json_api.md`: endpoint, permissions, sensitive-field, and conflict contract.

### Task 1: Fixed PrometheusRule Service Contract

**Files:**
- Modify: `devops/services.py`, `devops/tests.py`

- [ ] **Step 1: Write failing service tests.** Add `PrometheusRuleServiceTests` with mocked `CustomObjectsApi` for cross-namespace list, namespaced get, replace, delete, missing CRD, RBAC denial, timeout, invalid YAML, wrong GVK, identity mismatch, and resource-version conflict.
- [ ] **Step 2: Run RED.** Run `.venv/bin/python manage.py test devops.tests.PrometheusRuleServiceTests`; expect failure because helpers do not exist.
- [ ] **Step 3: Implement closed helpers.** Define constants for group `monitoring.coreos.com`, version `v1`, plural `prometheusrules`, kind `PrometheusRule`; load the encrypted cluster kubeconfig using the existing temporary-config pattern. Implement list/get/replace/delete helpers that derive namespace/name from validated selected identity and return only safe summaries.
- [ ] **Step 4: Implement YAML checks.** Use `yaml.safe_load` and `yaml.safe_dump`; require one mapping document with fixed `apiVersion` and `kind`, non-empty metadata name/namespace/resourceVersion, and identity exactly matching the selected rule. Reject multi-document YAML and any mismatch before contacting Kubernetes.
- [ ] **Step 5: Run GREEN.** Run `.venv/bin/python manage.py test devops.tests.PrometheusRuleServiceTests`; expect all service tests to pass without a live cluster.

### Task 2: Protected Page And Mutation Flow

**Files:**
- Modify: `devops/forms.py`, `devops/views.py`, `devops/urls.py`, `devops/tests.py`
- Create: `templates/devops/prometheus_rules.html`

- [ ] **Step 1: Write failing view tests.** Cover cluster viewer list/detail success; viewer update/delete denial; admin update success; conflict refresh-required response; delete without exact confirmation rejected; offline cluster and Kubernetes error safe rendering; no kubeconfig or raw error in response/audit.
- [ ] **Step 2: Run RED.** Run `.venv/bin/python manage.py test devops.tests.PrometheusRuleViewTests`; expect missing URL/view failures.
- [ ] **Step 3: Add forms and routes.** Add a YAML update form plus a delete-confirmation form. Add routes for page, rule detail, update, and delete beneath the DevOps namespace; require session login and `MODULE_CLUSTER` viewer for reads, administrator for writes; enforce POST and CSRF for mutations.
- [ ] **Step 4: Build the page.** Reuse the dense cluster-list visual language: selected cluster dropdown, namespace/name table, inspect action, YAML textarea, update action, and destructive delete confirmation. Show only safe status/error text; no arbitrary GVK, resource URL, kubeconfig, or raw Kubernetes exception.
- [ ] **Step 5: Audit mutations.** On successful update/delete, write cluster, namespace, rule name, outcome, and resource version only. On conflict or failure, audit only safe category/status where an audit is appropriate.
- [ ] **Step 6: Run GREEN.** Run `.venv/bin/python manage.py test devops.tests.PrometheusRuleViewTests`; expect page, permissions, validation, conflict, and deletion tests to pass.

### Task 3: Safe JSON API And Documentation

**Files:**
- Modify: `devops/api.py`, `devops/urls.py`, `devops/tests.py`, `docs/devops_json_api.md`

- [ ] **Step 1: Write failing API tests.** Cover list/detail/update/delete JSON routes, session and cluster role checks, admin-only writes, conflict response shape, confirmation enforcement, safe error omission, and absence of complete YAML from list responses.
- [ ] **Step 2: Run RED.** Run `.venv/bin/python manage.py test devops.tests.PrometheusRuleApiTests`; expect missing endpoint failures.
- [ ] **Step 3: Implement API handlers.** Return existing `{ok: false, code, message}` errors. List returns safe metadata; detail returns YAML only to an authorized viewer; update/delete accept selected identity and use the same service-layer validation as classic views. Never accept caller-supplied group/version/plural.
- [ ] **Step 4: Document contract.** Describe routes, session auth, cluster viewer/admin separation, cross-namespace list behavior, YAML/resourceVersion conflict behavior, confirmation requirement, and omission of credential/error details.
- [ ] **Step 5: Run GREEN.** Run `.venv/bin/python manage.py test devops.tests.PrometheusRuleApiTests`; expect all API contract tests to pass.

### Task 4: Integration Verification

- [ ] **Step 1: Run focused suites.** Run `.venv/bin/python manage.py test devops.tests.PrometheusRuleServiceTests devops.tests.PrometheusRuleViewTests devops.tests.PrometheusRuleApiTests`.
- [ ] **Step 2: Run affected regression suite.** Run `.venv/bin/python manage.py test devops` and `.venv/bin/python manage.py check`.
- [ ] **Step 3: Check schema and diff.** Run `.venv/bin/python manage.py makemigrations --check --dry-run` and `git diff --check`.
- [ ] **Step 4: Review Kubernetes boundaries.** Verify every mutation uses fixed GVK, selected identity, `resourceVersion`, cluster-admin authorization, CSRF, safe audit fields, and mocked Kubernetes calls. State that a live CRD/RBAC/Prometheus discovery test was intentionally not performed.
