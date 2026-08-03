# Controlled Operations Integrations Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver safe, disabled-by-default connectors for GitOps, vulnerability ingestion, and infrastructure planning, plus a Geist readiness workspace that makes their operational state visible.

**Architecture:** Add additive DevOps models and service-layer adapters that persist only safe summaries. Existing digest-only GitOps and vulnerability recorders remain the sole persistence boundaries for external findings. The API exposes narrowly serialized read models and bounded trigger actions, while the existing Vue app gains one Geist tab that consumes these APIs.

**Tech Stack:** Python 3.11, Django 4.2, SQLite-compatible Django migrations, vendored Vue 3, static CSS/JS, Django test runner.

---

### Task 1: Controlled Integration Persistence And Adapter Contracts

**Files:**
- Modify: `devops/models.py`
- Create: `devops/migrations/0042_controlled_integrations.py`
- Create: `devops/integrations.py`
- Create: `devops/test_controlled_integrations.py`

- [ ] **Step 1: Write the failing model and adapter tests**

```python
class ControlledIntegrationTests(TestCase):
    def test_connector_encrypts_config_and_exposes_no_secret_fields(self):
        connector = IntegrationConnector.objects.create(
            name='gitops-readonly', connector_type='gitops', config={'endpoint': 'https://internal.example', 'token': 'secret'},
        )
        self.assertNotIn('secret', connector.config_encrypted)
        self.assertEqual(connector.safe_summary(), {'id': connector.id, 'name': 'gitops-readonly', 'connector_type': 'gitops', 'enabled': False, 'read_only': True, 'status': 'blocked'})

    def test_disabled_connector_is_blocked_without_calling_adapter(self):
        connector = IntegrationConnector.objects.create(name='disabled', connector_type='gitops')
        adapter = mock.Mock()
        run = collect_gitops_connector(connector, adapter=adapter)
        self.assertEqual(run.status, GitOpsCollectionRun.STATUS_BLOCKED)
        adapter.collect.assert_not_called()
```

- [ ] **Step 2: Run the new tests and verify failure**

Run: `.venv/bin/python manage.py test devops.test_controlled_integrations`

Expected: FAIL because `IntegrationConnector` and `collect_gitops_connector` do not exist.

- [ ] **Step 3: Implement additive encrypted models and migration**

```python
class IntegrationConnector(models.Model):
    TYPE_GITOPS = 'gitops'
    TYPE_VULNERABILITY = 'vulnerability'
    name = models.CharField(max_length=100, unique=True)
    connector_type = models.CharField(max_length=30, choices=TYPE_CHOICES)
    enabled = models.BooleanField(default=False)
    read_only = models.BooleanField(default=True)
    config_encrypted = models.TextField(blank=True)
    last_status = models.CharField(max_length=20, choices=STATUS_CHOICES, default=STATUS_BLOCKED)

    def set_config(self, value):
        self.config_encrypted = encrypt_text(json.dumps(value, sort_keys=True)) if value else ''
```

Add `GitOpsCollectionRun`, `VulnerabilityImportRun`, `InfrastructureBlueprint`, and `InfrastructurePlan`, each with only status, count, digest, actor and timestamp metadata. Generate migration `0042_controlled_integrations.py` from the completed models and inspect it for encrypted fields and additive operations only.

- [ ] **Step 4: Implement adapter contracts with no external default client**

```python
def collect_gitops_connector(connector, adapter=None):
    run = GitOpsCollectionRun.objects.create(connector=connector, status=STATUS_PENDING)
    if not connector.enabled or not connector.read_only:
        return finish_run(run, STATUS_BLOCKED, 'connector_disabled')
    adapter = adapter or DisabledGitOpsAdapter()
    for finding in adapter.collect(connector.get_config()):
        record_gitops_drift(**normalize_gitops_finding(finding))
    return finish_run(run, STATUS_SUCCESS, 'completed')
```

`DisabledGitOpsAdapter` and its vulnerability equivalent must return a blocked outcome and must never make a network call. Normalizers reject unapproved kinds, malformed package/advisory values, raw documents, provider URLs, or unknown hosts.

- [ ] **Step 5: Run the focused tests and migration checks**

Run: `.venv/bin/python manage.py test devops.test_controlled_integrations && .venv/bin/python manage.py makemigrations devops --check --dry-run`

Expected: PASS; no pending model changes.

### Task 2: Readiness, Service Workflows, And Safe APIs

**Files:**
- Modify: `devops/services.py`
- Modify: `devops/api.py`
- Modify: `devops/urls.py`
- Modify: `devops/views.py`
- Modify: `devops/test_controlled_integrations.py`
- Modify: `docs/devops_json_api.md`

- [ ] **Step 1: Write failing permission and payload tests**

```python
def test_readiness_api_hides_connector_config_and_requires_security_admin(self):
    response = self.client.get('/devops/api/integration-readiness/')
    self.assertEqual(response.status_code, 401)
    self.login_as_security_viewer()
    self.assertEqual(self.client.get('/devops/api/integration-readiness/').status_code, 403)
    self.grant_security_admin()
    payload = self.client.get('/devops/api/integration-readiness/').json()
    self.assertNotIn('config', str(payload))
    self.assertNotIn('endpoint', str(payload))

def test_plan_creation_never_applies_provider_changes(self):
    response = self.client.post('/devops/api/infrastructure-blueprints/1/plans/', data='{}', content_type='application/json')
    self.assertEqual(response.status_code, 202)
    self.assertEqual(InfrastructurePlan.objects.get().status, 'pending')
```

- [ ] **Step 2: Run the focused tests and verify failure**

Run: `.venv/bin/python manage.py test devops.test_controlled_integrations`

Expected: FAIL because readiness and blueprint-plan routes do not exist.

- [ ] **Step 3: Add service-layer summary and bounded workflows**

```python
def integration_readiness_payload(now=None):
    return {
        'worker': worker_observability_payload()['worker'],
        'connectors': [connector.safe_summary() for connector in IntegrationConnector.objects.order_by('name')],
        'collections': safe_recent_collection_summaries(),
        'blueprint_plans': safe_recent_blueprint_plans(),
    }
```

Create `request_infrastructure_plan(blueprint, requester)` to validate an enabled, read-only blueprint; create a pending plan and audit it. It must not call Terraform, Ansible, a shell, or a provider SDK. Connector collection triggers must audit only their safe outcome category.

- [ ] **Step 4: Add protected endpoints and serializers**

```python
@api_login_required
@require_http_methods(['GET'])
def integration_readiness(request):
    if not has_role(request, DevOpsRole.ROLE_ADMIN, MODULE_SECURITY):
        return api_error('无权限', status=403, code='forbidden')
    return JsonResponse({'ok': True, **integration_readiness_payload()})
```

Add `GET /devops/api/integration-readiness/`, `GET /devops/api/integration-connectors/`, `POST /devops/api/integration-connectors/<id>/collect/`, `GET /devops/api/infrastructure-blueprints/`, and `POST /devops/api/infrastructure-blueprints/<id>/plans/`. Only safe serializer keys may be returned. Add parallel classic route only when a rendered readiness page is needed by the existing navigation; it must pass the same safe payload.

- [ ] **Step 5: Document API contracts and verify tests**

Add endpoint documentation that specifies login, role/module permission, safe response fields, disabled behavior, and the fact that no endpoint writes to Git, Kubernetes, hosts, or infrastructure providers.

Run: `.venv/bin/python manage.py test devops.test_controlled_integrations devops.test_governance_findings`

Expected: PASS; unauthenticated, viewer, admin, malformed-input, safe-field, and no-mutation cases covered.

### Task 3: Geist Integration Readiness Workspace

**Files:**
- Modify: `templates/devops/vue_app.html`
- Modify: `static/js/devops-vue.js`
- Modify: `static/css/devops-vue.css`
- Modify: `devops/tests.py`

- [ ] **Step 1: Write failing page and asset-contract tests**

```python
def test_devops_vue_keeps_geist_root_and_loads_readiness_workspace(self):
    response = self.client.get(reverse('devops:vue_app'))
    self.assertContains(response, 'ops-geist-console')
    self.assertContains(response, 'integration-readiness')
    self.assertContains(response, 'devops-vue.js?v=')
```

- [ ] **Step 2: Run the focused test and verify failure**

Run: `.venv/bin/python manage.py test devops.tests.DevOpsViewTests.test_devops_vue_keeps_geist_root_and_loads_readiness_workspace`

Expected: FAIL because the new readiness workspace marker is absent.

- [ ] **Step 3: Add the bounded Vue tab and API consumer**

```javascript
async loadIntegrationReadiness() {
  const response = await fetch('/devops/api/integration-readiness/', {credentials: 'same-origin'});
  const payload = await response.json();
  this.integrationReadiness = payload.ok ? payload : null;
}
```

Render dense Geist status rows for Worker, scheduler/integration health, connector summaries, collection counts, and blueprint plan state. Display only the safe fields returned by the API. Trigger buttons must be disabled for blocked connectors and can only post an existing record ID plus CSRF header; there is no URL, manifest, token, command, apply, or remediation input.

- [ ] **Step 4: Add scoped responsive CSS**

```css
.ops-geist-console .integration-readiness-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
  gap: 12px;
}
```

Keep tables and status chips compact, use existing Geist variables, preserve 390px width without horizontal overflow, and do not alter the WebSSH terminal exception.

- [ ] **Step 5: Verify page contract and JavaScript syntax**

Run: `.venv/bin/python manage.py test devops.tests.DevOpsViewTests && node --check static/js/devops-vue.js`

Expected: PASS.

### Task 4: Integration Review And Full Validation

**Files:**
- Modify: `README.md`
- Modify: `docs/devops_next_optimizations.md`
- Modify: `docs/devops_json_api.md`
- Test: `devops/test_controlled_integrations.py`, `devops/test_governance_findings.py`, `devops/tests.py`

- [ ] **Step 1: Write regression tests for prohibited behavior**

```python
def test_collection_never_calls_network_or_mutates_kubernetes(self):
    connector = self.enabled_gitops_connector()
    with mock.patch('requests.Session.request') as request:
        collect_gitops_connector(connector)
    request.assert_not_called()

def test_blueprint_api_has_no_apply_route(self):
    self.assertFalse(any('apply' in str(pattern.pattern) for pattern in devops_urls.urlpatterns))
```

- [ ] **Step 2: Run them and verify failure before any missing guard implementation**

Run: `.venv/bin/python manage.py test devops.test_controlled_integrations`

Expected: FAIL only if the implementation contains an unsafe default or apply route.

- [ ] **Step 3: Complete docs and safety guards**

Document the required connector configuration process without including credentials or secrets. State that external validation needs a separately authorized environment, and that the default implementation uses injected fake adapters in tests.

- [ ] **Step 4: Run the final validation suite**

Run:

```bash
.venv/bin/python manage.py check
.venv/bin/python manage.py makemigrations --check --dry-run
.venv/bin/python manage.py test devops
node --check static/js/devops-vue.js
git diff --check
```

Expected: all commands pass. Start the local server and inspect the authenticated DevOps Vue page at 390px, 768px, and 1440px; report that external provider connectivity remains unexercised unless explicitly authorized.
