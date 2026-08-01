# DevOps Bright Workbench Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rework `/devops/` into the approved bright, risk-prioritized workbench while preserving all existing DevOps data, permission, CSRF, and execution contracts.

**Architecture:** Keep the existing Vue bootstrap and all API calls intact. Add small computed presentation collections in `static/js/devops-vue.js`, replace only the dashboard tab markup, and scope the bright workbench component rules to `.ops-console-devops`. Retain the current functional tabs and their permission filtering.

**Tech Stack:** Django templates, vendored Vue 3, existing DevOps JSON APIs, local static CSS, Django test runner, Node syntax checking.

---

## File Structure

| File | Responsibility |
| --- | --- |
| `templates/devops/vue_app.html` | Opt the existing DevOps Vue root into the bright-workbench marker and bump only its local static cache keys. |
| `static/js/devops-vue.js` | Build presentation-only priority and active-work lists from already fetched dashboard, approval, command, task, and deployment data; render the approved dashboard hierarchy. |
| `static/css/devops-vue.css` | Define scoped light workspace, status rails, compact cards, bounded tables, and responsive rules. |
| `devops/tests.py` | Assert the dashboard template and static Vue source retain the approved rendering and safety contracts. |

## Task 1: Lock The Rendering Contract Before Restyling

**Files:**
- Modify: `devops/tests.py` in the existing DevOps dashboard test class
- Test: `.venv/bin/python manage.py test devops`

- [ ] **Step 1: Add failing rendering-contract assertions**

  Extend `test_vue_app_renders_shell` with the marker and cache-key assertions:

  ```python
  self.assertContains(response, 'ops-console-devops')
  self.assertContains(response, 'devops-vue.css?v=20260730-bright-workbench-01')
  self.assertContains(response, 'devops-vue.js?v=20260730-bright-workbench-01')
  ```

  Add a focused static-source test beside `test_vue_static_includes_approval_decision_controls`:

  ```python
  def test_vue_static_includes_bright_workbench_priority_sections(self):
      with open('static/js/devops-vue.js', 'r') as handle:
          content = handle.read()

      self.assertIn('priorityItems()', content)
      self.assertIn('activeWorkItems()', content)
      self.assertIn('需要处理', content)
      self.assertIn('运行中工作', content)
      self.assertIn('主机健康概览', content)
      self.assertIn('/devops/api/dashboard/', content)
      self.assertIn('X-CSRFToken', content)
  ```

- [ ] **Step 2: Run the targeted test to demonstrate the missing workbench contract**

  Run:

  ```bash
  .venv/bin/python manage.py test devops.tests.DevOpsViewTests.test_vue_app_renders_shell devops.tests.DevOpsViewTests.test_vue_static_includes_bright_workbench_priority_sections
  ```

  Expected: the new cache-key and source assertions fail before the template and Vue changes; existing authentication behavior remains unaffected.

## Task 2: Build Priority Collections Without Changing API Requests

**Files:**
- Modify: `static/js/devops-vue.js`
- Test: `node --check static/js/devops-vue.js`

- [ ] **Step 1: Add presentation-only computed lists after `hostMetrics()`**

  Use fields already returned by `/devops/api/dashboard/` and currently fetched workflow endpoints. Do not add a fetch, mutate source records, or expose command output. Add the following computed properties:

  ```javascript
  recentAlerts() {
      return (this.dashboard && this.dashboard.recent_alerts) || [];
  },
  pendingApprovals() {
      return (this.approvals || []).filter((item) => item.status === 'pending');
  },
  priorityItems() {
      const alerts = this.recentAlerts.map((item) => ({
          key: `alert-${item.id}`,
          kind: 'alert',
          tone: item.level === 'critical' ? 'danger' : 'warning',
          title: item.message || item.metric || '告警事件',
          meta: `${item.host ? item.host.name : '全局'} · ${item.created_at || '-'}`,
          label: item.level_label || item.status_label || '告警',
      }));
      const approvals = this.pendingApprovals.map((item) => ({
          key: `approval-${item.id}`,
          kind: 'approval',
          tone: 'warning',
          title: item.title || '待审批操作',
          meta: `${item.requester || '-'} · ${item.created_at || '-'}`,
          label: item.status_label || '待审批',
      }));
      return alerts.concat(approvals).slice(0, 6);
  },
  activeWorkItems() {
      const active = ['pending', 'running'];
      const mapItem = (item, kind, title) => ({
          key: `${kind}-${item.id}`,
          title,
          meta: item.created_at || '-',
          label: item.status_label || item.status || '进行中',
          tone: item.status === 'running' ? 'active' : 'waiting',
      });
      return []
          .concat((this.commands || []).filter((item) => active.includes(item.status)).map((item) => mapItem(item, 'command', item.host ? item.host.name : '命令执行')))
          .concat((this.tasks || []).filter((item) => active.includes(item.status)).map((item) => mapItem(item, 'task', item.name || '批量任务')))
          .concat((this.deployments || []).filter((item) => active.includes(item.status)).map((item) => mapItem(item, 'deployment', item.app ? item.app.name : '发布任务')))
          .slice(0, 6);
  },
  ```

- [ ] **Step 2: Keep all state and authorization behavior unchanged**

  Do not alter `apiFetch`, `loadAll`, `loadWorkflowSummaries`, `visibleTabs`,
  `canRunCommand`, `canRunTask`, `canDecideApproval`, or any POST endpoint.
  The new properties only read `dashboard`, `approvals`, `commands`, `tasks`,
  and `deployments` that are already loaded through current, scoped requests.

- [ ] **Step 3: Check syntax**

  Run:

  ```bash
  node --check static/js/devops-vue.js
  ```

  Expected: no output and exit code 0.

## Task 3: Replace Only The Dashboard Tab Markup

**Files:**
- Modify: `static/js/devops-vue.js`
- Test: `node --check static/js/devops-vue.js`

- [ ] **Step 1: Replace the current `activeTab === 'dashboard'` section**

  Retain all other tab sections. Render the A hierarchy using the computed data:

  ```html
  <section v-if="activeTab === 'dashboard'" class="vue-workbench" aria-labelledby="devops-workbench-title">
      <div class="vue-workbench-heading">
          <div>
              <h2 id="devops-workbench-title" class="visually-hidden">DevOps 工作概览</h2>
              <p class="vue-workbench-kicker">优先处理当前风险与运行中工作</p>
          </div>
          <span class="vue-workbench-refresh" :aria-busy="refreshing">[[ refreshing ? '正在刷新' : '数据已加载' ]]</span>
      </div>
      <div class="vue-stat-grid vue-workbench-stats">
          <div class="vue-stat-card"><div><div class="vue-stat-label">受管主机</div><div class="vue-stat-value">[[ counts.hosts || 0 ]]</div><div class="vue-stat-note">当前可访问范围</div></div></div>
          <div class="vue-stat-card"><div><div class="vue-stat-label">待处理告警</div><div class="vue-stat-value">[[ counts.open_alerts || 0 ]]</div><div class="vue-stat-note">按主机范围过滤</div></div></div>
          <div class="vue-stat-card"><div><div class="vue-stat-label">待审批</div><div class="vue-stat-value">[[ pendingApprovals.length ]]</div><div class="vue-stat-note">需要人工确认</div></div></div>
          <div class="vue-stat-card"><div><div class="vue-stat-label">运行中工作</div><div class="vue-stat-value">[[ activeWorkItems.length ]]</div><div class="vue-stat-note">命令、任务和发布</div></div></div>
      </div>
      <div class="vue-workbench-grid">
          <section class="vue-panel vue-priority-panel">
              <div class="vue-panel-header"><h2 class="vue-panel-title">需要处理</h2><span class="vue-panel-count">[[ priorityItems.length ]] 项</span></div>
              <div v-if="priorityItems.length" class="vue-priority-list">
                  <article v-for="item in priorityItems" :key="item.key" class="vue-priority-row" :class="'is-' + item.tone">
                      <span class="vue-priority-rail" aria-hidden="true"></span>
                      <div><div class="vue-row-title">[[ item.title ]]</div><div class="vue-row-meta">[[ item.meta ]]</div></div>
                      <span class="vue-status" :class="item.tone">[[ item.label ]]</span>
                  </article>
              </div>
              <div v-else class="vue-empty">当前没有需要处理的告警或审批。</div>
          </section>
          <section class="vue-panel">
              <div class="vue-panel-header"><h2 class="vue-panel-title">运行中工作</h2><span class="vue-panel-count">[[ activeWorkItems.length ]] 项</span></div>
              <div v-if="activeWorkItems.length" class="vue-priority-list">
                  <article v-for="item in activeWorkItems" :key="item.key" class="vue-priority-row" :class="'is-' + item.tone">
                      <span class="vue-priority-rail" aria-hidden="true"></span>
                      <div><div class="vue-row-title">[[ item.title ]]</div><div class="vue-row-meta">[[ item.meta ]]</div></div>
                      <span class="vue-status" :class="item.tone">[[ item.label ]]</span>
                  </article>
              </div>
              <div v-else class="vue-empty">当前没有运行中的命令、任务或发布。</div>
          </section>
      </div>
      <section class="vue-panel vue-health-panel">
          <div class="vue-panel-header"><h2 class="vue-panel-title">主机健康概览</h2><span class="vue-panel-count">[[ hostMetrics.length ]] 台</span></div>
          <div v-if="hostMetrics.length" class="vue-health-table-wrap">
              <table class="vue-health-table"><thead><tr><th>主机</th><th>CPU</th><th>内存</th><th>磁盘</th><th>状态</th></tr></thead>
              <tbody><tr v-for="item in hostMetrics" :key="item.host.id"><td><strong>[[ item.host.name ]]</strong><small>[[ item.host.ip || '-' ]]</small></td><td>[[ percent(item.cpu) ]]</td><td>[[ percent(item.memory) ]]</td><td>[[ percent(item.disk) ]]</td><td><span class="vue-status" :class="metricTone(item.cpu)">[[ metricTone(item.cpu) === 'danger' ? '告警' : '正常' ]]</span></td></tr></tbody></table>
          </div>
          <div v-else class="vue-empty">暂无可访问主机的指标数据。</div>
      </section>
  </section>
  ```

- [ ] **Step 2: Preserve accessible tab behavior and existing notices**

  Keep `role="tablist"`, `role="tab"`, keyboard handling, the `error`
  alert, and the success notice unchanged. Do not change `activeTab` keys,
  route references, or tab permission/feature filtering.

- [ ] **Step 3: Check syntax again**

  Run:

  ```bash
  node --check static/js/devops-vue.js
  ```

  Expected: no output and exit code 0.

## Task 4: Scope The Approved Bright Workbench Styles

**Files:**
- Modify: `templates/devops/vue_app.html`
- Modify: `static/css/devops-vue.css`
- Test: `git diff --check -- templates/devops/vue_app.html static/css/devops-vue.css`

- [ ] **Step 1: Apply the page marker and version local assets**

  Preserve the Vue root identifier and loading markup. Update the root and
  cache keys to:

  ```html
  <link rel="stylesheet" href="{% static 'css/devops-vue.css' %}?v=20260730-bright-workbench-01">
  <div id="devops-vue-root" class="devops-vue-shell ops-console-page ops-console-devops ops-bright-workbench">
  <script src="{% static 'js/devops-vue.js' %}?v=20260730-bright-workbench-01"></script>
  ```

- [ ] **Step 2: Append scoped CSS rules below `.ops-bright-workbench`**

  Define local custom properties and avoid changing generic Bootstrap rules:

  ```css
  .ops-bright-workbench {
      --workbench-canvas: #f4f7fa;
      --workbench-paper: #ffffff;
      --workbench-line: #dbe3ec;
      --workbench-ink: #17212b;
      --workbench-muted: #64748b;
      --workbench-primary: #1769e0;
      --workbench-danger: #bc2e43;
      --workbench-warning: #b95b00;
      --workbench-success: #17805f;
      color: var(--workbench-ink);
  }
  .ops-bright-workbench .vue-panel,
  .ops-bright-workbench .vue-stat-card,
  .ops-bright-workbench .vue-topbar,
  .ops-bright-workbench .vue-tabs {
      background: var(--workbench-paper);
      border-color: var(--workbench-line);
      box-shadow: none;
  }
  .ops-bright-workbench .vue-workbench-grid {
      display: grid;
      grid-template-columns: minmax(0, 1.45fr) minmax(280px, .9fr);
      gap: 16px;
  }
  .ops-bright-workbench .vue-priority-row {
      display: grid;
      grid-template-columns: 4px minmax(0, 1fr) auto;
      gap: 12px;
      align-items: center;
      padding: 12px 14px;
      border-bottom: 1px solid var(--workbench-line);
  }
  .ops-bright-workbench .vue-priority-rail { align-self: stretch; background: var(--workbench-primary); }
  .ops-bright-workbench .vue-priority-row.is-danger .vue-priority-rail { background: var(--workbench-danger); }
  .ops-bright-workbench .vue-priority-row.is-warning .vue-priority-rail { background: var(--workbench-warning); }
  ```

- [ ] **Step 3: Add narrow-width rules that prevent page-level overflow**

  ```css
  @media (max-width: 768px) {
      .ops-bright-workbench,
      .ops-bright-workbench .vue-workbench,
      .ops-bright-workbench .vue-workbench-grid { min-width: 0; }
      .ops-bright-workbench .vue-stat-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .ops-bright-workbench .vue-workbench-grid { grid-template-columns: minmax(0, 1fr); }
      .ops-bright-workbench .vue-health-table-wrap { overflow-x: auto; }
      .ops-bright-workbench .vue-health-table { min-width: 620px; }
  }
  ```

  Keep all table overflow inside `.vue-health-table-wrap`; do not add a global
  `overflow-x: hidden` rule that would conceal a broken layout.

- [ ] **Step 4: Check whitespace and template rendering**

  Run:

  ```bash
  git diff --check -- templates/devops/vue_app.html static/css/devops-vue.css
  .venv/bin/python manage.py check
  ```

  Expected: no whitespace errors and no Django system-check errors.

## Task 5: Validate Existing Contracts And Visual Behavior

**Files:**
- Test: `devops/tests.py`, `static/js/devops-vue.js`, rendered `/devops/`

- [ ] **Step 1: Run focused DevOps tests and static checks**

  ```bash
  .venv/bin/python manage.py test devops
  .venv/bin/python manage.py check
  node --check static/js/devops-vue.js
  git diff --check
  ```

  Expected: all commands pass. If pre-existing unrelated failures appear,
  report their exact owner and do not alter unrelated code to mask them.

- [ ] **Step 2: Inspect the rendered console at three widths**

  Use an authenticated local session with display-only test data. At 1440px,
  verify a four-card summary and two-column action row. At 768px, verify the
  action panels stack without clipping. At 390px, verify the two-column
  summary, horizontally scrollable tab strip, internal table scrolling, and
  `document.documentElement.scrollWidth === document.documentElement.clientWidth`.

- [ ] **Step 3: Exercise safe state coverage**

  Verify the empty priority queue, empty active-work list, loading state, and
  a mocked API error. Do not submit a command, task, approval decision,
  deployment, file operation, notification, or remote action during visual QA.

## Rollback

Revert only the four files named in the file structure table. No database,
API, deployment, remote-host, or authorization state changes are part of this
work.
