# Monitor Dense Observability Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the monitor dashboard command-center presentation with the approved high-density observability layout while preserving its existing Prometheus data and controls.

**Architecture:** Keep `monitor/views.py` and the dashboard JSON payload unchanged. Reorganize only the `monitor-dashboard` Vue branch in `static/js/ops-vue-pages.js`, reusing existing computed dashboard rows, filters, loading states, and refresh methods. Scope the visual system to `static/css/monitor-command-center.css` so no other Vue page is affected.

**Tech Stack:** Django template delivery, vendored Vue 3, static JavaScript, CSS Grid, Font Awesome already bundled by the project.

---

### Task 1: Lock the production dashboard DOM contract

**Files:**
- Modify: `monitor/tests.py:2555-2600`
- Test: `monitor/tests.py:MonitorDashboardTests`

- [ ] **Step 1: Write the failing regression test**

```python
def test_dashboard_frontend_uses_dense_observability_sections(self):
    with open('static/js/ops-vue-pages.js', 'r') as handle:
        vue_source = handle.read()
    with open('static/css/monitor-command-center.css', 'r') as handle:
        css_source = handle.read()

    for marker in ('ops-monitor-overview', 'ops-monitor-summary-grid',
                   'ops-monitor-chart-grid', 'ops-monitor-resource-table'):
        self.assertIn(marker, vue_source)
    self.assertIn('.ops-monitor-overview {', css_source)
    self.assertIn('@media (max-width: 760px)', css_source)
```

- [ ] **Step 2: Run the focused test and verify it fails**

Run: `.venv/bin/python manage.py test monitor.tests.MonitorDashboardTests.test_dashboard_frontend_uses_dense_observability_sections`

Expected: FAIL because the new dense-observability markers do not yet exist.

### Task 2: Render real monitor data in the approved information architecture

**Files:**
- Modify: `static/js/ops-vue-pages.js:1791-1812`

- [ ] **Step 1: Replace only the `kind === 'monitor-dashboard'` markup**

Keep the existing `dashboardTab`, source selector, node/Pod filters, `loadDashboard(true)`, loading state, error state, and `dashboardActiveRows` bindings. Add the following stable regions without changing the backend payload:

```html
<section class="ops-monitor-overview">
  <header class="ops-monitor-topbar">...</header>
  <section class="ops-monitor-summary-grid">...</section>
  <section class="ops-monitor-workspace">
    <div class="ops-monitor-chart-grid">...</div>
    <aside class="ops-monitor-sidepanels">...</aside>
  </section>
  <section class="ops-monitor-resource-table">...</section>
</section>
```

Map all labels to live values: node count, Pod count, healthy Pods, filtered-row count, node/Pod status, CPU, memory, disk, I/O, and load. Use percentage bars for snapshot resource values; do not label them as historical trends or P95 metrics.

- [ ] **Step 2: Run the focused test and verify it passes**

Run: `.venv/bin/python manage.py test monitor.tests.MonitorDashboardTests.test_dashboard_frontend_uses_dense_observability_sections`

Expected: PASS.

### Task 3: Add a scoped responsive light observability visual system

**Files:**
- Modify: `static/css/monitor-command-center.css`

- [ ] **Step 1: Replace command-center selectors with monitor overview selectors**

Define a light neutral background, 8px maximum card radius, indigo action accent, semantic success/warning/error states, fixed-size metric rows, and grid columns that collapse at 980px and 760px. Keep dropdown menus above charts with explicit stacking rules.

```css
.ops-monitor-overview { color: #20242f; }
.ops-monitor-summary-grid { display: grid; grid-template-columns: repeat(5, minmax(0, 1fr)); }
.ops-monitor-workspace { display: grid; grid-template-columns: minmax(0, 1fr) 304px; }
@media (max-width: 760px) { .ops-monitor-summary-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); } }
```

- [ ] **Step 2: Verify static JavaScript syntax and focused monitor tests**

Run:

```bash
node --check static/js/ops-vue-pages.js
.venv/bin/python manage.py test monitor.tests.MonitorDashboardTests
```

Expected: both commands exit 0.

### Task 4: Verify runtime rendering and regression safety

**Files:**
- Verify: `templates/vue/page.html`
- Verify: `monitor/tests.py`
- Verify: `static/js/ops-vue-pages.js`
- Verify: `static/css/monitor-command-center.css`

- [ ] **Step 1: Run Django and diff checks**

Run:

```bash
.venv/bin/python manage.py check
git diff --check
```

Expected: both commands exit 0.

- [ ] **Step 2: Inspect the authenticated dashboard in a browser**

Check desktop and 390px widths for a visible summary grid, chart/workspace panels, operational filters, no horizontal overflow, and no console errors. Confirm the source selector, node/Pod switcher, and refresh control remain present.
