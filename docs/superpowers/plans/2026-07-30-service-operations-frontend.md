# Service Operations Frontend Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Apply the Signal Lattice classic-operation treatment to service management, controlled runbooks, file distribution, and metric history without changing submission, permission, host-scope, upload, approval, or monitoring behavior.

**Architecture:** Extend the local `ops-console-theme.css` only through selectors rooted beneath `.ops-legacy-operation`. Add small semantic classes to existing Django template elements so existing forms, table rows, `chart_json`, and Django context data remain their sole behavior source.

**Tech Stack:** Django templates, local CSS, Bootstrap 4 utility classes, existing inline SVG chart JavaScript, Django test runner, no new runtime dependencies.

---

## File Structure

| File | Change |
| --- | --- |
| `static/css/ops-console-theme.css` | Add scoped service-action, runbook, file-distribution, metric-chart, and capacity-state rules. |
| `templates/devops/services.html` | Add page, operation, result, record, and table-wrapper hooks without altering the service form. |
| `templates/devops/files.html` | Add page, distribution submission, record, and table-wrapper hooks without altering multipart submission. |
| `templates/devops/runbooks.html` | Add page, management, list, initiation, and table-wrapper hooks while retaining role and host filtering. |
| `templates/devops/metrics.html` | Add page, filter, trend, legend, table-wrapper, and capacity-state hooks while retaining `chart_json` and inline script. |
| `devops/tests.py` | Keep existing workflow tests as the server-behavior contract; add a rendering-contract assertion only if a scoped template change breaks an existing test path. |

## Task 1: Extend the Scoped Service-Operation CSS Layer

**Files:**
- Modify: `static/css/ops-console-theme.css`
- Test: `git diff --check`, `.venv/bin/python manage.py check`

- [ ] **Step 1: Capture the baseline before shared stylesheet edits.**

Run:

```bash
git diff --check
.venv/bin/python manage.py check
```

Expected: no whitespace errors and no Django system-check errors. Do not revert unrelated dirty-worktree changes.

- [ ] **Step 2: Add only semantic classic-operation selectors.**

Append rules rooted at `body.ops-console .ops-legacy-operation` for these hooks:

```css
body.ops-console .ops-legacy-operation .ops-service-action,
body.ops-console .ops-legacy-operation .ops-file-distribution-action {
    border-left: 4px solid var(--ops-console-attention);
}

body.ops-console .ops-legacy-operation .ops-metric-trend {
    border: 1px solid var(--ops-console-line);
    background: #f8fbfb;
}
```

Use separate selectors for `.ops-runbook-management`, `.ops-runbook-initiation`,
`.ops-metric-filter`, `.ops-metric-legend`, `.ops-capacity-risk`,
`.ops-capacity-stable`, and `.ops-capacity-unknown`. Do not style generic
`.card`, `.table`, `.form-control`, `.metric-chart-wrap`, or `svg` selectors
outside the legacy-operation root.

- [ ] **Step 3: Make local action controls and metric legend stable at narrow widths.**

At `max-width: 768px`, let `.ops-runbook-initiation` and the metric legend wrap
without changing form field names or forcing page-level overflow. Preserve the
existing `.ops-legacy-table-wrap` horizontal scroll behavior and shared
focus-visible/reduced-motion rules.

- [ ] **Step 4: Validate CSS scope.**

Run:

```bash
git diff --check -- static/css/ops-console-theme.css
rg -n "ops-(service-action|file-distribution-action|runbook-management|metric-trend|capacity-risk)" static/css/ops-console-theme.css
.venv/bin/python manage.py check
```

Expected: all new hooks are scoped below `.ops-legacy-operation`, and the
Django system check succeeds.

## Task 2: Style Service Management and File Distribution Without Changing Submissions

**Files:**
- Modify: `templates/devops/services.html`
- Modify: `templates/devops/files.html`
- Test: `.venv/bin/python manage.py test devops --verbosity 1`

- [ ] **Step 1: Add service-management hooks around existing surfaces.**

Set the service root to:

```html
<div class="container-fluid px-4 ops-legacy-operation ops-service-page">
```

Append `ops-legacy-card ops-service-action` to the submission card,
`ops-legacy-card ops-service-result` to the conditional result card, and
`ops-legacy-card ops-legacy-records` plus `ops-legacy-table-wrap` to the record
surface. Preserve `method="post"`, `{% csrf_token %}`, `form.host`,
`form.service_name`, `form.action`, the submit button, result output, and all
record values.

- [ ] **Step 2: Add file-distribution hooks around the existing multipart form.**

Set the distribution root to `ops-legacy-operation ops-file-distribution-page`.
Append `ops-legacy-card ops-file-distribution-action` to the form card and
`ops-legacy-card ops-legacy-records` / `ops-legacy-table-wrap` to the record
card/body. Keep `method="post"`, `enctype="multipart/form-data"`,
`{% csrf_token %}`, `form.source_file`, `form.remote_path`, `form.hosts`, and
the detail URL unchanged.

- [ ] **Step 3: Confirm server-facing template invariants statically.**

Run:

```bash
rg -n "method=\"post\"|multipart/form-data|csrf_token|form\.(host|service_name|action|source_file|remote_path|hosts)|service_manage|file_distribution_detail" templates/devops/services.html templates/devops/files.html
git diff --check -- templates/devops/services.html templates/devops/files.html
```

Expected: every original POST, field rendering expression, and record detail
link remains present alongside the new class hooks.

- [ ] **Step 4: Run the service and distribution workflow contract.**

Run:

```bash
.venv/bin/python manage.py test devops --verbosity 1
```

Expected: existing unsafe-service-name, role/host-scope, file remote-path,
upload, and distribution rendering tests pass. Do not invoke a real SSH service
operation or file upload target.

## Task 3: Style Runbooks and Metric History Without Changing Permissions or Data Bridges

**Files:**
- Modify: `templates/devops/runbooks.html`
- Modify: `templates/devops/metrics.html`
- Test: `.venv/bin/python manage.py test devops --verbosity 1`

- [ ] **Step 1: Add runbook management, list, and initiation hooks.**

Set the root to `ops-legacy-operation ops-runbook-page`. Append
`ops-legacy-card ops-runbook-management` to the existing `{% if can_manage %}`
card. Append `ops-legacy-card ops-runbook-records` and
`ops-legacy-table-wrap` to the list card/body. Append `ops-runbook-initiation`
to the existing runbook initiation form only. Do not change `can_manage`,
`can_initiate`, `runbook.enabled`, `visible_host_ids`, POST action, CSRF token,
`host_id` select, or the edit URL.

- [ ] **Step 2: Add metric filter, trend, table, and capacity-state hooks.**

Set the root to `ops-legacy-operation ops-metric-history-page`. Apply
`ops-legacy-card ops-metric-filter` to the GET filter card and
`ops-legacy-card ops-metric-trend` to the trend card. Append
`ops-metric-legend` to the legend container. Add `ops-legacy-card` and
`ops-legacy-table-wrap` to each of the latest-metric, capacity-forecast, and
sample-record surfaces. Append `ops-capacity-risk`, `ops-capacity-stable`, or
`ops-capacity-unknown` to the existing capacity-state span branches.

- [ ] **Step 3: Preserve the chart and filter contract.**

Leave the following content unchanged apart from surrounding classes:

```html
<form method="get" class="row g-3 align-items-end">
<svg id="metricTrendChart" viewBox="0 0 960 320" preserveAspectRatio="none" role="img" aria-label="监控指标趋势图"></svg>
const chartData = {{ chart_json|safe }};
```

Run:

```bash
rg -n "can_manage|can_initiate|visible_host_ids|runbook_initiate|csrf_token|name=\"host\"|name=\"range\"|metricTrendChart|chart_json|role=\"img\"" templates/devops/runbooks.html templates/devops/metrics.html
git diff --check -- templates/devops/runbooks.html templates/devops/metrics.html
```

Expected: permission conditions, host filtering, filter parameters, and SVG
data bridge remain present.

- [ ] **Step 4: Run the runbook and metrics workflow contract.**

Run:

```bash
.venv/bin/python manage.py test devops --verbosity 1
```

Expected: existing runbook visible-host, metrics rendering, host/range filter,
capacity forecast, and permission tests pass.

## Task 4: Final Integration and Visual Safety Checks

**Files:**
- Verify: `static/css/ops-console-theme.css`
- Verify: `templates/devops/services.html`
- Verify: `templates/devops/runbooks.html`
- Verify: `templates/devops/files.html`
- Verify: `templates/devops/metrics.html`

- [ ] **Step 1: Run final static and test checks.**

Run:

```bash
git diff --check
.venv/bin/python manage.py check
.venv/bin/python manage.py test devops --verbosity 1
```

Expected: all commands exit successfully.

- [ ] **Step 2: Inspect accessible page behavior without submitting privileged work.**

Using an authorized test account, inspect each page at 390px, 768px, and
1440px. Verify white cards have dark readable text, action and evidence areas
remain distinct, tables scroll locally, the metric SVG label remains present,
and focus visibility remains clear. Do not submit a service action, runbook
approval, file distribution, or privileged workflow solely to validate visuals.

- [ ] **Step 3: Review scope before handoff.**

Run:

```bash
git diff -- static/css/ops-console-theme.css templates/devops/services.html templates/devops/runbooks.html templates/devops/files.html templates/devops/metrics.html
```

Expected: changes are limited to local CSS and semantic template hooks; no
views, forms, services, models, URLs, permissions, host-scope logic, API
payloads, migrations, or external dependencies changed.
