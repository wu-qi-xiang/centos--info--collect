# Legacy DevOps Operations Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Apply the Signal Lattice operations language to the six high-frequency, server-rendered DevOps pages while preserving every workflow, permission condition, form request, and server-side validation result.

**Architecture:** Add a narrow classic-page extension to the existing local console theme, scoped by `.ops-legacy-operation`, then add only semantic layout hooks to the selected templates. Keep each form's method, action, field rendering, CSRF token, hidden inputs, submit names and values, and each table's server-rendered data unchanged.

**Tech Stack:** Django templates, local CSS, Bootstrap 4 utility classes, Django test runner, no new runtime dependencies.

---

## File Structure

| File | Change |
| --- | --- |
| `static/css/ops-console-theme.css` | Add scoped classic-operation layout, navigation, status, focus, and responsive rules without changing the Vue-console styles. |
| `templates/devops/_nav.html` | Wrap existing permission-filtered links in a labelled navigation landmark and add navigation hook classes. |
| `templates/devops/commands.html` | Add page, action-panel, result, and record hooks around the existing command workflow. |
| `templates/devops/tasks.html` | Add equivalent hooks around the existing bulk-task workflow. |
| `templates/devops/approvals.html` | Add attention and pending-decision hooks while retaining the current approval controls. |
| `templates/devops/deployments.html` | Add separate preview, approval, execution, and rollback action hooks with current form semantics intact. |
| `templates/devops/alerts.html` | Add severity, silence, filtering, and alert-record hooks without altering alert lifecycle POSTs. |
| `devops/tests.py` | Do not modify unless the implementation introduces a template rendering regression; existing workflow tests remain the contract because no server behavior changes. |

## Task 1: Establish the Legacy Operations CSS Boundary

**Files:**
- Modify: `static/css/ops-console-theme.css`
- Test: `git diff --check`, `.venv/bin/python manage.py check`

- [ ] **Step 1: Capture the pre-change static and Django baseline.**

Run:

```bash
git diff --check
.venv/bin/python manage.py check
```

Expected: no whitespace errors and no Django system-check errors. Preserve unrelated dirty-worktree changes.

- [ ] **Step 2: Add a white-surface legacy page layer below the existing console rules.**

Add selectors rooted at `body.ops-console .ops-legacy-operation` only. Establish dark readable text, `#ffffff` card surfaces, restrained borders, compact card headers, semantic page heading accent, and `.ops-legacy-table-wrap { overflow-x: auto; }`. Do not use broad selectors such as `body.ops-console .card` or `body.ops-console h1`, because they would regress other classic pages or Vue roots.

Use explicit hooks such as:

```css
body.ops-console .ops-legacy-operation {
    color: #17242a;
}

body.ops-console .ops-legacy-operation .ops-legacy-card {
    border: 1px solid #c7d4d6;
    border-radius: 6px;
    background: #ffffff;
}

body.ops-console .ops-legacy-operation .ops-critical-action {
    border-left: 4px solid var(--ops-console-critical);
}
```

- [ ] **Step 3: Define semantic state and action-group rules.**

Style `.ops-attention-panel`, `.ops-preview-panel`, `.ops-execute-action`, `.ops-approval-action`, `.ops-rollback-action`, `.ops-alert-critical`, `.ops-alert-warning`, `.ops-alert-open`, `.ops-alert-resolved`, and `.ops-legacy-empty` using the existing signal, attention, and critical tokens. Preserve text labels and existing Bootstrap classes; semantic color must not be the sole status indicator.

- [ ] **Step 4: Add narrow responsive and accessible control rules.**

At `max-width: 768px`, allow `.ops-legacy-nav` and table wrappers to scroll horizontally; keep form controls at `width: 100%` only in their existing column containers; allow inline approval and alert forms to wrap. Keep the current shared focus-visible and reduced-motion rules. Do not change page-level overflow or introduce JavaScript.

- [ ] **Step 5: Validate the CSS boundary.**

Run:

```bash
git diff --check -- static/css/ops-console-theme.css
rg -n "ops-legacy-operation|ops-critical-action|ops-alert-critical" static/css/ops-console-theme.css
.venv/bin/python manage.py check
```

Expected: scoped selectors exist, no whitespace errors, and Django reports no system-check errors.

## Task 2: Preserve Navigation and Refine Command and Task Submission

**Files:**
- Modify: `templates/devops/_nav.html`
- Modify: `templates/devops/commands.html`
- Modify: `templates/devops/tasks.html`
- Test: `.venv/bin/python manage.py test devops --verbosity 1`

- [ ] **Step 1: Convert the shared link strip into a labelled landmark.**

Replace only the outer `<div class="devops-nav ...">` with:

```html
<nav class="devops-nav ops-legacy-nav d-flex flex-wrap gap-2 mb-4"
     aria-label="DevOps 操作导航">
```

Close it with `</nav>`. Keep all `{% if devops_navigation.* %}` blocks, URLs, labels, and anchor classes unchanged.

- [ ] **Step 2: Add command-page hooks without changing its POST form.**

Change the root to `class="container-fluid px-4 ops-legacy-operation ops-command-page"`. Add `ops-legacy-card ops-critical-action` to the command submission card, `ops-legacy-card ops-command-result` to the conditional result card, and `ops-legacy-card ops-legacy-records` plus `ops-legacy-table-wrap` to the history card/body. Do not change the form method, `{% csrf_token %}`, `form.host`, `form.command`, result output, or detail URL.

- [ ] **Step 3: Add equivalent bulk-task hooks.**

Change the root to `class="container-fluid px-4 ops-legacy-operation ops-task-page"`. Apply `ops-legacy-card ops-critical-action` to the submission card and `ops-legacy-card ops-legacy-records` / `ops-legacy-table-wrap` to the record surface. Preserve `form.name`, `form.hosts`, `form.command`, CSRF, submit button, status display, and task detail URL.

- [ ] **Step 4: Run the unchanged workflow contract.**

Run:

```bash
.venv/bin/python manage.py test devops --verbosity 1
```

Expected: existing command/task authorization, host-scope, and workflow tests pass. If a failure occurs, report it before editing view or service code, since those are out of scope.

## Task 3: Make Pending Approvals and Deployment Decision Paths Scannable

**Files:**
- Modify: `templates/devops/approvals.html`
- Modify: `templates/devops/deployments.html`
- Test: `.venv/bin/python manage.py test devops --verbosity 1`

- [ ] **Step 1: Add approval-page and pending-row hooks.**

Set the approval root to `ops-legacy-operation ops-approval-page`, the submission card to `ops-legacy-card ops-attention-panel`, and the list card/body to `ops-legacy-card ops-legacy-records` / `ops-legacy-table-wrap`. On the existing `{% if item.status == "pending" %}` table row, append `ops-pending-row` to the `<tr>` class. Keep requester self-approval prevention and both approval forms unchanged.

- [ ] **Step 2: Add deployment-page and form action hooks.**

Set the deployment root to `ops-legacy-operation ops-deployment-page`. Apply `ops-legacy-card` to application, release, preview, application-list, and release-record cards. Add `ops-preview-action` to the preview submit button, `ops-execute-action` to the execute submit button, and `ops-approval-action` to the approval submit button. Preserve `name="submit_mode"`, values `preview`, `execute`, and `approval`, CSRF, form fields, and all view-provided preview tables.

- [ ] **Step 3: Identify the read-only preview surface and any rollback action with hooks.**

Add `ops-preview-panel` to the `{% if preview %}` card. Find the existing rollback submit control in `deployments.html` and append `ops-rollback-action` without changing its form `action`, method, hidden inputs, or submit value. Add `ops-legacy-table-wrap` to each existing `table-responsive` used by this template.

- [ ] **Step 4: Validate approvals and deployment behavior stays server-owned.**

Run:

```bash
.venv/bin/python manage.py test devops --verbosity 1
rg -n "submit_mode|approval_decide|csrf_token|ops-(preview|execute|approval|rollback)-action" templates/devops/approvals.html templates/devops/deployments.html
```

Expected: test suite passes and the original CSRF/action/submit-mode markers remain alongside the styling hooks.

## Task 4: Add Alert Severity and Silence-Management Visual Structure

**Files:**
- Modify: `templates/devops/alerts.html`
- Test: `.venv/bin/python manage.py test devops --verbosity 1`

- [ ] **Step 1: Add page, silence, filter, and record surface hooks.**

Set the page root to `ops-legacy-operation ops-alert-page`. Apply `ops-legacy-card ops-silence-create` to the silence form card, `ops-legacy-card ops-silence-list` plus `ops-legacy-table-wrap` to the silence list, `ops-legacy-card ops-alert-filters` to the GET filter card, and `ops-legacy-card ops-alert-records` plus `ops-legacy-table-wrap` to the records card. Preserve every existing input name and filter value.

- [ ] **Step 2: Add semantic classes to the existing level and status badges.**

Append `ops-alert-critical`, `ops-alert-warning`, or `ops-alert-info` to the existing level badge according to its existing Django condition. Append `ops-alert-open`, `ops-alert-processing`, `ops-alert-resolved`, or `ops-alert-silenced` to the existing status badge according to its existing condition. Keep `display_level` and `display_status` text and all current Bootstrap badge classes.

- [ ] **Step 3: Add compact hooks to destructive and state-changing actions.**

Append `ops-silence-delete` to the existing silence delete button and `ops-alert-update-form` to the alert update form. Do not add confirmation JavaScript, alter form actions, or expose hidden request values.

- [ ] **Step 4: Validate existing filtering and lifecycle tests.**

Run:

```bash
.venv/bin/python manage.py test devops --verbosity 1
rg -n "silence_(create|delete)|alert_update|name=\"next\"|ops-alert-" templates/devops/alerts.html
```

Expected: tests pass and the original POST endpoints plus redirect-preservation input remain present.

## Task 5: Perform Static, Runtime, and Visual Completion Checks

**Files:**
- Verify: `static/css/ops-console-theme.css`
- Verify: `templates/devops/_nav.html`
- Verify: `templates/devops/commands.html`
- Verify: `templates/devops/tasks.html`
- Verify: `templates/devops/approvals.html`
- Verify: `templates/devops/deployments.html`
- Verify: `templates/devops/alerts.html`

- [ ] **Step 1: Run the final static and Django checks.**

Run:

```bash
git diff --check
.venv/bin/python manage.py check
.venv/bin/python manage.py test devops --verbosity 1
```

Expected: all commands exit successfully.

- [ ] **Step 2: Inspect the authenticated UI without executing operations.**

With an authorized test account, open command, task, approval, deployment, and alert pages at 390px, 768px, and 1440px. Verify the labelled navigation, a visible primary heading, table-local scrolling, focus visibility, readable dark text on white surfaces, and semantic action/status treatment. Do not submit commands, tasks, approvals, deployments, rollbacks, alert updates, or silence changes merely for visual inspection.

- [ ] **Step 3: Review the final diff against the scope boundary.**

Run:

```bash
git diff -- static/css/ops-console-theme.css templates/devops/_nav.html templates/devops/commands.html templates/devops/tasks.html templates/devops/approvals.html templates/devops/deployments.html templates/devops/alerts.html
```

Expected: only local CSS and semantic template hooks changed; there are no URL, permission, form-value, CSRF, API, model, migration, or server-side workflow changes.
