# Operations Console Frontend Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver a responsive, accessible Signal Lattice visual system for the
shared operations shell and the AIOps, DevOps, and monitor Vue consoles without
changing API, permission, CSRF, or remote-operation behavior.

**Architecture:** Add one namespaced static token layer after the legacy styles,
then make only explicit shell and Vue-root opt-ins. Keep `custom.css` and
`app-modern.css` as legacy compatibility sources. Update AIOps and DevOps tab
markup in place so that existing reactive state, request URLs, and payload keys
remain unchanged.

**Tech Stack:** Django templates, static CSS, vendored Vue 3, Bootstrap 4,
existing jQuery/custom.js, Django test runner, Node syntax checking.

---

## File Structure

| File | Change |
| --- | --- |
| `static/css/ops-console-theme.css` | New namespaced Signal Lattice tokens, shell overrides, focus, skip link, mobile layout, and reduced motion rules. |
| `templates/base.html` | Load the local theme, opt authenticated application pages into the console class, add a skip link, and label the return-to-top control. |
| `templates/header.html` | Split sidebar parent navigation from its disclosure button and retain all existing Django URL/permission conditions. |
| `static/js/custom.js` | Update only the sidebar disclosure selector/behavior for the new button markup. |
| `templates/aiops/dashboard.html` | Add the console page marker only. |
| `static/js/aiops-vue.js` | Preserve all data APIs; add tab roles, selected state, panel association, arrow-key navigation, and live/busy state markup. |
| `static/css/aiops-vue.css` | Apply Signal Lattice hierarchy, evidence rails, compact tabs, and responsive states inside `.aiops-shell`. |
| `templates/devops/vue_app.html` | Add the console page marker only. |
| `static/js/devops-vue.js` | Preserve bootstrap fetches and CSRF writes; add tab semantics and keyboard navigation. |
| `static/css/devops-vue.css` | Apply the shared console component language inside `.devops-vue-shell`. |
| `templates/vue/page.html` | Add an opt-in class to monitor Vue roots without changing the JSON bridge. |
| `static/css/ops-vue-pages.css` | Apply scoped monitor Vue token consumption and responsive/focus states. |
| `aiops/tests.py`, `devops/tests.py`, `monitor/tests.py` | Add narrow rendering-contract tests only if an existing test module has a matching template assertion pattern; do not add payload tests for unchanged payloads. |

### Task 1: Establish A Scoped Console Token Layer

**Files:**
- Create: `static/css/ops-console-theme.css`
- Modify: `templates/base.html`
- Test: static stylesheet inclusion and Django template rendering through `manage.py check`

- [ ] **Step 1: Capture the baseline before shared shell edits**

Run:

```bash
.venv/bin/python manage.py check
node --check static/js/custom.js
```

Expected: Django reports no system-check errors and Node reports no syntax
error. Record an environment failure rather than changing unrelated runtime
configuration.

- [ ] **Step 2: Add semantic tokens and accessibility primitives in a new local stylesheet**

Create `static/css/ops-console-theme.css` with selectors rooted at
`body.ops-console`. Define these token values and use semantic aliases rather
than restyling generic Bootstrap classes:

```css
body.ops-console {
    --ops-console-workspace: #10161c;
    --ops-console-surface: #182329;
    --ops-console-raised: #203039;
    --ops-console-line: #35505a;
    --ops-console-signal: #2fd4bd;
    --ops-console-attention: #ffb653;
    --ops-console-critical: #ff6470;
    --ops-console-text: #e7f2f1;
    --ops-console-muted: #9bb5b8;
    --ops-console-focus: #7af4de;
}

body.ops-console .skip-link:focus,
body.ops-console :focus-visible {
    outline: 3px solid var(--ops-console-focus);
    outline-offset: 3px;
}

@media (prefers-reduced-motion: reduce) {
    body.ops-console *, body.ops-console *::before, body.ops-console *::after {
        animation-duration: 0.01ms !important;
        transition-duration: 0.01ms !important;
        scroll-behavior: auto !important;
    }
}
```

Add shell rules only below `body.ops-console` for `.app-sidebar`,
`.main-content`, sidebar groups, shared page headings, and console roots. At
`max-width: 768px`, set `--ops-console-nav-height` on the shell and use it in
`.main-content` padding; do not retain the legacy fixed `132px` offset.

- [ ] **Step 3: Load the stylesheet and add shared semantic hooks**

In `templates/base.html`, load the new local stylesheet after
`app-modern.css`, add `ops-console` to the existing `body` class, insert a
first-child skip link targeting `#main-content`, and set that identifier on the
existing `<main>`. Keep all existing CSS/JS load order intact. Update the
return-to-top button to include `aria-label="返回顶部"` and mark its Font
Awesome `<i>` as `aria-hidden="true"`.

Required shape:

```html
<body class="fade-in ops-console">
    <a class="skip-link" href="#main-content">跳到主要内容</a>
    ...
    <main id="main-content" class="main-content" tabindex="-1">
```

- [ ] **Step 4: Validate the shared token task**

Run:

```bash
git diff --check -- static/css/ops-console-theme.css templates/base.html
.venv/bin/python manage.py check
```

Expected: no whitespace errors and no Django system-check errors.

### Task 2: Repair Sidebar Disclosure Semantics Without Changing Navigation

**Files:**
- Modify: `templates/header.html`
- Modify: `static/js/custom.js`
- Modify: `static/css/ops-console-theme.css`
- Test: `node --check static/js/custom.js`

- [ ] **Step 1: Replace each `sidebar-parent-link` dual-purpose anchor with a link and button pair**

For every `.sidebar-nav-group`, retain the current URL in a normal
`.sidebar-parent-link` anchor. Add a sibling `button` with
`class="sidebar-disclosure"`, `type="button"`, the existing target's
`aria-controls`, and `aria-expanded="false"`. Use a chevron icon marked
`aria-hidden="true"`; the button must have an explicit Chinese `aria-label`
that names the section.

Example shape:

```html
<div class="sidebar-parent-row">
    <a class="nav-link sidebar-parent-link" href="{% url 'asset_management' %}">
        <i class="fas fa-boxes-stacked" aria-hidden="true"></i><span>资产管理</span>
    </a>
    <button class="sidebar-disclosure" type="button" aria-label="展开资产管理"
            aria-expanded="false" aria-controls="sidebar-assets-subnav">
        <i class="fas fa-chevron-down" aria-hidden="true"></i>
    </button>
</div>
```

Do not alter `{% if devops_navigation.* %}` conditions, link URLs, labels, or
the account section.

- [ ] **Step 2: Narrow the existing custom.js handler to disclosure buttons**

Change the sidebar event binding from `.sidebar-parent-link` to
`.sidebar-disclosure`. On click, find the closest `.sidebar-nav-group`, toggle
only its `.is-open` class, and synchronize `aria-expanded`. Do not call
`preventDefault()` on normal navigation anchors.

```javascript
$('.sidebar-disclosure').on('click', function () {
    var group = $(this).closest('.sidebar-nav-group');
    var expanded = !group.hasClass('is-open');
    group.toggleClass('is-open', expanded);
    $(this).attr('aria-expanded', expanded ? 'true' : 'false');
});
```

- [ ] **Step 3: Style the new row and button only inside the console shell**

Add `.ops-console .sidebar-parent-row` as a flex row, let the link use the
available inline space, and make `.sidebar-disclosure` a fixed 36px square.
Provide hover and focus-visible states through the semantic tokens. Keep
submenus hidden/displayed only through the existing `.is-open` convention.

- [ ] **Step 4: Validate disclosure behavior statically**

Run:

```bash
node --check static/js/custom.js
rg -n "sidebar-parent-link.*role=|sidebar-disclosure|aria-expanded" templates/header.html static/js/custom.js
```

Expected: no anchor retains `role="button"`; every disclosure target is a
button and the script uses `.sidebar-disclosure`.

### Task 3: Make AIOps The Accessible Reference Console

**Files:**
- Modify: `templates/aiops/dashboard.html`
- Modify: `static/js/aiops-vue.js`
- Modify: `static/css/aiops-vue.css`
- Test: `node --check static/js/aiops-vue.js`, `.venv/bin/python manage.py test aiops`

- [ ] **Step 1: Add an AIOps page marker without changing payload injection**

Keep `aiops_payload|json_script`, local Vue inclusion, and all route behavior
unchanged. Add `ops-console-page ops-console-aiops` to the root class so CSS is
limited to the AIOps workspace.

- [ ] **Step 2: Add keyboard-safe tab selection to the existing Vue instance**

Keep the `tabs` list and `active` values unchanged. Add a `selectTab(key)`
method that assigns `this.active = key`, plus `onTabKeydown(event, index)` that
selects the next/previous tab for `ArrowRight`, `ArrowLeft`, `Home`, and `End`
and calls `event.preventDefault()` only for those keys.

```javascript
onTabKeydown: function (event, index) {
    var keys = this.tabs.map(function (tab) { return tab.key; });
    var target = index;
    if (event.key === 'ArrowRight') target = (index + 1) % keys.length;
    else if (event.key === 'ArrowLeft') target = (index - 1 + keys.length) % keys.length;
    else if (event.key === 'Home') target = 0;
    else if (event.key === 'End') target = keys.length - 1;
    else return;
    event.preventDefault();
    this.selectTab(keys[target]);
}
```

- [ ] **Step 3: Update AIOps template strings with ARIA relationships**

Change `.aiops-tabs` to `role="tablist"`. Each button gets `role="tab"`,
`:aria-selected="active === tab.key"`, `:id="\'aiops-tab-\' + tab.key"`,
`:aria-controls="\'aiops-panel-\' + tab.key"`, `:tabindex="active === tab.key ? 0 : -1"`,
`@click="selectTab(tab.key)"`, and `@keydown="onTabKeydown($event, index)"`.
Add matching panel id/role/labelledby attributes to each top-level tab section.
For every existing dynamic error message, add `role="status" aria-live="polite"`.
Keep every `fetch`, payload field, and `v-if` business condition unchanged.

- [ ] **Step 4: Apply AIOps visual hierarchy under `.aiops-shell`**

Use the shared tokens for surfaces and state. Make `.aiops-tabs` a single-row
horizontal scroller with `scrollbar-width: thin` at narrow widths. Add the
evidence rail only to existing incident, correlation, diagnostic, and service
impact result groups using a 3px `border-inline-start` whose color follows the
existing severity/status class. Do not add decorative gradients, nested cards,
or automatically moving indicators.

- [ ] **Step 5: Run focused AIOps checks**

Run:

```bash
node --check static/js/aiops-vue.js
.venv/bin/python manage.py test aiops
```

Expected: no JavaScript syntax error and existing AIOps host-scope/payload/API
tests pass. If a test fails, preserve the exact output before changing code.

### Task 4: Apply The Same Interaction Contract To DevOps Vue

**Files:**
- Modify: `templates/devops/vue_app.html`
- Modify: `static/js/devops-vue.js`
- Modify: `static/css/devops-vue.css`
- Test: `node --check static/js/devops-vue.js`, `.venv/bin/python manage.py test devops`

- [ ] **Step 1: Mark the root as a console page**

Add `ops-console-page ops-console-devops` to the existing root class. Do not
change `#devops-vue-root`, script versions, API URLs, or loading template.

- [ ] **Step 2: Extend existing tab selection rather than replacing it**

Retain `setActiveTab(key, event)` and its current logic. Add an
`onTabKeydown(event, index)` method based on `this.visibleTabs`, using the same
ArrowRight/ArrowLeft/Home/End behavior as Task 3. Call `this.setActiveTab`
with the selected visible tab key and prevent default only for handled keys.

- [ ] **Step 3: Add DevOps tab/panel semantics without changing permission filtering**

Set `.vue-tabs` to `role="tablist"`. Apply tab ids, controls, selected state,
and roving tabindex to the existing `v-for="tab in visibleTabs"` buttons.
Set matching `role="tabpanel"` and `aria-labelledby` attributes on each active
section. Keep `visibleTabs`, bootstrap loading, and all existing command/task
POST calls unchanged. Give the existing global `error` container
`role="alert"`, and the initial loading block `aria-busy="true"`.

- [ ] **Step 4: Restyle DevOps components within `.devops-vue-shell` only**

Map existing panel, toolbar, badge, table, action, and empty-state selectors to
the shared token layer. Use `--ops-console-attention` for approval/pending
states, `--ops-console-critical` for blocked/failed states, and
`--ops-console-signal` for successful/ready states. Preserve stable control
dimensions and make tab strips scroll horizontally below 768px.

- [ ] **Step 5: Run focused DevOps checks**

Run:

```bash
node --check static/js/devops-vue.js
.venv/bin/python manage.py test devops
```

Expected: no syntax error and the existing role, host-scope, API, approval,
and CSRF-backed workflow tests pass.

### Task 5: Integrate Monitor Vue Without Breaking Its Generic Payload Bridge

**Files:**
- Modify: `templates/vue/page.html`
- Modify: `static/css/ops-vue-pages.css`
- Test: `node --check static/js/ops-vue-pages.js`, `.venv/bin/python manage.py test monitor`

- [ ] **Step 1: Make the generic Vue root a scoped console target**

Add `ops-console-page` and a `ops-console-kind-{{ vue_page_kind }}` class to
the existing `#ops-vue-root` element. Retain `vue_page_payload|safe`, all
conditional static imports, and webssh behavior exactly as written.

- [ ] **Step 2: Consume shared tokens in monitor UI selectors only**

At the end of `ops-vue-pages.css`, add selectors rooted at
`.ops-vue-page.ops-console-page` for page headings, filters, status badges,
table wrappers, controls, focus states, empty/error states, and narrow screens.
Do not modify the existing `body` or `.main-content` dark overrides in the
monitor-dashboard template during this task; keep command-center behavior
isolated while sharing the semantic colors where selectors already exist.

- [ ] **Step 3: Validate monitor bridge compatibility**

Run:

```bash
node --check static/js/ops-vue-pages.js
.venv/bin/python manage.py test monitor
```

Expected: no syntax error and monitoring payload, form, threshold, and alert
behavior tests pass.

### Task 6: Run Cross-Surface Regression And Visual Validation

**Files:**
- Modify: only files from Tasks 1-5 if a failure is directly attributable to the change
- Test: Django checks, focused test suites, static checks, and browser/manual QA

- [ ] **Step 1: Run aggregate static and backend checks**

Run:

```bash
git diff --check -- templates static docs
node --check static/js/custom.js
node --check static/js/aiops-vue.js
node --check static/js/devops-vue.js
node --check static/js/ops-vue-pages.js
.venv/bin/python manage.py check
.venv/bin/python manage.py test aiops devops monitor
```

Expected: every command exits zero. Do not run remote SSH, webhook, alerting,
or deployment actions as part of frontend validation.

- [ ] **Step 2: Run local visual QA against a development server**

Open authenticated AIOps, DevOps, monitor dashboard, monitor query, and one
legacy DevOps form at 1440px, 768px, and 390px. Verify the following on each
applicable view:

```text
- no page-level horizontal overflow or hidden first interactive element
- sidebar link navigates and its separate disclosure button toggles correctly
- skip link, tab controls, filters, actions, and return-to-top have visible focus
- long Chinese labels, host names, and tables stay contained or use local scrolling
- reduced-motion preference removes new transition/animation effects
- no new remote assets are requested
```

- [ ] **Step 3: Review scope and rollback boundary**

Confirm the final diff contains no model, migration, API, URL, permission,
payload, CSRF, secret, external-integration, or unrelated legacy-template
change. If a visual regression cannot be resolved locally, revert only the
namespaced selector or per-surface edit that caused it; do not revert unrelated
user changes.
