# DevOps Bright Workbench Design

## Status

Proposed from the approved Style A prototype. This document defines the
DevOps console presentation only. It does not authorize changes to API
contracts, permissions, host scope, CSRF handling, or remote execution.

## Goal

Make `/devops/` a clear daily-work console for operators: within the first
screen, they can identify items that need action, see work already in progress,
and move to the appropriate operational surface without scanning decorative
panels or a long flat navigation row.

## Audience And Principle

The primary user is an operator handling hosts, alerts, approvals, tasks, and
deployments repeatedly during a workday. The interface uses a light, neutral
workspace with compact information blocks. Color has one purpose: state.

## Visual Direction

- Canvas: cool neutral `#f4f7fa`; panels: white `#ffffff`; structural lines:
  `#dbe3ec`.
- Text: dark slate `#17212b`; subdued text: `#64748b`; primary action and
  navigable link: blue `#1769e0`.
- State: green for healthy, amber for waiting or attention, red for urgent or
  failing, blue for active work. State colors are never used as decoration.
- Corners remain small and functional. Panels use light borders rather than
  shadows. Typography remains the existing local system stack.
- The signature element is the action queue: every urgent, pending, or running
  item starts with a slim status rail, so priority is recognizable before the
  operator reads every field.

## Desktop Layout

1. Header: page title, short operational description, last refresh time,
   "查看运行记录", and "刷新数据".
2. Summary row: managed hosts, open alerts, pending approvals, and active
   work. Each count includes a short qualifier rather than an ornamental trend.
3. Priority row: "需要处理" occupies the wider column; "运行中工作" occupies
   the companion column. These lists show title, scoped metadata, and one
   status label.
4. Host health table follows immediately. It retains its own horizontal
   scrolling container on constrained widths rather than widening the page.
5. Lower-frequency functions stay available through grouped DevOps navigation;
   they do not compete with the priority queue on first load.

## Navigation And Interaction

- Keep existing route and permission-derived tab availability unchanged.
- Render the most-used DevOps destinations as a compact, horizontally
  scrollable navigation strip on narrow screens. Do not wrap it into multiple
  unstable rows.
- Keep existing refresh, form submission, command, task, approval, deployment,
  file, notification, and audit behavior unchanged.
- The visual redesign must preserve loading, error, empty, and success states.
  A state message names the next available operator action.

## Responsive Behavior

- At desktop width, the summary is four equal columns and the action queue is
  wider than active work.
- At tablet and phone widths, the summary becomes a two-column grid. The action
  queue and active-work panels stack vertically.
- The application shell and console root use `minmax(0, ...)` or `min-width: 0`
  where necessary so child content cannot create page-level horizontal overflow.
- Wide data tables scroll within their own wrapper. Toolbar controls wrap or
  scroll within their own region; the page itself must not overflow at 390px.
- Interactive controls retain stable dimensions and readable labels.

## Implementation Boundaries

Likely presentation files are `templates/devops/vue_app.html`,
`static/js/devops-vue.js`, and `static/css/devops-vue.css`. Existing data comes
from `/devops/api/bootstrap/`, `/devops/api/dashboard/`, and current scoped
workflow endpoints. Changes must not alter endpoint payloads, API URLs,
authorization checks, or request sequencing without separate approval.

## Acceptance Criteria

- The `/devops/` visual hierarchy matches the approved Style A prototype while
  using live, permission-scoped existing data.
- Operators see unresolved alerts, pending approvals, and active work before
  lower-priority history or configuration information.
- Existing tabs and operations remain available to users who currently have the
  corresponding permission.
- At 390px, 768px, and 1440px there is no page-level horizontal overflow;
  tables retain bounded internal scrolling where needed.
- No remote frontend dependency, build system, API contract, permission model,
  CSRF behavior, or remote execution behavior is added or changed.

## Validation

Validate the affected DevOps rendering and permissions with focused Django
tests, `manage.py check`, JavaScript syntax checking, `git diff --check`, and
browser inspection at the three defined widths. Browser testing must exercise
only display and safe refresh behavior; no remote command or deployment action
is invoked for visual verification.
