# Legacy DevOps Operations Design

## Scope

This phase applies the existing Signal Lattice console language to the
high-frequency legacy DevOps operation group:

- `commands.html`
- `tasks.html`
- `approvals.html`
- `deployments.html`
- `alerts.html`
- `templates/devops/_nav.html`

It deliberately excludes K8s connection, cluster deletion, credential,
service-discovery, audit, and other legacy pages. Those workflows need their
own focused review because they handle infrastructure identity or destructive
operations.

## User Goal

Operators must be able to distinguish the page purpose, current risk, pending
action, and result record at a glance. Forms stay compact, tables remain the
primary scanning surface, and destructive or approval-gated actions remain
visibly distinct without changing their server-side behavior.

## Design

Each page receives an `ops-legacy-operation` root class and uses a shared local
stylesheet layer beneath `body.ops-console`. The layer retains white legacy
surfaces and dark text for form readability, but applies the Signal Lattice
semantic colors to page headers, selected navigation, alert states, action
groups, table headings, focus indicators, and empty states.

`_nav.html` becomes a compact grouped navigation strip. It remains a collection
of normal links with the existing permission conditions; it gains landmarks and
an accessible label but no JavaScript disclosure behavior.

Commands and tasks use a critical-action edge around their submission panels.
Approvals use attention for pending decisions. Deployments use distinct preview,
approval, execution, and rollback action clusters. Alerts use semantic severity
and silence controls with no lifecycle rule changes. Tables use local horizontal
scroll on narrow screens and retain their server-rendered contents.

## Non-Goals And Invariants

- No view, URL, model, form, API, payload, permission, host-scope, CSRF,
  approval, command, deployment, alert, silence, or audit behavior changes.
- No new external asset, frontend build step, remote font, remote CDN, or
  automatic action.
- Existing POST confirmation behavior remains in place.
- Secrets, command output, credentials, and protected data are not newly
  rendered or serialized.

## Accessibility And Responsive Behavior

- Each page has one visible primary heading and a labelled navigation landmark.
- Form labels and server-side errors stay next to their existing fields.
- Existing table wrappers retain horizontal scroll below 768px; no page-level
  overflow is introduced.
- Focus-visible and reduced-motion behavior comes from the shared console
  stylesheet.
- Status colors are paired with existing text labels, so color is never the
  sole state indicator.

## Validation

Run `manage.py check`, focused `devops` tests, template rendering tests where
available, and static diff checks. Manually inspect command, task, approval,
deployment, and alert pages at 390px, 768px, and 1440px using an authorized
user; do not execute a remote command, deployment, approval, or silence merely
for visual verification.
