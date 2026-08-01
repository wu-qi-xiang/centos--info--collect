# Service Operations Frontend Design

## Scope

Apply the existing Signal Lattice classic-operation language to these four
server-rendered DevOps pages only:

- `templates/devops/services.html`
- `templates/devops/runbooks.html`
- `templates/devops/files.html`
- `templates/devops/metrics.html`

Use `templates/devops/_nav.html` unchanged because its navigation landmark was
completed in the preceding phase. Extend only the existing local
`static/css/ops-console-theme.css` stylesheet.

## Goal

Make the service-operation workflow legible at a glance: operators can see the
pending action, its execution or approval boundary, the resulting state, and
the historical evidence without changing how any operation is authorized or
submitted.

## Shared Pattern

Each selected template receives an `ops-legacy-operation` root class and a
page-specific marker. Cards, action zones, result surfaces, filters, chart
surfaces, and table wrappers receive local semantic hooks. The shared
stylesheet targets those hooks beneath `body.ops-console .ops-legacy-operation`
only, retaining white cards and dark content for classic form readability.

All tables retain their existing server-rendered rows and use the existing
Bootstrap responsive wrapper plus `ops-legacy-table-wrap` for narrow screens.
Existing text labels remain the authoritative expression of a state; color is
only supporting evidence.

## Service Management

The service form becomes a bounded action panel. The existing selected host,
service name, and action fields remain unchanged. Its submission button retains
the original form semantics, while the panel gains a visual action boundary.
The conditional result stays a separate evidence surface, followed by a compact
record table with local horizontal scrolling.

## Controlled Runbooks

The management form, visible runbook list, and approval-initiation controls are
visually separated. Management and edit controls stay within existing
`can_manage` conditions. Initiation controls remain within existing
`can_initiate`, enabled-runbook, and visible-host checks. The approval
initiation form keeps its POST endpoint, CSRF token, host selector, and submit
behavior. The runbook table remains the primary scan surface.

## File Distribution

The upload form retains its multipart encoding, file input, target-host field,
remote-path validation path, and background submission behavior. Its panel uses
an execution-boundary treatment. The distribution record table retains its
existing detail URL and exposes local horizontal scrolling at narrow widths.

## Metric History

The host and time-range filter remains a GET form with unchanged field names and
selected values. The trend chart stays backed by the existing `chart_json`
payload and inline SVG script. Its chart surface receives local hierarchy and
legend styling only. Latest metrics, capacity forecast, and sample tables keep
their current context values, state text, and server-side empty states, with
semantic risk and stable treatments as supporting visual signals.

## Non-Goals And Invariants

- No view, URL, model, form, API, payload, permission, host-scope, CSRF,
  command, file-distribution, approval, remote-path, monitoring, chart, or
  audit behavior changes.
- No new external asset, frontend build step, JavaScript framework, remote font,
  or CDN dependency.
- No automatic service operation, runbook initiation, file upload, or filter
  submission.
- Do not expose command output beyond existing template rendering, credentials,
  encrypted values, uploaded file contents, or protected host data.
- Exclude notification, on-call, K8s, security policy, credential, audit, and
  other DevOps pages from this phase.

## Accessibility And Responsive Behavior

- Retain one visible primary heading per page and the existing labelled DevOps
  navigation landmark.
- Preserve labels and Django form errors adjacent to their existing fields.
- Keep table overflow local below 768px; do not introduce page-level horizontal
  overflow.
- Let action groups wrap in narrow containers while keeping controls stable.
- Reuse the shared focus-visible and reduced-motion behavior.
- Retain SVG `role="img"` and its existing accessible label for the metric trend.

## Validation

Run `git diff --check`, `manage.py check`, and focused `devops` tests. Render
the four pages through authenticated test-client coverage where available.
For manual browser QA, inspect desktop, tablet, and narrow views without
submitting a service operation, runbook approval, file distribution, or any
other privileged action solely for visual validation.
