# Operations Console Frontend Design

## Status

Approved direction. This document defines the first implementation wave; it
does not authorize changing API contracts, authorization behavior, CSRF
handling, or remote-operation workflows.

## Context And Goal

The product is an internal DevOps and AIOps operations platform. Its users are
operators who repeatedly scan alerts, traces, approvals, changes, and service
health under time pressure. The primary job of the frontend is to make the
current signal, risk, and available action unambiguous without reducing data
density.

The current frontend has a shared Django shell, isolated AIOps/DevOps/monitor
Vue screens, and a large set of legacy Django pages. The first wave refreshes
the shared shell and the high-frequency console screens while retaining a
compatibility layer for legacy pages.

## Scope

Included:

- A namespaced operations-console token layer and shared shell treatment.
- Responsive navigation, visible focus, skip navigation, and reduced-motion
  support in the shared shell.
- AIOps, DevOps Vue, and monitor Vue visual hierarchy and component states.
- Tab semantics, loading/error announcement, and compact mobile layouts where
  the affected Vue markup already owns the controls.

Excluded:

- API, payload, permission, host-scope, CSRF, form validation, or URL changes.
- A full rewrite of the legacy `templates/devops/*.html` page collection.
- New frontend build tooling, remote runtime dependencies, remote fonts, or
  new CDN assets.
- Removal of the existing external Font Awesome dependency. Its local-vendor
  migration is a separately scoped compatibility task.

## Design Direction: Signal Lattice

The console uses a disciplined dark work surface, with color reserved for
signal meaning. The signature is an evidence rail: a narrow ordered status
edge on incident, change, and diagnostic groups that communicates chronology
and severity. It is an information-bearing device, not decoration.

### Tokens

| Role | Value | Use |
| --- | --- | --- |
| Workspace | `#10161c` | page background |
| Surface | `#182329` | panels, navigation, popovers |
| Raised surface | `#203039` | selected/hovered controls |
| Structural line | `#35505a` | separators and inactive outlines |
| Signal | `#2fd4bd` | primary actions and healthy live signal |
| Attention | `#ffb653` | pending, degraded, review-required states |
| Critical | `#ff6470` | failures and destructive risk |

Text uses the existing local system stack for compatibility. Data labels,
timestamps, identifiers, and metric values use the existing monospace fallback
only where comparison benefits from alignment. No viewport-relative font sizes
are introduced.

### Layout

Desktop retains the existing sidebar and puts each screen's active work area
in a constrained, dense console canvas. AIOps and DevOps retain their current
navigation/data model; their tabs become a single horizontally scrollable row
on narrow widths rather than wrapping into the first viewport. Tables preserve
their own horizontal scroll behavior instead of making the page overflow.

On mobile, the header/side navigation must occupy a measured CSS variable, not
a hard-coded content offset. Controls retain stable hit targets and labels may
wrap without changing toolbar height unpredictably.

### Interaction And Accessibility

- All new focus treatment uses `:focus-visible`; focus never relies on color
  alone.
- Tab lists expose `tablist`, `tab`, `tabpanel`, `aria-selected`, and keyboard
  arrow navigation when their Vue component is changed.
- Loading, refresh, and error states expose `aria-busy` or a concise live
  status message. Empty states name the next operator action.
- Visual motion is limited to user-triggered feedback below 150ms. A
  `prefers-reduced-motion` rule removes transitions and nonessential indicators.
- Navigation disclosure uses a real button with `aria-expanded`; a navigable
  destination remains separately accessible.

## Architecture And File Boundaries

| Layer | Responsibility | Planned boundary |
| --- | --- | --- |
| Shared shell | tokens, sidebar, focus, mobile nav | new scoped stylesheet plus `base.html` and `header.html` markup only |
| AIOps console | diagnostic signal hierarchy and tabs | `templates/aiops/dashboard.html`, `aiops-vue.js`, `aiops-vue.css` |
| DevOps console | command/approval/deployment hierarchy and tabs | `templates/devops/vue_app.html`, `devops-vue.js`, `devops-vue.css` |
| Monitor Vue | consistent console components | `templates/vue/page.html`, `ops-vue-pages.css`, narrowly scoped JS only when semantics require it |
| Legacy pages | compatibility | do not restructure in this wave |

Existing `custom.css` and `app-modern.css` remain compatibility sources. New
tokens and overrides are namespaced so they do not redefine generic Bootstrap
classes across legacy screens.

## Phased Delivery

1. Build the scoped token and shell layer, then repair navigation semantics and
   the mobile content offset.
2. Make AIOps the reference screen: signal hierarchy, evidence rail, compact
   tab behavior, and accessible state feedback.
3. Apply the same component language to DevOps Vue and monitor Vue screens
   without changing their request sequencing or data contracts.
4. Validate high-frequency legacy pages against the compatibility layer. Plan
   any legacy-template migration as separate, bounded modules.

## Acceptance Criteria

- Existing Django and Vue routes continue to render with unchanged API and
  form behavior.
- AIOps, DevOps, and monitor console pages share semantic status, surface,
  spacing, and focus tokens while remaining distinct operational workflows.
- At 390px, 768px, and 1440px there is no page-level horizontal overflow, and
  navigation does not hide the first interactive content.
- Keyboard users can skip navigation, operate disclosure controls, use changed
  tab lists, and identify the focused element.
- Reduced-motion preference removes nonessential new motion.
- New frontend assets are local static files only.

## Validation And Rollback

Run Django checks, JavaScript syntax checks, affected app tests, and visual
inspection of authenticated console screens at desktop and mobile widths.
Validate DevOps permissions, CSRF-backed operations, monitor payload pages,
and AIOps host-scope behavior without invoking live remote execution.

Rollback is file-scoped: remove the new namespaced stylesheet and revert only
the related shell/Vue template and CSS changes. No database migration, API, or
external system state is part of this work.
