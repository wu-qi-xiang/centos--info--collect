# UI Standards

Use for Django templates, Vue-backed pages, and static CSS/JS.

## Product Fit

- This is an operations platform. UI should be dense, readable, restrained, and optimized for repeated operational work.
- Do not add marketing-style landing pages, decorative hero sections, or nested decorative cards.
- Prefer tables, filters, compact summaries, status badges, and clear action buttons.

## Layout

- Keep shared shell changes in `templates/base.html`, `templates/header.html`, and `templates/footer.html`.
- Keep feature-specific markup in feature templates.
- Use full-width operational sections rather than cards inside cards.
- Keep controls stable in size so filters, counters, and action buttons do not shift layout.
- Ensure button and table text fits at desktop and mobile widths.

## Vue-Backed Pages

- Update the Python payload builder and static JS consumer together.
- Keep `templates/vue/page.html` generic unless the bridge itself changes.
- Preserve CSRF behavior in fetch calls.
- Keep payload keys stable for existing consumers unless intentionally changing them.

## CSS And Assets

- Prefer existing static CSS files:
  - `static/css/app-modern.css`
  - `static/css/custom.css`
  - `static/css/devops-vue.css`
  - `static/css/aiops-vue.css`
  - `static/css/ops-vue-pages.css`
- Prefer existing vendored assets over remote CDN dependencies.
- Do not introduce a frontend build system unless explicitly requested.

## Forms

- Preserve server-side validation and error rendering.
- Keep labels, required fields, help text, and errors close to the relevant inputs.
- For secret fields, avoid rendering existing secret values.

## Manual QA

For UI-heavy changes, inspect:

- Desktop width.
- Mobile/narrow width.
- Empty state.
- Error state.
- Long labels or long host/app names.
- Permission-limited user view if host scope or role visibility is involved.

