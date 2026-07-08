---
name: centos-frontend-ui-dev
description: Work on Django templates, Vue-rendered pages, static CSS/JS, Bootstrap UI, DevOps/AIOps Vue pages, and visual consistency in centos--info--collect.
---

# Centos Frontend UI Dev

## When To Use

Use for `templates/`, `static/`, Vue-rendered pages through `PyLinux/vue.py`, Bootstrap layout, DevOps/AIOps frontends, or visual consistency work.

## Execution Rule

For development work, the main agent plans and delegates after user confirmation. Subagents perform implementation within explicit file/responsibility ownership. The main agent reviews, integrates, validates, and reports.

## Fast Path

### Change a classic Django template page

Read:
1. the target view
2. target template under `templates/`
3. `templates/base.html`, `templates/header.html`, `templates/footer.html` if layout changes
4. matching CSS/JS in `static/`
5. affected app tests

Change:
1. Preserve server-side validation and error rendering.
2. Keep CSRF tokens intact.
3. Avoid exposing secrets through templates or data attributes.
4. Match the existing operational dashboard style.

### Change a Vue-backed page

Read:
1. `PyLinux/vue.py`
2. `templates/vue/page.html`
3. the Python payload builder view
4. matching static JS and CSS
5. affected app tests

Change:
1. Update payload builder and JS consumer together.
2. Preserve CSRF handling for fetch calls.
3. Keep controls stable in size and text fitting at desktop/mobile widths.
4. Do not introduce a frontend build system unless explicitly requested.

### Change shared visual style

Read:
1. `static/css/app-modern.css`
2. `static/css/custom.css`
3. feature CSS such as `devops-vue.css`, `aiops-vue.css`, `ops-vue-pages.css`
4. representative templates/pages

Change:
1. Keep the UI dense, readable, restrained, and task-focused.
2. Avoid nested cards and decorative page sections.
3. Prefer vendored/static assets over remote CDN dependencies.

## Invariants

- The project mixes classic Django templates with Vue pages; do not assume a build step.
- Vue is vendored as `static/vendor/vue.global.prod.js`.
- Bootstrap assets are vendored under `static/bootstrap/`.
- First screen should remain a usable operations interface, not a landing page.

## Validation

```bash
.venv/bin/python manage.py check
```

Run affected app tests for payload or permission changes. For UI-heavy changes, run the dev server and inspect desktop and mobile widths.

## Shared References

- `../centos-feature-dev/references/task-router.md`
- `../centos-feature-dev/references/change-recipes.md`
- `../centos-feature-dev/references/django-legacy-standards.md`
- `../centos-feature-dev/references/ui-standards.md`
- `../centos-feature-dev/references/security-checkpoints.md`
- `../centos-feature-dev/references/review-checklist.md`
- `../centos-feature-dev/references/file-map.md`
