# Example: Change A Vue-Backed Page

## User Request

Add a status filter to the DevOps Vue command list.

## Skill Path

1. `centos-feature-dev`
2. `centos-frontend-ui-dev`
3. `centos-devops-automation-dev`
4. `../references/ui-standards.md`
5. `../references/test-patterns.md`

## Read Order

1. `devops/api.py`
2. `devops/views.py`
3. `PyLinux/vue.py`
4. `templates/vue/page.html`
5. `static/js/devops-vue.js`
6. `static/css/devops-vue.css`
7. `devops/tests.py`

## Implementation Notes

- Keep `templates/vue/page.html` generic unless the bridge changes.
- Update API filtering and JS consumer together.
- Preserve CSRF behavior for any POST/fetch calls.
- Keep filter controls compact and stable in width.
- Ensure permission-limited users only see scoped results.

## Tests

- API returns only matching status.
- Host scope still applies.
- Invalid status falls back safely or returns validation error according to local pattern.

## Manual QA

- Desktop command list.
- Narrow/mobile width.
- Empty filtered state.
- Long command text and host names.

