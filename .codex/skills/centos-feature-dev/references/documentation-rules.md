# Documentation Rules

Update documentation when behavior visible to developers, operators, API callers, or deployers changes.

## Required Updates

| Change | Documentation |
|---|---|
| New or changed DevOps JSON API | `docs/devops_json_api.md` |
| New environment variable | `README.md` and `.env.example` if present |
| Runtime/deployment behavior | `README.md`, `deploy/`, or `k8s/` notes as relevant |
| Security default or production check | `README.md` and `PyLinux/checks.py` behavior notes |
| New operational workflow | relevant `docs/` page or feature skill reference |
| Removed or hardened risky behavior | revise outdated docs so they do not contradict code |

## DevOps API Documentation Must Include

- Method and path.
- Authentication behavior.
- Required role/module permission.
- Host scope behavior.
- Request query/body fields.
- Success response shape.
- Error response shape.
- Sensitive fields intentionally omitted.

Use `../templates/api-doc-entry.md`.

## Style

- Keep docs factual and concise.
- Prefer tables for API fields and environment variables.
- Do not include real secrets, private endpoints, production tokens, or credentials.
- Do not create extra process notes unless they are directly useful for future development.
