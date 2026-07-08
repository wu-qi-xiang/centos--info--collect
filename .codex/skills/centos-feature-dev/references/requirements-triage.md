# Requirements Triage

Use this before editing when the request is vague, cross-module, security-sensitive, data-model-changing, or has multiple implementation paths.

## Mandatory Main-Agent Plan

For new features, optimizations, requirement changes, and multi-step development, the main agent must draft the implementation plan before any file edits or subagent delegation. The user must confirm the plan or explicitly ask to proceed before implementation begins. After confirmation, all development implementation must be delegated to subagents with clear file/responsibility ownership. The main agent reviews, integrates, validates, and reports rather than doing the primary development work directly.

A direct main-agent edit without subagent execution is allowed only for non-development housekeeping or a tiny, specific correction with no design choice, no permission/security impact, no schema/API/runtime change, no cross-module behavior, and no substantive implementation work.

## Direct Main-Agent Action Is Usually OK For Non-Development Only

Proceed without a subagent only when all are true:

- The request is read-only analysis, command output reporting, validation, or non-development housekeeping.
- No source code, tests, templates, migrations, APIs, permissions, runtime behavior, or user-facing functionality changes are required.
- No schema, permission model, secret handling, deployment, external integration, or cross-module decision is needed.
- The action can be completed by reading files, running checks, summarizing output, or making a tiny documentation/skill correction.

Examples:

- Run `manage.py check` and summarize the result.
- Inspect a file or command output and explain behavior.
- Validate skill links after a documentation-only skill update.
- Correct a typo in a skill instruction when no development behavior changes.

## Ask Or Plan First

Ask a concise question or draft an implementation plan when any condition applies:

- The user describes a goal but not the target workflow.
- The change alters roles, host scope, approval rules, or sensitive data visibility.
- A model field, migration, new API, deployment setting, or background job is needed.
- The UI change could affect multiple templates or Vue payloads.
- There are two or more plausible implementation paths with different tradeoffs.
- Live SSH, SMTP, cron, Kubernetes, Docker, webhook, or LLM access might be required.

## Centos-Specific Clarifying Questions

### New DevOps API

- Who calls this API: Vue page, external system, or manual operator?
- Which role/module permission should gate it?
- Does it expose host-specific data, and should host scope apply?
- Should the response be paginated or limited?
- Which fields are sensitive and must be omitted?

### New Host Field

- Is the field sensitive, and should it be encrypted?
- Should it appear in list, detail, forms, CSV import/export, search, or API payloads?
- What should happen to existing rows?
- Is the field editable by all operators or only admins?

### Permission Or Approval Change

- Which roles are affected: admin, operator, viewer, or unconfigured users?
- Is the default allow or deny for users without explicit roles?
- Should existing approvals, tasks, or audit records change behavior?
- Which action should be audited?

### Monitoring Or AIOps Change

- Is the source metric already stored in `MetricSample`, or does collection need to change?
- Should alert identity/fingerprint change?
- Should silence, repeat count, and notification deduplication apply?
- Is LLM/network required, or must local fallback remain sufficient?

### UI Change

- Is this classic Django template, Vue payload, or both?
- Which desktop and mobile widths should be checked?
- Should old legacy pages remain available?
- Does the UI include secrets or privileged actions?

### Deployment Change

- Is this local-only, container runtime, Kubernetes, or production behavior?
- What is the env var name and default?
- Should unsafe defaults trigger `manage.py check` warnings?
- Does the change affect SQLite local development?

## Option Comparison Format

Use this when multiple approaches are viable:

```markdown
## Options

| Dimension | Option A | Option B | Option C |
|---|---|---|---|
| Scope | | | |
| Code impact | | | |
| Data/migration impact | | | |
| Security risk | | | |
| Test effort | | | |
| Runtime risk | | | |

Recommendation: <option>, because <reason>.
```
