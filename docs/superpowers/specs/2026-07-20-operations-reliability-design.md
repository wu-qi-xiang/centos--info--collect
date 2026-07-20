# Operations Reliability Design

## Goal

Deliver five ordered improvements that make the operations platform easier to
operate in production, reduce AIOps data exposure, and add controlled
reliability workflows without weakening the existing permission, approval, or
host-scope rules.

## Scope And Order

1. P0: Align runtime and roadmap documentation with the verified Python 3.11
   and Django 4.2.16 baseline.
2. P1: Provide a PostgreSQL and Nginx production deployment reference while
   retaining the current SQLite local-development path and MySQL compatibility.
3. P2: Minimize AIOps alert and LLM data, with retention and bounded cleanup.
4. P3: Add service SLO summaries and error-budget release gating.
5. P4: Add approval-gated, manually initiated executable runbooks.

Each milestone must pass its focused tests before the next milestone begins.
No milestone may silently change existing host visibility, session
authentication, encrypted storage, or remote-command policy.

## P0: Documentation Baseline

The README and CI workflow are the authoritative runtime source: Python 3.11
and Django 4.2.16. Development skills, project-layout documentation, and the
optimization roadmap must state the same baseline. The roadmap must move
already delivered functionality out of future recommendations and retain only
work that is absent from the checkout.

Acceptance: a repository search finds no active instruction that directs users
to run the project on Django 2.1 or Python 3.6, and the roadmap has no item
described as pending when its implementation and test coverage exist.

Rollback: documentation-only changes are reverted as a single commit.

## P1: Production Deployment Reference

Add an opt-in Compose configuration for PostgreSQL and an Nginx reverse proxy.
The base local Compose configuration remains unchanged and continues to mount
SQLite for local development. The production reference uses environment
variables already supported by `PyLinux.settings`, shares the existing
static/media volumes, starts the existing web and Worker processes, and uses
the existing liveness/readiness endpoints for health checks.

The Nginx example serves static and media paths, forwards application requests
to Gunicorn, and does not terminate TLS with a repository-managed certificate.
Deployment documentation covers migration order, `manage.py check --deploy`,
database backup preflight, safe rollback, and the fact that PostgreSQL is the
reference topology while MySQL remains compatible.

Acceptance: Compose syntax validates, production settings select PostgreSQL
from environment variables, and no production reference contains credentials
or encourages SQLite for multi-worker production use.

Rollback: remove the opt-in files and documentation; the base development
topology remains unaffected.

## P2: AIOps Data Governance

Replace raw AIOps alert and LLM-response persistence with a fixed, bounded
analysis input: alert name, severity, an approved host identifier, a truncated
summary, and a fixed-size safe label subset. Reject or omit arbitrary labels,
annotations, URLs, credentials, tokens, command text, and payload blobs.

The LLM receives the same sanitized summary. The platform must keep local
rule-based recommendations when LLM configuration is absent or a request
fails. Add an environment-controlled positive retention period and a
management command that deletes only expired analysis records; a non-positive
value disables automatic deletion. APIs and templates return only the existing
safe analysis fields.

Acceptance: tests prove that secrets and raw payload fragments cannot persist
or appear in UI/API payloads, cleanup respects its boundary, and the dashboard
remains usable without an LLM.

Rollback: disable cleanup through configuration and retain the pre-existing
safe display path; migrations, if any, are additive.

## P3: Service SLO And Error Budgets

Create a service-bound SLO model rather than adding unstructured fields to
`ServiceCatalog`. It supports availability, latency, and error-rate objectives
through a closed set of backend Prometheus query templates, a numeric target,
and an enabled flag. Arbitrary PromQL is intentionally out of scope.

An evaluator obtains a bounded metric result from an enabled configured
Prometheus integration and stores a safe calculation summary. If the computed
error budget is exhausted, a new deployment is not enqueued: the platform
creates or reuses a pending approval and records an audit entry. It never
automatically rolls back a release or executes a remote command.

Read access follows service visibility and host scope. Creation, editing, and
evaluation require the existing security administrator role. Missing or failed
Prometheus data produces an explicit unavailable state, not a budget-exhausted
state.

Acceptance: fixed templates accept only allowed metric kinds, budget exhaustion
gates a release through approval, and out-of-scope users cannot read or modify
SLO data.

Rollback: disabling SLOs restores the existing deployment path; the new model
and audit history remain additive.

## P4: Controlled Executable Runbooks

Introduce versioned runbook templates containing a name, a fixed command
template, permitted target scope, an optional linked service, a trigger class,
and an approval requirement. Inputs are constrained to server-defined context;
operators cannot use a runbook to inject arbitrary command text or select
out-of-scope hosts.

The AIOps dashboard exposes suggestions only. It does not enqueue work. An
authorized operator explicitly initiates a runbook, after which the request
passes the existing command policy, host-scope check, approval workflow, durable
Worker, result recording, and audit path. The default is approval required.
No runbook automatically executes because of an alert.

Lists and APIs expose names, versions, trigger classes, safe target counts, and
state only. They never expose credential material, raw alert payloads, command
output, full command templates, or approval comments outside the existing
authorized detail paths.

Acceptance: tests prove that runbooks cannot bypass command policy, host scope,
approval, or Worker idempotency; unauthenticated and unauthorized requests are
rejected; an AIOps suggestion alone has no remote side effect.

Rollback: disable a runbook or remove its permission without changing existing
manual command and deployment behavior.

## Test Strategy

Run focused Django tests for each changed app, then `manage.py check` and the
full affected regression suites. Use mocked Prometheus and SSH; do not contact
live databases, Prometheus, LLM endpoints, or remote hosts. Validate Compose
configuration without bringing up an external production stack.

## Non-Goals

- Replacing the current durable Worker with Celery or RQ.
- Removing SQLite local development or MySQL compatibility.
- Adding arbitrary user-authored PromQL or remote command interpolation.
- Automatic rollback or automatic remote remediation.
- Changing the custom session-authentication contract.
