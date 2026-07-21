# Sequential Operations Reliability Design

## Goal

Deliver the five ordered reliability improvements for the operations platform
without changing the local SQLite development path, custom session
authentication, host-scope enforcement, command policy, or default remote
execution behavior.

## Delivery Order

1. **P0: AIOps data and secret governance.** Encrypt the LLM API key, keep
   a blank update value as "retain the existing key", and persist only a
   bounded, allowlisted alert summary. Add positive retention cleanup for
   analysis records. The LLM receives the same sanitized input. Local
   rule-based suggestions remain available when the LLM is unavailable.
2. **P1: Opt-in PostgreSQL and Nginx production reference.** Add a separate
   Compose override, Nginx configuration, and deployment document. It must
   leave the SQLite development Compose unchanged, use environment-supplied
   PostgreSQL credentials, and not start a live stack during validation.
3. **P2: RBAC administration closure.** Record permission changes with enough
   non-sensitive detail to identify the old and new access state. Add explicit
   revoke and clear operations, protected by the existing security-admin
   authorization, and align shared navigation with module permissions.
4. **P3: Service SLO and error-budget release gate.** Bind SLOs to services,
   evaluate only fixed server-side Prometheus query templates, and make an
   exhausted budget create or reuse a deployment approval instead of enqueueing
   a release. Missing or failed metrics are an explicit unavailable state and
   do not block a release.
5. **P4: Approval-gated executable runbooks.** Store versioned, fixed command
   templates with explicit target scope. AIOps may suggest a runbook only; an
   authorized operator must initiate it, after which the existing command
   policy, host scope, approval, Worker, result, and audit paths apply.

## Security Boundaries

- AIOps must not persist or expose raw webhook payloads, arbitrary labels,
  URLs, credentials, tokens, command text, or raw LLM responses.
- SLOs accept a closed set of metric kinds and no user-authored PromQL.
- Runbooks reject interpolation tokens, substitutions, and user-provided
  command parameters. They never create a direct SSH execution path.
- New host-specific reads and writes use the existing host-scope helpers.
- APIs, audit entries, and list payloads omit encrypted secrets, command
  templates, command output, and external integration values.

## Failure And Rollback Behavior

- P0 falls back to local rule-based analysis when LLM configuration or a
  request fails. Retention cleanup is disabled by a non-positive setting.
- P1 is additive; stopping the production override restores the unchanged
  local-development topology.
- P2 revocation affects only the selected permission records and is auditable.
- P3 does not treat unavailable Prometheus data as an exhausted error budget.
- P4 defaults to approval required and never starts work from an alert alone.

## Validation

Each priority follows test-driven development: add a failing focused test,
verify the expected failure, implement the smallest change, then run focused
and affected regression suites. Final validation includes migration checks,
Django checks, the full test suite, Compose syntax validation, and a review of
secret and host-scope boundaries. Tests use mocks and do not call live
PostgreSQL, Nginx, Prometheus, LLM, SSH, webhook, or production systems.
