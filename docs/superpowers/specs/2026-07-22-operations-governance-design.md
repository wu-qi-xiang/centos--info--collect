# Operations Governance Design

## Goal

Strengthen the operations platform's deployment confidence, continuous SLO
visibility, capacity planning, and local backup recovery verification without
adding an external service or accessing a production integration.

## Scope

1. CI validates the production Django configuration, Compose rendering, and
   static-file collection without starting containers or contacting a network
   dependency.
2. The existing scheduler evaluates enabled service SLOs on a fixed interval,
   stores a bounded safe history, and emits a notification only when a state
   transition reaches `exhausted`.
3. The DevOps capacity view derives a simple linear forecast from existing
   `MetricSample` rows for CPU, memory, and disk. It reports a threshold date,
   stable trend, or insufficient data. It never exposes raw monitoring data
   outside the current user's host scope.
4. A `restore_runtime` management command verifies an explicitly supplied,
   local encrypted SQLite archive in an explicitly supplied empty directory.
   It rejects parent traversal, symlinks, non-empty targets, unsupported
   archives, and invalid manifests. It does not access S3, a production
   database, SSH, SMTP, webhook, or network service.
5. The operations roadmap documents completed work accurately and documents
   the new validation paths.

## Design

### CI deployment guard

The GitHub Actions quality gate receives a production-safe environment made of
non-secret test values. It runs `manage.py check --deploy`, renders both
Compose files with `config --quiet`, and runs `collectstatic --noinput` into a
temporary directory. These checks do not build images, start services, or
connect to PostgreSQL.

### SLO history and transition notifications

`ServiceSloEvaluation` stores only the SLO foreign key, safe state, safe
summary, and evaluation time. The periodic task calls the existing evaluator,
records the resulting state, and detects the preceding stored state. A
transition into `exhausted` uses the existing notification service with a
bounded message. Repeated exhausted evaluations do not resend a notification.
No PromQL, endpoint, label, raw response, secret, or credential is stored.

### Capacity forecast

A small service helper selects the recent per-host metric samples visible to
the requester. With sufficient chronologically distinct samples, it uses a
least-squares straight line to estimate when the metric reaches the existing
100 percent threshold. Non-positive slopes are reported as stable, and sparse
or invalid series are reported as insufficient. The API returns only a bounded
forecast summary and the classic DevOps metrics page renders the same safe
summary.

### Local restore drill

The command reuses the existing archive crypto and archive-validation helpers.
It accepts `--archive` and `--target-dir`; both must be explicit local paths.
The target directory must already exist, be a real directory, and be empty.
After decrypting into a private temporary directory, it verifies the manifest,
extracts only safe members, and validates the restored SQLite database with
SQLite's integrity check. A successful drill leaves the verified restore under
the target directory for a human to inspect. The command does not overwrite
or delete a caller-owned directory.

## Permissions and Failure Handling

Capacity output follows the existing metrics module permission and host scope.
SLO periodic work is server-side and uses existing notification channel rules;
failure to notify must not prevent the recorded evaluation. The restore command
is an operator-run local tool and fails closed before any extraction when path
or archive validation fails. CI uses placeholders only and must not print
credential values.

## Acceptance Criteria

- The CI workflow fails on invalid production configuration, invalid Compose,
  or failed static collection without contacting external systems.
- Scheduler tests prove enabled SLOs are evaluated, history is safe, and one
  notification occurs per transition into `exhausted`.
- Forecast tests cover rising, stable, insufficient, and out-of-scope series.
- Restore tests cover a valid local encrypted archive and all path/archive
  rejection cases; no test uses S3 or a production database.
- The roadmap does not list already completed navigation, Nginx, or LLM key
  encryption as pending work.
