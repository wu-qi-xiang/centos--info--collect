# Controlled Operations Integrations Design

**Goal:** Add safe, configurable integration foundations for delivery readiness, GitOps drift collection, SBOM/CVE ingestion, and infrastructure blueprints without bypassing the existing DevOps permission, approval, and audit model.

## Confirmed Decisions

- Integration connectors are disabled by default and may only perform configured read-only collection.
- No API response, audit record, or UI payload may expose connector URLs, access tokens, raw manifests, raw scan reports, credentials, or arbitrary provider responses.
- Kubernetes remains read-only. Reconciliation, patching, and infrastructure apply operations are intentionally outside this delivery.
- A privileged execution request must use the existing approval model. The new features create plans and findings only; they never enqueue arbitrary shell commands.
- New operational pages use the existing Geist shell and Vue-backed DevOps workspace rather than creating a separate frontend stack.

## Architecture

The DevOps app gains three narrowly scoped domains. `IntegrationConnector` stores encrypted connection configuration, enabled/read-only status, collection cadence, and a safe last-run summary. Adapter modules accept the decrypted configuration only within the service boundary, normalize provider data, and return safe domain records. They never make writes to Kubernetes, Git repositories, or infrastructure providers.

`GitOpsCollectionRun` records an attempted collection and its summary. A GitOps adapter accepts an injected client for tests, enumerates only allowed Kubernetes kinds, and passes normalized desired/observed manifests to the existing digest-only drift recorder. `VulnerabilityImportRun` similarly accepts normalized SBOM/CVE findings and uses the existing deduplicated finding recorder. Raw reports are discarded after normalization.

`InfrastructureBlueprint` stores declarative, validated blueprint metadata and a digest of its definition. `InfrastructurePlan` records an immutable, safe plan summary. Planning is read-only and may be queued through the existing persisted Worker model. An apply path is not added. This preserves approval and rollback design until a provider and change-management workflow are explicitly approved.

`integration_readiness_payload()` combines existing Worker/Scheduler/notification summaries with connector health states. It is an admin-only, safe read model. The existing DevOps Vue page receives a new Geist tab that displays readiness, collection outcomes, drift counts, vulnerability counts, and blueprint plans without rendering sensitive provider data.

## Data Model

| Model | Purpose | Sensitive data handling |
|---|---|---|
| `IntegrationConnector` | Provider type, name, enabled/read-only status, schedule and encrypted config | Store config encrypted; API returns no config, URL, token or provider response |
| `GitOpsCollectionRun` | Collection lifecycle, counts and safe failure category | No manifests, repository identities or Kubernetes responses |
| `VulnerabilityImportRun` | SBOM/CVE import lifecycle and counts | No raw report, package version or scanner credentials |
| `InfrastructureBlueprint` | Approved blueprint metadata and definition digest | No provider credentials or raw templates through API |
| `InfrastructurePlan` | Read-only planning result linked to a blueprint | Only safe counts, digest, status and failure category |

All models have timestamps and creator attribution where an operator creates or triggers a record. State values use `pending`, `running`, `success`, `failed`, or `blocked` consistently with existing DevOps task semantics.

## Permissions And APIs

- Connector configuration, readiness, imports, and blueprint planning require the existing admin role plus `MODULE_SECURITY`.
- GitOps findings keep the existing `MODULE_CLUSTER` read permission; vulnerability findings keep `MODULE_SECURITY` and host-scope filtering.
- All new endpoints use the project JSON shape, require session login, and return only safe serializers.
- `POST` collection and plan endpoints require the administrator permission and create an audit event. They cannot accept a URL, command, raw manifest, credential, or arbitrary provider payload from the browser.
- Background execution uses vetted job types only. Tests inject fake adapters; no real network call occurs in unit tests.

## User Experience

The DevOps Vue application gets an `Integration Readiness` tab in the existing Geist console. The tab is an operational dashboard: status strip, connector/worker/scheduler health rows, latest collection summaries, drift/vulnerability counts, and pending blueprint plans. It offers only bounded actions: run a configured collection or create a plan for an existing blueprint. It has no secret fields in list payloads and no direct apply/remediation button.

## Failure Handling

- Disabled or incomplete connectors report `blocked` with a non-sensitive reason code.
- Adapter errors are normalized to a short failure category; detailed transport responses are not persisted or returned.
- Background job timeout follows the existing Worker timeout path and produces an audit event.
- A failed collection or plan does not alter existing findings, deployments, clusters, assets, or approvals.

## Validation

- Test connector configuration encryption/safe serialization, permission denial, disabled connector behavior, and audit creation.
- Test GitOps collection with an injected fake adapter; assert digest-only storage and no Kubernetes mutation.
- Test SBOM/CVE normalization, host scope, deduplication, and no raw report storage.
- Test blueprint plan lifecycle, Worker handling, and rejection of apply behavior.
- Run focused `devops` tests, `manage.py check`, migration consistency checks, JavaScript syntax checks, and authenticated-browser UI checks when a test account is available.

## Rollback

The migration is additive. Rolling back application deployment disables connector execution through settings and hides the new Vue tab; existing operational data and workflows remain unchanged. Database rollback is only appropriate before production records are created and follows the normal release process.
