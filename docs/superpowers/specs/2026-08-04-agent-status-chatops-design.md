# Host Agent, Status Page, and WeCom ChatOps Design

## Goal

Extend the operations platform with a safe outbound host heartbeat, a public
sanitized status page, and a restricted WeCom ChatOps entry point.

## Host Agent

- Each `NewLinux` host may have one `HostAgent` registration.
- An authorized operator creates a registration and receives an opaque
  credential exactly once. The database stores only a password hash.
- The agent calls an HTTPS endpoint with its registration ID and credential.
  It may send agent version, heartbeat time, collection delay, and a bounded
  safe system summary. Credentials, keys, paths, command output, and arbitrary
  payload fields are rejected.
- Administrators can revoke a registration. Revoked credentials cannot submit
  heartbeats. The Agent never executes remote commands and does not replace SSH.

## Public Status

- `GET /status/` is intentionally unauthenticated and returns only a derived,
  cacheable public view from `ServiceCatalog`, `ServiceSlo`, `AlertEvent`,
  `Incident`, and active `MaintenanceWindow` data.
- The page can display service names, aggregate state, availability trend,
  maintenance notices, and short generic incident state transitions.
- It must not display host names or addresses, alert/incident descriptions,
  versions, owners, internal URLs, credentials, or unfiltered database fields.

## WeCom ChatOps

- `POST /devops/chatops/wecom/` accepts a signed JSON message using a configured
  HMAC secret. Signature comparison is constant-time and occurs before parsing
  or performing any action.
- A `ChatOpsIdentity` binds a WeCom user ID to an existing local user. Existing
  module permissions govern all actions.
- The first release supports service status query, pending-approval query,
  alert acknowledgement, and links to existing authenticated approval/runbook
  pages. It never invokes remote commands, deployments, rollbacks, or runbooks.
- Raw body, signature, token, webhook address, and user-supplied message text
  are neither persisted nor written to the audit log. Audits contain only the
  resolved local user, action, safe target ID, and outcome category.

## Deployment

- `WECOM_CHATOPS_WEBHOOK_SECRET` is required to enable inbound ChatOps and is
  not stored in the database.
- The public status page is read-only. Production deployment should provide
  HTTPS and upstream rate limiting for both unauthenticated endpoints.
