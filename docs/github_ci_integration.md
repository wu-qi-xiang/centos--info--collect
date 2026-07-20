# GitHub CI Release Trigger

GitHub Actions can notify the platform after a successful workflow run. The
endpoint only queues an existing pending deployment; it never creates a
release, accepts a deployment command, or stores a GitHub secret.

## Configuration

Set `GITHUB_WEBHOOK_SECRET` to the GitHub Webhook secret. The endpoint returns
`503` until this variable is configured. Configure each deployment app with its
repository in normalized `owner/repo` form and create a pending release whose
`version` is the commit SHA sent by GitHub.

Expose the isolated URL configuration at this path:

```
path('integrations/github/', include('devops.github_urls'))
```

The resulting endpoint is:

```
POST /integrations/github/workflow-run/
```

## Contract

GitHub must send the `workflow_run` event with `X-Hub-Signature-256` and
`X-GitHub-Delivery`. Payloads are limited to 1 MiB and are authenticated with
HMAC SHA-256 using constant-time comparison. Only `completed` runs with a
`success` conclusion are considered.

The handler reads `repository.full_name` and `workflow_run.head_sha`, then
matches exactly one `pending` `DeploymentRelease` by application repository and
release version. It queues that release through the existing deployment service
only when deployment approval is not required. A pending deployment approval,
or the global forced-deployment-approval setting, returns
`awaiting_approval` after recording the delivery and never queues the release.
Unknown, duplicate, unsupported, and non-successful deliveries never execute a
deployment. Audit records retain only the delivery identifier and a fixed safe
summary; they do not retain headers, signatures, secrets, or the raw payload.

Responses use `{ "ok": boolean, "code": string }`. A queued deployment adds
`release_id`; accepted but ignored deliveries return `202` with an explanatory
code. Invalid input returns `400`, invalid signatures return `401`, ambiguous
matching releases return `409`, and missing configuration returns `503`.
