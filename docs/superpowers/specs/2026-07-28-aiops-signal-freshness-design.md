# AIOps Signal Freshness Design

## Goal

Provide a read-only AIOps view that identifies visible hosts whose CPU, memory,
or disk observations are missing or stale before an incident is inferred from
incomplete telemetry.

## Approach

The analysis reads the latest `MetricSample` for the three existing metric
categories. A sample at most one hour old is fresh. Each visible host is
classified as `healthy` when all categories are fresh, `partial` when at least
one category is fresh but one or more are missing or stale, `stale` when every
known category is older than one hour, or `absent` when no category was ever
observed. Results are bounded and deterministically ordered by operational
urgency, then host ID.

The protected API requires session login, monitor-history viewer permission,
and applies `visible_hosts_for_request`. It returns only host display name,
overall state, and each metric's fixed `fresh`/`missing`/`stale` state. It
omits metric values, host IPs, credentials, metric source data, and timestamps.
It ignores future samples and considers a sample exactly one hour old fresh. It
makes no writes and calls no external service.

## UI

The existing AIOps dashboard exposes the endpoint only to authorized viewers.
A Signal Freshness tab performs an explicit user-triggered GET for either the
last six or twenty-four hours of inspection context. It has loading, empty,
and error states and has no remediation or polling control.

## Validation

Tests cover all four states, bounds, scope, permission, invalid window,
GET-only behavior, and sensitive-field omission. Validation also includes the
AIOps and DevOps regression suites, Django checks, migration dry run, JS syntax,
and anonymous HTTP protection.
