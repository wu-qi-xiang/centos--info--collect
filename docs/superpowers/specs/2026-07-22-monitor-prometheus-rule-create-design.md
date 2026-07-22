# Monitor PrometheusRule Create Design

## Goal

Allow operators to select a connected Kubernetes cluster from the monitor
alert-settings page, view its PrometheusRule summaries, and create a new rule
without duplicating the existing edit/delete implementation.

## Scope

1. Add a PrometheusRule section to `/monitor/` with a connected-cluster
   selector and rule summary list.
2. Reuse the existing K8s cluster connection records and PrometheusRule list
   service; do not create a parallel cluster or credential configuration.
3. Add a dedicated create service/API/view path. It validates one
   `monitoring.coreos.com/v1` PrometheusRule YAML document with valid
   `metadata.name` and `metadata.namespace`, and rejects `resourceVersion`.
4. Show the create form only to K8s cluster administrators. View access
   requires the existing K8s cluster read permission.
5. Keep existing update/delete paths, optimistic `resourceVersion` checks,
   audit masking, and direct-management page behavior unchanged.

## Design

The alert-settings view loads only clusters accessible through the existing
cluster module. Selecting a cluster uses a `cluster` query parameter and
renders rule summaries: namespace, name, resource version, and creation time.
Each summary links to the existing DevOps PrometheusRule detail page.

For an administrator, the same section renders a YAML textarea and posts to a
monitor-owned create route. That route delegates all Kubernetes interaction to
a new DevOps service function, so cluster credential loading, API client
cleanup, error normalization, and timeout handling remain centralized.

Creation YAML uses a separate validator from replacement: it allows no
`metadata.resourceVersion`, requires exactly one approved resource kind and
identity, and calls Kubernetes `create_namespaced_custom_object`. On success,
the audit log includes only cluster identity, namespace, rule name, action,
and safe outcome. It never stores or returns kubeconfig, YAML in an API
response, raw Kubernetes errors, or credentials.

## Permission And Error Behavior

The monitor page remains available to its established monitor roles. The
PrometheusRule section is omitted for users without K8s cluster read access.
Users with K8s read access can list and follow details but cannot see the
creation form. K8s cluster administrators can submit it with CSRF protection.
Service failures map to the existing bounded Kubernetes messages; validation
errors keep the submitted YAML only in the same server-side form response.

## Acceptance Criteria

- A cluster-read user can select a configured cluster from alert settings and
  see only safe PrometheusRule summaries.
- A cluster administrator can create a validated rule and receives a safe
  confirmation; the audit does not contain YAML or kubeconfig.
- Invalid kind, identity, multiple YAML documents, resourceVersion, and
  Kubernetes errors produce safe failures without creating a resource.
- Users without cluster permission cannot read the section; users without
  cluster-admin permission cannot create.
- Existing PrometheusRule update/delete tests and routes remain compatible.
