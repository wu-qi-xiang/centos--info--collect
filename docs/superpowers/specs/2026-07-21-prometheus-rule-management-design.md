# PrometheusRule Management Design

## Goal

Add a dedicated DevOps page for querying, viewing, editing, and deleting
existing `monitoring.coreos.com/v1` `PrometheusRule` resources from configured
Kubernetes clusters. The page uses the current encrypted cluster kubeconfig
flow and synchronizes each approved mutation directly to the selected cluster.

## Scope

- Present a cluster dropdown styled consistently with the existing K8s cluster
  list page.
- Query all namespaces in the selected cluster and list only
  `PrometheusRule` custom resources.
- Show a complete YAML document for an explicitly selected rule.
- Update an existing rule from YAML only when its `metadata.resourceVersion`
  matches the currently stored Kubernetes resource version.
- Delete one explicitly selected rule after a second confirmation.
- Keep create-rule support out of this phase.

## Authorization And Data Handling

- `MODULE_CLUSTER` viewers can list rules and view their YAML.
- `MODULE_CLUSTER` administrators can update and delete rules.
- The server accepts only the fixed group, version, and kind above. It derives
  the target namespace and name from the selected resource identity, never
  from an arbitrary Kubernetes URL or user-selected GVK.
- Kubeconfig, tokens, certificates, and raw Kubernetes error bodies never
  appear in templates, JSON responses, or audits.
- Audit entries contain only cluster ID/name, namespace, rule name, action,
  outcome, and resource version. They do not include YAML content.

## Resource Operations

1. The list operation uses Kubernetes `CustomObjectsApi` to list the fixed
   resource across all namespaces.
2. Detail retrieval uses the selected cluster, namespace, and name, then
   serializes the returned fixed resource as YAML for editing.
3. Update parses YAML safely, verifies identity and fixed GVK against the
   selected rule, requires `metadata.resourceVersion`, then replaces the
   namespaced custom object. Kubernetes conflict responses return a safe
   refresh-required error and never overwrite a newer object.
4. Delete uses the selected identity only and is guarded by an explicit
   confirmation value.

## Failure Behavior

- A missing Prometheus Operator CRD, Kubernetes RBAC denial, timeout, offline
  cluster, invalid YAML, identity mismatch, or conflict produces a safe summary
  and does not affect other clusters or rules.
- A failed update/delete does not create local shadow state; the cluster remains
  the source of truth.

## Validation

Tests mock Kubernetes `CustomObjectsApi` and cover cross-namespace listing,
viewer/admin permissions, YAML validation, identity/GVK/resource-version
protection, conflict behavior, delete confirmation, audit sanitization, and
safe Kubernetes failures. No test contacts a live cluster.
