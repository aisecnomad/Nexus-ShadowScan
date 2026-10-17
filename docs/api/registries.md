# Vendor registries

Vendor registries are cloud-provider or platform-level registries of deployed AI agents: AWS
Agent Registry, Microsoft Agent 365, Google Agent Registry and similar. A connector that reads
one of these yields one finding per registry record rather than per deployed resource. The
findings carry a `registry_record` metadata block that describes the record's registration
status, descriptor type and resource bindings.

## Registry record contract

Every registry-record finding carries `metadata["registry_record"]` with the schema
`shadowscan.registry-record/v1`:

```json
{
  "schema": "shadowscan.registry-record/v1",
  "registry": "aws-agent-registry",
  "registry_id": "arn:aws:...:registry/abcd",
  "record_id": "rec-123",
  "status": "approved",
  "descriptor_type": "agent",
  "bindings": [
    {
      "resource": "<exact finding.resource of the deployed object>",
      "provider": "aws",
      "account": "123456789012",
      "region": "us-east-1",
      "coverage": "in-scope"
    }
  ],
  "publisher": "platform-team",
  "updated_at": "2026-09-01T00:00:00Z",
  "listing_complete": true,
  "approval_mode": "manual"
}
```

## Reconciliation statuses

| Status | Meaning |
|--------|---------|
| `approved` | The record is sanctioned in the vendor registry |
| `pending` | Awaiting approval |
| `rejected` | Rejected by the registry |
| `unknown` | Status not reported by the registry |

## Trusted approvals

`TrustedApprovals` maps registry types to the account IDs and registry IDs the operator trusts.
Findings from trusted registries with `approved` status contribute to inventory reconciliation
even without a local Capability Card.

::: shadowscan.registries
    options:
      show_root_heading: true
      members_order: source
      show_source: false
      docstring_style: google
