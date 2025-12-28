# Actions

Actions define what Sheriff does when a policy matches a resource.

## Available Actions

| Action | Description | Severity |
|--------|-------------|----------|
| `alert` | Send Slack notification + Cloud Logging | High |
| `log` | Send to Cloud Logging only | Low |
| `stop` | Stop the compute instance | Critical |
| `remediate` | Auto-fix policy violations | Medium |
| `dns` | Register/update DNS record | Operational |
| `inventory` | Log asset inventory event | Operational |

## Alert

Sends a Slack notification and logs the violation to Cloud Logging.

```yaml
actions:
  - alert
```

**Output Example:**
```
🚨 Policy Violation: no-external-ip
• Resource: my-instance
• Project: my-project
• Severity: HIGH
• Description: Block instances with public IP addresses
```

## Log

Records the policy match in Cloud Logging without sending alerts.

```yaml
actions:
  - log
```

Use for informational policies that don't require immediate attention.

## Stop

Stops a compute instance immediately.

!!! warning
    Use with caution. This action stops running workloads.

```yaml
actions:
  - alert
  - stop
```

## Remediate

Auto-fixes policy violations. Currently supports:

- **Adding missing labels**

```yaml
- name: add-default-labels
  resource: instance
  filters:
    - "labels.managed-by": absent
  actions:
    - remediate
  remediation:
    add_labels:
      managed-by: sheriff
```

## DNS

Registers or updates DNS records in Cloud DNS.

```yaml
filters:
  - "labels.dns": present
actions:
  - dns
```

Requirements:
- Instance must have `labels.dns: present`
- Cloud DNS must be configured in `settings.yaml`

## Inventory

Logs inventory events to Cloud Logging for asset tracking.

```yaml
actions:
  - inventory
```

## Combining Actions

Actions execute in order:

```yaml
actions:
  - alert      # First: notify
  - stop       # Then: stop instance
```

## See Also

- [Policies Reference](policies.md)
- [Filter Reference](filters.md)
