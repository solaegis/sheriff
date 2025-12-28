# Policies

Policies are the core of Sheriff's automation. Each policy defines:

1. **Resource type** to match
2. **Filters** to narrow down resources
3. **Actions** to execute on matching resources

## Policy Structure

```yaml
policies:
  - name: policy-name           # Unique identifier
    description: "Description"  # Human-readable description
    resource: instance          # GCP resource type
    severity: high              # high | medium | low
    filters:                    # Matching conditions
      - "labels.env": present
    actions:                    # Actions to execute
      - alert
      - dns
```

## Resource Types

| Resource Type | Description |
|---------------|-------------|
| `instance` | Compute Engine VMs |
| `forwardingRule` | Load Balancer forwarding rules |

## Example Policies

### Security: Block External IPs

```yaml
- name: no-external-ip
  description: "Block instances with public IP addresses"
  resource: instance
  severity: high
  filters:
    - "networkInterfaces.0.accessConfigs": present
  actions:
    - alert
```

### Compliance: Require Labels

```yaml
- name: require-env-label
  description: "Require 'env' label on all instances"
  resource: instance
  severity: high
  filters:
    - "labels.env": absent
  actions:
    - alert
```

### Operational: Auto-Register DNS

```yaml
- name: instance-dns-registration
  description: "Auto-register DNS for labeled instances"
  resource: instance
  filters:
    - "labels.dns": present
  actions:
    - dns
    - inventory
```

### Cost: Block GPUs in Non-Prod

```yaml
- name: no-gpu-in-nonprod
  description: "Block GPU instances in non-production"
  resource: instance
  severity: medium
  filters:
    - "guestAccelerators": present
    - "labels.env": not_equals:prod
  actions:
    - alert
```

## Policy Categories

Sheriff includes policies for:

| Category | Purpose |
|----------|---------|
| **Security** | External IP blocking, Shielded VM, service account restrictions |
| **Compliance** | Label requirements, region restrictions |
| **Cost** | Instance size limits, GPU restrictions |
| **Operational** | DNS registration, asset tracking |

## See Also

- [Filter Reference](filters.md)
- [Action Reference](actions.md)
