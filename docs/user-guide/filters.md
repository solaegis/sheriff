# Filters

Filters narrow down which resources a policy applies to. All filters must match for the policy to trigger (AND logic).

## Filter Syntax

```yaml
filters:
  - "field.path": condition
```

## Operators

### Presence Operators

| Operator | Description | Example |
|----------|-------------|---------|
| `present` | Field exists and is not empty | `"labels.env": present` |
| `absent` | Field missing or empty | `"labels.env": absent` |

### Equality Operators

| Operator | Description | Example |
|----------|-------------|---------|
| `value` | Exact match | `"labels.env": "prod"` |
| `not_equals:` | Not equal | `"labels.env": not_equals:prod` |

### Pattern Matching

| Operator | Description | Example |
|----------|-------------|---------|
| `regex:` | Regular expression | `"name": regex:^prod-.*` |
| `contains:` | List/dict contains | `"metadata.items": contains:enable-oslogin` |

### Numeric Comparison

| Operator | Description | Example |
|----------|-------------|---------|
| `>` | Greater than | `"diskSizeGb": ">100"` |
| `<` | Less than | `"diskSizeGb": "<50"` |

### List Membership

| Operator | Description | Example |
|----------|-------------|---------|
| `in:` | Value in list | `"zone": { in: [us-east4-a, us-east4-b] }` |
| `not_in:` | Value not in list | `"zone": { not_in: [us-west1-a] }` |

## Field Paths

Use dot notation to access nested fields:

```yaml
# Simple field
"status": "RUNNING"

# Nested field
"labels.env": "prod"

# Array index
"networkInterfaces.0.accessConfigs": present

# Deeply nested
"shieldedInstanceConfig.enableSecureBoot": false
```

## Examples

### Check if instance has external IP

```yaml
filters:
  - "networkInterfaces.0.accessConfigs": present
```

### Check if instance is NOT in production

```yaml
filters:
  - "labels.env": not_equals:prod
```

### Check if name starts with "dev-"

```yaml
filters:
  - "name": regex:^dev-
```

### Check if zone is in approved list

```yaml
filters:
  - "zone":
      in:
        - us-east4-a
        - us-east4-b
        - us-central1-a
```

### Check if disk is larger than 100GB

```yaml
filters:
  - "diskSizeGb": ">100"
```

### Combine multiple conditions (AND)

```yaml
filters:
  - "labels.env": "dev"
  - "guestAccelerators": present
  - "scheduling.preemptible": false
```

## See Also

- [Policies Reference](policies.md)
- [Actions Reference](actions.md)
