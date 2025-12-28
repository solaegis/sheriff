# Configuration

Sheriff uses two YAML configuration files:

- `settings.yaml` - Runtime configuration (GCP settings, integrations)
- `policies.yaml` - Policy definitions

## settings.yaml Reference

```yaml
# Sheriff configuration
sheriff:
  pubsub:
    subscription: "projects/YOUR_PROJECT/subscriptions/sheriff-events"

# DNS configuration
dns:
  provider: "cloud_dns"
  cloud_dns:
    project: "your-gcp-project"
    managed_zone: "your-zone-name"
    domain_suffix: "example.com"
    default_ttl: 300
    nameserver: "1.1.1.2"

# Inventory configuration
inventory:
  provider: "gcp_asset"
  gcp_asset:
    scope: "folders/123456789"  # or organizations/123456789
    asset_types:
      - "compute.googleapis.com/Instance"

# Alerting
slack:
  webhook_url: "${SLACK_WEBHOOK}"  # Use environment variable
```

## Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `GOOGLE_APPLICATION_CREDENTIALS` | Path to service account key | No (uses ADC) |
| `GCP_PROJECT` | Default GCP project | No |
| `SLACK_WEBHOOK` | Slack webhook URL for alerts | Yes |

## Example Configuration

### Minimal Setup

```yaml
sheriff:
  pubsub:
    subscription: "projects/my-project/subscriptions/sheriff"

dns:
  provider: "cloud_dns"
  cloud_dns:
    project: "my-project"
    managed_zone: "my-zone"
    domain_suffix: "gcp.company.com"
```

### Production Setup

```yaml
sheriff:
  pubsub:
    subscription: "projects/prod-infra/subscriptions/sheriff-compute"

dns:
  provider: "cloud_dns"
  cloud_dns:
    project: "prod-infra"
    managed_zone: "prod-internal"
    domain_suffix: "prod.gcp.company.com"
    default_ttl: 300
    nameserver: "8.8.8.8"

inventory:
  provider: "gcp_asset"
  gcp_asset:
    scope: "organizations/123456789"
    asset_types:
      - "compute.googleapis.com/Instance"
      - "compute.googleapis.com/Disk"
```

## Next Steps

- [Define policies](../user-guide/policies.md)
- [Available actions](../user-guide/actions.md)
