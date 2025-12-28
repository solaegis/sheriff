# Sheriff

**GCP Resource Life-Cycle Management Tool**

Sheriff is a policy-driven automation framework for managing Google Cloud Platform resources. It subscribes to GCP Pub/Sub events and applies configurable policies to enforce security, compliance, and operational standards.

## Features

- **Policy-Driven Automation** - Define declarative policies in YAML
- **Real-Time Event Processing** - React to GCP resource changes via Pub/Sub
- **Security Enforcement** - Block external IPs, require Shielded VMs, enforce labels
- **Cloud-Native DNS** - Automatic DNS registration via Cloud DNS
- **Asset Inventory** - Integration with GCP Asset Inventory
- **Alerting** - Slack notifications for policy violations

## Quick Start

```bash
# Clone the repository
git clone https://github.com/solaegis/sheriff.git
cd sheriff

# Install dependencies with uv
uv sync

# Configure settings
cp settings.yaml.example settings.yaml
# Edit settings.yaml with your configuration

# Run checks
task check

# Start sheriff
uv run python sheriff.py
```

## Documentation

- [Installation Guide](getting-started/installation.md)
- [Configuration Reference](getting-started/configuration.md)
- [Policy DSL Reference](user-guide/policies.md)
- [API Documentation](api/sheriff.md)

## Architecture

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│  GCP Event  │────▶│   Pub/Sub   │────▶│   Sheriff   │
└─────────────┘     └─────────────┘     └──────┬──────┘
                                               │
                    ┌──────────────────────────┼──────────────────────────┐
                    │                          │                          │
              ┌─────▼─────┐            ┌───────▼───────┐          ┌───────▼───────┐
              │  Policy   │            │   Cloud DNS   │          │    Slack      │
              │  Engine   │            │  Registration │          │    Alerts     │
              └───────────┘            └───────────────┘          └───────────────┘
```

## License

Copyright © Solaegis
