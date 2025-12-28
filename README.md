# 🤠 Sheriff

<div align="center">

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/downloads/)
[![Ruff](https://img.shields.io/badge/Linter-Ruff-000000.svg?style=for-the-badge&logo=ruff&logoColor=white)](https://github.com/astral-sh/ruff)
[![Mypy](https://img.shields.io/badge/Types-Mypy-blue.svg?style=for-the-badge&logo=python&logoColor=white)](https://github.com/python/mypy)
[![Conventional Commits](https://img.shields.io/badge/Commits-Conventional-yellow.svg?style=for-the-badge&logo=conventionalcommits&logoColor=white)](https://conventionalcommits.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg?style=for-the-badge)](LICENSE)
[![Repo Size](https://img.shields.io/github/repo-size/solaegis/sheriff?style=for-the-badge)](https://github.com/solaegis/sheriff)

**Sheriff - The GCP Resource Life-Cycle Management Authority**

*Enforce security, compliance, and operational standards across your Google Cloud Platform footprint in real-time.*

</div>

---

Sheriff is a high-performance, asynchronous automation framework designed to safeguard your Google Cloud Platform resources. By consuming GCP Pub/Sub event streams, Sheriff applies declarative policies to evaluate resource changes and trigger remediation actions instantly.

## 🚀 Key Capabilities

- 🔒 **Security Hardening**: Instantly react to insecure configurations (e.g., external IPs, non-shielded VMs).
- 📋 **Declarative Policy DSL**: define complex logic in standardized YAML policies.
- ⚡ **Asynchronous Core**: built on `asyncio` and `httpx` for massive scale and speed.
- 🌐 **Automated DNS**: Seamlessly manage Cloud DNS records based on resource state.
- 📊 **Metric-Driven**: Built-in integration with Google Cloud Monitoring and Logging.
- 🔔 **Intelligent Alerting**: Multi-channel notifications via Slack and structured logs.

## Quick Start

```bash
# Install with uv
uv sync

# Configure
cp settings.yaml.example settings.yaml
vim settings.yaml

# Run checks
task check

# Start sheriff
uv run sheriff
```

## Documentation

📚 **[Full Documentation](https://solaegis.github.io/sheriff)**

- [Installation Guide](docs/getting-started/installation.md)
- [Configuration Reference](docs/getting-started/configuration.md)
- [Policy DSL Reference](docs/user-guide/policies.md)
- [API Documentation](docs/api/sheriff.md)

## Example Policy

```yaml
policies:
  - name: no-external-ip
    description: "Block instances with public IP addresses"
    resource: instance
    severity: high
    filters:
      - "networkInterfaces.0.accessConfigs": present
    actions:
      - alert

  - name: require-env-label
    description: "Require 'env' label on all instances"
    resource: instance
    filters:
      - "labels.env": absent
    actions:
      - alert
```

## Development

```bash
# Setup development environment
task setup

# Run all checks
task check

# Serve documentation locally
task docs:serve
```

## License

Distributed under the MIT License. See `LICENSE` for more information.

Copyright © 2025 Solaegis
