# Installation

## Prerequisites

- Python 3.11 or higher
- [uv](https://docs.astral.sh/uv/) (recommended) or pip
- GCP project with appropriate permissions
- Pub/Sub subscription for GCP audit logs

## Install with uv (Recommended)

```bash
# Clone the repository
git clone https://github.com/solaegis/sheriff.git
cd sheriff

# Install dependencies
uv sync

# Install with docs dependencies
uv sync --group docs
```

## Install with pip

```bash
# Clone the repository
git clone https://github.com/solaegis/sheriff.git
cd sheriff

# Create virtual environment
python -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -e .
```

## GCP Setup

### 1. Enable Required APIs

```bash
gcloud services enable \
    pubsub.googleapis.com \
    cloudasset.googleapis.com \
    dns.googleapis.com \
    monitoring.googleapis.com \
    logging.googleapis.com
```

### 2. Create Pub/Sub Subscription

Create a sink to route audit logs to Pub/Sub:

```bash
gcloud logging sinks create sheriff-sink \
    pubsub.googleapis.com/projects/YOUR_PROJECT/topics/sheriff-events \
    --log-filter='resource.type="gce_instance"'
```

### 3. Service Account Permissions

Sheriff requires the following IAM roles:

- `roles/pubsub.subscriber` - Read from Pub/Sub
- `roles/compute.viewer` - Read compute resources
- `roles/dns.admin` - Manage Cloud DNS records
- `roles/cloudasset.viewer` - Query Asset Inventory
- `roles/monitoring.metricWriter` - Write custom metrics

## Verify Installation

```bash
# Run all quality checks
task check

# View available tasks
task --list
```

## Next Steps

- [Configure settings.yaml](configuration.md)
- [Define policies](../user-guide/policies.md)
