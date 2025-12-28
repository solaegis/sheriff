# Architecture

## Overview

Sheriff is a policy-driven automation framework for GCP resources. It subscribes to Pub/Sub events and applies configurable policies.

```
┌─────────────────────────────────────────────────────────────────┐
│                        GCP Environment                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────┐     ┌─────────────┐                           │
│  │   Compute   │────▶│  Audit Log  │                           │
│  │   Engine    │     │   Events    │                           │
│  └─────────────┘     └──────┬──────┘                           │
│                             │                                   │
│                             ▼                                   │
│                      ┌──────────────┐                           │
│                      │   Pub/Sub    │                           │
│                      │ Subscription │                           │
│                      └──────┬───────┘                           │
│                             │                                   │
└─────────────────────────────┼───────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                         Sheriff                                  │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────┐     ┌─────────────┐     ┌─────────────┐       │
│  │   Message   │────▶│   Policy    │────▶│   Action    │       │
│  │  Processor  │     │   Engine    │     │  Handlers   │       │
│  └─────────────┘     └─────────────┘     └──────┬──────┘       │
│                                                  │              │
│  ┌───────────────────────────────────────────────┴──────────┐  │
│  │                     Action Outputs                        │  │
│  ├──────────┬──────────┬──────────┬──────────┬──────────────┤  │
│  │  Slack   │   DNS    │ Logging  │  Stop    │  Remediate   │  │
│  └──────────┴──────────┴──────────┴──────────┴──────────────┘  │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## Core Components

### sheriff.py

Main application entry point:

- **Message Processing**: Pulls messages from Pub/Sub
- **Resource Retrieval**: Fetches full resource details from Compute API
- **Policy Matching**: Delegates to policy_engine
- **Action Dispatch**: Calls appropriate action handlers

### policy_engine.py

Policy evaluation and action execution:

- **Filter Evaluation**: Supports complex filter operators
- **Pattern Matching**: Regex, contains, comparisons
- **Action Handlers**: alert, log, stop, remediate

### cloud_dns.py

Cloud DNS integration:

- **Record Management**: Create, delete, replace A records
- **Zone Management**: Works with managed zones

### gcp_inventory.py

Asset Inventory integration:

- **Instance Listing**: Query instances across org/folder
- **Label Filtering**: Filter by instance labels

## Data Flow

1. **Event Received**: GCP audit log event arrives via Pub/Sub
2. **Message Parsed**: Extract resource type, ID, and project
3. **Resource Fetched**: Get full resource details from Compute API
4. **Policies Evaluated**: Match resource against all policies
5. **Actions Executed**: Run matching policy actions
6. **State Updated**: Store resource in Datastore for deletion tracking

## Threading Model

Sheriff uses threading for concurrency:

- **Main Thread**: Pulls Pub/Sub messages
- **Worker Threads**: Process individual messages
- **Thread-Local Clients**: Each thread has its own API client

!!! note
    `httplib2` is not thread-safe, so each thread creates its own instance.

## Configuration

```
settings.yaml          # Runtime configuration
policies.yaml          # Policy definitions
```

See [Configuration Guide](../getting-started/configuration.md) for details.
