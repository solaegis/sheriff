# Contributing

## Development Setup

```bash
# Clone the repository
git clone https://github.com/solaegis/sheriff.git
cd sheriff

# Install all dependencies (dev + docs)
uv sync --group dev --group docs

# Install pre-commit hooks
uv run pre-commit install
```

## Development Workflow

### Running Checks

```bash
# Run all quality checks
task check

# Individual checks
task lint          # Ruff linting
task format        # Ruff formatting
task check:type    # Mypy type checking
task test          # Pytest
```

### Available Tasks

```bash
task --list
```

| Task | Description |
|------|-------------|
| `setup` | Setup development environment |
| `lint` | Run linter |
| `format` | Run formatter |
| `check` | Run all quality checks |
| `check:type` | Run static type analysis |
| `test` | Run tests |
| `release` | Create a new release |
| `pip:audit` | Audit dependencies for vulnerabilities |
| `upgrade` | Upgrade all dependencies |
| `docs:serve` | Serve documentation locally |
| `docs:build` | Build documentation |

## Commit Convention

We use [Conventional Commits](https://www.conventionalcommits.org/):

```
type(scope): description

[optional body]

[optional footer]
```

### Types

| Type | Description |
|------|-------------|
| `feat` | New feature |
| `fix` | Bug fix |
| `docs` | Documentation |
| `refactor` | Code refactoring |
| `test` | Tests |
| `chore` | Maintenance |

### Examples

```bash
git commit -m "feat(policies): add region restriction policy"
git commit -m "fix(dns): handle missing zone config"
git commit -m "docs: update filter reference"
```

## Code Style

- **Python 3.11+** required
- **Ruff** for linting and formatting
- **Google-style docstrings**
- **Type hints** on all functions

### Example

```python
def process_resource(resource: dict[str, Any], policy: Policy) -> bool:
    """Process a resource against a policy.

    Args:
        resource: The GCP resource dictionary.
        policy: The policy to evaluate.

    Returns:
        True if the policy matched, False otherwise.
    """
    ...
```

## Documentation

```bash
# Serve docs locally
task docs:serve

# Build docs
task docs:build
```

View at http://localhost:8000
