# Python Project Rules

These rules apply to all Python development in this project.

## Environment & Dependency Management
- Always use `uv` for environment and dependency management.
- Do not use `pip` directly.
- Add new dependencies using `uv add` or `uv add --dev`.
- Ensure `uv.lock` is kept up-to-date.

## Code Quality
- Enforce `Ruff` for linting and formatting.
- All code must pass `task lint` and `task format` before submission.
- Use Google-style docstrings for all functions and classes.

## Task Orchestration
- Use `Taskfile.yaml` to define and run common tasks.
- Avoid running raw commands when a task exists (e.g., use `task lint` instead of `uv run ruff check .`).

## Commit & Release
- Use Conventional Commits.
- Use `cz bump` via `task release` for versioning and changelog generation.
- Ensure all commits pass `pre-commit` hooks.
