from __future__ import annotations


def resolve_config(
    *,
    cli: str | None,
    environment: str | None,
    config_file: str | None,
    default: str | None,
) -> str | None:
    """Return the highest-precedence value that was explicitly supplied."""
    for value in (default, config_file, environment, cli):
        if value is not None:
            return value
    return None
