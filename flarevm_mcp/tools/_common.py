"""Shared helpers for tool modules."""


def _text(content):
    """Handlers return plain text; dispatch wraps it. Kept for the migrated bodies."""
    return str(content)
