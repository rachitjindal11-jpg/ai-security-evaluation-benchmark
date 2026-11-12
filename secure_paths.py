"""A simple secure filesystem path validation demonstration."""
from pathlib import Path


def resolve_within(root: Path, user_path: str) -> Path:
    """Resolve a candidate and reject paths that escape the configured root.

    Note: path resolution alone is not a defense against concurrent symlink swaps.
    """
    base = root.resolve(strict=True)
    candidate = (base / user_path).resolve(strict=False)
    if not candidate.is_relative_to(base):
        raise ValueError("Path escapes allowed root")
    return candidate
