import pytest
from security_eval.secure_paths import resolve_within


def test_allows_child(tmp_path):
    assert resolve_within(tmp_path, "docs/readme.txt") == tmp_path / "docs/readme.txt"


def test_blocks_traversal(tmp_path):
    with pytest.raises(ValueError):
        resolve_within(tmp_path, "../secret.txt")


def test_blocks_absolute_path(tmp_path):
    with pytest.raises(ValueError):
        resolve_within(tmp_path, "/etc/passwd")


def test_blocks_symlink_escape(tmp_path):
    outside = tmp_path.parent / "outside-test"
    outside.mkdir(exist_ok=True)
    (tmp_path / "link").symlink_to(outside, target_is_directory=True)
    with pytest.raises(ValueError):
        resolve_within(tmp_path, "link/secret.txt")
