"""Test scaffolding: every test builds a throwaway project on disk.

Scanning takes a path, so the fixtures are real directories. Keeping them real
(rather than mocking the filesystem) is deliberate: the cross-file pass depends
on what is *actually* on disk next to the config, and a mock would let a broken
HDV202 keep passing forever.
"""

import os
import sys

import pytest

SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)

from headervet.engine import scan  # noqa: E402


@pytest.fixture
def project(tmp_path):
    """Factory: ``project(files={...})`` writes files and returns the root."""

    def _make(files=None):
        for name, content in (files or {}).items():
            target = tmp_path / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8", newline="\n")
        return tmp_path

    return _make


@pytest.fixture
def hits(project):
    """Factory: build a project and return the set of rule ids that fired."""

    def _hits(files):
        root = project(files)
        return {f.rule.id for f in scan(root).findings}

    return _hits


@pytest.fixture
def one(project):
    """Scan a project and return all findings (sorted by rule id)."""

    def _find(files, path="."):
        root = project(files)
        return sorted(scan(path and root).findings, key=lambda f: (f.rule.id, f.line))

    return _find
